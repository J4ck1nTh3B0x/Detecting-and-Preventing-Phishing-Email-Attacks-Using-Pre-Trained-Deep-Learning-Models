import logging
import logging.config
import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification
import re
import threading
from pathlib import Path

# Import configuration
from config import (
    LOGGING, MODEL_DIR, MODEL_PATH, CONFIG_PATH, TOKENIZER_PATH,
    CACHE_DIR, EMAIL_CACHE_DIR, THREAT_INTEL_CACHE
)

# Configure logging
logging.config.dictConfig(LOGGING)
logger = logging.getLogger("phishing_detector")

# Thread safety for tokenizer
_tokenizer_lock = threading.Lock()


class PhishingDetector:
    def __init__(self):
        self.model = None
        self.tokenizer = None
        self.device = "cuda" if torch.cuda.is_available() else "cpu"
        logger.info(f"Device set to use {self.device}")

    def load_model(self, model_path: str):
        """
        Load local fine-tuned model (e.g. your mBERT phishing_mail_detect_model).
        """
        try:
            self.tokenizer = AutoTokenizer.from_pretrained(model_path)
            self.model = AutoModelForSequenceClassification.from_pretrained(model_path)
            self.model.to(self.device)

            model_type = getattr(self.model.config, "model_type", "unknown")
            num_labels = getattr(self.model.config, "num_labels", "unknown")
            id2label = getattr(self.model.config, "id2label", {})
            label2id = getattr(self.model.config, "label2id", {})

            logger.info(f"[phishing_detector] Loaded transformers model from {model_path}")
            logger.info(f"[phishing_detector] Model architecture: {model_type}")
            logger.info(f"[phishing_detector] Number of labels: {num_labels}")
            logger.info(f"[phishing_detector] Label mapping: id2label={id2label}, label2id={label2id}")

        except Exception as e:
            logger.error(f"[phishing_detector] Failed to load model: {e}")

    
    def preprocess_for_model(self, text: str) -> str:
        """
        Normalize cleaned email text for model understanding.
        Keeps context while removing token noise the model can't interpret.
        """
        # Replace link placeholders with a neutral token
        text = re.sub(r"\[URL:[^\]]+\]", " [LINK] ", text)

        # Replace mailto or www patterns with [LINK]
        text = re.sub(r"https?://\S+|www\.\S+|mailto:\S+", " [LINK] ", text)

        # Remove long random hash-like strings (tracking IDs etc.)
        text = re.sub(r"\b[a-zA-Z0-9]{20,}\b", "", text)

        # Normalize multiple spaces and newlines
        text = re.sub(r"\s+", " ", text).strip()

        return text

    def predict(self, text: str):
        """
        Run the phishing model and produce a human-friendly explanation.
        """
        if not self.model or not self.tokenizer:
            logger.warning("[phishing_detector] Model not loaded.")
            return {
                "label": "unknown",
                "score": 0.0,
                "explanation": "The phishing detection model is not available for analysis."
            }

        # Handle extremely short emails
        if not text or len(text.split()) < 5:
            logger.info("[phishing_detector] Text too short for reliable analysis.")
            return {
                "label": "unknown",
                "score": 0.0,
                "explanation": "This email is too short for reliable analysis."
            }
        
        # Clean text for model understanding
        text = self.preprocess_for_model(text)

        # --- SLIDING WINDOW INFERENCE SETUP ---
        # Use tokenizer/model max length but cap at 512 for safety unless tokenizer supports longer
        tokenizer_max = getattr(self.tokenizer, "model_max_length", 512) or 512
        max_len = min(512, int(tokenizer_max))

        # Build token ids once (no truncation) and perform overlapping sliding window
        with _tokenizer_lock:
            token_ids = self.tokenizer.encode(text, add_special_tokens=True, truncation=False)

        # quick path if short enough
        if len(token_ids) <= max_len:
            with _tokenizer_lock:
                inputs = self.tokenizer(
                    text,
                    truncation=True,
                    padding=True,
                    max_length=max_len,
                    return_tensors="pt"
                ).to(self.device)
                with torch.no_grad():
                    outputs = self.model(**inputs)
                    scores = torch.nn.functional.softmax(outputs.logits, dim=-1)[0]
                    label_idx = torch.argmax(scores).item()
                    label = self.model.config.id2label[label_idx].lower()
                    confidence = float(scores[label_idx].cpu().numpy())

        else:
            # sliding window params: choose overlap (25% of window or 128 tokens cap)
            overlap = min(128, max(32, max_len // 4))
            stride = max_len - overlap
            if stride <= 0:
                stride = max_len // 2

            # create list of token-id chunks with overlap
            chunks_ids = []
            for start in range(0, len(token_ids), stride):
                chunk = token_ids[start:start + max_len]
                if not chunk:
                    continue
                chunks_ids.append(chunk)
                if start + max_len >= len(token_ids):
                    break

            # convert id-chunks back to text for safe tokenization on each chunk
            chunk_texts = []
            for ids in chunks_ids:
                t = self.tokenizer.decode(ids, skip_special_tokens=True).strip()
                if t:
                    chunk_texts.append(t)

            if not chunk_texts:
                # fallback
                label = "unknown"
                confidence = 0.0
            else:
                # determine index of the 'phish' label in config if available
                id2label = getattr(self.model.config, "id2label", {})
                phish_idx = None
                try:
                    for k, v in id2label.items():
                        if str(v).lower() == "phish":
                            phish_idx = int(k)
                            break
                except Exception:
                    phish_idx = None
                if phish_idx is None:
                    # fallback to 1 if two-label model, else 0
                    phish_idx = 1 if len(id2label) >= 2 else 0

                # batch chunk inference for speed and reduced overhead
                batch_size = 8
                chunk_probs = []  # list of phish-probabilities per chunk
                for i in range(0, len(chunk_texts), batch_size):
                    batch_texts = chunk_texts[i:i + batch_size]
                    with _tokenizer_lock:
                        inputs = self.tokenizer(
                            batch_texts,
                            truncation=True,
                            padding=True,
                            max_length=max_len,
                            return_tensors="pt"
                        ).to(self.device)

                        with torch.no_grad():
                            out = self.model(**inputs)
                            probs = torch.nn.functional.softmax(out.logits, dim=-1).cpu()
                            # extract phish probability per example, fallback to index if necessary
                            for p in probs:
                                # safe indexing
                                try:
                                    ph = float(p[phish_idx].item())
                                except Exception:
                                    # fallback: take max prob of non-zero index
                                    ph = float(p.max().item())
                                chunk_probs.append(ph)

                # aggregation strategies
                avg_phish = float(sum(chunk_probs) / len(chunk_probs))
                max_phish = float(max(chunk_probs))
                # weighted combination: favors average but respects peak
                combined = (avg_phish * 0.6) + (max_phish * 0.4)


                # --- SAFETY-BOOST: Do NOT auto-classify as phish ---
                # Boost only slightly; never let one chunk dominate
                max_conf = max_phish

                if max_conf > 0.98:
                    combined = min(0.92, max(combined, combined + 0.10))
                elif max_conf > 0.92:
                    combined = min(0.88, max(combined, combined + 0.07))
                elif max_conf > 0.85:
                    combined = min(0.82, max(combined, combined + 0.04))

                confidence = combined
                # do not set label here — leave final labeling to the downstream thresholds




        # Remap generic labels
        # ----------------------------
        # POST-PROCESSING ADJUSTMENTS
        # ----------------------------

        # OPTION 2: Short-message heuristic (length only, no content/semantic checks)
        text_len = len(text)
        if text_len < 200:
            confidence *= 0.85

        # OPTION 1: Threshold logic (final decision)
        if confidence >= 0.85:
            label = "phish"
        elif confidence >= 0.65:
            label = "maybephish"
        else:
            label = "safe"

        if label in ["label_0", "0"]:
            label = "safe"
        elif label in ["label_1", "1"]:
            label = "phish"

        explanation = (self._generate_explanation(text, label, confidence))
        return {"label": label, "score": confidence, "explanation": explanation}

    def _generate_explanation(self, text: str, label: str, confidence: float) -> str:
        """
        Create a natural-language explanation for the classification.
        """
        text_lower = text.lower()
        has_links = bool(re.search(r"http[s]?://|www\.", text_lower))
        has_urgent = any(word in text_lower for word in ["verify", "urgent", "account", "password", "click", "login", "confirm"])
        has_money = any(word in text_lower for word in ["payment", "invoice", "bank", "credit", "refund", "payroll"])
        has_threat = any(word in text_lower for word in ["suspend", "limit", "blocked", "failure", "deactivate"])
        has_official = any(word in text_lower for word in ["dear", "support", "team", "customer service", "thank you", "regards"])

        if label == "phish":
            reasons = []
            if has_links:
                reasons.append("it contains links that could redirect to unsafe websites")
            if has_urgent:
                reasons.append("it uses urgent language like ‘verify your account’ or ‘click here’")
            if has_money:
                reasons.append("it mentions financial actions such as payments or refunds")
            if has_threat:
                reasons.append("it threatens account suspension or limitation")
            if not reasons:
                reasons.append("its language and structure resemble known phishing patterns")

            combined = "; ".join(reasons)
            base = f"This email appears suspicious — {combined}."
            conf_note = (
                " The model is highly confident in this prediction."
                if confidence > 0.85
                else " The model is somewhat confident, so review carefully."
            )
            return base + conf_note

        elif label == "safe":
            safe_reasons = []
            if has_official:
                safe_reasons.append("it has a polite and professional tone")
            if not has_links:
                safe_reasons.append("it doesn’t include any suspicious links")
            if not has_urgent and not has_threat:
                safe_reasons.append("it avoids pressure or fear tactics")

            if not safe_reasons:
                safe_reasons.append("its content appears consistent with a normal business email")

            base = f"This email looks safe — {', '.join(safe_reasons)}."
            conf_note = (
                " The model is very confident this is legitimate."
                if confidence > 0.85
                else " However, exercise standard caution."
            )
            return base + conf_note

        else:
            return (
                "The model could not determine if this email is phishing or safe. "
                "It might be too short or unclear to analyze."
            )
