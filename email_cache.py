# email_cache.py
"""
SQLite cache for analyzed emails.

This version MERGES your original helpers with SOC upgrades:
- Keeps your original functions: init_db, pagination/search, update, etc.
- Adds SOC columns: spf_result, dkim_result, dmarc_result, intel_links
- Parses JSON fields robustly (risk_links, intel_links)
- Fixes get_email_by_id to query by id (not msg_id)
- Backward compatible with existing DB (auto-migrations)
"""

import os
import sqlite3
import json
import logging
import traceback
from datetime import datetime
from typing import List, Dict, Any
import base64

# Try to import gmail_utils, but don't fail if it's not available
try:
    from gmail_utils import extract_html_from_email
except ImportError:
    extract_html_from_email = None

logger = logging.getLogger("email_cache")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "emails.db")
DB_FILE = os.path.join(os.path.dirname(__file__), "emails.db")


# -----------------------------------------------------------------------------
# Connection
# -----------------------------------------------------------------------------
def get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn


# -----------------------------------------------------------------------------
# Init + Migration
# -----------------------------------------------------------------------------

def init_db():
    """Initialize DB schema and make sure email_overrides uses canonical columns.

    Canonical emails table is 'emails'.
    Canonical manual override table is 'email_overrides' with columns:
        msg_id TEXT PRIMARY KEY,
        label TEXT,
        score REAL,
        ts INTEGER

    This function will:
    - create emails table if absent
    - create email_overrides if absent with the canonical schema
    - detect legacy override tables/columns and migrate them safely to canonical schema
    """
    logger.info("[email_cache] init_db() starting")
    conn = get_db()
    cur = conn.cursor()

    # 1) ensure primary emails table exists
    cur.execute("""
        CREATE TABLE IF NOT EXISTS emails (
            id TEXT PRIMARY KEY,
            subject TEXT,
            sender TEXT,
            date TEXT,
            snippet TEXT,
            body TEXT,
            raw TEXT,
            prediction_label TEXT,
            prediction_score REAL,
            explanation TEXT,
            html_body TEXT,
            internal_date INTEGER,
            risk_links TEXT DEFAULT '[]',
            attachments TEXT DEFAULT '[]',
            spf_result TEXT,
            dkim_result TEXT,
            dmarc_result TEXT,
            intel_links TEXT DEFAULT '[]',
            analysis_status TEXT DEFAULT 'pending'
        )
    """)

    # 2) Ensure canonical override table exists (idempotent)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS email_overrides (
            msg_id TEXT PRIMARY KEY,
            label TEXT,
            score REAL,
            ts INTEGER
        )
    """)
    conn.commit()

    # 3) Inspect existing override table columns; migrate if legacy schema detected
    try:
        cur.execute("PRAGMA table_info(email_overrides)")
        rows = cur.fetchall()
        existing_cols = {r[1] for r in rows}

        # If canonical columns present -> nothing to do
        if {"msg_id", "label"}.issubset(existing_cols):
            logger.debug("[email_cache] email_overrides in canonical form")
        else:
            # Detect common legacy schemas and migrate
            logger.info("[email_cache] detected non-canonical email_overrides schema, attempting safe migration")
            # Attempt to read legacy known variants
            # Common legacy column sets we've seen: (message_id, override_label, override_score)
            legacy_sets = [
                {"message_id", "override_label"},
                {"message_id", "label"},  # sometimes only different name used
                {"msg_id", "override_label"},
            ]

            matched = None
            for s in legacy_sets:
                if s.issubset(existing_cols):
                    matched = s
                    break

            if matched:
                logger.info("[email_cache] legacy override schema matched columns: %s", matched)
                # create tmp canonical table and copy data
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS email_overrides_tmp (
                        msg_id TEXT PRIMARY KEY,
                        label TEXT,
                        score REAL,
                        ts INTEGER
                    )
                """)
                # Build a safe copy SELECT using best-match column names
                # Try mappings in order of likelihood
                select_clause = None
                if {"message_id", "override_label", "override_score"}.issubset(existing_cols):
                    select_clause = "SELECT message_id, override_label, override_score, COALESCE(ts, 0) FROM email_overrides"
                elif {"message_id", "override_label"}.issubset(existing_cols):
                    select_clause = "SELECT message_id, override_label, NULL, COALESCE(ts, 0) FROM email_overrides"
                elif {"msg_id", "override_label"}.issubset(existing_cols):
                    select_clause = "SELECT msg_id, override_label, NULL, COALESCE(ts, 0) FROM email_overrides"
                elif {"message_id", "label"}.issubset(existing_cols):
                    select_clause = "SELECT message_id, label, NULL, COALESCE(ts, 0) FROM email_overrides"
                else:
                    # Fallback: copy any first two/three columns into canonical positions
                    cols_list = list(existing_cols)
                    # ensure deterministic order
                    cols_list.sort()
                    # build select using available columns (may produce NULLs)
                    c0 = cols_list[0]
                    c1 = cols_list[1] if len(cols_list) > 1 else "NULL"
                    c2 = cols_list[2] if len(cols_list) > 2 else "NULL"
                    select_clause = f"SELECT {c0}, {c1}, {c2}, COALESCE(ts, 0) FROM email_overrides"

                try:
                    cur.execute("BEGIN")
                    cur.execute(f"INSERT OR REPLACE INTO email_overrides_tmp (msg_id, label, score, ts) {select_clause}")
                    cur.execute("DROP TABLE IF EXISTS email_overrides")
                    cur.execute("ALTER TABLE email_overrides_tmp RENAME TO email_overrides")
                    conn.commit()
                    logger.info("[email_cache] legacy email_overrides migrated to canonical schema")
                except Exception as e:
                    conn.rollback()
                    logger.exception("[email_cache] failed to migrate legacy email_overrides: %s", e)
            else:
                # No recognized legacy schema; attempt to coerce by creating canonical table and leaving legacy table untouched
                logger.warning("[email_cache] email_overrides exists with unexpected columns %s. Creating canonical table and leaving legacy content intact.", existing_cols)
                # canonical table already created above; nothing else to do safely

    except Exception as e:
        logger.exception("[email_cache] error while checking/migrating email_overrides: %s", e)
    finally:
        conn.commit()
        conn.close()

    # Run email table migrations (adds new columns to emails if missing)
    try:
        migrate_add_columns()
    except Exception:
        logger.exception("[email_cache] migrate_add_columns() failed during init")

    logger.info("[email_cache] init_db() completed")



# -----------------------------------------------------------------------------
# Manual classification overrides (safe / phish)
# Stored separately so model predictions remain untouched.
# -----------------------------------------------------------------------------

def set_manual_override(msg_id: str, label: str, score: float = 1.0):
    """
    Store a user override:
      label: 'safe' or 'phish'
      score: float (user certainty)
    This function ensures canonical table and writes normalized label.
    """
    if not msg_id:
        logger.warning("[email_cache] set_manual_override called with empty msg_id")
        return

    label_norm = (label or "").strip().lower()
    if label_norm not in ("safe", "phish"):
        logger.warning("[email_cache] set_manual_override ignoring unsupported label: %s", label)
        return

    conn = get_db()
    cur = conn.cursor()
    try:
        # ensure canonical table exists (idempotent)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS email_overrides (
                msg_id TEXT PRIMARY KEY,
                label TEXT,
                score REAL,
                ts INTEGER
            )
        """)
        cur.execute("""
            INSERT OR REPLACE INTO email_overrides (msg_id, label, score, ts)
            VALUES (?, ?, ?, strftime('%s','now'))
        """, (msg_id, label_norm, float(score)))
        conn.commit()
        logger.info("[email_cache] set_manual_override saved %s -> %s", msg_id, label_norm)
    except Exception as e:
        logger.exception("[email_cache] set_manual_override failed: %s", e)
    finally:
        conn.close()


def get_manual_override(msg_id: str):
    """Return override record {label, score, ts} or None."""
    if not msg_id:
        return None
    conn = get_db()
    cur = conn.cursor()
    try:
        # ensure canonical table exists to avoid "no such table" errors
        cur.execute("""
            CREATE TABLE IF NOT EXISTS email_overrides (
                msg_id TEXT PRIMARY KEY,
                label TEXT,
                score REAL,
                ts INTEGER
            )
        """)
        cur.execute("SELECT label, score, ts FROM email_overrides WHERE msg_id = ? LIMIT 1", (msg_id,))
        row = cur.fetchone()
        if not row:
            return None
        return {"label": row[0], "score": row[1], "ts": row[2]}
    except Exception as e:
        logger.exception("[email_cache] get_manual_override failed: %s", e)
        return None
    finally:
        conn.close()



def clear_manual_override(msg_id: str):
    """Delete user override record."""
    conn = get_db()
    cur = conn.cursor()
    try:
        cur.execute("DELETE FROM email_overrides WHERE msg_id = ?", (msg_id,))
        conn.commit()
    except Exception as e:
        logger.error("[email_cache] clear_manual_override failed: %s", e)
    finally:
        conn.close()



def migrate_add_columns():
    """
    Ensure new SOC columns exist.
    (Supersedes old migrate_add_risk_links by covering all fields.)
    """
    conn = get_db()
    cur = conn.cursor()
    try:
        cur.execute("PRAGMA table_info(emails)")
        cols = {c[1] for c in cur.fetchall()}
        migrations = []
        if "risk_links" not in cols:
            migrations.append("ALTER TABLE emails ADD COLUMN risk_links TEXT DEFAULT '[]'")
        if "spf_result" not in cols:
            migrations.append("ALTER TABLE emails ADD COLUMN spf_result TEXT")
        if "dkim_result" not in cols:
            migrations.append("ALTER TABLE emails ADD COLUMN dkim_result TEXT")
        if "dmarc_result" not in cols:
            migrations.append("ALTER TABLE emails ADD COLUMN dmarc_result TEXT")
        if "intel_links" not in cols:
            migrations.append("ALTER TABLE emails ADD COLUMN intel_links TEXT DEFAULT '[]'")
        if "analysis_status" not in cols:
            migrations.append("ALTER TABLE emails ADD COLUMN analysis_status TEXT DEFAULT 'completed'")

        for sql in migrations:
            try:
                cur.execute(sql)
                conn.commit()
                logger.info(f"[email_cache] Applied migration: {sql}")
            except Exception as e:
                logger.warning(f"[email_cache] Migration skipped ({sql}): {e}")
    except Exception as e:
        logger.error("[email_cache] Migration check failed: %s", e)
    finally:
        conn.close()


# -----------------------------------------------------------------------------
# Save / Update
# -----------------------------------------------------------------------------
def cache_email_immediately(**data):
    """
    Cache email immediately after download with minimal analysis.
    Shows emails instantly to users while analysis runs in background.

    Expected keys:
      msg_id (or id), subject, sender, date, snippet, body, raw,
      html_body, internal_date, attachments
    """
    msg_key = data.get("msg_id") or data.get("id")
    if not msg_key:
        logger.warning("[email_cache] cache_email_immediately called without id/msg_id")
        return

    conn = get_db()
    cur = conn.cursor()

    try:
        # Insert with "pending" status - minimal data for immediate display
        cur.execute("""
            INSERT OR REPLACE INTO emails
            (id, subject, sender, date, snippet, body, raw,
             prediction_label, prediction_score, explanation,
             html_body, internal_date, analysis_status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            msg_key,
            data.get("subject"),
            data.get("sender"),
            data.get("date"),
            data.get("snippet"),
            data.get("body", ""),
            data.get("raw"),
            "analyzing",  # Show as analyzing
            0.0,
            "Analysis in progress...",
            data.get("html_body", ""),
            data.get("internal_date"),
            "pending"
        ))

        conn.commit()
        logger.info("[email_cache] Cached email immediately: %s (status: analyzing)", msg_key)
    except Exception as e:
        logger.error("[email_cache] Failed to cache email immediately %s: %s", msg_key, e)
    finally:
        conn.close()


def cache_email(**data):
    """
    Insert or update an email record with complete analysis results.

    Expected keys:
      msg_id (or id), subject, sender, date, snippet, body, raw,
      prediction_label, prediction_score, explanation, html_body, internal_date,
      extra = {
        "risk_links": [...],
        "spf_result": str,
        "dkim_result": str,
        "dmarc_result": str,
        "intel_links": [...]
      }
    """
    # DEBUG: Add detailed logging for database operations
    msg_key = data.get("msg_id") or data.get("id")
    logger.info(f"[DEBUG] Attempting to cache email: {(msg_key or '')[:12]}... (subject: '{data.get('subject', '')[:30]}...')")

    conn = get_db()
    cur = conn.cursor()

    if not msg_key:
        logger.warning("[email_cache] cache_email called without id/msg_id")
        return

    extra = data.get("extra", {}) or {}
    risk_links = extra.get("risk_links", [])
    intel_links = extra.get("intel_links", [])
    attachments = extra.get("attachments", [])  # list of {filename, mimeType, size, attachmentId}
    spf = extra.get("spf_result")
    dkim = extra.get("dkim_result")
    dmarc = extra.get("dmarc_result")


    try:
        # Debug: Log what we're trying to cache
        logger.debug("[email_cache] Attempting to cache email %s: subject='%s', sender='%s'",
                    msg_key, data.get("subject", "")[:50], data.get("sender", "")[:50])

        cur.execute("""
            INSERT OR REPLACE INTO emails
            (id, subject, sender, date, snippet, body, raw,
             prediction_label, prediction_score, explanation,
             html_body, internal_date, risk_links, attachments,
             spf_result, dkim_result, dmarc_result, intel_links, analysis_status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            msg_key,
            data.get("subject"),
            data.get("sender"),
            data.get("date"),
            data.get("snippet"),
            data.get("body"),
            data.get("raw"),
            data.get("prediction_label"),
            float(data.get("prediction_score", 0.0)),
            data.get("explanation"),
            data.get("html_body"),
            data.get("internal_date"),
            json.dumps(risk_links, ensure_ascii=False),
            json.dumps(attachments, ensure_ascii=False),
            spf,
            dkim,
            dmarc,
            json.dumps(intel_links, ensure_ascii=False),
            "completed"  # Mark as completed
        ))

        conn.commit()
        logger.info("[email_cache] Successfully cached email %s", msg_key)
    except Exception as e:
        logger.error("[email_cache] Failed to cache email %s: %s", msg_key, e)
        import traceback
        logger.error("[email_cache] Full traceback: %s", traceback.format_exc())
    finally:
        conn.close()


def get_all_msg_ids() -> list[str]:
    """
    Return a list of all message IDs stored in the cache.
    Used by local re-evaluation loop.
    """
    conn = get_db()
    cur = conn.cursor()
    try:
        cur.execute("SELECT id FROM emails ORDER BY internal_date DESC")
        rows = cur.fetchall()
        return [r["id"] for r in rows]
    except Exception as e:
        logger.error("[email_cache] get_all_msg_ids failed: %s", e)
        return []
    finally:
        conn.close()



def update_email_prediction(
    msg_id: str,
    label: str,
    score: float,
    explanation: str,
    risk_links: List[Dict[str, Any]] | None = None,
    intel_links: List[Dict[str, Any]] | None = None,
    spf: str | None = None,
    dkim: str | None = None,
    dmarc: str | None = None,
):
    """Update phishing prediction and optional SOC intel for an existing record."""
    conn = get_db()
    cur = conn.cursor()
    try:
        cur.execute("""
            UPDATE emails
            SET prediction_label = ?, prediction_score = ?, explanation = ?,
                risk_links = COALESCE(?, risk_links),
                intel_links = COALESCE(?, intel_links),
                spf_result = COALESCE(?, spf_result),
                dkim_result = COALESCE(?, dkim_result),
                dmarc_result = COALESCE(?, dmarc_result)
            WHERE id = ?
        """, (
            label,
            float(score),
            explanation,
            json.dumps(risk_links, ensure_ascii=False) if risk_links is not None else None,
            json.dumps(intel_links, ensure_ascii=False) if intel_links is not None else None,
            spf, dkim, dmarc,
            msg_id
        ))
        conn.commit()

        # --------------------------------------------------------------
        # STRICT-MATCH OVERRIDE AUTO-CLEAR
        # --------------------------------------------------------------
        try:
            override = get_manual_override(msg_id)
            if override:
                manual = (override["label"] or "").strip().lower()
                model  = (label or "").strip().lower()

                # Remove override ONLY when final model label matches user override
                if manual == model:
                    clear_manual_override(msg_id)
        except Exception as e:
            logger.error("[email_cache] override auto-clear failed: %s", e)
    except Exception as e:
        logger.error("[email_cache] update_email_prediction failed: %s", e)
    finally:
        conn.close()


# -----------------------------------------------------------------------------
# Fetch (single)
# -----------------------------------------------------------------------------
def get_cached_email(msg_id: str) -> Dict[str, Any] | None:
    """Fetch one email record by message ID."""
    conn = get_db()
    cur = conn.cursor()
    try:
        cur.execute("SELECT * FROM emails WHERE id = ? LIMIT 1", (msg_id,))
        row = cur.fetchone()
        if not row:
            return None
        data = dict(row)

        # Parse JSON safely
        # Parse JSON safely
        for k in ("risk_links", "intel_links", "attachments"):
            try:
                data[k] = json.loads(data.get(k) or "[]")
            except Exception:
                data[k] = []

        # attachment_count convenience (useful for inbox)
        try:
            data["attachment_count"] = len(data.get("attachments") or [])
        except Exception:
            data["attachment_count"] = 0


        # Compatibility for code using msg_id
        data["msg_id"] = data["id"]
        return data
    except Exception as e:
        logger.error("[email_cache] get_cached_email failed: %s", e)
        return None
    finally:
        conn.close()


def get_email_by_id(msg_id: str) -> Dict[str, Any] | None:
    """
    Retrieve a single cached email record by message ID from the SQLite cache.
    (Fixed to query WHERE id = ?)
    """
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()

        cur.execute("SELECT * FROM emails WHERE id = ? LIMIT 1", (msg_id,))
        row = cur.fetchone()
        conn.close()

        if not row:
            return None

        data = dict(row)
        # Parse JSON safely
        for k in ("risk_links", "intel_links", "attachments"):
            try:
                data[k] = json.loads(data.get(k) or "[]")
            except Exception:
                data[k] = []

        # attachment_count convenience (useful for inbox)
        try:
            data["attachment_count"] = len(data.get("attachments") or [])
        except Exception:
            data["attachment_count"] = 0


        data["msg_id"] = data["id"]
        return data
    except Exception as e:
        logger.error(f"[email_cache] get_email_by_id error: {e}")
        return None



# --- Raw email getter for UI Access ---
def get_email_raw(msg_id: str):
    """
    Return raw email bytes for display and download.
    Compatible wrapper so old code still works.
    """
    item = get_cached_email(msg_id)
    if not item:
        return None

    raw_encoded = item.get("raw")
    if not raw_encoded:
        return None

    try:
        return base64.urlsafe_b64decode(raw_encoded.encode("utf-8"))
    except Exception:
        return None


# -----------------------------------------------------------------------------
# Fetch (lists)
# -----------------------------------------------------------------------------
def get_total_count() -> int:
    """Return total number of emails in cache."""
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM emails")
    total = cur.fetchone()[0]
    conn.close()
    return total


def get_paginated_emails(page: int = 1, per_page: int = 50) -> List[Dict[str, Any]]:
    """
    Return paginated list of cached emails.
    If per_page == -1, returns all.
    """
    conn = get_db()
    cur = conn.cursor()
    if per_page == -1:
        cur.execute("""
            SELECT id, subject, sender, date, snippet,
                   prediction_label, prediction_score, attachments
            FROM emails
            ORDER BY internal_date DESC
        """)

    else:
        offset = (page - 1) * per_page
        cur.execute("""
            SELECT id, subject, sender, date, snippet,
                   prediction_label, prediction_score, attachments
            FROM emails
            ORDER BY internal_date DESC
            LIMIT ? OFFSET ?
        """, (per_page, offset))

    rows = cur.fetchall()
    conn.close()
    result = []
    for r in rows:
        d = dict(r)
        d["msg_id"] = d["id"]  # compatibility
        # parse attachments JSON and provide count (defensive)
        try:
            d["attachments"] = json.loads(d.get("attachments") or "[]")
        except Exception:
            d["attachments"] = []
        d["attachment_count"] = len(d["attachments"])
        result.append(d)

    return result


def search_emails(query: str, page: int = 1, per_page: int = 50) -> List[Dict[str, Any]]:
    """Search emails by subject, sender, or snippet."""
    conn = get_db()
    cur = conn.cursor()
    q = f"%{query}%"
    if per_page == -1:
        cur.execute("""
            SELECT id, subject, sender, date, snippet,
                   prediction_label, prediction_score
            FROM emails
            WHERE subject LIKE ? OR sender LIKE ? OR snippet LIKE ?
            ORDER BY internal_date DESC
        """, (q, q, q))
    else:
        offset = (page - 1) * per_page
        cur.execute("""
            SELECT id, subject, sender, date, snippet,
                   prediction_label, prediction_score
            FROM emails
            WHERE subject LIKE ? OR sender LIKE ? OR snippet LIKE ?
            ORDER BY internal_date DESC
            LIMIT ? OFFSET ?
        """, (q, q, q, per_page, offset))
    rows = cur.fetchall()
    conn.close()
    result = []
    for r in rows:
        d = dict(r)
        d["msg_id"] = d["id"]
        result.append(d)
    return result


def count_search_results(query: str) -> int:
    """Return number of search results for a query."""
    conn = get_db()
    cur = conn.cursor()
    q = f"%{query}%"
    cur.execute("""
        SELECT COUNT(*) FROM emails
        WHERE subject LIKE ? OR sender LIKE ? OR snippet LIKE ?
    """, (q, q, q))
    total = cur.fetchone()[0]
    conn.close()
    return total


def get_cached_emails(limit: int = 100000) -> List[Dict[str, Any]]:
    """
    Return up to `limit` cached email summaries (id + basic fields).
    Useful for rescans and offline jobs.
    """
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        SELECT id, subject, sender, date, snippet, prediction_label, prediction_score
        FROM emails
        ORDER BY internal_date DESC
        LIMIT ?
    """, (limit,))
    rows = cur.fetchall()
    conn.close()
    result = []
    for r in rows:
        d = dict(r)
        d["msg_id"] = d["id"]
        result.append(d)
    return result


def get_email_html_body(msg_id: str):
    """Return HTML body for display inside iframe"""
    try:
        raw = get_email_raw(msg_id)
        if not raw:
            return "<p>(No raw email data found)</p>"

        if extract_html_from_email:
            html = extract_html_from_email(raw)
            return html or "<p>(No HTML content)</p>"
        else:
            return "<p>(HTML extraction not available)</p>"

    except Exception as e:
        logger.error(f"Error extracting HTML: {e}")
        logger.debug(traceback.format_exc())
        return f"<p>Error extracting HTML: {e}</p>"


def fetch_messages(page: int = 1, per_page: int = 25, q: str | None = None, label: str | None = None, db_path: str | None = None):
    """
    Returns paged messages from the emails table for the inbox API.
    The shape of returned rows matches what app.py expects:
      - a list of dicts where each dict contains at least:
        id, subject, sender, date, prediction_label, prediction_score
    """
    conn = None
    try:
        if db_path:
            conn = sqlite3.connect(db_path)
            conn.row_factory = sqlite3.Row
        else:
            conn = get_db()

        cur = conn.cursor()

        # Build WHERE clause using EFFECTIVE label = COALESCE(override.label, emails.prediction_label)
        where_clauses = []
        params = []

        if q:
            where_clauses.append("(e.subject LIKE ? OR e.sender LIKE ?)")
            likeq = f"%{q}%"
            params.extend([likeq, likeq])

        effective_label_sql = "COALESCE(o.label, e.prediction_label)"
        label_values = None
        if label:
            # support comma-separated values e.g. "safe,unknown"
            label_values = [v.strip() for v in label.split(',') if v.strip()]
            if len(label_values) == 1:
                where_clauses.append(f"{effective_label_sql} = ?")
                params.append(label_values[0])
            elif len(label_values) > 1:
                placeholders = ",".join(["?"] * len(label_values))
                where_clauses.append(f"{effective_label_sql} IN ({placeholders})")
                params.extend(label_values)

        where_sql = (" WHERE " + " AND ".join(where_clauses)) if where_clauses else ""

        # Count total
        count_sql = (
            "SELECT COUNT(1) as cnt FROM emails e "
            "LEFT JOIN email_overrides o ON o.msg_id = e.id "
            + where_sql
        )
        try:
            cur.execute(count_sql, tuple(params))
            row = cur.fetchone()
            if row:
                total = row["cnt"]
            else:
                total = 0
        except Exception as e:
            print(f"Error counting messages: {e}")
            total = 0

        # Paging
        if per_page == -1:
            limit_offset_sql = " ORDER BY e.internal_date DESC"
            query_params = tuple(params)
        else:
            limit_offset_sql = " ORDER BY e.internal_date DESC LIMIT ? OFFSET ?"
            offset = (page - 1) * per_page
            query_params = tuple(params + [per_page, offset])

        # Main query
        select_sql = f"""
            SELECT
                e.id AS id,
                e.subject AS subject,
                e.sender AS sender,
                e.date AS date,
                COALESCE(o.label, e.prediction_label, 'unknown') AS prediction_label,
                COALESCE(e.prediction_score, 0.0) AS prediction_score
            FROM emails e
            LEFT JOIN email_overrides o ON o.msg_id = e.id
            {where_sql}
            {limit_offset_sql}
        """

        # Execute the query
        cur.execute(select_sql, query_params)
        rows = [dict(row) for row in cur.fetchall()]

        return {
            "total": total,
            "page": page,
            "per_page": per_page,
            "items": rows
        }

    except Exception as e:
        print(f"Error in fetch_messages: {e}")
        return {
            "total": 0,
            "page": page,
            "per_page": per_page,
            "items": []
        }
    finally:
        if conn:
            try:
                conn.close()
            except:
                pass
