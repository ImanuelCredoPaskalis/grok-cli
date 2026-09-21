#!/usr/bin/env python3
"""
Inject OAuth tokens into 9router SQLite (providerConnections).
DB default: /var/lib/9router/db/data.sqlite

Also enriches providerSpecificData from cli-chat-proxy /v1/user so 9router
can send x-userid + track hasGrokCodeAccess / subscriptionTier.
"""
from __future__ import annotations

import json
import sqlite3
import time
import uuid
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Any


GROK_CLI_USER_URL = "https://cli-chat-proxy.grok.com/v1/user?include=subscription"
GROK_CLI_RESPONSES_URL = "https://cli-chat-proxy.grok.com/v1/responses"
GROK_CLI_VERSION = "0.2.99"
GROK_CLI_CLIENT_ID = "grok-shell"
GROK_CLI_TOKEN_AUTH = "xai-grok-cli"
# free model used for pre-inject usability gate
CHAT_TEST_MODEL = "grok-4.5"


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _expires_at(expires_in: int | None) -> str | None:
    if not expires_in:
        return None
    return datetime.fromtimestamp(time.time() + int(expires_in), tz=timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%S.%f"
    )[:-3] + "Z"


def decode_jwt_payload(token: str | None) -> dict[str, Any] | None:
    if not token:
        return None
    try:
        import base64

        parts = token.split(".")
        if len(parts) < 2:
            return None
        pad = "=" * (-len(parts[1]) % 4)
        return json.loads(base64.urlsafe_b64decode(parts[1] + pad))
    except Exception:
        return None


def decode_jwt_email(token: str | None) -> str | None:
    payload = decode_jwt_payload(token)
    if not payload:
        return None
    return payload.get("email") or payload.get("preferred_username")


def decode_jwt_user_id(token: str | None) -> str | None:
    payload = decode_jwt_payload(token)
    if not payload:
        return None
    return (
        payload.get("principal_id")
        or payload.get("sub")
        or payload.get("user_id")
        or payload.get("userId")
    )


def _merge_psd(old: dict | None, new: dict | None) -> dict:
    """Merge PSD; non-None new values win. None in new does not wipe old."""
    out = dict(old or {})
    for k, v in (new or {}).items():
        if v is not None:
            out[k] = v
        elif k not in out:
            out[k] = None
    return out


def fetch_grok_user_profile(
    access_token: str,
    *,
    user_id: str | None = None,
    timeout: float = 25.0,
) -> dict[str, Any]:
    """
    GET cli-chat-proxy /v1/user?include=subscription.
    Returns {ok, userId, email, hasGrokCodeAccess, subscriptionTier, error?, raw?}
    """
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/json",
        "x-xai-token-auth": GROK_CLI_TOKEN_AUTH,
        "x-grok-client-identifier": GROK_CLI_CLIENT_ID,
        "x-grok-client-version": GROK_CLI_VERSION,
        "x-grok-client-mode": "headless",
        "User-Agent": f"grok-shell/{GROK_CLI_VERSION}",
    }
    if user_id:
        headers["x-userid"] = str(user_id)

    req = urllib.request.Request(GROK_CLI_USER_URL, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode(errors="ignore")
            data = json.loads(body) if body else {}
    except urllib.error.HTTPError as e:
        err_body = e.read().decode(errors="ignore")[:300]
        return {
            "ok": False,
            "status": e.code,
            "error": err_body or str(e),
            "userId": user_id,
            "email": None,
            "hasGrokCodeAccess": None,
            "subscriptionTier": None,
        }
    except Exception as e:
        return {
            "ok": False,
            "status": None,
            "error": str(e)[:300],
            "userId": user_id,
            "email": None,
            "hasGrokCodeAccess": None,
            "subscriptionTier": None,
        }

    tier = data.get("subscriptionTier")
    if tier is None:
        tier = data.get("subscription_tier")
    if tier is None and isinstance(data.get("subscription"), dict):
        tier = data["subscription"].get("tier") or data["subscription"].get("name")
    # normalize empty string / placeholders
    if tier in ("", "null", "None"):
        tier = None

    uid = (
        data.get("userId")
        or data.get("principalId")
        or data.get("id")
        or user_id
    )
    return {
        "ok": True,
        "status": 200,
        "userId": uid,
        "email": data.get("email"),
        "hasGrokCodeAccess": data.get("hasGrokCodeAccess"),
        "subscriptionTier": tier,
        "error": None,
    }


def test_chat_token(
    tokens: dict[str, Any],
    *,
    model: str = CHAT_TEST_MODEL,
    email: str | None = None,
    user_id: str | None = None,
    timeout: float = 45.0,
    prompt: str = "reply with exactly: PONG",
) -> dict[str, Any]:
    """
    Pre-inject usability gate: POST cli-chat-proxy /v1/responses with the
    OAuth access token for model (default grok-4.5).

    usable=True  → safe to inject into 9router
      - HTTP 200 (got a completion)
      - HTTP 429 (auth accepted; free quota / rate limit only)
    usable=False → do NOT inject
      - 401 auth fail, 403 free blocked, 402 billing, network/other

    Never logs or returns raw tokens.
    """
    access = tokens.get("access_token") or tokens.get("accessToken")
    out: dict[str, Any] = {
        "ok": False,
        "usable": False,
        "status": None,
        "code": None,
        "error": None,
        "model": model,
        "text_head": None,
        "reason": None,
    }
    if not access:
        out["error"] = "missing access_token"
        out["reason"] = "no_token"
        return out

    email = email or decode_jwt_email(access) or decode_jwt_email(
        tokens.get("id_token") or tokens.get("idToken")
    )
    uid = user_id or decode_jwt_user_id(access)

    headers = {
        "Authorization": f"Bearer {access}",
        "Content-Type": "application/json",
        "Accept": "application/json",
        "x-xai-token-auth": GROK_CLI_TOKEN_AUTH,
        "x-grok-client-identifier": GROK_CLI_CLIENT_ID,
        "x-grok-client-version": GROK_CLI_VERSION,
        "x-grok-client-mode": "headless",
        "x-grok-session-id": str(uuid.uuid4()),
        "x-grok-conv-id": str(uuid.uuid4()),
        "x-grok-req-id": str(uuid.uuid4()),
        "x-grok-turn-idx": "1",
        "x-grok-model-override": model,
        "User-Agent": f"grok-shell/{GROK_CLI_VERSION}",
    }
    if email:
        headers["x-email"] = str(email)
    if uid:
        headers["x-userid"] = str(uid)

    body = {
        "model": model,
        "input": [{"type": "message", "role": "user", "content": prompt}],
        "stream": False,
        "store": False,
        "max_output_tokens": 16,
    }
    data = json.dumps(body).encode()
    req = urllib.request.Request(
        GROK_CLI_RESPONSES_URL, data=data, headers=headers, method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode(errors="ignore")
            out["status"] = resp.status
            out["ok"] = True
            out["usable"] = True
            out["reason"] = "chat_ok"
            out["text_head"] = raw[:180]
            try:
                parsed = json.loads(raw) if raw else {}
                # Responses API: output[].content[] text
                texts: list[str] = []
                for item in parsed.get("output") or []:
                    if not isinstance(item, dict):
                        continue
                    for c in item.get("content") or []:
                        if isinstance(c, dict) and c.get("text"):
                            texts.append(str(c["text"]))
                        elif isinstance(c, dict) and c.get("type") == "output_text":
                            texts.append(str(c.get("text") or ""))
                if texts:
                    out["text_head"] = " ".join(texts)[:120]
            except Exception:
                pass
            return out
    except urllib.error.HTTPError as e:
        err_body = e.read().decode(errors="ignore")
        out["status"] = e.code
        code = None
        msg = err_body[:240] if err_body else str(e)
        try:
            j = json.loads(err_body) if err_body else {}
            code = j.get("code") or (j.get("error") if isinstance(j.get("error"), str) else None)
            if isinstance(j.get("error"), dict):
                msg = j["error"].get("message") or msg
                code = code or j["error"].get("code")
            elif isinstance(j.get("error"), str):
                msg = j.get("error") or msg
            elif j.get("message"):
                msg = str(j.get("message"))
        except Exception:
            pass
        out["code"] = code
        out["error"] = (msg or "")[:240]
        out["text_head"] = (err_body or "")[:180]

        # Auth accepted but free quota / rate limited → still injectable
        if e.code == 429:
            out["ok"] = False
            out["usable"] = True
            out["reason"] = "quota_or_rate"
            return out
        if e.code == 401:
            out["reason"] = "auth_fail"
            return out
        if e.code == 403:
            out["reason"] = "forbidden"
            return out
        if e.code == 402:
            out["reason"] = "billing"
            return out
        out["reason"] = f"http_{e.code}"
        return out
    except Exception as e:
        out["error"] = str(e)[:240]
        out["reason"] = "network"
        return out


def enrich_tokens_profile(
    tokens: dict[str, Any],
    *,
    user_id: str | None = None,
    fetch_profile: bool = True,
) -> dict[str, Any]:
    """
    Build PSD enrichment from JWT + optional live /v1/user.
    Never raises — soft-fail returns best-effort fields.
    """
    access = tokens.get("access_token") or tokens.get("accessToken")
    jwt_uid = decode_jwt_user_id(access)
    uid = user_id or jwt_uid
    out: dict[str, Any] = {
        "userId": uid,
        "hasGrokCodeAccess": None,
        "subscriptionTier": None,
        "profileOk": False,
        "profileError": None,
    }
    if not fetch_profile or not access:
        return out

    prof = fetch_grok_user_profile(access, user_id=uid)
    if prof.get("ok"):
        out["profileOk"] = True
        out["userId"] = prof.get("userId") or uid
        out["hasGrokCodeAccess"] = prof.get("hasGrokCodeAccess")
        out["subscriptionTier"] = prof.get("subscriptionTier")
        if prof.get("email"):
            out["email"] = prof["email"]
    else:
        out["profileError"] = prof.get("error")
        out["profileStatus"] = prof.get("status")
    return out


def inject_connection(
    db_path: str,
    provider: str,
    tokens: dict[str, Any],
    *,
    email: str | None = None,
    display_name: str | None = None,
    user_id: str | None = None,
    auth_method: str = "device_code",
    extra_psd: dict | None = None,
    fetch_profile: bool = True,
) -> dict:
    """
    Upsert a providerConnections row. Returns the connection dict.
    tokens: access_token/refresh_token/expires_in/scope/id_token (OAuth shape)

    When fetch_profile=True (default) and provider is grok-cli, probe
    cli-chat-proxy /v1/user to fill userId / hasGrokCodeAccess / subscriptionTier.
    """
    access = tokens.get("access_token") or tokens.get("accessToken")
    refresh = tokens.get("refresh_token") or tokens.get("refreshToken")
    expires_in = tokens.get("expires_in") or tokens.get("expiresIn")
    scope = tokens.get("scope")
    id_token = tokens.get("id_token") or tokens.get("idToken")

    email = email or decode_jwt_email(id_token) or decode_jwt_email(access)
    now = _now_iso()
    expires_at = _expires_at(expires_in)

    # JWT fallback user id before live profile
    jwt_uid = decode_jwt_user_id(access)
    resolved_uid = user_id or jwt_uid

    profile_meta: dict[str, Any] = {}
    if fetch_profile and provider in ("grok-cli", "gcli", "grok-build", "gb"):
        profile_meta = enrich_tokens_profile(
            tokens, user_id=resolved_uid, fetch_profile=True
        )
        resolved_uid = profile_meta.get("userId") or resolved_uid

    psd = {
        "authMethod": auth_method,
        "idToken": id_token,
        "email": email or profile_meta.get("email"),
        "userId": resolved_uid,
        "hasGrokCodeAccess": profile_meta.get("hasGrokCodeAccess"),
        "subscriptionTier": profile_meta.get("subscriptionTier"),
    }
    if extra_psd:
        # extra_psd non-None wins over auto profile
        for k, v in extra_psd.items():
            if v is not None:
                psd[k] = v
            elif k not in psd:
                psd[k] = None

    data = {
        "displayName": display_name,
        "accessToken": access,
        "refreshToken": refresh,
        "expiresAt": expires_at,
        "scope": scope,
        "testStatus": "active",
        "expiresIn": expires_in,
        "providerSpecificData": psd,
        "lastRefreshAt": now,
        "backoffLevel": 0,
    }

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        cur = conn.cursor()
        existing = None
        if email:
            existing = cur.execute(
                "SELECT * FROM providerConnections WHERE provider=? AND email=?",
                (provider, email),
            ).fetchone()

        if existing:
            row = dict(existing)
            old = json.loads(row["data"] or "{}")
            merged = {**old, **{k: v for k, v in data.items() if v is not None}}
            old_psd = old.get("providerSpecificData") or {}
            new_psd = data.get("providerSpecificData") or {}
            merged["providerSpecificData"] = _merge_psd(old_psd, new_psd)
            # clear stale error state on successful re-inject
            for k in ("lastError", "errorCode", "errorMessage"):
                if k in merged and data.get("accessToken"):
                    # keep lastError for ops visibility unless explicitly cleared elsewhere
                    pass
            cur.execute(
                """UPDATE providerConnections
                   SET name=?, email=?, isActive=1, data=?, updatedAt=?
                   WHERE id=?""",
                (
                    email or row["name"],
                    email,
                    json.dumps(merged),
                    now,
                    row["id"],
                ),
            )
            conn.commit()
            return {
                "id": row["id"],
                "provider": provider,
                "email": email,
                "action": "updated",
                "updated": True,
                "userId": resolved_uid,
                "hasGrokCodeAccess": psd.get("hasGrokCodeAccess"),
                "subscriptionTier": psd.get("subscriptionTier"),
                "profileOk": profile_meta.get("profileOk"),
            }

        row_max = cur.execute(
            "SELECT MAX(priority) AS m FROM providerConnections WHERE provider=?",
            (provider,),
        ).fetchone()
        priority = int(row_max["m"] or 0) + 1
        cid = str(uuid.uuid4())
        cur.execute(
            """INSERT INTO providerConnections
               (id, provider, authType, name, email, priority, isActive, data, createdAt, updatedAt)
               VALUES (?,?,?,?,?,?,?,?,?,?)""",
            (
                cid,
                provider,
                "oauth",
                email or f"{provider}-{cid[:8]}",
                email,
                priority,
                1,
                json.dumps(data),
                now,
                now,
            ),
        )
        conn.commit()
        return {
            "id": cid,
            "provider": provider,
            "email": email,
            "priority": priority,
            "action": "created",
            "updated": False,
            "userId": resolved_uid,
            "hasGrokCodeAccess": psd.get("hasGrokCodeAccess"),
            "subscriptionTier": psd.get("subscriptionTier"),
            "profileOk": profile_meta.get("profileOk"),
        }
    finally:
        conn.close()


def backfill_grok_profiles(
    db_path: str,
    *,
    provider: str = "grok-cli",
    only_missing: bool = True,
    limit: int | None = None,
    sleep_s: float = 0.15,
) -> dict[str, Any]:
    """
    Re-probe /v1/user for existing grok-cli rows and fill PSD metadata.
    Does not change access/refresh tokens.
    """
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    stats = {
        "scanned": 0,
        "updated": 0,
        "skipped": 0,
        "failed": 0,
        "with_userId": 0,
        "with_code_access": 0,
        "with_tier": 0,
        "samples": [],
    }
    try:
        rows = conn.execute(
            "SELECT id, email, data FROM providerConnections WHERE provider=? AND isActive=1",
            (provider,),
        ).fetchall()
        for row in rows:
            if limit is not None and stats["scanned"] >= limit:
                break
            stats["scanned"] += 1
            data = json.loads(row["data"] or "{}")
            psd = data.get("providerSpecificData") or {}
            access = data.get("accessToken")
            if not access:
                stats["skipped"] += 1
                continue
            if only_missing and psd.get("userId") and psd.get("hasGrokCodeAccess") is not None:
                stats["skipped"] += 1
                if psd.get("userId"):
                    stats["with_userId"] += 1
                if psd.get("hasGrokCodeAccess"):
                    stats["with_code_access"] += 1
                if psd.get("subscriptionTier"):
                    stats["with_tier"] += 1
                continue

            jwt_uid = decode_jwt_user_id(access)
            hint_uid = psd.get("userId") or jwt_uid
            prof = fetch_grok_user_profile(access, user_id=hint_uid)
            if not prof.get("ok"):
                # still set JWT userId if missing
                if not psd.get("userId") and jwt_uid:
                    psd["userId"] = jwt_uid
                    data["providerSpecificData"] = psd
                    conn.execute(
                        "UPDATE providerConnections SET data=?, updatedAt=? WHERE id=?",
                        (json.dumps(data), _now_iso(), row["id"]),
                    )
                    conn.commit()
                    stats["updated"] += 1
                    stats["with_userId"] += 1
                    stats["failed"] += 1
                    if len(stats["samples"]) < 5:
                        stats["samples"].append(
                            {
                                "email": row["email"],
                                "userId": jwt_uid,
                                "profileOk": False,
                                "error": (prof.get("error") or "")[:120],
                            }
                        )
                else:
                    stats["failed"] += 1
                time.sleep(sleep_s)
                continue

            new_psd = _merge_psd(
                psd,
                {
                    "userId": prof.get("userId") or hint_uid,
                    "hasGrokCodeAccess": prof.get("hasGrokCodeAccess"),
                    "subscriptionTier": prof.get("subscriptionTier"),
                    "email": prof.get("email") or psd.get("email") or row["email"],
                },
            )
            data["providerSpecificData"] = new_psd
            conn.execute(
                "UPDATE providerConnections SET data=?, updatedAt=? WHERE id=?",
                (json.dumps(data), _now_iso(), row["id"]),
            )
            conn.commit()
            stats["updated"] += 1
            if new_psd.get("userId"):
                stats["with_userId"] += 1
            if new_psd.get("hasGrokCodeAccess"):
                stats["with_code_access"] += 1
            if new_psd.get("subscriptionTier"):
                stats["with_tier"] += 1
            if len(stats["samples"]) < 5:
                stats["samples"].append(
                    {
                        "email": row["email"],
                        "userId": str(new_psd.get("userId") or "")[:36],
                        "hasGrokCodeAccess": new_psd.get("hasGrokCodeAccess"),
                        "subscriptionTier": new_psd.get("subscriptionTier"),
                        "profileOk": True,
                    }
                )
            time.sleep(sleep_s)
        return stats
    finally:
        conn.close()


def count_provider(db_path: str, provider: str) -> int:
    conn = sqlite3.connect(db_path)
    try:
        return conn.execute(
            "SELECT COUNT(*) FROM providerConnections WHERE provider=? AND isActive=1",
            (provider,),
        ).fetchone()[0]
    finally:
        conn.close()


if __name__ == "__main__":
    import argparse
    import sys

    ap = argparse.ArgumentParser(description="9router grok-cli inject helpers")
    ap.add_argument(
        "--db",
        default=os.path.expanduser("~/.9router/db/data.sqlite"),
        help="9router sqlite path",
    )
    sub = ap.add_subparsers(dest="cmd", required=True)

    bf = sub.add_parser("backfill", help="Fill userId/hasGrokCodeAccess/subscriptionTier")
    bf.add_argument("--all", action="store_true", help="Re-probe even if already filled")
    bf.add_argument("--limit", type=int, default=None)
    bf.add_argument("--provider", default="grok-cli")

    args = ap.parse_args()
    if args.cmd == "backfill":
        stats = backfill_grok_profiles(
            args.db,
            provider=args.provider,
            only_missing=not args.all,
            limit=args.limit,
        )
        print(json.dumps(stats, indent=2))
        sys.exit(0 if stats.get("failed", 0) == 0 or stats.get("updated", 0) else 0)
