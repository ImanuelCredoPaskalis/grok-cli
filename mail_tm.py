#!/usr/bin/env python3
"""Temporary email providers for xAI signup OTP.

Priority (GAC-proven first, then bake-off winners):
  1) ncaori         (ncaori.my.id / nca.my.id catch-all)
  2) zoromail       (zoromail.com REST domains)
  3) tempmail.lol   (best free pure-API token rate)
  4) smailpro       (sonjj unique domains)
  5) tempmail.plus / emailnator / temp-mail.io / mail.tm / guerrilla / maildrop
"""
from __future__ import annotations

import os
import random
import re
import time
import uuid
import urllib.parse
from typing import Any

from curl_cffi import requests as creq

JSON_HEADERS = {
    "Accept": "application/json",
    "Content-Type": "application/json",
}
# xAI/SpaceXAI emails: "confirmation code: HPN-7Z9" (preferred) or legacy 6-char
OTP_HYPHEN_RE = re.compile(
    r"(?:confirmation\s+)?code[:\s]+([A-Z0-9]{3}-[A-Z0-9]{3})\b",
    re.I,
)
OTP_HYPHEN_BARE_RE = re.compile(r"\b([A-Z0-9]{3}-[A-Z0-9]{3})\b", re.I)
OTP_LEGACY_RE = re.compile(
    r"(?:confirmation\s+)?code[:\s]+([A-Z0-9]{6})\b",
    re.I,
)
# pure 6-digit only when clearly labeled confirmation/OTP (avoid ad tracking ids)
OTP_DIGIT6_LABELED_RE = re.compile(
    r"(?:confirmation\s+code|verification\s+code|otp|one[- ]time(?:\s+pass(?:word|code))?)"
    r"[:\s#]*([0-9]{6})\b",
    re.I,
)
SKIP_HYPHEN = {
    "per-100", "max-100", "min-100", "dir-top", "top-dir", "moz-osx",
    "pre-built", "pre-made", "one-time", "set-up", "sign-up", "log-in",
    "opt-out", "opt-in", "non-stop", "all-in", "end-to", "to-end",
}
SKIP_LEGACY = {
    "signup", "verify", "account", "please", "gmail", "xaiapp", "spacex",
    "edge", "chrome", "safari", "webkit", "mozilla", "button", "submit",
    "create", "ignore", "footer", "strong", "hidden", "center", "inline",
    "mobile", "column", "screen", "border", "margin", "height", "weight",
    "family", "system", "domain", "tensor", "mailto", "adjust", "bottom",
    "unleash", "online", "tools", "power", "ultimate", "directory",
}
# subjects/from that are emailnator ads — never treat as OTP source
AD_MARKERS = (
    "ai tools", "unleash the power", "adsvpn", "buysellads", "directory of online",
    "temp mail", "emailnator", "disposable gmail",
)
XAI_MARKERS = (
    "x.ai", "xai", "grok", "spacex", "confirmation code", "validation code",
    "verify your email", "email verification", "accounts.x.ai",
)


def _decode_qpish(blob: str) -> str:
    # quoted-printable soft line breaks in tempmail bodies
    return (blob or "").replace("=\r\n", "").replace("=\n", "")


def _looks_like_ad(blob: str) -> bool:
    low = (blob or "").lower()
    return any(m in low for m in AD_MARKERS) and not any(m in low for m in XAI_MARKERS)


def _has_xai_context(blob: str) -> bool:
    low = (blob or "").lower()
    return any(m in low for m in XAI_MARKERS)


def _extract_code(blob: str) -> str | None:
    text = _decode_qpish(blob)
    if not text or _looks_like_ad(text):
        return None
    xaiish = _has_xai_context(text)

    # 1) labeled hyphen code (subject: confirmation code: HPN-7Z9)
    for m in OTP_HYPHEN_RE.finditer(text):
        code = m.group(1).upper()
        if code.lower() not in SKIP_HYPHEN:
            return code

    # 2) bare hyphen — only when xAI context present (avoid ad junk like DIR-TOP)
    if xaiish:
        for m in OTP_HYPHEN_BARE_RE.finditer(text):
            code = m.group(1).upper()
            low = code.lower()
            if low in SKIP_HYPHEN or low.startswith("per-"):
                continue
            # xAI codes are typically mixed alnum, not pure words
            if re.fullmatch(r"[A-Z]{3}-[A-Z]{3}", code) and low in SKIP_HYPHEN:
                continue
            return code

    # 3) labeled legacy 6-char alnum (HAR: AX3BBY) — reject pure-digit unless xAI-labeled
    for m in OTP_LEGACY_RE.finditer(text):
        code = m.group(1).upper()
        low = code.lower()
        if low in SKIP_LEGACY:
            continue
        if code.isdigit():
            # only accept pure digits with strong xAI confirmation label nearby
            if not xaiish:
                continue
            window = text[max(0, m.start() - 40) : m.end() + 10]
            if not re.search(r"confirmation|verification|otp|one[- ]time", window, re.I):
                continue
        return code

    # 4) labeled pure 6-digit OTP (rare for xAI, but some flows use it)
    if xaiish:
        for m in OTP_DIGIT6_LABELED_RE.finditer(text):
            return m.group(1)

    return None


class EmailNator:
    """Gmail-like temp addresses via emailnator.com (plus/dot/googlemail).

    Produces real *@gmail.com / *@googlemail.com aliases that often pass
    disposable-mail filters better than random temp domains.
    """

    HOME = "https://www.emailnator.com"
    GEN = "https://www.emailnator.com/generate-email"
    LIST = "https://www.emailnator.com/message-list"
    # Prefer real Gmail alias styles first; domain= is plain disposable.
    STYLES = ("plusGmail", "dotGmail", "googleMail")

    def __init__(self, impersonate: str = "chrome131"):
        self.s = creq.Session()
        self.impersonate = impersonate
        self.address: str | None = None
        self._bootstrapped = False

    def _headers(self) -> dict[str, str]:
        xsrf = self.s.cookies.get("XSRF-TOKEN")
        h = {
            "Accept": "application/json, text/plain, */*",
            "Content-Type": "application/json",
            "X-Requested-With": "XMLHttpRequest",
            "Origin": self.HOME,
            "Referer": f"{self.HOME}/",
        }
        if xsrf:
            h["X-XSRF-TOKEN"] = urllib.parse.unquote(xsrf)
        return h

    def _bootstrap(self) -> None:
        if self._bootstrapped:
            return
        r = self.s.get(self.HOME + "/", impersonate=self.impersonate, timeout=30)
        if r.status_code >= 400:
            raise RuntimeError(f"emailnator home {r.status_code}")
        if not self.s.cookies.get("XSRF-TOKEN"):
            raise RuntimeError("emailnator missing XSRF-TOKEN")
        self._bootstrapped = True

    def create_account(self) -> str:
        self._bootstrap()
        r = self.s.post(
            self.GEN,
            json={"email": list(self.STYLES)},
            headers=self._headers(),
            impersonate=self.impersonate,
            timeout=30,
        )
        if r.status_code >= 400:
            raise RuntimeError(f"emailnator generate {r.status_code}: {r.text[:200]}")
        data = r.json() if r.content else {}
        emails = data.get("email") or []
        if not emails:
            raise RuntimeError(f"emailnator empty: {data}")
        self.address = str(emails[0]).strip()
        # Only accept gmail/googlemail aliases — domain= style is disposable junk.
        low = self.address.lower()
        if not (low.endswith("@gmail.com") or low.endswith("@googlemail.com")):
            raise RuntimeError(f"emailnator non-gmail alias: {self.address}")
        return self.address

    def wait_code(self, timeout: int = 150) -> str:
        if not self.address:
            raise RuntimeError("emailnator no address")
        deadline = time.time() + timeout
        seen: set[str] = set()
        while time.time() < deadline:
            r = self.s.post(
                self.LIST,
                json={"email": self.address},
                headers=self._headers(),
                impersonate=self.impersonate,
                timeout=30,
            )
            if r.status_code < 400 and r.content:
                data = r.json() if r.content else {}
                msgs = data.get("messageData") or []
                for m in msgs:
                    mid = str(m.get("messageID") or "")
                    subj = str(m.get("subject") or "")
                    frm = str(m.get("from") or "")
                    if not mid or mid.upper() == "ADSVPN" or mid in seen:
                        continue
                    if _looks_like_ad(f"{subj} {frm}"):
                        seen.add(mid)
                        continue
                    # subject alone may already carry "confirmation code: ABC-DEF"
                    code = _extract_code(f"{subj} {frm}")
                    if code:
                        return code
                    # full body via message-list + messageID (returns HTML/string)
                    r2 = self.s.post(
                        self.LIST,
                        json={"email": self.address, "messageID": mid},
                        headers=self._headers(),
                        impersonate=self.impersonate,
                        timeout=30,
                    )
                    body = ""
                    if r2.status_code < 400 and r2.content:
                        body = r2.text
                        try:
                            j = r2.json()
                            if isinstance(j, str):
                                body = j
                            elif isinstance(j, dict):
                                # successful body is often raw HTML string in response;
                                # if JSON dict, join known fields
                                body = (
                                    " ".join(
                                        str(j.get(k, "") or "")
                                        for k in (
                                            "messageData",
                                            "body",
                                            "html",
                                            "text",
                                            "content",
                                            "subject",
                                        )
                                    )
                                    or body
                                )
                        except Exception:
                            pass
                    blob = f"{subj} {frm} {body}"
                    code = _extract_code(blob)
                    if code:
                        return code
                    # mark seen only after we attempted body — allow retry if body 5xx early
                    if r2.status_code < 500:
                        seen.add(mid)
            time.sleep(3)
        raise TimeoutError(f"emailnator no OTP for {self.address}")


class SmailPro:
    """smailpro.com via sonjj payload-signed API.

    Creates unique *@domain addresses (not gmail aliases). Good for signup when
    emailnator gmail norms are already taken. Chat free tier still may 403.
    """

    SITE = "https://smailpro.com"
    BASE = "https://api.sonjj.com/v1/temp_email"

    def __init__(self, impersonate: str = "chrome131"):
        self.s = creq.Session()
        self.impersonate = impersonate
        self.address: str | None = None
        self._bootstrapped = False

    def _boot(self) -> None:
        if self._bootstrapped:
            return
        r = self.s.get(self.SITE + "/", impersonate=self.impersonate, timeout=30)
        if r.status_code >= 400:
            raise RuntimeError(f"smailpro home {r.status_code}")
        self._bootstrapped = True

    def _payload(self, params: dict[str, str]) -> str:
        self._boot()
        from urllib.parse import urlencode

        r = self.s.get(
            f"{self.SITE}/app/payload",
            params=params,
            impersonate=self.impersonate,
            timeout=30,
            headers={
                "Accept": "text/plain, */*",
                "Referer": self.SITE + "/",
            },
        )
        if r.status_code >= 400 or not (r.text or "").strip():
            raise RuntimeError(f"smailpro payload {r.status_code}: {(r.text or '')[:120]}")
        return r.text.strip()

    def _api(self, path: str, params: dict[str, str]) -> dict:
        from urllib.parse import urlencode

        payload = self._payload(params)
        r = self.s.get(
            f"{self.BASE}{path}",
            params={"payload": payload},
            impersonate=self.impersonate,
            timeout=30,
            headers={
                "Accept": "application/json, text/plain, */*",
                "Origin": self.SITE,
                "Referer": self.SITE + "/",
            },
        )
        if r.status_code >= 400:
            raise RuntimeError(f"smailpro {path} {r.status_code}: {(r.text or '')[:200]}")
        try:
            data = r.json()
        except Exception as e:
            raise RuntimeError(f"smailpro {path} bad json: {(r.text or '')[:160]}") from e
        if isinstance(data, dict) and data.get("detail"):
            # {"detail":{"error":{"code":400,"message":"Invalid domain: ..."}}}
            err = data.get("detail")
            if isinstance(err, dict):
                msg = (err.get("error") or {}).get("message") or err
            else:
                msg = err
            raise RuntimeError(f"smailpro {path}: {msg}")
        return data if isinstance(data, dict) else {"raw": data}

    def create_account(self) -> str:
        last: Exception | None = None
        for _ in range(5):
            try:
                data = self._api("/create", {"url": f"{self.BASE}/create"})
                email = data.get("email")
                if not email:
                    raise RuntimeError(f"smailpro no email: {data}")
                self.address = str(email)
                return self.address
            except Exception as e:
                last = e
                time.sleep(0.4)
        raise RuntimeError(f"smailpro create failed: {last}")

    def wait_code(self, timeout: int = 150) -> str:
        if not self.address:
            raise RuntimeError("smailpro no address")
        deadline = time.time() + timeout
        seen: set[str] = set()
        while time.time() < deadline:
            try:
                data = self._api(
                    "/inbox",
                    {"url": f"{self.BASE}/inbox", "email": self.address},
                )
            except Exception:
                time.sleep(3)
                continue
            msgs = data.get("messages") or []
            if not isinstance(msgs, list):
                msgs = []
            for m in msgs:
                mid = str(m.get("mid") or m.get("id") or m.get("message_id") or "")
                if not mid or mid in seen:
                    continue
                subj = str(m.get("subject") or "")
                frm = str(m.get("from") or m.get("sender") or "")
                if _looks_like_ad(f"{subj} {frm}"):
                    seen.add(mid)
                    continue
                code = _extract_code(f"{subj} {frm}")
                if code:
                    return code
                # full body
                body = ""
                try:
                    full = self._api(
                        "/message",
                        {
                            "url": f"{self.BASE}/message",
                            "email": self.address,
                            "mid": mid,
                        },
                    )
                    body = str(full.get("body") or full.get("html") or full.get("text") or "")
                except Exception:
                    body = str(m.get("body") or m.get("text") or m.get("preview") or "")
                blob = f"{subj} {frm} {body}"
                code = _extract_code(blob)
                if code:
                    return code
                seen.add(mid)
            time.sleep(3)
        raise TimeoutError(f"smailpro no OTP for {self.address}")


class TempMailIO:
    """temp-mail.io free public API (api.internal.temp-mail.io)."""

    BASE = "https://api.internal.temp-mail.io/api/v3"

    def __init__(self, impersonate: str = "chrome131"):
        self.s = creq.Session()
        self.impersonate = impersonate
        self.address: str | None = None
        self.token: str | None = None

    def create_account(self) -> str:
        r = self.s.post(
            f"{self.BASE}/email/new",
            json={"min_name_length": 8, "max_name_length": 12},
            headers=JSON_HEADERS,
            impersonate=self.impersonate,
            timeout=30,
        )
        if r.status_code >= 400:
            raise RuntimeError(f"temp-mail.io create {r.status_code}: {r.text[:200]}")
        data = r.json()
        self.address = data.get("email")
        self.token = data.get("token")
        if not self.address:
            raise RuntimeError(f"temp-mail.io bad: {data}")
        return self.address

    def wait_code(self, timeout: int = 150) -> str:
        if not self.address:
            raise RuntimeError("temp-mail.io no address")
        deadline = time.time() + timeout
        seen: set[str] = set()
        while time.time() < deadline:
            r = self.s.get(
                f"{self.BASE}/email/{self.address}/messages",
                headers={
                    "Accept": "application/json",
                    "Application-Name": "web",
                    "Application-Version": "2.4.2",
                },
                impersonate=self.impersonate,
                timeout=30,
            )
            if r.status_code < 400 and r.content:
                msgs = r.json() if r.content else []
                if not isinstance(msgs, list):
                    msgs = msgs.get("messages") or msgs.get("mail_list") or []
                for m in msgs:
                    mid = str(m.get("id") or m.get("_id") or m.get("message_id") or id(m))
                    if mid in seen:
                        continue
                    seen.add(mid)
                    # body may be inline; else fetch
                    blob = " ".join(
                        str(m.get(k, "") or "")
                        for k in (
                            "subject",
                            "body",
                            "body_text",
                            "body_html",
                            "html",
                            "text",
                            "preview",
                            "from",
                        )
                    )
                    if not _extract_code(blob) and m.get("id"):
                        try:
                            r2 = self.s.get(
                                f"{self.BASE}/email/{self.address}/messages/{m['id']}",
                                headers={"Accept": "application/json"},
                                impersonate=self.impersonate,
                                timeout=30,
                            )
                            if r2.status_code < 400 and r2.content:
                                full = r2.json()
                                blob += " " + " ".join(
                                    str(full.get(k, "") or "")
                                    for k in (
                                        "subject",
                                        "body",
                                        "body_text",
                                        "body_html",
                                        "html",
                                        "text",
                                    )
                                )
                        except Exception:
                            pass
                    code = _extract_code(blob)
                    if code:
                        return code
            time.sleep(3)
        raise TimeoutError(f"temp-mail.io no OTP for {self.address}")


class TempMailLol:
    BASE = "https://api.tempmail.lol/v2"

    def __init__(self, impersonate: str = "chrome131"):
        self.s = creq.Session()
        self.impersonate = impersonate
        self.address: str | None = None
        self.token: str | None = None

    def create_account(self) -> str:
        r = self.s.post(
            f"{self.BASE}/inbox/create",
            headers=JSON_HEADERS,
            impersonate=self.impersonate,
            timeout=30,
        )
        if r.status_code >= 400:
            raise RuntimeError(f"tempmail.lol create {r.status_code}: {r.text[:200]}")
        data = r.json()
        self.address = data.get("address") or data.get("email")
        self.token = data.get("token")
        if not self.address or not self.token:
            raise RuntimeError(f"tempmail.lol bad response: {data}")
        return self.address

    def wait_code(self, timeout: int = 150) -> str:
        deadline = time.time() + timeout
        seen: set[str] = set()
        while time.time() < deadline:
            r = self.s.get(
                f"{self.BASE}/inbox",
                params={"token": self.token},
                headers={"Accept": "application/json"},
                impersonate=self.impersonate,
                timeout=30,
            )
            if r.status_code < 400:
                data = r.json() if r.content else {}
                emails = data if isinstance(data, list) else data.get("emails") or data.get("messages") or []
                for m in emails:
                    mid = str(m.get("id") or m.get("_id") or m.get("date") or id(m))
                    if mid in seen:
                        continue
                    seen.add(mid)
                    blob = " ".join(
                        str(m.get(k, "") or "")
                        for k in ("subject", "body", "html", "text", "preview", "content")
                    )
                    code = _extract_code(blob)
                    if code:
                        return code
            time.sleep(3)
        raise TimeoutError(f"tempmail.lol no OTP for {self.address}")


class GuerrillaMail:
    BASE = "https://api.guerrillamail.com/ajax.php"

    def __init__(self, impersonate: str = "chrome131"):
        self.s = creq.Session()
        self.impersonate = impersonate
        self.address: str | None = None
        self.sid_token: str | None = None
        self.seq = 0

    def create_account(self) -> str:
        r = self.s.get(
            self.BASE,
            params={"f": "get_email_address", "lang": "en"},
            impersonate=self.impersonate,
            timeout=30,
        )
        if r.status_code >= 400:
            raise RuntimeError(f"guerrilla create {r.status_code}: {r.text[:200]}")
        data = r.json()
        self.address = data.get("email_addr")
        self.sid_token = data.get("sid_token")
        if not self.address:
            raise RuntimeError(f"guerrilla bad: {data}")
        return self.address

    def wait_code(self, timeout: int = 150) -> str:
        deadline = time.time() + timeout
        seen: set[str] = set()
        while time.time() < deadline:
            r = self.s.get(
                self.BASE,
                params={
                    "f": "check_email",
                    "sid_token": self.sid_token,
                    "seq": self.seq,
                },
                impersonate=self.impersonate,
                timeout=30,
            )
            if r.status_code < 400 and r.content:
                data = r.json()
                self.sid_token = data.get("sid_token") or self.sid_token
                for m in data.get("list") or []:
                    mid = str(m.get("mail_id"))
                    if not mid or mid in seen:
                        continue
                    seen.add(mid)
                    # fetch full
                    r2 = self.s.get(
                        self.BASE,
                        params={
                            "f": "fetch_email",
                            "sid_token": self.sid_token,
                            "email_id": mid,
                        },
                        impersonate=self.impersonate,
                        timeout=30,
                    )
                    full = r2.json() if r2.content else m
                    blob = " ".join(
                        str(full.get(k, "") or m.get(k, "") or "")
                        for k in (
                            "mail_subject",
                            "mail_body",
                            "mail_excerpt",
                            "subject",
                            "body",
                        )
                    )
                    code = _extract_code(blob)
                    if code:
                        return code
            time.sleep(3)
        raise TimeoutError(f"guerrilla no OTP for {self.address}")


class MailTM:
    BASE = "https://api.mail.tm"

    def __init__(self, impersonate: str = "chrome131"):
        self.s = creq.Session()
        self.impersonate = impersonate
        self.token: str | None = None
        self.address: str | None = None
        self.password: str | None = None

    def _req(self, method: str, path: str, **kw) -> Any:
        headers = {**JSON_HEADERS, **kw.pop("headers", {})}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        r = self.s.request(
            method,
            self.BASE + path,
            headers=headers,
            impersonate=self.impersonate,
            timeout=kw.pop("timeout", 30),
            **kw,
        )
        if r.status_code >= 400:
            raise RuntimeError(f"mail.tm {method} {path} -> {r.status_code} {r.text[:200]}")
        if r.status_code == 204 or not r.content:
            return None
        return r.json()

    def create_account(self) -> str:
        data = self._req("GET", "/domains")
        domains = data if isinstance(data, list) else data.get("hydra:member", [])
        active = [d["domain"] for d in domains if d.get("isActive", True)]
        if not active:
            raise RuntimeError("mail.tm no domains")
        local = "xai" + uuid.uuid4().hex[:10]
        self.address = f"{local}@{active[0]}"
        self.password = uuid.uuid4().hex + "Aa1!"
        self._req("POST", "/accounts", json={"address": self.address, "password": self.password})
        tok = self._req("POST", "/token", json={"address": self.address, "password": self.password})
        self.token = tok["token"]
        return self.address

    def wait_code(self, timeout: int = 150) -> str:
        deadline = time.time() + timeout
        seen: set[str] = set()
        while time.time() < deadline:
            data = self._req("GET", "/messages") or {}
            msgs = data if isinstance(data, list) else data.get("hydra:member", [])
            for m in msgs:
                mid = m.get("id")
                if not mid or mid in seen:
                    continue
                seen.add(mid)
                full = self._req("GET", f"/messages/{mid}") or {}
                blob = " ".join(str(full.get(k, "") or "") for k in ("subject", "intro", "text", "html"))
                code = _extract_code(blob)
                if code:
                    return code
            time.sleep(3)
        raise TimeoutError(f"mail.tm no OTP for {self.address}")


class TempMailPlus:
    """tempmail.plus invent-style shared inbox (no create).

    Invent local@domain, poll /api/mails. Shared = OTP race risk.
    Domains: mailto.plus, fexpost.com, fexbox.org, mailbox.in.ua, ...
    """

    BASE = "https://tempmail.plus/api"
    DOMAINS = (
        "mailto.plus",
        "fexpost.com",
        "fexbox.org",
        "mailbox.in.ua",
        "rover.info",
        "chapsmail.com",
        "fextemp.com",
        "merepost.com",
        "tmpbox.net",
        "moakt.cc",
    )

    def __init__(self, impersonate: str = "chrome131"):
        self.s = creq.Session()
        self.impersonate = impersonate
        self.address: str | None = None
        self.domain: str | None = None
        self.local: str | None = None

    def create_account(self) -> str:
        import random

        self.local = "xai" + uuid.uuid4().hex[:10]
        self.domain = random.choice(self.DOMAINS)
        self.address = f"{self.local}@{self.domain}"
        # warm list endpoint
        r = self.s.get(
            f"{self.BASE}/mails",
            params={"email": self.address, "limit": 1, "epin": ""},
            headers={"Accept": "application/json"},
            impersonate=self.impersonate,
            timeout=30,
        )
        if r.status_code >= 400:
            raise RuntimeError(f"tempmail.plus invent {r.status_code}: {r.text[:200]}")
        return self.address

    def wait_code(self, timeout: int = 150) -> str:
        if not self.address:
            raise RuntimeError("tempmail.plus no address")
        deadline = time.time() + timeout
        seen: set[str] = set()
        while time.time() < deadline:
            r = self.s.get(
                f"{self.BASE}/mails",
                params={"email": self.address, "limit": 20, "epin": ""},
                headers={"Accept": "application/json"},
                impersonate=self.impersonate,
                timeout=30,
            )
            if r.status_code < 400 and r.content:
                data = r.json() if r.content else {}
                mails = data.get("mail_list") or data.get("mails") or data.get("list") or []
                if isinstance(data, list):
                    mails = data
                for m in mails:
                    mid = str(m.get("mail_id") or m.get("id") or m.get("_id") or "")
                    if not mid or mid in seen:
                        continue
                    seen.add(mid)
                    blob = " ".join(
                        str(m.get(k, "") or "")
                        for k in ("subject", "from_mail", "from", "text", "preview", "summary")
                    )
                    code = _extract_code(blob)
                    if code:
                        return code
                    # full body
                    try:
                        r2 = self.s.get(
                            f"{self.BASE}/mails/{mid}",
                            params={"email": self.address, "epin": ""},
                            headers={"Accept": "application/json"},
                            impersonate=self.impersonate,
                            timeout=30,
                        )
                        if r2.status_code < 400 and r2.content:
                            full = r2.json()
                            blob2 = " ".join(
                                str(full.get(k, "") or "")
                                for k in (
                                    "subject",
                                    "text",
                                    "html",
                                    "from_mail",
                                    "from",
                                    "body",
                                )
                            )
                            code = _extract_code(blob2)
                            if code:
                                return code
                    except Exception:
                        pass
            time.sleep(3)
        raise TimeoutError(f"tempmail.plus no OTP for {self.address}")


class Maildrop:
    """maildrop.cc GraphQL invent-style shared inbox."""

    GQL = "https://api.maildrop.cc/graphql"
    DOMAIN = "maildrop.cc"

    def __init__(self, impersonate: str = "chrome131"):
        self.s = creq.Session()
        self.impersonate = impersonate
        self.address: str | None = None
        self.mailbox: str | None = None

    def create_account(self) -> str:
        self.mailbox = "xai" + uuid.uuid4().hex[:10]
        self.address = f"{self.mailbox}@{self.DOMAIN}"
        # warm inbox query
        q = {
            "query": "query($mailbox:String!){inbox(mailbox:$mailbox){id headerfrom subject date}}",
            "variables": {"mailbox": self.mailbox},
        }
        r = self.s.post(
            self.GQL,
            json=q,
            headers=JSON_HEADERS,
            impersonate=self.impersonate,
            timeout=30,
        )
        if r.status_code >= 400:
            raise RuntimeError(f"maildrop invent {r.status_code}: {r.text[:200]}")
        return self.address

    def wait_code(self, timeout: int = 150) -> str:
        if not self.mailbox:
            raise RuntimeError("maildrop no mailbox")
        deadline = time.time() + timeout
        seen: set[str] = set()
        while time.time() < deadline:
            q = {
                "query": "query($mailbox:String!){inbox(mailbox:$mailbox){id headerfrom subject date}}",
                "variables": {"mailbox": self.mailbox},
            }
            r = self.s.post(
                self.GQL,
                json=q,
                headers=JSON_HEADERS,
                impersonate=self.impersonate,
                timeout=30,
            )
            if r.status_code < 400 and r.content:
                data = r.json() if r.content else {}
                msgs = ((data.get("data") or {}).get("inbox")) or []
                for m in msgs:
                    mid = str(m.get("id") or "")
                    if not mid or mid in seen:
                        continue
                    seen.add(mid)
                    blob = " ".join(str(m.get(k, "") or "") for k in ("subject", "headerfrom"))
                    code = _extract_code(blob)
                    if code:
                        return code
                    # full message
                    try:
                        q2 = {
                            "query": (
                                "query($mailbox:String!,$id:String!)"
                                "{message(mailbox:$mailbox,id:$id){id headerfrom subject data html}}"
                            ),
                            "variables": {"mailbox": self.mailbox, "id": mid},
                        }
                        r2 = self.s.post(
                            self.GQL,
                            json=q2,
                            headers=JSON_HEADERS,
                            impersonate=self.impersonate,
                            timeout=30,
                        )
                        if r2.status_code < 400 and r2.content:
                            full = ((r2.json().get("data") or {}).get("message")) or {}
                            blob2 = " ".join(
                                str(full.get(k, "") or "")
                                for k in ("subject", "headerfrom", "data", "html")
                            )
                            code = _extract_code(blob2)
                            if code:
                                return code
                    except Exception:
                        pass
            time.sleep(3)
        raise TimeoutError(f"maildrop no OTP for {self.address}")


class NcaoriMail:
    """GAC-proven catch-all: invent *@ncaori.my.id / *@nca.my.id, poll nca.my.id API.

    Inbox response already includes full body_text/body_html — no separate read.
    """

    BASE = "https://www.nca.my.id"
    DOMAINS = ("ncaori.my.id", "nca.my.id")
    WORDS1 = (
        "swift", "crystal", "storm", "frost", "shadow", "ember", "azure",
        "phantom", "silver", "iron", "crimson", "golden", "neo", "cosmic",
        "lunar", "solar", "dark", "light", "void", "flux",
    )
    WORDS2 = (
        "core", "leaf", "forge", "wave", "peak", "gate", "pulse", "blade",
        "shard", "drift", "hive", "node", "edge", "beacon", "nova", "cloud",
        "moon", "star", "wind", "spark",
    )

    def __init__(self, impersonate: str = "chrome131"):
        self.s = creq.Session()
        self.impersonate = impersonate
        self.address: str | None = None

    def create_account(self) -> str:
        local = f"{random.choice(self.WORDS1)}_{random.choice(self.WORDS2)}{uuid.uuid4().hex[:4]}"
        domain = random.choice(self.DOMAINS)
        self.address = f"{local}@{domain}"
        # warm inbox endpoint (invent style — no explicit create)
        r = self.s.get(
            f"{self.BASE}/api/emails",
            params={"recipient": self.address},
            headers=JSON_HEADERS,
            impersonate=self.impersonate,
            timeout=30,
        )
        if r.status_code >= 500:
            raise RuntimeError(f"ncaori warm {r.status_code}: {(r.text or '')[:120]}")
        return self.address

    def wait_code(self, timeout: int = 150) -> str:
        if not self.address:
            raise RuntimeError("ncaori no OTP for no address")
        deadline = time.time() + timeout
        seen: set[str] = set()
        # adaptive poll: fast first 20s, then ease (mail usually lands 2–8s)
        poll = float(os.getenv("OTP_POLL_S", "0.8"))
        poll_max = float(os.getenv("OTP_POLL_MAX_S", "2.0"))
        t0 = time.time()
        while time.time() < deadline:
            r = self.s.get(
                f"{self.BASE}/api/emails",
                params={"recipient": self.address},
                headers=JSON_HEADERS,
                impersonate=self.impersonate,
                timeout=15,
            )
            if r.status_code < 400 and r.content:
                try:
                    data = r.json()
                except Exception:
                    data = {}
                msgs = data.get("emails") if isinstance(data, dict) else []
                for m in msgs or []:
                    mid = str(m.get("id") or "")
                    if mid and mid in seen:
                        continue
                    if mid:
                        seen.add(mid)
                    blob = " ".join(
                        str(m.get(k, "") or "")
                        for k in ("subject", "sender", "body_text", "body_html", "preview")
                    )
                    code = _extract_code(blob)
                    if code:
                        return code
            # ramp poll interval after first 12s
            if time.time() - t0 > 12:
                poll = min(poll_max, poll * 1.15)
            time.sleep(poll)
        raise TimeoutError(f"ncaori no OTP for {self.address}")


class Zoromail:
    """GAC-proven REST tempmail: domains from API, create email, poll messages.

    https://zoromail.com/public_api.php/v1
    """

    API = "https://zoromail.com/public_api.php/v1"

    def __init__(self, impersonate: str = "chrome131"):
        self.s = creq.Session()
        self.impersonate = impersonate
        self.address: str | None = None

    def _api(self, method: str, path: str, **kw) -> Any:
        r = self.s.request(
            method,
            self.API + path,
            headers={**JSON_HEADERS, **kw.pop("headers", {})},
            impersonate=self.impersonate,
            timeout=kw.pop("timeout", 30),
            **kw,
        )
        if r.status_code >= 400:
            raise RuntimeError(f"zoromail {method} {path} -> {r.status_code} {(r.text or '')[:160]}")
        try:
            payload = r.json() if r.content else {}
        except Exception as e:
            raise RuntimeError(f"zoromail bad json: {e}") from e
        if not isinstance(payload, dict) or payload.get("success") is not True:
            err = (payload or {}).get("error") if isinstance(payload, dict) else payload
            raise RuntimeError(f"zoromail api error: {err}")
        return payload.get("data")

    def create_account(self) -> str:
        domains = self._api("GET", "/domains")
        if not isinstance(domains, list) or not domains:
            raise RuntimeError("zoromail no domains")
        domain = random.choice(domains)
        username = "xai" + uuid.uuid4().hex[:10]
        data = self._api(
            "POST",
            "/emails",
            json={"username": username, "domain": domain},
        )
        if isinstance(data, dict):
            self.address = data.get("email") or f"{username}@{domain}"
        else:
            self.address = f"{username}@{domain}"
        return self.address

    def wait_code(self, timeout: int = 150) -> str:
        if not self.address:
            raise RuntimeError("zoromail no address")
        deadline = time.time() + timeout
        seen: set[str] = set()
        while time.time() < deadline:
            try:
                msgs = self._api("GET", f"/emails/{self.address}/messages") or []
            except Exception:
                msgs = []
            if not isinstance(msgs, list):
                msgs = []
            for m in msgs:
                mid = str(m.get("id") or "")
                if mid and mid in seen:
                    continue
                if mid:
                    seen.add(mid)
                blob = " ".join(str(m.get(k, "") or "") for k in ("subject", "from", "preview", "text"))
                code = _extract_code(blob)
                if code:
                    return code
                if mid:
                    try:
                        full = self._api("GET", f"/messages/{mid}") or {}
                        blob2 = " ".join(
                            str(full.get(k, "") or "")
                            for k in ("subject", "from", "text", "body_text", "html", "body_html")
                        )
                        code = _extract_code(blob2)
                        if code:
                            return code
                    except Exception:
                        pass
            time.sleep(3)
        raise TimeoutError(f"zoromail no OTP for {self.address}")


class EmailBox:
    """Unified mailbox: create_account() + wait_code() + address."""

    # GAC-proven first (custom domains), then best free pure-API from bake-off.
    # Disposable classics last — often domain-rejected by xAI.
    DEFAULT_PREFER = [
        # 2026-08-12: tested OTP delivery — these 6 work
        "tempmail.lol",
        "smailpro",
        "mail.tm",
        "tempmail.plus",
        "guerrilla",
        "maildrop",
        # emailnator works but Gmail alias pool is small (existing email errors)
        "emailnator",
        # ncaori/zoromail: OTP delivery broken as of 2026-08-12
        "ncaori",
        "zoromail",
        # temp-mail.io: domain rejected by xAI
        "temp-mail.io",
    ]

    # canonical names for matrix tests / CLI
    ALL = [
        "ncaori",
        "zoromail",
        "tempmail.lol",
        "temp-mail.io",
        "emailnator",
        "smailpro",
        "guerrilla",
        "mail.tm",
        "tempmail.plus",
        "maildrop",
    ]

    def __init__(self, prefer: list[str] | None = None, pinned: bool = False):
        self.prefer = prefer or list(self.DEFAULT_PREFER)
        self.pinned = pinned  # if True: never leave this prefer list
        self.provider_name: str | None = None
        self.impl: Any = None
        self.address: str | None = None

    def _make(self, name: str) -> Any:
        if name in ("ncaori", "ncaorimail", "nca"):
            return NcaoriMail()
        if name in ("zoromail", "zoro"):
            return Zoromail()
        if name in ("smailpro", "smail", "sonjj"):
            return SmailPro()
        if name in ("emailnator", "gmailnator"):
            return EmailNator()
        if name in ("temp-mail.io", "tempmail.io", "tempmailio"):
            return TempMailIO()
        if name in ("tempmail.lol", "tempmail", "lol"):
            return TempMailLol()
        if name in ("guerrilla", "guerrillamail"):
            return GuerrillaMail()
        if name in ("mail.tm", "mailtm"):
            return MailTM()
        if name in ("tempmail.plus", "tempmailplus", "plus"):
            return TempMailPlus()
        if name in ("maildrop", "maildrop.cc"):
            return Maildrop()
        raise ValueError(f"unknown mail provider: {name}")

    def create_account(self) -> str:
        errors = []
        for name in self.prefer:
            try:
                impl = self._make(name)
                addr = impl.create_account()
                self.impl = impl
                self.provider_name = name
                self.address = addr
                return addr
            except Exception as e:
                errors.append(f"{name}: {e}")
        raise RuntimeError("all email providers failed: " + " | ".join(errors))

    def wait_code(self, timeout: int = 150) -> str:
        if not self.impl:
            raise RuntimeError("no mailbox")
        return self.impl.wait_code(timeout=timeout)


if __name__ == "__main__":
    box = EmailBox()
    print(box.create_account(), box.provider_name)
