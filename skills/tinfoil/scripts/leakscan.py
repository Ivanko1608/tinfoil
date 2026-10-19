#!/usr/bin/env python3
"""
leakscan.py - stdlib-only scanner for secrets, PII, and business-sensitive data.

Scans files, folders, git history, staged changes, or stdin for material that
should not be on the public internet: credentials, personal identifiers,
financial/government IDs, internal infrastructure, identity-revealing paths,
location data, and file metadata (EXIF GPS, document authors, tracked changes).

Usage:
  leakscan.py PATH [PATH ...]           scan files/folders (git-aware)
  leakscan.py REPO --history            also scan every commit on every branch
  leakscan.py REPO --staged             scan only what is staged (pre-commit)
  leakscan.py REPO --push               scan only commits a push adds, read
                                        from pre-push stdin (pre-push hook)
  echo "text" | leakscan.py --stdin     scan text (e.g. a draft before posting)

Options:
  --denylist FILE   personal terms that must never appear (one per line,
                    're:' prefix for regex). Also read from $LEAKSCAN_DENYLIST
                    and ~/.config/leakscan/denylist.txt
  --json            machine-readable output
  --reveal          print raw matches instead of masked ones (local use only)
  --fail-on LEVEL   exit 1 if any finding >= LEVEL (default: high; 'none' = never)
  --max-commits N   cap history scan depth
  --include-deps    also scan node_modules/, target/, vendor/, dist/ ...

Suppress false positives with a .leakscanignore file in the scan root / repo
top: lines of 'fp:<fingerprint>', 'detector:<id>', or a path glob.
"""
import argparse
import fnmatch
import hashlib
import json
import math
import os
import re
import struct
import subprocess
import sys
import zipfile
from collections import Counter
from dataclasses import dataclass, asdict

SEV = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
MAX_TEXT_BYTES = 2_000_000
PER_DETECTOR_TEXT_CAP = 40

SKIP_DIRS = {".git", "node_modules", "target", "vendor", "dist", "build", ".venv",
             "venv", "__pycache__", ".next", ".nuxt", ".gradle", ".tox",
             ".mypy_cache", ".pytest_cache", "coverage", ".cache", ".terraform"}
LOCKFILES = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "Cargo.lock",
             "go.sum", "poetry.lock", "Pipfile.lock", "composer.lock",
             "Gemfile.lock", "bun.lockb", "flake.lock"}
IMAGE_EXT = {".jpg", ".jpeg", ".tif", ".tiff", ".png", ".webp"}
OFFICE_EXT = {".docx", ".xlsx", ".pptx", ".odt", ".ods", ".odp"}


@dataclass
class Finding:
    severity: str
    category: str
    detector: str
    path: str
    line: int
    match: str
    note: str = ""
    where: str = "worktree"
    fingerprint: str = ""


# --------------------------------------------------------------------------- #
# helpers / validators
# --------------------------------------------------------------------------- #
PLACEHOLDER = re.compile(
    r"(?i)(x{4,}|\byour[_-]|example|changeme|change_me|placeholder|dummy|fake|"
    r"sample|redacted|<[^>]*>|\$\{|\{\{|%\(|process\.env|os\.environ|getenv|"
    r"env\(|\*{3,}|\btodo\b|replace|insert|_here\b|\.\.\.|\btest\b|"
    r"^password$|^secret$|^token$|^pass(word)?123|^admin$|^root$|^null$|^none$)")


def entropy(s):
    if not s:
        return 0.0
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in Counter(s).values())


def not_placeholder(val):
    return not PLACEHOLDER.search(val) and len(set(val)) > 3


def luhn(digits):
    tot = 0
    for i, ch in enumerate(reversed(digits)):
        x = int(ch)
        if i % 2:
            x *= 2
            if x > 9:
                x -= 9
        tot += x
    return tot % 10 == 0


TEST_CARDS = {"4242424242424242", "4111111111111111", "5555555555554444",
              "4000056655665556", "378282246310005", "371449635398431",
              "6011111111111117", "5105105105105100", "4012888888881881",
              "4000000000000002", "4000000000009995", "5200828282828210"}


def v_card(m, line):
    d = re.sub(r"\D", "", m.group(0))
    if d in TEST_CARDS:
        return {"severity": "low", "note": "well-known test card number"}
    if not 13 <= len(d) <= 19 or len(set(d)) < 4:
        return None
    if not re.match(r"^(4|5[1-5]|2[2-7]|3[47]|6(011|5))", d) or not luhn(d):
        return None
    return {}


def v_iban(m, line):
    s = re.sub(r"\s", "", m.group(0)).upper()
    if not 15 <= len(s) <= 34:
        return None
    try:
        num = "".join(str(int(c, 36)) for c in s[4:] + s[:4])
    except ValueError:
        return None
    return {} if int(num) % 97 == 1 else None


DNI_LETTERS = "TRWAGMYFPDXBNJZSQVHLCKE"


def v_dni(m, line):
    s = re.sub(r"[\s-]", "", m.group(0)).upper()
    if s[0] in "XYZ":
        n = str("XYZ".index(s[0])) + s[1:8]
    else:
        n = s[:8]
    if not n.isdigit() or len(set(n)) < 3:
        return None
    return {} if DNI_LETTERS[int(n) % 23] == s[-1] else None


def v_snils(m, line):
    d = re.sub(r"\D", "", m.group(0))
    if len(d) != 11:
        return None
    body, ctrl = d[:9], int(d[9:])
    if int(body) <= 1001998:
        return None
    s = sum(int(body[i]) * (9 - i) for i in range(9))
    c = s if s < 100 else (0 if s in (100, 101) else s % 101)
    if c == 100:
        c = 0
    return {} if c == ctrl else None


def v_inn(m, line):
    d = [int(c) for c in m.group(0)]

    def chk(w, ds):
        return sum(a * b for a, b in zip(w, ds)) % 11 % 10
    if len(d) == 10:
        return {} if chk([2, 4, 10, 3, 5, 9, 4, 6, 8], d) == d[9] else None
    if len(d) == 12:
        ok = (chk([7, 2, 4, 10, 3, 5, 9, 4, 6, 8], d) == d[10] and
              chk([3, 7, 2, 4, 10, 3, 5, 9, 4, 6, 8], d) == d[11])
        return {} if ok else None
    return None


EMAIL_SKIP_DOMAINS = {"example.com", "example.org", "example.net", "test.com",
                      "domain.com", "email.com", "localhost", "foo.com",
                      "bar.com", "users.noreply.github.com",
                      "noreply.github.com", "sentry.io", "mail.com"}
FILE_TLDS = {"png", "jpg", "jpeg", "gif", "svg", "webp", "js", "ts", "css",
             "py", "rs", "go", "md", "json", "html", "tsx", "jsx", "lock"}
EMAIL_SKIP_LOCAL = {"user", "test", "foo", "bar", "name", "you", "your.name",
                    "john.doe", "jane.doe", "someone", "me", "email", "admin"}


def v_email(m, line):
    addr = m.group(0)
    local, _, dom = addr.rpartition("@")
    dom_l, local_l = dom.lower(), local.lower()
    if dom_l in EMAIL_SKIP_DOMAINS or dom_l.endswith(".example") \
            or dom_l.endswith(".test") or dom_l.endswith(".invalid"):
        return None
    if dom_l.rsplit(".", 1)[-1] in FILE_TLDS:
        return None
    if local_l.startswith(("noreply", "no-reply", "donotreply")) \
            or local_l in EMAIL_SKIP_LOCAL or local_l == "git":
        return None
    return {}


def v_phone(m, line):
    d = re.sub(r"\D", "", m.group(0))
    if not 9 <= len(d) <= 15 or len(set(d)) < 4:
        return None
    return {}


def v_ipv4_octets(m, line):
    parts = m.group(0).split(".")
    return {} if all(0 <= int(p) <= 255 for p in parts) else None


COMMON_PUBLIC_IPS = {"8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9",
                     "208.67.222.222", "208.67.220.220", "255.255.255.255"}


def v_public_ip(m, line):
    ip = m.group(0)
    parts = [int(p) for p in ip.split(".")]
    if any(p > 255 for p in parts) or ip in COMMON_PUBLIC_IPS:
        return None
    a, b, c = parts[0], parts[1], parts[2]
    if (a, b, c) in ((192, 0, 2), (198, 51, 100), (203, 0, 113)) \
            or (a == 198 and b in (18, 19)) or len(set(parts)) == 1 \
            or parts[3] == 0 or line[m.end():m.end() + 1] == "/":
        return None
    if a in (0, 10, 127) or a >= 224 or (a == 172 and 16 <= b <= 31) \
            or (a == 192 and b == 168) or (a == 169 and b == 254) \
            or (a == 100 and 64 <= b <= 127):
        return None
    start = m.start()
    pre = line[max(0, start - 12):start].lower()
    if re.search(r"(v|version|ver|@|=\s*\"?)\s*$", pre) and "ip" not in pre:
        return None
    # dotted version strings like 1.2.3.4 with small numbers are common
    if all(p < 30 for p in parts):
        return None
    return {}


GENERIC_USERS = {"user", "username", "runner", "ubuntu", "node", "app", "root",
                 "admin", "you", "yourname", "your-name", "me", "name", "test",
                 "default", "public", "shared", "vagrant", "ec2-user", "debian",
                 "pi", "claude", "<user>", "$user", "%username%", "jenkins",
                 "builder", "build", "travis", "circleci", "linuxbrew"}


def v_home(m, line):
    u = m.group(1).lower()
    if u in GENERIC_USERS or u.startswith(("$", "%", "<", "{")):
        return None
    return {"note": "home path reveals local username"}


def v_prompt(m, line):
    if m.group(1).lower() in ("git", "user", "you", "root") and \
            m.group(2).lower() in ("host", "hostname", "localhost", "server",
                                   "machine", "github.com"):
        return None
    if m.group(1).lower() == "git":
        return None
    return {"note": "shell prompt reveals user@hostname"}


def v_secret_value(m, line):
    val = m.group(1)
    if not not_placeholder(val):
        return None
    if entropy(val) < 3.0:
        return None
    return {}


def v_url_creds(m, line):
    pw = m.group(1)
    host = m.group(0).rsplit("@", 1)[-1].split("/")[0].split(":")[0].lower()
    if host in ("localhost", "127.0.0.1", "0.0.0.0", "host", "hostname") \
            or re.search(r"(^|\.)example\.(com|org|net)$|\.(test|example|invalid)$",
                         host):
        return {"severity": "low", "note": "credential-shaped URL pointing at "
                "a placeholder host"}
    if not not_placeholder(pw) or pw.lower() in ("pass", "pwd", "postgres",
                                                 "password", "secret", "guest"):
        return {"severity": "low", "note": "credential-shaped URL with what "
                "looks like a placeholder password"}
    return {}


def v_gps(m, line):
    try:
        lat, lon = [float(x) for x in re.split(r"\s*,\s*", m.group(0))]
    except ValueError:
        return None
    if not (-90 <= lat <= 90 and -180 <= lon <= 180) or (lat == 0 and lon == 0):
        return None
    return {"note": f"coordinates ~{lat:.3f},{lon:.3f} - check what is there"}


def v_saas(m, line):
    sub = m.group(1).lower()
    if sub in ("hooks", "api", "app", "www", "status", "support", "help",
               "your-domain", "yourcompany", "your-company", "example",
               "mycompany", "company", "team", "workspace"):
        return None
    return {}


# --------------------------------------------------------------------------- #
# detectors: (id, category, severity, regex, validator, context, group, lockok)
# --------------------------------------------------------------------------- #
def D(id, cat, sev, pat, validator=None, context=None, group=0, lockok=False,
      flags=0):
    return dict(id=id, cat=cat, sev=sev, rx=re.compile(pat, flags),
                validator=validator,
                ctx=re.compile(context, re.I) if context else None,
                group=group, lockok=lockok)


DETECTORS = [
    # --- credentials ---------------------------------------------------------
    D("private_key", "secret", "critical",
      r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----"),
    D("aws_access_key", "secret", "critical", r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    D("github_token", "secret", "critical",
      r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,})\b"),
    D("gitlab_token", "secret", "critical", r"\bglpat-[A-Za-z0-9_-]{20,}"),
    D("slack_token", "secret", "critical", r"\bxox[abposr]-[A-Za-z0-9-]{10,}"),
    D("slack_webhook", "secret", "high",
      r"https://hooks\.slack\.com/services/[A-Za-z0-9/_-]{20,}"),
    D("discord_webhook", "secret", "high",
      r"https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d+/[\w-]+"),
    D("stripe_live_key", "secret", "critical",
      r"\b(?:sk|rk)_live_[0-9a-zA-Z]{20,}"),
    D("google_api_key", "secret", "high", r"\bAIza[0-9A-Za-z_-]{35}\b"),
    D("anthropic_key", "secret", "critical", r"\bsk-ant-[A-Za-z0-9_-]{20,}"),
    D("openai_key", "secret", "critical",
      r"\bsk-(?!ant-)(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{32,}"),
    D("huggingface_token", "secret", "critical", r"\bhf_[A-Za-z0-9]{34,}\b"),
    D("telegram_bot_token", "secret", "critical",
      r"\b\d{8,10}:AA[A-Za-z0-9_-]{33}\b"),
    D("sendgrid_key", "secret", "critical", r"\bSG\.[\w-]{22}\.[\w-]{43}\b"),
    D("npm_token", "secret", "critical", r"\bnpm_[A-Za-z0-9]{36}\b"),
    D("twilio_key", "secret", "medium", r"\bSK[0-9a-fA-F]{32}\b"),
    D("wireguard_private_key", "secret", "critical",
      r"(?i)PrivateKey\s*=\s*[A-Za-z0-9+/]{42,43}="),
    D("jwt", "secret", "high",
      r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
    D("url_credentials", "secret", "high",
      r"\b[a-zA-Z][a-zA-Z0-9+.-]{1,20}://[^\s/:@'\"]{1,64}:([^\s/@'\"]{1,128})@[^\s/'\"]+",
      v_url_creds, group=0, lockok=True),
    D("npmrc_auth_token", "secret", "high", r"_auth(?:Token)?\s*=\s*(\S{8,})",
      v_secret_value, group=1, lockok=True),
    D("env_secret_assignment", "secret", "high",
      r"^\s*(?:export\s+)?[A-Z0-9_]*(?:PASSWORD|PASSWD|SECRET|TOKEN|API_KEY|APIKEY|"
      r"ACCESS_KEY|PRIVATE_KEY|DSN|CREDENTIALS?)[A-Z0-9_]*\s*=\s*([^\s#'\"]{8,})",
      v_secret_value, group=1),
    D("secret_assignment", "secret", "medium",
      r"(?i)\b[\w.-]*(?:password|passwd|pwd|secret|api[_-]?key|apikey|access[_-]?key|"
      r"auth[_-]?token|bearer|token|private[_-]?key|client[_-]?secret)[\w.-]*[\"']?\s*"
      r"(?::|=|:=|=>)\s*[\"']([^\"'\s]{12,})[\"']",
      v_secret_value, group=1),
    # --- personal identifiers -----------------------------------------------
    D("email", "pii", "medium",
      r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,24}\b", v_email),
    D("phone_international", "pii", "medium",
      r"(?<![\w+/.])\+\d{1,3}[\s.-]?\(?\d{1,4}\)?(?:[\s.-]?\d{2,4}){2,4}(?![\w/])",
      v_phone),
    D("phone_with_context", "pii", "medium",
      r"(?<![\d+])(?:\d[\s.-]?){8,10}\d(?!\d)", v_phone,
      context=r"(phone|tel[eé]fono|\btel\b|mobile|m[oó]vil|whatsapp|"
              r"телефон|\bтел\b|контакт)"),
    D("date_of_birth", "pii", "high", r"\b\d{1,4}[./-]\d{1,2}[./-]\d{1,4}\b",
      context=r"(\bborn\b|\bdob\b|date of birth|birthday|fecha de nacimiento|"
              r"nacido|дата рождения|родил)"),
    D("street_address_es", "pii", "medium",
      r"(?i)\b(?:calle|c/|avda\.?|avenida|plaza|pza\.?|paseo|carrer|passeig|"
      r"traves[ií]a|camino|ronda)\s+[A-ZÀ-ÿa-z][\wÀ-ÿ' .-]{2,40}?,?\s*"
      r"(?:n[ºo°]\.?\s*)?\d{1,4}\b"),
    D("street_address_ru", "pii", "medium",
      r"(?i)(?:ул\.|улица|проспект|пр-т|пер\.|переулок|бульвар|шоссе)\s*"
      r"[А-Яа-яЁё\w .-]{2,40},?\s*(?:д\.|дом)\s*\d+"),
    D("street_address_en", "pii", "low",
      r"\b\d{1,5}\s+(?:[A-Z][a-z]+\s){1,3}(?:Street|St\.|Avenue|Ave\.|Road|Rd\.|"
      r"Boulevard|Blvd\.|Lane|Ln\.|Drive|Dr\.|Court|Ct\.)"),
    # --- financial ----------------------------------------------------------
    D("payment_card", "financial", "critical", r"\b(?:\d[ -]?){12,18}\d\b",
      v_card),
    D("iban", "financial", "high",
      r"\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{4}){2,7}(?:[ ]?[A-Z0-9]{1,4})?\b", v_iban),
    # --- government IDs -----------------------------------------------------
    D("es_dni_nie", "gov-id", "high", r"\b(?:[XYZ]\d{7}|\d{8})[-\s]?[A-Z]\b",
      v_dni),
    D("ru_snils", "gov-id", "critical", r"\b\d{3}-\d{3}-\d{3}[ -]\d{2}\b",
      v_snils),
    D("ru_inn", "gov-id", "high", r"\b\d{10}(?:\d{2})?\b", v_inn,
      context=r"(ИНН|\bINN\b)"),
    D("ru_passport", "gov-id", "critical", r"\b\d{2}\s?\d{2}\s?\d{6}\b",
      context=r"(паспорт|passport|серия|pasaporte)"),
    D("passport_number", "gov-id", "critical", r"\b[A-Z]{0,2}\d{6,9}\b",
      context=r"(passport no|passport number|passport #|n[uú]mero de pasaporte|"
              r"pasaporte n)"),
    D("es_social_security", "gov-id", "high", r"\b\d{2}[ /-]?\d{8}[ /-]?\d{2}\b",
      context=r"(\bnss\b|seguridad social|n[uú]m\. afiliaci[oó]n)"),
    D("ssn_us", "gov-id", "critical", r"\b\d{3}-\d{2}-\d{4}\b",
      context=r"(\bssn\b|social security)"),
    # --- infrastructure -----------------------------------------------------
    D("private_ip", "infra", "low",
      r"\b(?:10\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}\b",
      v_ipv4_octets),
    D("public_ip", "infra", "low", r"\b(?:\d{1,3}\.){3}\d{1,3}\b", v_public_ip),
    D("internal_hostname", "infra", "medium",
      r"(?i)\b(?:[a-z0-9-]+\.)+(?:internal|corp|intranet|lan|home\.arpa|"
      r"localdomain)\b"),
    D("saas_workspace", "business", "medium",
      r"(?i)\b([a-z0-9-]+)\.(?:atlassian\.net|slack\.com|sharepoint\.com|"
      r"my\.salesforce\.com|zendesk\.com|freshdesk\.com|monday\.com|"
      r"bamboohr\.com|workable\.com|okta\.com)\b", v_saas),
    D("google_doc_link", "business", "medium",
      r"https://(?:docs\.google\.com/(?:document|spreadsheets|presentation|forms)/d/"
      r"|drive\.google\.com/(?:file/d/|drive/folders/|open\?id=))[\w-]{20,}"),
    D("confidentiality_marker", "business", "medium",
      r"(?i)\b(confidential|internal use only|internal only|do not distribute|"
      r"not for distribution|under nda|trade secret|конфиденциально|"
      r"для служебного пользования|confidencial|uso interno)\b"),
    # --- identity / location -----------------------------------------------
    D("home_path", "identity", "medium",
      r"(?:(?:(?<![^\s\"'=:(])|(?<=file://))(?:/home/|/Users/)"
      r"|[A-Za-z]:\\{1,2}Users\\{1,2})([A-Za-z0-9._-]+)",
      v_home),
    D("shell_prompt", "identity", "medium",
      r"\b([a-z_][a-z0-9_-]{1,31})@([A-Za-z0-9-]{2,63}):(?:~|/)", v_prompt),
    D("gps_coordinates", "location", "medium",
      r"(?<![\d.])-?\d{1,2}\.\d{4,}\s*,\s*-?\d{1,3}\.\d{4,}(?![\d.])", v_gps),
]

# risky filenames: (glob, severity, note)
FILE_RULES = [
    ("id_rsa", "critical", "SSH private key"),
    ("id_dsa", "critical", "SSH private key"),
    ("id_ecdsa", "critical", "SSH private key"),
    ("id_ed25519", "critical", "SSH private key"),
    ("*.p12", "high", "certificate bundle (often includes private key)"),
    ("*.pfx", "high", "certificate bundle (often includes private key)"),
    ("*.jks", "high", "Java keystore"),
    ("*.keystore", "high", "keystore"),
    ("*.kdbx", "high", "KeePass database"),
    ("*.key", "medium", "key file - check contents"),
    (".env", "high", "environment file"),
    (".env.*", "high", "environment file"),
    (".npmrc", "medium", "may hold registry auth token"),
    (".pypirc", "high", "PyPI credentials"),
    (".netrc", "high", "machine credentials"),
    (".git-credentials", "critical", "stored git credentials"),
    ("credentials", "high", "credentials file"),
    ("credentials.json", "high", "credentials file"),
    ("client_secret*.json", "high", "OAuth client secret"),
    ("service-account*.json", "high", "cloud service-account key"),
    ("*serviceaccount*.json", "high", "cloud service-account key"),
    ("terraform.tfstate*", "high", "Terraform state (contains secrets in plaintext)"),
    ("kubeconfig", "high", "Kubernetes credentials"),
    ("*.ovpn", "medium", "VPN profile - may embed keys"),
    ("*.har", "high", "HTTP archive - contains cookies/auth headers"),
    (".bash_history", "high", "shell history"),
    (".zsh_history", "high", "shell history"),
    (".python_history", "medium", "REPL history"),
    (".psql_history", "high", "DB shell history"),
    (".mysql_history", "high", "DB shell history"),
    ("*.sqlite", "medium", "database file - may hold real data"),
    ("*.sqlite3", "medium", "database file - may hold real data"),
    ("*.db", "medium", "database file - may hold real data"),
    ("*.dump", "medium", "possible database dump"),
    ("*.bak", "low", "backup file"),
    ("*.log", "low", "log file - often contains IPs, emails, tokens"),
    (".DS_Store", "low", "leaks names of neighbouring files"),
    ("Thumbs.db", "low", "Windows thumbnail cache"),
]
SAFE_ENV_SUFFIXES = (".example", ".sample", ".template", ".dist", ".defaults")


def file_rule(path):
    name = os.path.basename(path)
    low = name.lower()
    if low.startswith(".env") and low.endswith(SAFE_ENV_SUFFIXES):
        return None
    if path.replace("\\", "/").endswith(".kube/config"):
        return ("high", "Kubernetes credentials")
    for glob, sev, note in FILE_RULES:
        if fnmatch.fnmatch(low, glob.lower()):
            return (sev, note)
    return None


TEST_PATH = re.compile(r"(?i)(^|/)(tests?|testdata|fixtures?|__tests__|spec|"
                       r"examples?|mocks?)(/|$)|_test\.|\.test\.|\.spec\.")


# --------------------------------------------------------------------------- #
# scanner core
# --------------------------------------------------------------------------- #
class Scanner:
    def __init__(self, denylist, reveal=False):
        self.findings = []
        self.reveal = reveal
        self.deny = denylist
        self.files_scanned = 0
        self.commits_scanned = 0

    def add(self, f):
        f.fingerprint = hashlib.sha256(
            f"{f.detector}\0{f.match}".encode("utf-8", "replace")).hexdigest()[:12]
        self.findings.append(f)

    def scan_line(self, line, path, lineno, where, lockfile=False):
        if len(line) > 20000:
            line = line[:20000]
        for d in DETECTORS:
            if lockfile and not d["lockok"]:
                continue
            if d["ctx"] and not d["ctx"].search(line):
                continue
            for m in d["rx"].finditer(line):
                extra = {}
                if d["validator"]:
                    extra = d["validator"](m, line)
                    if extra is None:
                        continue
                sev, note = extra.get("severity", d["sev"]), extra.get("note", "")
                if d["cat"] == "secret" and TEST_PATH.search(path) \
                        and sev == "critical":
                    sev = "high"
                    note = (note + "; " if note else "") + "in a test/fixture " \
                        "path - probably a throwaway, confirm it is not used for real"
                self.add(Finding(
                    severity=sev, category=d["cat"], detector=d["id"], path=path,
                    line=lineno, match=m.group(d["group"]), note=note,
                    where=where))
        if not lockfile:
            for label, rx in self.deny:
                for m in rx.finditer(line):
                    self.add(Finding("high", "denylist", "denylist", path, lineno,
                                     m.group(0), f"matched denylist entry {label}",
                                     where))

    def scan_text(self, text, path, where="worktree", lockfile=False,
                  start_line=1):
        for i, line in enumerate(text.splitlines(), start_line):
            self.scan_line(line, path, i, where, lockfile)
        # PEM blocks span lines; private_key regex already catches header.

    # ---- file dispatch ----------------------------------------------------
    def scan_file(self, full, rel, where="worktree"):
        self.files_scanned += 1
        rule = file_rule(rel)
        if rule:
            self.add(Finding(rule[0], "file", "risky_file", rel, 0,
                             os.path.basename(rel), rule[1], where))
        ext = os.path.splitext(full)[1].lower()
        try:
            size = os.path.getsize(full)
        except OSError:
            return
        if ext in IMAGE_EXT:
            self.scan_image(full, rel, where)
            return
        if ext == ".pdf":
            self.scan_pdf(full, rel, where)
            return
        if ext in OFFICE_EXT:
            self.scan_office(full, rel, where)
            return
        if size > MAX_TEXT_BYTES:
            return
        try:
            with open(full, "rb") as fh:
                raw = fh.read()
        except OSError:
            return
        if b"\0" in raw[:8192]:
            return
        text = raw.decode("utf-8", "replace")
        if ext == ".ipynb":
            self.check_notebook(text, rel, where)
        self.scan_text(text, rel, where,
                       lockfile=os.path.basename(rel) in LOCKFILES)

    def check_notebook(self, text, rel, where):
        try:
            nb = json.loads(text)
        except ValueError:
            return
        n = sum(1 for c in nb.get("cells", []) if c.get("outputs"))
        if n:
            self.add(Finding("low", "file", "notebook_outputs", rel, 0,
                             f"{n} cells", "notebook has saved outputs - GitHub "
                             "renders them; check for real data/paths", where))

    # ---- metadata ---------------------------------------------------------
    def scan_image(self, full, rel, where):
        try:
            with open(full, "rb") as fh:
                b = fh.read(4_000_000)
        except OSError:
            return
        tiff = None
        texts = {}
        if b[:2] == b"\xff\xd8":
            i = 2
            while i + 4 < len(b) and b[i] == 0xFF:
                marker, seglen = b[i + 1], struct.unpack(">H", b[i + 2:i + 4])[0]
                seg = b[i + 4:i + 2 + seglen]
                if marker == 0xE1 and seg[:6] == b"Exif\0\0":
                    tiff = seg[6:]
                elif marker == 0xE1 and b"ns.adobe.com/xap" in seg[:64]:
                    texts["XMP"] = seg.decode("utf-8", "replace")
                if marker == 0xDA:
                    break
                i += 2 + seglen
        elif b[:4] in (b"II*\0", b"MM\0*"):
            tiff = b
        elif b[:8] == b"\x89PNG\r\n\x1a\n":
            i = 8
            while i + 8 <= len(b):
                ln = struct.unpack(">I", b[i:i + 4])[0]
                typ = b[i + 4:i + 8]
                data = b[i + 8:i + 8 + ln]
                if typ == b"eXIf":
                    tiff = data
                elif typ in (b"tEXt", b"iTXt", b"zTXt"):
                    k, _, v = data.partition(b"\0")
                    texts[k.decode("latin-1")] = v.decode("utf-8", "replace")
                if typ == b"IEND":
                    break
                i += 12 + ln
        elif b[:4] == b"RIFF" and b[8:12] == b"WEBP":
            i = 12
            while i + 8 <= len(b):
                typ, ln = b[i:i + 4], struct.unpack("<I", b[i + 4:i + 8])[0]
                if typ == b"EXIF":
                    data = b[i + 8:i + 8 + ln]
                    tiff = data[6:] if data[:6] == b"Exif\0\0" else data
                elif typ == b"XMP ":
                    texts["XMP"] = b[i + 8:i + 8 + ln].decode("utf-8", "replace")
                i += 8 + ln + (ln & 1)
        if tiff:
            for tag, val in parse_exif(tiff).items():
                if tag == "GPS":
                    self.add(Finding("high", "metadata", "exif_gps", rel, 0, val,
                                     "image embeds GPS location", where))
                elif tag in ("Artist", "Copyright", "OwnerName",
                             "CameraOwnerName", "BodySerialNumber"):
                    self.add(Finding("medium", "metadata", "exif_identity", rel, 0,
                                     f"{tag}={val}", "", where))
                elif tag in ("Make", "Model"):
                    self.add(Finding("info", "metadata", "exif_device", rel, 0,
                                     f"{tag}={val}", "device fingerprint", where))
        for k, v in texts.items():
            if k.lower() in ("author", "copyright", "comment", "description",
                             "source", "xmp", "xml:com.adobe.xmp"):
                self.add(Finding("low", "metadata", "image_text_chunk", rel, 0,
                                 k, "embedded text metadata - inspect", where))
            self.scan_text(v, rel + f" [{k}]", where)

    def scan_pdf(self, full, rel, where):
        try:
            with open(full, "rb") as fh:
                b = fh.read(20_000_000)
        except OSError:
            return
        for key in (b"Author", b"Creator", b"Producer", b"Title", b"Subject",
                    b"Keywords", b"Company"):
            for m in re.finditer(rb"/" + key + rb"\s*(\((?:\\.|[^\\)])*\)|<[0-9A-Fa-f\s]*>)", b):
                val = decode_pdf_string(m.group(1)).strip()
                if not val:
                    continue
                sev = "medium" if key in (b"Author", b"Company") else "info"
                if key in (b"Creator", b"Producer") and re.search(
                        r"(?i)(word|libreoffice|latex|chrome|skia|quartz|acrobat|"
                        r"ghostscript|pdf|tex|writer|google)", val):
                    sev = "info"
                self.add(Finding(sev, "metadata", "pdf_" + key.decode().lower(),
                                 rel, 0, val, "", where))
        if b"/Annots" in b:
            self.add(Finding("low", "metadata", "pdf_annotations", rel, 0,
                             "/Annots", "PDF has annotations/comments", where))
        if b.count(b"%%EOF") > 1:
            self.add(Finding("medium", "metadata", "pdf_incremental_updates", rel,
                             0, f"{b.count(b'%%EOF')} revisions",
                             "earlier revisions (incl. 'deleted' text or "
                             "metadata) may be recoverable", where))
        # cheap text sweep for paths/emails in uncompressed parts
        self.scan_text(b.decode("latin-1"), rel + " [raw]", where)

    def scan_office(self, full, rel, where):
        try:
            z = zipfile.ZipFile(full)
        except (zipfile.BadZipFile, OSError):
            return
        names = set(z.namelist())

        def rd(n):
            try:
                return z.read(n).decode("utf-8", "replace")
            except KeyError:
                return ""
        meta = rd("docProps/core.xml") + rd("docProps/app.xml") + rd("meta.xml")
        for tag in ("dc:creator", "cp:lastModifiedBy", "Company", "Manager",
                    "meta:initial-creator"):
            for m in re.finditer(r"<%s[^>]*>([^<]+)</%s>" % (tag, tag), meta):
                self.add(Finding("medium", "metadata", "office_" +
                                 tag.split(":")[-1].lower(), rel, 0,
                                 m.group(1), "", where))
        if any(n.startswith("word/comments") or n.startswith("xl/comments")
               or n.startswith("ppt/comments") for n in names):
            self.add(Finding("medium", "metadata", "office_comments", rel, 0,
                             "comments", "document contains review comments",
                             where))
        body = ""
        for n in names:
            if re.match(r"(word/document|word/comments|word/footnotes|"
                        r"word/header\d*|word/footer\d*|xl/sharedStrings|"
                        r"ppt/slides/slide\d+|ppt/notesSlides/notesSlide\d+|"
                        r"content)\.xml$", n):
                body += "\n" + rd(n)
        authors = set(re.findall(r'<w:(?:ins|del)\b[^>]*w:author="([^"]+)"',
                                 body))
        for a in authors:
            self.add(Finding("medium", "metadata", "office_tracked_changes", rel,
                             0, a, "tracked changes by this author - deleted "
                             "text is still in the file", where))
        text = re.sub(r"</w:p>|</a:p>|<text:p[^>]*>", "\n", body)
        text = re.sub(r"<[^>]+>", " ", text)
        self.scan_text(text, rel + " [text]", where)


def decode_pdf_string(s):
    if s.startswith(b"<"):
        h = re.sub(rb"\s", b"", s[1:-1])
        try:
            raw = bytes.fromhex(h.decode())
        except ValueError:
            return ""
    else:
        raw = re.sub(rb"\\([nrtbf()\\])", lambda m: {
            b"n": b"\n", b"r": b"\r", b"t": b"\t", b"b": b"\b", b"f": b"\f",
            b"(": b"(", b")": b")", b"\\": b"\\"}[m.group(1)], s[1:-1])
    if raw[:2] == b"\xfe\xff":
        return raw[2:].decode("utf-16-be", "replace")
    return raw.decode("latin-1")


def parse_exif(b):
    out = {}
    if len(b) < 8:
        return out
    e = "<" if b[:2] == b"II" else ">" if b[:2] == b"MM" else None
    if not e:
        return out
    sizes = {1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 7: 1, 9: 4, 10: 8}

    def ifd(off):
        res = {}
        if off <= 0 or off + 2 > len(b):
            return res
        n = struct.unpack(e + "H", b[off:off + 2])[0]
        for i in range(min(n, 500)):
            p = off + 2 + i * 12
            if p + 12 > len(b):
                break
            tag, typ, cnt = struct.unpack(e + "HHI", b[p:p + 8])
            sz = sizes.get(typ, 1) * cnt
            if sz <= 4:
                data = b[p + 8:p + 8 + sz]
            else:
                o = struct.unpack(e + "I", b[p + 8:p + 12])[0]
                data = b[o:o + sz]
            res[tag] = (typ, cnt, data)
        return res

    def ascii_(t):
        return t[2].split(b"\0")[0].decode("utf-8", "replace").strip()

    def rationals(t):
        vals = []
        for i in range(t[1]):
            chunk = t[2][i * 8:i * 8 + 8]
            if len(chunk) < 8:
                break
            n, d = struct.unpack(e + "II", chunk)
            vals.append(n / d if d else 0.0)
        return vals

    try:
        root = ifd(struct.unpack(e + "I", b[4:8])[0])
        names = {0x010F: "Make", 0x0110: "Model", 0x013B: "Artist",
                 0x8298: "Copyright"}
        for tag, name in names.items():
            if tag in root and root[tag][0] == 2:
                v = ascii_(root[tag])
                if v:
                    out[name] = v
        if 0x8769 in root:
            sub = ifd(struct.unpack(e + "I", root[0x8769][2][:4])[0])
            for tag, name in {0xA430: "CameraOwnerName",
                              0xA431: "BodySerialNumber"}.items():
                if tag in sub and sub[tag][0] == 2:
                    v = ascii_(sub[tag])
                    if v:
                        out[name] = v
        if 0x8825 in root:
            g = ifd(struct.unpack(e + "I", root[0x8825][2][:4])[0])
            if 2 in g and 4 in g:
                la, lo = rationals(g[2]), rationals(g[4])
                if len(la) == 3 and len(lo) == 3:
                    lat = la[0] + la[1] / 60 + la[2] / 3600
                    lon = lo[0] + lo[1] / 60 + lo[2] / 3600
                    if 1 in g and g[1][2][:1] == b"S":
                        lat = -lat
                    if 3 in g and g[3][2][:1] == b"W":
                        lon = -lon
                    if lat or lon:
                        out["GPS"] = f"{lat:.5f},{lon:.5f}"
            elif g:
                out["GPS"] = "GPS block present"
    except (struct.error, IndexError, ZeroDivisionError):
        pass
    return out


# --------------------------------------------------------------------------- #
# git
# --------------------------------------------------------------------------- #
def git(top, *args, input_=None):
    try:
        r = subprocess.run(["git", "-C", top, "-c", "core.quotepath=off", *args],
                           capture_output=True, input=input_, timeout=600)
        return r.stdout.decode("utf-8", "replace") if r.returncode == 0 else None
    except (OSError, subprocess.TimeoutExpired):
        return None


def git_top(path):
    p = path if os.path.isdir(path) else os.path.dirname(os.path.abspath(path))
    out = git(p, "rev-parse", "--show-toplevel")
    return out.strip() if out else None


def scan_diff_stream(sc, lines, where_prefix):
    """Parse unified diff (with commit markers) and scan added lines."""
    commit, path, lineno = "", None, 0
    for raw in lines:
        if raw.startswith("__LEAKSCAN_COMMIT__ "):
            commit = raw.split()[1][:10]
            sc.commits_scanned += 1
            continue
        if raw.startswith("+++ "):
            p = raw[4:].strip()
            path = None if p == "/dev/null" else (p[2:] if p.startswith("b/") else p)
            continue
        if raw.startswith("@@"):
            m = re.search(r"\+(\d+)", raw)
            lineno = int(m.group(1)) if m else 0
            continue
        if raw.startswith("+") and path:
            sc.scan_line(raw[1:], path, lineno,
                         f"{where_prefix}{commit}" if commit else where_prefix,
                         lockfile=os.path.basename(path) in LOCKFILES)
            lineno += 1


NOREPLY_EMAIL_DOMAINS = ("noreply.github.com", "@users.noreply.gitlab.com")
NULL_SHA = re.compile(r"0+")
COMMIT_SHA = re.compile(r"[0-9a-f]{7,64}")


def is_noreply_email(email):
    local = email.rpartition("@")[0].lower()
    return email.endswith(NOREPLY_EMAIL_DOMAINS) or \
        local.startswith(("noreply", "no-reply", "donotreply"))


def scan_commits(sc, top, revs, where_prefix, max_commits=0):
    args = ["log", *revs, "-p", "--no-color", "--no-ext-diff", "--unified=0",
            "--format=__LEAKSCAN_COMMIT__ %H"]
    if max_commits:
        args.insert(1, f"-n{max_commits}")
    proc = subprocess.Popen(["git", "-C", top, "-c", "core.quotepath=off", *args],
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    lines = (l.decode("utf-8", "replace").rstrip("\n") for l in proc.stdout)
    scan_diff_stream(sc, lines, where_prefix)
    proc.wait()


def get_added_paths(top, revs):
    out = git(top, "log", *revs, "--format=", "--name-only", "--diff-filter=A")
    return sorted(set(filter(None, (out or "").splitlines())))


def scan_identities(sc, top, revs, where):
    out = git(top, "log", *revs, "--format=%an%x1f%ae%x1f%cn%x1f%ce")
    if not out:
        return
    ids = set()
    for l in out.splitlines():
        parts = l.split("\x1f")
        if len(parts) != 4:
            continue
        ids.add((parts[0], parts[1]))
        ids.add((parts[2], parts[3]))
    ids = {(n, em) for n, em in ids if em and not is_noreply_email(em)}
    if len(ids) > 8:
        sc.add(Finding("info", "identity", "commit_identity", ".git", 0,
                       f"{len(ids)} identities", "multi-contributor history;"
                       " run `git log --format='%an <%ae>' | sort -u` and "
                       "check only your own entries", where))
        return
    for name, email in sorted(ids):
        sc.add(Finding("high", "identity", "commit_identity", ".git", 0,
                       f"{name} <{email}>", "author/committer email is "
                       "published with every commit; use a noreply address",
                       where))


def scan_timezones(sc, top, revs, where):
    out = git(top, "log", *revs, "--format=%ad", "--date=format:%z")
    tzs = Counter(filter(None, (out or "").splitlines()))
    if tzs:
        sc.add(Finding("info", "location", "commit_timezones", ".git", 0,
                       ", ".join(f"{k}x{v}" for k, v in tzs.most_common()),
                       "commit timestamps reveal timezone(s) and "
                       "working hours", where))


def scan_history(sc, top, max_commits):
    revs = ["--all"]
    scan_commits(sc, top, revs, "history:", max_commits)
    for p in get_added_paths(top, revs):
        rule = file_rule(p)
        if rule and not os.path.exists(os.path.join(top, p)):
            sc.add(Finding(rule[0], "file", "risky_file", p, 0,
                           os.path.basename(p),
                           rule[1] + " - deleted from HEAD but still in "
                           "history", "history"))
    scan_identities(sc, top, revs, "history")
    scan_timezones(sc, top, revs, "history")


def get_pushed_shas(push_lines):
    """Local shas from git pre-push stdin lines, skipping branch deletions."""
    shas = []
    for line in push_lines:
        parts = line.split()
        if len(parts) != 4:
            continue
        local_sha = parts[1]
        if NULL_SHA.fullmatch(local_sha) or not COMMIT_SHA.fullmatch(local_sha):
            continue
        shas.append(local_sha)
    return shas


def get_pushed_shas_from_pre_commit(top, environ):
    """pre-commit eats the hook's stdin and passes one pushed ref in env vars.

    It leaves PRE_COMMIT_TO_REF unset when the push includes a root commit.
    """
    ref = environ.get("PRE_COMMIT_TO_REF") or environ.get("PRE_COMMIT_LOCAL_BRANCH")
    if not ref or ref.startswith("-"):
        return []
    out = git(top, "rev-parse", "--verify", "--quiet", ref + "^{commit}")
    return [out.strip()] if out else []


def scan_push(sc, top, shas):
    """Scan only the commits a push adds: those not yet on any remote."""
    if not shas:
        return
    revs = [*shas, "--not", "--remotes"]
    scan_commits(sc, top, revs, "push:")
    for p in get_added_paths(top, revs):
        rule = file_rule(p)
        if rule:
            sc.add(Finding(rule[0], "file", "risky_file", p, 0,
                           os.path.basename(p), rule[1], "push"))
    scan_identities(sc, top, revs, "push")


def scan_staged(sc, top):
    out = git(top, "diff", "--cached", "--no-color", "--no-ext-diff",
              "--unified=0")
    if out is None:
        return
    scan_diff_stream(sc, out.splitlines(), "staged")
    names = git(top, "diff", "--cached", "--name-only", "--diff-filter=A") or ""
    for p in filter(None, names.splitlines()):
        rule = file_rule(p)
        if rule:
            sc.add(Finding(rule[0], "file", "risky_file", p, 0,
                           os.path.basename(p), rule[1], "staged"))


# --------------------------------------------------------------------------- #
# walking, ignore, output
# --------------------------------------------------------------------------- #
def walk(root, include_deps):
    if os.path.isfile(root):
        yield root
        return
    for dp, dns, fns in os.walk(root):
        if not include_deps:
            dns[:] = [d for d in dns if d not in SKIP_DIRS]
        else:
            dns[:] = [d for d in dns if d != ".git"]
        for fn in fns:
            yield os.path.join(dp, fn)


def load_denylist(path):
    entries = []
    paths = [p for p in (path, os.environ.get("LEAKSCAN_DENYLIST"),
                         os.path.expanduser("~/.config/leakscan/denylist.txt"))
             if p]
    for p in paths:
        if not os.path.isfile(p):
            continue
        with open(p, encoding="utf-8") as fh:
            for i, raw in enumerate(fh, 1):
                line = raw.rstrip("\n")
                if not line.strip() or line.lstrip().startswith("#"):
                    continue
                label = f"#{i} of {os.path.basename(p)}"
                if line.startswith("re:"):
                    try:
                        entries.append((label, re.compile(line[3:], re.I)))
                    except re.error as ex:
                        print(f"leakscan: bad denylist regex line {i}: {ex}",
                              file=sys.stderr)
                else:
                    term = line.strip()
                    entries.append((label, re.compile(
                        r"(?<!\w)" + re.escape(term) + r"(?!\w)", re.I)))
        break  # first existing denylist wins
    return entries


def load_ignore(root):
    rules = {"fp": set(), "detector": set(), "glob": []}
    p = os.path.join(root, ".leakscanignore")
    if os.path.isfile(p):
        with open(p, encoding="utf-8") as fh:
            for l in fh:
                l = l.strip()
                if not l or l.startswith("#"):
                    continue
                if l.startswith("fp:"):
                    rules["fp"].add(l[3:].strip())
                elif l.startswith("detector:"):
                    rules["detector"].add(l[9:].strip())
                else:
                    rules["glob"].append(l)
    return rules


def ignored(f, rules):
    if f.fingerprint in rules["fp"] or f.detector in rules["detector"]:
        return True
    base = f.path.split(" [")[0]
    return any(fnmatch.fnmatch(base, g) or fnmatch.fnmatch(base, g.rstrip("/") + "/*")
               for g in rules["glob"])


def mask(s, reveal):
    s = s.replace("\n", " ").replace("\r", " ")
    if reveal:
        return s
    n = len(s)
    if n <= 4:
        return "\u2022" * n
    if n <= 10:
        return s[0] + "\u2022" * (n - 2) + s[-1]
    return s[:4] + "\u2022" * min(n - 6, 10) + s[-2:] + f" ({n} chars)"


def read_pushed_shas(top):
    if "PRE_COMMIT_REMOTE_NAME" in os.environ:
        return get_pushed_shas_from_pre_commit(top, os.environ)
    return get_pushed_shas(sys.stdin.read().splitlines())


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("paths", nargs="*")
    ap.add_argument("--history", action="store_true")
    ap.add_argument("--staged", action="store_true")
    ap.add_argument("--push", action="store_true")
    ap.add_argument("--stdin", action="store_true")
    ap.add_argument("--denylist")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--reveal", action="store_true")
    ap.add_argument("--fail-on", default="high",
                    choices=["critical", "high", "medium", "low", "none"])
    ap.add_argument("--max-commits", type=int, default=0)
    ap.add_argument("--include-deps", action="store_true")
    a = ap.parse_args()

    if not a.paths and not a.stdin:
        a.paths = ["."]
    sc = Scanner(load_denylist(a.denylist), a.reveal)
    ignore_root = os.path.abspath(a.paths[0]) if a.paths else os.getcwd()
    tops = set()

    if a.stdin:
        sc.scan_text(sys.stdin.read(), "<stdin>", "stdin")

    for root in a.paths:
        root_abs = os.path.abspath(root)
        top = git_top(root_abs)
        if top:
            tops.add(top)
            ignore_root = top
        if a.staged:
            if top:
                scan_staged(sc, top)
            continue
        if a.push:
            if top:
                scan_push(sc, top, read_pushed_shas(top))
            continue
        files = list(walk(root_abs, a.include_deps))
        gitignored = set()
        if top and files:
            rels = [os.path.relpath(f, top) for f in files]
            out = git(top, "check-ignore", "--stdin",
                      input_="\n".join(rels).encode())
            if out:
                gitignored = set(out.splitlines())
        base = top or (root_abs if os.path.isdir(root_abs)
                       else os.path.dirname(root_abs))
        for f in files:
            rel = os.path.relpath(f, base)
            n_before = len(sc.findings)
            sc.scan_file(f, rel)
            if rel in gitignored:
                for fd in sc.findings[n_before:]:
                    fd.severity = "info"
                    fd.where = "gitignored"
                    fd.note = (fd.note + "; " if fd.note else "") + \
                        "file is gitignored (not published via git)"

    if a.history:
        for top in tops:
            scan_history(sc, top, a.max_commits)

    rules = load_ignore(ignore_root)
    seen, findings = set(), []
    wt_keys = {(f.detector, f.match) for f in sc.findings
               if f.where in ("worktree", "gitignored")}
    for f in sc.findings:
        if ignored(f, rules):
            continue
        if f.where.startswith("history:"):
            if (f.detector, f.match) in wt_keys:
                continue  # already reported from the working tree
            f.note = (f.note + "; " if f.note else "") + \
                "not in current files but still in git history"
        key = (f.detector, f.path, f.line, f.match, f.where.split(":")[0])
        if key in seen:
            continue
        seen.add(key)
        findings.append(f)
    # same string at the same spot caught by several detectors: keep the
    # most severe, most specific one
    best = {}
    for f in findings:
        k = (f.path, f.line, f.match, f.where)
        if k not in best or SEV[f.severity] > SEV[best[k].severity]:
            best[k] = f
    findings = list(best.values())
    findings.sort(key=lambda f: (-SEV[f.severity], f.category, f.detector,
                                 f.path, f.line))

    counts = Counter(f.severity for f in findings)
    if a.json:
        out = [dict(asdict(f), match=mask(f.match, a.reveal)) for f in findings]
        print(json.dumps({"files_scanned": sc.files_scanned,
                          "commits_scanned": sc.commits_scanned,
                          "counts": counts, "findings": out}, indent=1,
                         ensure_ascii=False))
    else:
        print(f"leakscan: {sc.files_scanned} files, {sc.commits_scanned} commits"
              f" | " + ", ".join(f"{counts.get(s, 0)} {s}" for s in SEV))
        per_det = Counter()
        cur = None
        for f in findings:
            if f.severity != cur:
                cur = f.severity
                print(f"\n== {cur.upper()} ==")
            per_det[(f.severity, f.detector)] += 1
            if per_det[(f.severity, f.detector)] > PER_DETECTOR_TEXT_CAP:
                continue
            loc = f"{f.path}:{f.line}" if f.line else f.path
            where = "" if f.where == "worktree" else f" [{f.where}]"
            print(f"  {f.category}/{f.detector}  {loc}{where}")
            print(f"      {mask(f.match, a.reveal)}   fp:{f.fingerprint}"
                  + (f"\n      note: {f.note}" if f.note else ""))
        for (sev, det), n in per_det.items():
            if n > PER_DETECTOR_TEXT_CAP:
                print(f"  ... {n - PER_DETECTOR_TEXT_CAP} more {det} ({sev}) "
                      f"- use --json for all")
        if not findings:
            print("\nNo findings. (A clean scan is not a clean bill of health - "
                  "context leaks need a human/LLM read.)")

    if a.fail_on != "none" and any(SEV[f.severity] >= SEV[a.fail_on]
                                   for f in findings):
        sys.exit(1)


if __name__ == "__main__":
    main()
