"""Generate controlled SYNTHETIC dataset (no real credentials, no real PII).

Scale targets (configurable via --positives/--negatives/--hardneg):
  positives ~50k across secret types, negatives ~100k diverse hard negatives,
  plus an eval-only hard-negative holdout (--hardneg, never used for training).

Every negative value is UNIQUE (uuid/hash/timestamp/id generators), so
legitimate contextual diversity survives deduplication. Every record carries
full provenance: record_id, source, license, language, leak_group, etc.

Layout (Phase 4): datasets/synthetic/<bucket>/part.jsonl
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import random
import string
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SYN = ROOT / "datasets" / "synthetic"

LICENSE = "LeakLens-synthetic; generated locally; no third-party data; safe to redistribute"
SOURCE = "leaklens-synthetic-generator"
VERSION = "2.0"

ALNUM = string.ascii_letters + string.digits
HEX = "0123456789abcdef"

# ---------- value generators (all non-functional) ----------
def rstr(n, alpha=ALNUM):
    return "".join(random.choice(alpha) for _ in range(n))

def aws_key(): return "AKIA" + rstr(16, string.ascii_uppercase + string.digits)
def gh_token(): return random.choice(["ghp_", "gho_", "github_pat_"]) + rstr(36)
def google_key(): return "AIza" + rstr(35, ALNUM + "-_")
def azure_key(): return base64.b64encode(rstr(32).encode()).decode() + "=="
def slack_token(): return random.choice(["xoxb-", "xoxp-", "xapp-"]) + rstr(24, ALNUM + "-")
def stripe_key(): return random.choice(["sk_live_", "sk_test_"]) + rstr(24)
def db_url(env):
    return f"postgresql://svc_{rstr(6).lower()}:{rstr(14)}@{env}-db.internal:5432/app"
def jwt_token():
    b64 = ALNUM + "-_"
    return "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." + rstr(28, b64) + "." + rstr(32, b64)
def bearer_token(): return rstr(32, ALNUM + "-_~+/=")
def private_key(): return "-----BEGIN RSA PRIVATE KEY-----\n" + "\n".join(rstr(64, ALNUM + "+/=") for _ in range(3))
def generic_secret(): return rstr(random.randint(20, 40), ALNUM + "-_~")
def password_val(): return rstr(random.randint(12, 18), ALNUM + "!@#$%^&*")
def email_val(): return f"user{rstr(6).lower()}@example.com"
def phone_val(): return f"+1-{random.randint(200,989)}-{random.randint(200,989)}-{random.randint(1000,9999)}"
def ip_val(): return ".".join(str(random.randint(1, 254)) for _ in range(4))
def cc_val():  # Luhn-valid TEST number range, non-functional
    body = "400000" + rstr(9, string.digits)
    digits = [int(d) for d in body]
    s = 0
    for i, d in enumerate(reversed(digits)):
        dd = d * 2 if i % 2 == 0 else d
        s += dd - 9 if dd > 9 else dd
    return body + str((10 - s % 10) % 10)

POSITIVE_TYPES = [  # (secret_type, bucket, generator, target_share_of_positives)
    ("AWS_CREDENTIAL", "credentials", aws_key, 5000),
    ("GITHUB_TOKEN", "tokens", gh_token, 5000),
    ("GOOGLE_CREDENTIAL", "credentials", google_key, 4000),
    ("AZURE_CREDENTIAL", "credentials", azure_key, 4000),
    ("STRIPE_SECRET", "tokens", stripe_key, 3000),
    ("SLACK_TOKEN", "tokens", slack_token, 3000),
    ("DATABASE_CREDENTIAL", "database", lambda: db_url("prod"), 6000),
    ("JWT", "tokens", jwt_token, 4000),
    ("BEARER_TOKEN", "tokens", bearer_token, 3000),
    ("PRIVATE_KEY", "private_keys", private_key, 3000),
    ("API_KEY", "real_secret_like", generic_secret, 3500),
    ("PASSWORD", "real_secret_like", password_val, 3500),
    ("PII_EMAIL", "pii", email_val, 1000),
    ("PII_PHONE", "pii", phone_val, 1000),
    ("PII_IP", "pii", ip_val, 500),
    ("PII_CREDIT_CARD", "pii", cc_val, 500),
]

# ---------- unique hard-negative generators ----------
def neg_uuid(): return str(uuid.uuid4())
def neg_sha256(): return hashlib.sha256(rstr(24).encode()).hexdigest()
def neg_sha1(): return hashlib.sha1(rstr(24).encode()).hexdigest()
def neg_md5(): return hashlib.md5(rstr(24).encode()).hexdigest()
def neg_timestamp():
    base = datetime(2020, 1, 1) + timedelta(seconds=random.randint(0, 250_000_000))
    return base.strftime(random.choice(["%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d %H:%M:%S", "%d/%b/%Y:%H:%M:%S %z"]))
def neg_version():
    return f"{random.randint(0,12)}.{random.randint(0,30)}.{random.randint(0,30)}"
def neg_public_id():
    return random.choice(["req-", "obj-", "build-", "run-", "commit-"]) + rstr(random.randint(8, 16), HEX)
def neg_b64():
    return base64.b64encode(f"asset-{rstr(12)}-chunk".encode()).decode()
def neg_css(): return "#" + rstr(6, HEX)
def neg_asset_fp(): return f"main.{rstr(8, HEX)}.js"
def neg_integrity(): return "sha512-" + base64.b64encode(rstr(48).encode()).decode()
def neg_localhost():
    return f"http://localhost:{random.choice([3000, 5000, 8000, 8080, 5432])}/{rstr(6).lower()}"
def neg_local_db():
    return f"postgresql://dev:dev@localhost:5432/devdb_{rstr(4).lower()}"
def neg_fake_cred(): return f"fake-{rstr(4).lower()}-key-{rstr(12)}"
def neg_dummy_key(): return f"dummy_api_key_{rstr(10)}"
def neg_example_db(): return f"postgresql://user:password@localhost:5432/example"
def neg_test_jwt(): return "eyJhbGciOiJub25lIn0." + rstr(20, ALNUM) + ".test-signature"
def neg_high_entropy(): return rstr(random.randint(24, 48))
def neg_checksum(): return f"{rstr(8, HEX)}:{rstr(4, HEX)}:{rstr(4, HEX)}"

NEGATIVE_TYPES = [  # (bucket, reason_label, generator, weight)
    ("placeholders", "PLACEHOLDER", None, 8),            # special: varied placeholder templates
    ("test_secrets", "TEST_SECRET", None, 8),            # special: unique test values
    ("documentation", "DOCUMENTATION_EXAMPLE", None, 8), # special: doc sentences
    ("high_entropy_non_secret", "HIGH_ENTROPY_NON_SECRET", neg_high_entropy, 10),
    ("high_entropy_non_secret", "FALSE_POSITIVE", neg_uuid, 8),
    ("high_entropy_non_secret", "FALSE_POSITIVE", neg_sha256, 8),
    ("high_entropy_non_secret", "FALSE_POSITIVE", neg_sha1, 5),
    ("high_entropy_non_secret", "FALSE_POSITIVE", neg_md5, 5),
    ("high_entropy_non_secret", "FALSE_POSITIVE", neg_b64, 6),
    ("high_entropy_non_secret", "FALSE_POSITIVE", neg_checksum, 4),
    ("high_entropy_non_secret", "FALSE_POSITIVE", neg_integrity, 4),
    ("high_entropy_non_secret", "FALSE_POSITIVE", neg_css, 4),
    ("high_entropy_non_secret", "FALSE_POSITIVE", neg_asset_fp, 4),
    ("high_entropy_non_secret", "FALSE_POSITIVE", neg_public_id, 6),
    ("high_entropy_non_secret", "FALSE_POSITIVE", neg_timestamp, 5),
    ("high_entropy_non_secret", "FALSE_POSITIVE", neg_version, 4),
    ("credentials", "EXAMPLE_SECRET", neg_fake_cred, 5),
    ("credentials", "EXAMPLE_SECRET", neg_dummy_key, 5),
    ("credentials", "TEST_SECRET", neg_example_db, 4),
    ("credentials", "TEST_SECRET", neg_local_db, 4),
    ("credentials", "TEST_SECRET", neg_localhost, 4),
    ("tokens", "TEST_SECRET", neg_test_jwt, 4),
]

PLACEHOLDER_VARS = ["YOUR_API_KEY", "YOUR_API_KEY_HERE", "REPLACE_ME", "CHANGE_ME",
                    "INSERT_TOKEN", "<API_KEY>", "${API_KEY}", "${YOUR_API_KEY}",
                    "example-key", "dummy-key", "sample-token", "CHANGEME"]
ASSIGN_OPS = [" = ", "=", ": ", ":", " => "]
QUOTES = ['"', "'", ""]
VAR_NAMES = ["api_key", "API_KEY", "apiKey", "secret", "SECRET", "token", "auth_token",
             "password", "client_secret", "webhook_secret", "db_password", "private_key"]

FILE_CONTEXTS = [  # (path, language, file_ext, env)
    (".env", "dotenv", ".env", "production"), (".env.example", "dotenv", ".env", "example"),
    ("README.md", "markdown", ".md", "documentation"), ("docs/setup.md", "markdown", ".md", "documentation"),
    ("tests/test_auth.py", "python", ".py", "testing"), ("tests/fixtures.json", "json", ".json", "fixture"),
    ("src/config.py", "python", ".py", "production"), ("src/auth.py", "python", ".py", "production"),
    ("config/production.yaml", "yaml", ".yaml", "production"), ("config/staging.yaml", "yaml", ".yaml", "staging"),
    ("docker-compose.yml", "yaml", ".yml", "development"), ("Dockerfile", "dockerfile", "", "production"),
    ("main.tf", "hcl", ".tf", "production"), ("k8s/secret.yaml", "yaml", ".yaml", "production"),
    ("application.properties", "properties", ".properties", "production"),
    ("application.yml", "yaml", ".yml", "staging"), ("config.json", "json", ".json", "production"),
    ("src/index.ts", "typescript", ".ts", "production"), ("main.go", "go", ".go", "production"),
    ("lib.rs", "rust", ".rs", "production"), ("App.java", "java", ".java", "production"),
    ("server.js", "javascript", ".js", "production"), ("deploy.sh", "shell", ".sh", "production"),
    ("deploy.ps1", "powershell", ".ps1", "production"), ("settings.toml", "toml", ".toml", "development"),
    ("app.ini", "ini", ".ini", "development"), (".github/workflows/ci.yml", "yaml", ".yml", "staging"),
]

LEGACY_LABEL = {"REAL_SECRET": "TRUE_SECRET", "PLACEHOLDER": "PLACEHOLDER",
                "EXAMPLE_SECRET": "EXAMPLE", "TEST_SECRET": "TEST_SECRET",
                "DOCUMENTATION_EXAMPLE": "DOCUMENTATION",
                "HIGH_ENTROPY_NON_SECRET": "BENIGN_HIGH_ENTROPY",
                "FALSE_POSITIVE": "FALSE_POSITIVE", "BENIGN_CONFIG": "BENIGN_CONFIG"}


def _record(text, secret_type, context_label, contains, path, lang, ext, env,
            template_id, leak_group, split_hint="train_pool"):
    fp = path
    return {
        "record_id": f"syn-{_record.n:07d}", "text": text,
        "masked_value": text[:80], "category": secret_type, "secret_type": secret_type,
        "context_label": context_label, "label": LEGACY_LABEL[context_label],
        "contains_secret": contains, "is_positive": contains,
        "original_label": context_label, "normalized_label": context_label,
        "source": SOURCE, "source_version": VERSION, "license": LICENSE,
        "access_date": datetime.now(timezone.utc).date().isoformat(),
        "repository_id": f"synthetic://{env}", "group": leak_group,
        "leak_group": leak_group, "template_id": template_id,
        "file_type": lang, "file_context": fp, "language": lang, "file_ext": ext,
        "environment": env, "synthetic": True, "source_type": "synthetic",
        "external": False, "transformation": "generated",
        "split_hint": split_hint,
    }
_record.n = 0


def _next():
    _record.n += 1
    return _record.n


def _render(var, val):
    return f"{var}{random.choice(ASSIGN_OPS)}{random.choice(QUOTES)}{val}{random.choice(QUOTES)}"


def gen_positive(secret_type, gen, idx):
    val = gen()
    ctx_roll = random.random()
    if secret_type == "PRIVATE_KEY":
        text, var = val, "private_key"
    elif secret_type.startswith("PII_"):
        text, var = f"contact_{secret_type.lower()} = {val}", "contact"
    elif secret_type == "DATABASE_CREDENTIAL":
        text, var = f"DATABASE_URL={val}", "DATABASE_URL"
    elif secret_type == "JWT":
        text, var = f"Authorization: Bearer {val}", "Authorization"
    elif secret_type == "BEARER_TOKEN":
        text, var = f"Authorization: Bearer {val}", "Authorization"
    else:
        var = random.choice(VAR_NAMES)
        text = _render(var, val)
    # same value, different context (context learning; shared leak_group)
    leak = f"pos-{secret_type}-{idx}"
    path, lang, ext, env = random.choice(FILE_CONTEXTS)
    if ctx_roll < 0.08:  # documentation/example context variant of a real-looking value
        path, lang, ext, env = random.choice([c for c in FILE_CONTEXTS if c[3] in ("documentation", "example", "testing")])
        ctx_label, contains = "DOCUMENTATION_EXAMPLE", 0
    else:
        ctx_label, contains = "REAL_SECRET", 1
    _next()
    return _record(text, secret_type, ctx_label, contains, path, lang, ext, env,
                   f"tpl-pos-{secret_type}", leak)


def gen_negative(bucket, reason, gen, idx):
    if gen is None:  # template families with internal variation
        if bucket == "placeholders":
            text = _render(random.choice(VAR_NAMES), random.choice(PLACEHOLDER_VARS))
            reason = "PLACEHOLDER"
        elif bucket == "test_secrets":
            text = _render(random.choice(VAR_NAMES),
                           f"test-{rstr(3).lower()}-{rstr(8, HEX)}")
            reason = "TEST_SECRET"
        else:
            text = random.choice([
                f"# use your own {random.choice(VAR_NAMES)} here: {rstr(6)}",
                f"// example only — replace {rstr(4)} before deploying",
                f"docs: set {random.choice(VAR_NAMES)} to the value from vault ({rstr(4)})",
            ])
            reason = "DOCUMENTATION_EXAMPLE"
    else:
        val = gen()
        var = random.choice(VAR_NAMES + ["session_id", "request_id", "sha", "checksum",
                                         "version", "color", "build", "correlation_id"])
        text = _render(var, val)
    path, lang, ext, env = random.choice(FILE_CONTEXTS)
    _next()
    return _record(text, "GENERIC_SECRET", reason, 0, path, lang, ext, env,
                   f"tpl-neg-{bucket}-{reason}", f"neg-{bucket}-{idx}")


def main(n_pos=50000, n_neg=100000, n_hardneg=25000, seed=42):
    random.seed(seed)
    _record.n = 0
    buckets: dict[str, list[dict]] = {}

    def emit(bucket, rec):
        buckets.setdefault(bucket, []).append(rec)

    # positives per type
    total_share = sum(s for _, _, _, s in POSITIVE_TYPES)
    made = 0
    for stype, bucket, gen, share in POSITIVE_TYPES:
        count = round(n_pos * share / total_share)
        for i in range(count):
            emit(bucket, gen_positive(stype, gen, made))
            made += 1
    # negatives weighted
    wsum = sum(w for _, _, _, w in NEGATIVE_TYPES)
    made_n = 0
    k = 0
    while made_n < n_neg:
        bucket, reason, gen, w = NEGATIVE_TYPES[k % len(NEGATIVE_TYPES)]
        emit(bucket, gen_negative(bucket, reason, gen, made_n))
        made_n += 1
        k += 1
    # eval-only hard-negative holdout (different seed stream → distinct template ids)
    holdout = []
    random.seed(seed + 999)
    for i in range(n_hardneg):
        bucket, reason, gen, w = random.choice(NEGATIVE_TYPES)
        r = gen_negative(bucket, reason, gen, f"h{i}")
        r["template_id"] = "holdout-" + r["template_id"]
        r["leak_group"] = "holdout-" + r["leak_group"]
        r["split_hint"] = "hardneg_holdout"
        r["record_id"] = f"syn-h{i:07d}"
        holdout.append(r)

    SYN.mkdir(parents=True, exist_ok=True)
    counts = {}
    for bucket, recs in buckets.items():
        d = SYN / bucket
        d.mkdir(parents=True, exist_ok=True)
        (d / "part.jsonl").write_text("\n".join(json.dumps(r) for r in recs) + "\n", encoding="utf-8")
        counts[bucket] = len(recs)
    (SYN / "hardneg_holdout.jsonl").write_text("\n".join(json.dumps(r) for r in holdout) + "\n", encoding="utf-8")
    total_pos = sum(1 for rs in buckets.values() for r in rs if r["contains_secret"])
    total_neg = sum(1 for rs in buckets.values() for r in rs if not r["contains_secret"])
    print(f"positives={total_pos} negatives={total_neg} holdout={len(holdout)} buckets={counts}")
    # manifest entry
    man_p = ROOT / "datasets" / "manifests" / "dataset_manifest.json"
    man = {"sources": []} if not man_p.exists() else json.loads(man_p.read_text())
    man["sources"] = [s for s in man["sources"] if s.get("name") != "leaklens-synthetic-v2"]
    man["sources"].append({
        "name": "leaklens-synthetic-v2", "source": "scripts/generate_synthetic_data.py",
        "license": LICENSE, "version": VERSION,
        "download_date": datetime.now(timezone.utc).date().isoformat(),
        "description": "Scaled controlled synthetic secrets + unique hard negatives (non-functional values only)",
        "record_count": total_pos + total_neg, "accepted": total_pos + total_neg, "rejected": 0,
        "label_schema": "contains_secret + secret_type + context_label",
        "preprocessing": "none", "deduplication": "see duplicate_report.json",
        "allowed_use": "training/evaluation", "redaction_status": "n/a (synthetic, non-functional)"})
    man["updated"] = datetime.now(timezone.utc).isoformat()
    man_p.parent.mkdir(parents=True, exist_ok=True)
    man_p.write_text(json.dumps(man, indent=2))
    return {"positives": total_pos, "negatives": total_neg, "holdout": len(holdout)}


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--positives", type=int, default=50000)
    ap.add_argument("--negatives", type=int, default=100000)
    ap.add_argument("--hardneg", type=int, default=25000)
    ap.add_argument("--seed", type=int, default=42)
    a = ap.parse_args()
    main(a.positives, a.negatives, a.hardneg, a.seed)
