"""LeakLens CLI — same scanner core as the API."""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from backend.app.ml.inference.predict import ml_probability  # noqa: E402
from backend.app.reports.exporters import to_csv, to_html, to_json, to_sarif  # noqa: E402
from backend.app.scanner.core import ScanConfig  # noqa: E402
from backend.app.scanner.pipeline import scan_path  # noqa: E402


def cmd_scan(args) -> int:
    cfg = ScanConfig(root=args.path)
    ml_fn = None
    if args.model and args.model != "none":
        ml_fn = lambda line, fp, var, ent: ml_probability(line, fp, var, ent)  # noqa: E731
    res = scan_path(args.path, cfg, use_ml=ml_fn)
    findings = res["findings"]
    if args.severity and args.severity != "all":
        order = {"low": 0, "medium": 1, "high": 2}
        thr = order[args.severity.lower()]
        findings = [f for f in findings if order.get(f["severity"].lower(), 0) >= thr]
    stats = {"files_discovered": res["files_discovered"], "files_scanned": res["files_scanned"],
             "candidates": res["candidates"], "duration_ms": res["duration_ms"]}
    fmt = (args.format or "text").lower()
    out = ""
    if fmt == "json":
        out = to_json(args.path, "cli", stats, findings)
    elif fmt == "csv":
        out = to_csv(findings)
    elif fmt == "sarif":
        out = json.dumps(to_sarif(args.path, findings), indent=2)
    elif fmt == "html":
        out = to_html(args.path, "cli", stats, findings)
    else:
        lines = [f"LeakLens Security Scan", f"Files scanned: {stats['files_scanned']}", ""]
        for f in findings[:200]:
            lines.append(f"{f['severity']:7s} {f['file_path']}:{f['line_number']}")
            lines.append(f"         {f.get('detector_name')} [{f.get('masked_value')}]")
        lines.append(f"\nScan complete: {len(findings)} findings.")
        out = "\n".join(lines)
    if args.output:
        Path(args.output).write_text(out, encoding="utf-8")
        print(f"Wrote {args.output}")
    else:
        print(out)
    return 0


def cmd_create_admin(args) -> int:
    import getpass

    from backend.app.core.security import hash_password  # noqa: E402
    from backend.app.database.db import Base, SessionLocal, engine  # noqa: E402
    from backend.app.models.entities import User  # noqa: E402

    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        if db.query(User).count() > 0:
            print("Setup already completed: a user exists. Use the login screen.")
            return 1
        username = (args.username or input("Username: ")).strip()
        if len(username) < 3:
            print("Username must be at least 3 characters.")
            return 1
        pw = getpass.getpass("Password (min 8 chars, not echoed): ")
        if len(pw) < 8:
            print("Password must be at least 8 characters.")
            return 1
        if getpass.getpass("Repeat password: ") != pw:
            print("Passwords do not match.")
            return 1
        db.add(User(username=username, password_hash=hash_password(pw)))
        db.commit()
        print(f"Admin user '{username}' created. Log in through the UI or POST /api/auth/login.")
        return 0
    finally:
        db.close()


def cmd_benchmark(args) -> int:
    from scripts.benchmark_model import main as bench_main
    bench_main(args.path or ".")
    return 0


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="leaklens")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sc = sub.add_parser("scan", help="Scan a local path")
    sc.add_argument("path", nargs="?", default=".")
    sc.add_argument("--format", default="text", choices=["text", "json", "csv", "sarif", "html"])
    sc.add_argument("--severity", default="all", choices=["all", "low", "medium", "high"])
    sc.add_argument("--output", default="")
    sc.add_argument("--model", default="production")
    sc.set_defaults(func=cmd_scan)
    b = sub.add_parser("benchmark", help="Benchmark a repository")
    b.add_argument("path", nargs="?", default=".")
    b.set_defaults(func=cmd_benchmark)
    c = sub.add_parser("create-admin", help="Create the first local admin user")
    c.add_argument("--username", default="")
    c.set_defaults(func=cmd_create_admin)
    return ap


def main() -> None:
    ap = build_parser()
    args = ap.parse_args()
    raise SystemExit(args.func(args))


if __name__ == "__main__":
    main()
