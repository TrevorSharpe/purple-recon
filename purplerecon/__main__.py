import argparse
import sys
from .scanner import run_scan
from .report import to_terminal, to_html, to_json, to_sarif


def main():
    p = argparse.ArgumentParser(
        prog="purplerecon",
        description="Non-destructive web vulnerability assessment. AUTHORIZED USE ONLY.",
    )
    p.add_argument("target", help="URL or host to assess (you must be authorized)")
    p.add_argument("--no-paths", action="store_true", help="skip sensitive-path discovery")
    p.add_argument("--no-cve", action="store_true", help="skip NVD CVE correlation")
    p.add_argument("--html", metavar="FILE", help="write an HTML report to FILE")
    p.add_argument("--json", metavar="FILE", help="write a JSON report to FILE")
    p.add_argument("--sarif", metavar="FILE", help="write a SARIF 2.1.0 report to FILE (CI)")
    p.add_argument("-q", "--quiet", action="store_true", help="suppress terminal report")
    p.add_argument("-y", "--yes", action="store_true",
                   help="confirm you are authorized to scan this target")
    args = p.parse_args()

    if not args.yes:
        ans = input(f"Confirm you are authorized to scan {args.target}? [y/N] ").strip().lower()
        if ans != "y":
            print("Aborted.")
            sys.exit(1)

    result = run_scan(args.target, do_paths=not args.no_paths, do_cve=not args.no_cve)

    if not args.quiet:
        print(to_terminal(result))

    for flag, fn, label in (
        (args.html, to_html, "HTML"),
        (args.json, to_json, "JSON"),
        (args.sarif, to_sarif, "SARIF"),
    ):
        if flag:
            with open(flag, "w", encoding="utf-8") as fh:
                fh.write(fn(result))
            print(f"{label} report written to {flag}")


if __name__ == "__main__":
    main()
