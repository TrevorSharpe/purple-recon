import argparse
import sys
from .scanner import run_scan
from .report import to_terminal, to_html


def main():
    p = argparse.ArgumentParser(
        prog="purplerecon",
        description="Non-destructive web vulnerability assessment. AUTHORIZED USE ONLY.",
    )
    p.add_argument("target", help="URL or host to assess (you must be authorized)")
    p.add_argument("--no-paths", action="store_true", help="skip sensitive-path discovery")
    p.add_argument("--no-cve", action="store_true", help="skip NVD CVE correlation")
    p.add_argument("--html", metavar="FILE", help="write an HTML report to FILE")
    p.add_argument("-y", "--yes", action="store_true",
                   help="confirm you are authorized to scan this target")
    args = p.parse_args()

    if not args.yes:
        ans = input(f"Confirm you are authorized to scan {args.target}? [y/N] ").strip().lower()
        if ans != "y":
            print("Aborted.")
            sys.exit(1)

    result = run_scan(args.target, do_paths=not args.no_paths, do_cve=not args.no_cve)
    print(to_terminal(result))

    if args.html:
        with open(args.html, "w", encoding="utf-8") as fh:
            fh.write(to_html(result))
        print(f"\nHTML report written to {args.html}")


if __name__ == "__main__":
    main()
