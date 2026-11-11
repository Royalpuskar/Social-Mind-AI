"""Command-line interface for TraceGuard."""
import argparse
import json

from .analyzer import analyze_url


def main() -> int:
    parser = argparse.ArgumentParser(description="Explainable, local URL risk triage")
    parser.add_argument("url", help="URL to inspect (no network request is made)")
    parser.add_argument("--json", action="store_true", help="Print machine-readable JSON")
    args = parser.parse_args()
    try:
        result = analyze_url(args.url)
    except ValueError as exc:
        parser.error(str(exc))
    if args.json:
        print(json.dumps(result.to_dict(), indent=2))
        return 0
    print(f"URL: {result.url}")
    print(f"Risk: {result.risk_level} ({result.risk_score}/100)")
    if not result.findings:
        print("Findings: No configured warning signals detected.")
    else:
        print("Findings:")
        for finding in result.findings:
            print(f"- {finding.message} (+{finding.points})")
    print("\nReminder: this heuristic result cannot certify that a link is safe.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
