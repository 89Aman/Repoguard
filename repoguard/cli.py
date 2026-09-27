import argparse
import sys
from pathlib import Path
from repoguard.core.engine import run_repoguard


def main(args=None) -> int:
    parser = argparse.ArgumentParser(
        prog="repoguard",
        description="RepoGuard: End-to-end Python Repository Security & VAPT Scanner",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser("scan", help="Scan repository for security vulnerabilities")
    scan_parser.add_argument("path", nargs="?", default=".", help="Target repository directory (default: current directory)")
    scan_parser.add_argument("--url", dest="url", default=None, help="Live application base URL to perform DAST and API assessment")
    scan_parser.add_argument("--token", dest="token", default=None, help="Authentication token for protected API testing")
    scan_parser.add_argument("--token2", dest="token2", default=None, help="Secondary authentication token for IDOR testing")
    scan_parser.add_argument("-o", "--output-dir", dest="output_dir", default="repoguard-output", help="Output directory for reports (default: repoguard-output)")
    scan_parser.add_argument("--no-dedup", dest="dedup", action="store_false", default=True, help="Disable duplicate finding consolidation")

    parsed = parser.parse_args(args)

    if parsed.command == "scan":
        target_path = parsed.path
        if not Path(target_path).exists():
            print(f"Error: Target path '{target_path}' does not exist.", file=sys.stderr)
            return 2

        print("=" * 60)
        print("RepoGuard Security Assessment")
        print(f"Target Path: {Path(target_path).resolve()}")
        if parsed.url:
            print(f"Target URL:  {parsed.url}")
        print("=" * 60)

        report_data, exit_code = run_repoguard(
            repo_path=target_path,
            url=parsed.url,
            token=parsed.token,
            token2=parsed.token2,
            output_dir=parsed.output_dir,
            deduplicate=parsed.dedup,
        )

        sumry = report_data.summary
        print("\nScan Results Summary:")
        print(f"  Total Findings:      {sumry.total_findings}")
        print(f"  Critical:            {sumry.critical_count}")
        print(f"  High:                {sumry.high_count}")
        print(f"  Medium:              {sumry.medium_count}")
        print(f"  Low / Info:          {sumry.low_count + sumry.info_count}")
        print(f"  Endpoints Found:     {sumry.total_endpoints}")
        print(f"  Unprotected Routes:  {sumry.unprotected_endpoints}")

        if report_data.top_fixes:
            print("\nIssues to Fix First:")
            for idx, fix in enumerate(report_data.top_fixes[:5], 1):
                loc = fix.file_path or fix.endpoint or "Global"
                print(f"  {idx}. [{fix.severity}] {fix.title} ({loc})")

        print(f"\nReports generated in: {Path(parsed.output_dir).resolve()}")
        print(f"  HTML: {Path(parsed.output_dir) / 'report.html'}")
        print(f"  JSON: {Path(parsed.output_dir) / 'findings.json'}")

        if exit_code != 0:
            print("\nBUILD FAILED: Critical security findings detected.", file=sys.stderr)
        else:
            print("\nBUILD PASSED: No critical security findings detected.")

        return exit_code

    return 0


if __name__ == "__main__":
    sys.exit(main())
