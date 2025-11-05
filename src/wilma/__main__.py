"""
CLI entry point for Wilma

Copyright (C) 2024  Ethan Troy

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
"""

import sys
import argparse

from wilma.checker import BedrockSecurityChecker
from wilma.reports import ReportGenerator
from wilma.enums import SecurityMode, RiskLevel


def main():
    """Main function to run the enhanced security checker."""
    parser = argparse.ArgumentParser(
        description='Wilma - AWS Bedrock Security Configuration Checker',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                     # Run security check (default)
  %(prog)s --learn            # Learn what each check does
  %(prog)s --output json      # Output in JSON format
  %(prog)s --fix logging      # Get step-by-step fix for logging issues
        """
    )

    parser.add_argument('--profile', help='AWS profile name to use', default=None)
    parser.add_argument('--region', help='AWS region to check', default=None)
    parser.add_argument('--learn', action='store_true', help='Learning mode - explains each check')
    parser.add_argument('--fix', help='Get detailed remediation steps for a specific issue type')
    parser.add_argument('--output', choices=['json', 'text'], default='text', help='Output format')
    parser.add_argument('--output-file', help='Save report to file', default=None)

    args = parser.parse_args()

    # Determine mode
    if args.learn:
        mode = SecurityMode.LEARN
    else:
        mode = SecurityMode.STANDARD

    # Handle fix mode
    if args.fix:
        print(f"\n[FIX] Remediation Guide for: {args.fix}")
        print("This feature is coming soon!")
        print("For now, run the security check to see fix commands for each issue.")
        return

    try:
        # Initialize and run the checker
        checker = BedrockSecurityChecker(
            profile_name=args.profile,
            region=args.region,
            mode=mode
        )

        # Run all checks
        checker.run_all_checks()

        # Generate report
        report_generator = ReportGenerator(checker)
        report = report_generator.generate_report(output_format=args.output)

        # Output report
        if args.output_file:
            with open(args.output_file, 'w') as f:
                f.write(report)
            print(f"\n[SUCCESS] Report saved to: {args.output_file}")
        else:
            print(report)

        # Exit with appropriate code
        if any(f['risk_level'] == RiskLevel.CRITICAL for f in checker.findings):
            sys.exit(2)
        elif any(f['risk_level'] == RiskLevel.HIGH for f in checker.findings):
            sys.exit(1)
        else:
            sys.exit(0)

    except KeyboardInterrupt:
        print("\n\n[WARN] Check interrupted by user")
        sys.exit(3)
    except Exception as e:
        print(f"\n[ERROR] Error running security checker: {str(e)}")
        print("\n[TIPS] Troubleshooting tips:")
        print("  1. Check your AWS credentials: aws configure list")
        print("  2. Ensure you have the necessary IAM permissions")
        print("  3. Try specifying a region: --region us-east-1")
        sys.exit(3)


if __name__ == '__main__':
    main()
