"""
CLI entry point for Wilma

Copyright (C) 2024  Ethan Troy

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
"""

import argparse
import sys

from wilma.checker import BedrockSecurityChecker
from wilma.config import WilmaConfig, create_example_config
from wilma.enums import RiskLevel, SecurityMode
from wilma.reports import ReportGenerator


def main():
    """Main function to run the enhanced security checker."""
    parser = argparse.ArgumentParser(
        description='Wilma - AWS Bedrock Security Configuration Checker',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                              # Run security check (default)
  %(prog)s --learn                      # Learn what each check does
  %(prog)s --output json                # Output in JSON format
  %(prog)s --fix logging                # Get step-by-step fix for logging issues
  %(prog)s --config ~/.wilma/custom.yaml   # Use custom configuration
  %(prog)s --checks iam,network         # Run only IAM and network checks
  %(prog)s --min-risk HIGH              # Show only HIGH and CRITICAL findings
  %(prog)s --create-config              # Create example config file
        """
    )

    parser.add_argument('--profile', help='AWS profile name to use', default=None)
    parser.add_argument('--region', help='AWS region to check', default=None)
    parser.add_argument('--learn', action='store_true', help='Learning mode - explains each check')
    parser.add_argument('--fix', help='Get detailed remediation steps for a specific issue type')
    parser.add_argument('--output', choices=['json', 'text'], default='text', help='Output format')
    parser.add_argument('--output-file', help='Save report to file', default=None)
    parser.add_argument('--config', help='Path to custom configuration file', default=None)
    parser.add_argument('--checks', help='Comma-separated list of checks to run (e.g., iam,network,genai)', default=None)
    parser.add_argument('--min-risk', choices=['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'],
                        help='Minimum risk level to include in report', default=None)
    parser.add_argument('--create-config', help='Create an example configuration file at specified path',
                        metavar='PATH', default=None)
    parser.add_argument('--show-config', action='store_true', help='Display current configuration and exit')

    args = parser.parse_args()

    # Handle --create-config flag
    if args.create_config:
        output_path = args.create_config
        create_example_config(output_path)
        print(f"\n[SUCCESS] Example configuration created at: {output_path}")
        print("Edit this file to customize Wilma's behavior, then use --config to load it.")
        return

    # Load configuration
    config = WilmaConfig(config_path=args.config)

    # Override config with CLI arguments if provided
    if args.checks:
        check_list = [c.strip() for c in args.checks.split(',')]
        config.config['checks']['enabled'] = check_list
        print(f"[INFO] Running selective checks: {', '.join(check_list)}")

    if args.min_risk:
        config.config['output']['min_risk_level'] = args.min_risk
        print(f"[INFO] Filtering findings: minimum risk level = {args.min_risk}")

    # Handle --show-config flag
    if args.show_config:
        config.print_config()
        return

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
            mode=mode,
            config=config
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
            print(f"\n[SUCCESS] There! Report saved to: {args.output_file}")
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
        print(f"\n[ERROR] Oh Fred... Error running security checker: {str(e)}")
        print("\n[TIPS] Let me help you troubleshoot:")
        print("  1. Check your AWS credentials: aws configure list")
        print("  2. Ensure you have the necessary IAM permissions")
        print("  3. Try specifying a region: --region us-east-1")
        sys.exit(3)


if __name__ == '__main__':
    main()
