#!/usr/bin/env python3
"""
Test runner for the Crypto Hunter project.

This script runs all tests in the project using pytest.
"""
import os
import sys
import pytest
import argparse


def main():
    """Run the tests."""
    parser = argparse.ArgumentParser(description='Run Crypto Hunter tests')
    parser.add_argument('--unit', action='store_true', help='Run only unit tests')
    parser.add_argument('--integration', action='store_true', help='Run only integration tests')
    parser.add_argument('--coverage', action='store_true', help='Generate coverage report')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    parser.add_argument('--test-path', help='Specific test path to run')
    args = parser.parse_args()

    # Set environment variables for testing
    os.environ['FLASK_ENV'] = 'testing'
    os.environ['TESTING'] = 'True'

    # Default pytest arguments
    pytest_args = []

    # Add verbosity if requested
    if args.verbose:
        pytest_args.append('-v')

    # Determine which tests to run
    if args.unit:
        pytest_args.append('crypto_hunter_web/tests/test_*.py')
    elif args.integration:
        pytest_args.append('crypto_hunter_web/tests/integration/')
    elif args.test_path:
        pytest_args.append(args.test_path)
    else:
        # Run all tests by default
        pytest_args.append('crypto_hunter_web/tests/')

    # Add coverage if requested
    if args.coverage:
        pytest_args = ['--cov=crypto_hunter_web', '--cov-report=term', '--cov-report=html'] + pytest_args

    # Run the tests
    return pytest.main(pytest_args)


if __name__ == '__main__':
    sys.exit(main())
