#!/usr/bin/env python
"""Django management entry point for the local synthetic M1 website."""
import os
import sys


def main():
    # Django's explicit test --settings option remains a CLI override; an
    # inherited environment value cannot silently choose another application.
    os.environ["DJANGO_SETTINGS_MODULE"] = "config.settings"
    from config.hosted_preflight import enforce_hosted_preflight, validate_hosted_management
    validate_hosted_management(sys.argv, os.environ)
    enforce_hosted_preflight()
    from django.core.management import execute_from_command_line

    execute_from_command_line(sys.argv)


if __name__ == "__main__":
    main()
