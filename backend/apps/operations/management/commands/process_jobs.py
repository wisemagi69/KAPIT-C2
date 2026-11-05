import time

from django.core.management.base import BaseCommand, CommandError

from apps.operations.worker import process_one


class Command(BaseCommand):
    help = "Prepare private deterministic candidates. This command never approves or publishes."

    def add_arguments(self, parser):
        parser.add_argument("--once", action="store_true", help="Process currently available jobs and exit.")
        parser.add_argument("--interval", type=float, default=2.0)

    def handle(self, *args, **options):
        if options["interval"] < 0.1:
            raise CommandError("Interval must be at least 0.1 seconds.")
        while True:
            processed = process_one()
            if processed:
                continue
            if options["once"]:
                return
            time.sleep(options["interval"])
