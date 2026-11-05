"""Explicit native operator validation; preparation is the default and reads no evidence."""
import json
import uuid

from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand, CommandError

from apps.operations.errors import ApiError
from apps.operations.evidence_processing import validate_evidence, tools
from .retention_inventory import require_native


def _identifier(value):
    try:
        parsed = uuid.UUID(value)
        if str(parsed) != value:
            raise ValueError
        return parsed
    except (TypeError, ValueError, AttributeError):
        raise CommandError("INVALID_EVIDENCE_OPERATION", returncode=2) from None


class Command(BaseCommand):
    help = "Validate one explicitly named synthetic private evidence object; default readiness only."
    requires_system_checks = []
    requires_migrations_checks = False

    def add_arguments(self, parser):
        parser.add_argument("--actor", required=True)
        parser.add_argument("--evidence", required=True)
        parser.add_argument("--operation", required=True)
        mode = parser.add_mutually_exclusive_group()
        mode.add_argument("--prepare", action="store_true")
        mode.add_argument("--execute", action="store_true")

    def handle(self, *args, **options):
        actor_id = _identifier(options["actor"])
        evidence_id = _identifier(options["evidence"])
        operation_id = _identifier(options["operation"])
        code = "EVIDENCE_UNAVAILABLE"
        try:
            require_native()  # before current-tools or any actor/evidence ORM query
            if not options["execute"]:
                with tools.current_tools() as manifest:
                    tools.assert_current(manifest)
                result = {"status": "PREPARED_NOT_EXECUTED", "attempts": 0, "validation": "NOT_RUN"}
            else:
                actor = get_user_model().objects.filter(pk=actor_id, is_active=True).first()
                if actor is None:
                    raise CommandError("EVIDENCE_UNAVAILABLE", returncode=2)
                result = validate_evidence(actor, evidence_id, operation_id)
                result = {"status": "PRIVATE_ATTEMPT_RESULT", "state": result["state"],
                          "validation_code": result["validation_code"]}
        except tools.ToolUnavailable as error:
            code = error.code if error.code in tools.FAILURE_CODES else "PROVENANCE_UNAVAILABLE"
            result = {"status": "UNAVAILABLE", "validation_code": code, "attempts": 0}
        except ApiError:
            result = {"status": "UNAVAILABLE", "validation_code": code, "attempts": 0}
        except CommandError:
            raise
        except Exception:
            result = {"status": "UNAVAILABLE", "validation_code": code, "attempts": 0}
        self.stdout.write(json.dumps(result, sort_keys=True))
        if result["status"] == "UNAVAILABLE":
            raise CommandError(result["validation_code"], returncode=2)
