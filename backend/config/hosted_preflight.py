"""Read-only hosted startup gate shared by ordinary and direct entrypoints."""
import math
import os
from pathlib import Path
import sys


def validate_hosted_management(argv, env):
    if env.get("KAPIT_RUNTIME_CONTEXT") == "hosted-demo":
        # Schema changes and seeding run only through infra/hosted/hosted.py.
        if argv[1:] != ["process_jobs"]:
            raise RuntimeError("The hosted profile only permits the reviewed process_jobs worker through manage.py.")
        return
    if env.get("KAPIT_RUNTIME_CONTEXT") != "supabase-m1":
        return
    if len(argv) < 2 or argv[1] not in {"seed_demo", "process_jobs"}:
        raise RuntimeError("Direct hosted management only permits reviewed seed_demo/process_jobs. Use the Supabase preparation launcher for migrations; hosted test/flush/reset are not authorized.")
    options = list(argv[2:])
    if argv[1] == "seed_demo" and options:
        raise RuntimeError("Direct hosted seed_demo does not accept configuration overrides.")
    while options:
        item = options.pop(0)
        if item == "--once":
            continue
        if item == "--interval" and options:
            try:
                interval = float(options.pop(0))
                if math.isfinite(interval) and interval >= 0.1:
                    continue
            except ValueError:
                pass
        raise RuntimeError("Direct hosted worker arguments cannot override settings/database/import paths.")


def enforce_hosted_preflight():
    if os.environ.get("KAPIT_RUNTIME_CONTEXT") not in {"supabase-m1", "hosted-demo"}:
        return
    root = Path(__file__).resolve().parents[2]
    sys.path.insert(0, str(root))
    from infra.supabase.prepare import django_bootstrap
    # Genuine database/catalog/history reads. No marker flag or schema mutation.
    django_bootstrap(apply_migrations=False)
