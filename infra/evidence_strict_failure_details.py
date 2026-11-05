"""Pure failure-only identities; no native execution, IO or saved clearance.

Future runtime callers must separately pin this module and the frozen strict
validator before loading. This transform cannot recover discarded raw frames.
"""
from infra.native import strict_probe as _strict

__all__ = ('parse_failure_details',)


def parse_failure_details(raw):
    """Retain only identities from an unchanged-validator accepted failure."""
    summary = _strict.parse_failure(raw)
    document = _strict._failure_document(raw)
    return {
        'schema': 1,
        'scope': 'PUBLIC_STRICT_FAILURE_DETAILS_ONLY',
        'private_input_allowed': False,
        'diagnostic': summary['diagnostic'],
        'completed': summary['completed'],
        'passed': False,
        'case_count': summary['case_count'],
        'native_eligible': False,
        'failed_case_ids': [row['case'] for row in document['cases'] if row['passed'] is False],
    }
