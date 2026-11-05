"""Inert failure-only categories; no runtime wiring or readiness authority.

Future callers must separately pin this module and the unchanged strict helper.
Discarded categories from earlier saved summaries cannot be recovered here.
"""
from infra.native import strict_probe as _strict

__all__ = ('parse_failure_categories',)


def parse_failure_categories(raw):
    """Retain only closed categories from unchanged-validator accepted failures."""
    summary = _strict.parse_failure(raw)
    document = _strict._failure_document(raw)
    failed = [
        {'case': row['case'], 'strict': row['strict'], 'upstream': row['upstream'],
         'normalization_observed': row['normalization_observed']}
        for row in document['cases'] if row['passed'] is False
    ]
    return {
        'schema': 1,
        'scope': 'PUBLIC_STRICT_FAILURE_CATEGORIES_ONLY',
        'private_input_allowed': False,
        'native_eligible': False,
        'passed': False,
        'diagnostic': summary['diagnostic'],
        'completed': summary['completed'],
        'case_count': summary['case_count'],
        'failed_case_ids': [row['case'] for row in failed],
        'failed_cases': failed,
    }
