"""Pure public category observations, without runtime or eligibility authority.

Parsing cannot establish common engine/options/generation, input identity,
currentness, cleanup, cause, correctness, repair or strict-suite acceptance.
"""
from dataclasses import dataclass
from enum import Enum
import json

__all__ = (
    'DetectionControlRefused', 'DetectionObservation', 'Comparison',
    'parse_detection_controls', 'compare_detection_controls',
)

_REFUSAL = 'Detection control observation refused'
_SCOPE = 'PUBLIC_DETECTION_CONTROL_COMPARISON_ONLY'
_IDS = ('raw_upstream', 'png_strict', 'png_upstream')
_CATEGORIES = ('CLEAN', 'NOT_CLEAN')


class DetectionControlRefused(ValueError):
    """One fixed non-content-bearing refusal for all unsupported inputs."""

    def __init__(self):
        super().__init__(_REFUSAL)


def _validate_categories(values):
    if any(type(value) is not str or value not in _CATEGORIES for value in values):
        raise DetectionControlRefused()


@dataclass(frozen=True, slots=True)
class DetectionObservation:
    """Three immutable finite categories; not a runtime proof or authority."""

    raw_upstream: str
    png_strict: str
    png_upstream: str

    def __post_init__(self):
        _validate_categories((self.raw_upstream, self.png_strict, self.png_upstream))


class Comparison(str, Enum):
    """Observational classifications only; none selects a cause or repair."""

    RAW_DETECTION_PNG_CLEAN = 'RAW_DETECTION_PNG_CLEAN'
    ALL_CLEAN_UNRESOLVED = 'ALL_CLEAN_UNRESOLVED'
    PNG_ENTRY_POINTS_DIFFER = 'PNG_ENTRY_POINTS_DIFFER'
    PNG_DETECTION_OBSERVED = 'PNG_DETECTION_OBSERVED'


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError()
        result[key] = value
    return result


def _reject_constant(_value):
    raise ValueError()


def _decode(raw):
    # Catch in a separate frame and return, so JSONDecodeError.doc and Unicode
    # error objects cannot remain in a public exception's cause or context.
    try:
        return json.loads(raw.decode('utf-8'), object_pairs_hook=_unique_object,
                          parse_constant=_reject_constant)
    except (ValueError, RecursionError):
        return None


def parse_detection_controls(raw, returncode):
    """Parse exactly one 1..4096-byte closed JSON document after exact int 0.

    ERROR, incomplete output and every invalid document refuse atomically.
    Returned fields contain only finite non-error categories, never raw input.
    """
    if (type(raw) is not bytes or not 1 <= len(raw) <= 4096
            or type(returncode) is not int or returncode != 0):
        raise DetectionControlRefused()
    document = _decode(raw)
    if (type(document) is not dict
            or set(document) != {'schema_version', 'scope', 'controls', 'completed'}
            or type(document['schema_version']) is not int
            or document['schema_version'] != 1
            or type(document['completed']) is not int
            or document['completed'] != 3
            or type(document['scope']) is not str or document['scope'] != _SCOPE):
        raise DetectionControlRefused()
    rows = document['controls']
    if type(rows) is not list or len(rows) != 3:
        raise DetectionControlRefused()
    categories = []
    for expected_id, row in zip(_IDS, rows):
        if (type(row) is not dict or set(row) != {'id', 'category'}
                or type(row['id']) is not str or row['id'] != expected_id):
            raise DetectionControlRefused()
        categories.append(row['category'])
    return DetectionObservation(*categories)


def compare_detection_controls(observation):
    """Revalidate a finite observation and classify; never infer eligibility."""
    if type(observation) is not DetectionObservation:
        raise DetectionControlRefused()
    values = tuple(getattr(observation, name, None) for name in _IDS)
    _validate_categories(values)
    raw, strict, upstream = values
    if strict != upstream:
        return Comparison.PNG_ENTRY_POINTS_DIFFER
    if strict == 'NOT_CLEAN':
        return Comparison.PNG_DETECTION_OBSERVED
    if raw == 'NOT_CLEAN':
        return Comparison.RAW_DETECTION_PNG_CLEAN
    return Comparison.ALL_CLEAN_UNRESOLVED
