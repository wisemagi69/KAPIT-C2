import json

from rest_framework.parsers import BaseParser

from .errors import ApiError


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


class BoundedJSONParser(BaseParser):
    media_type = "application/json"

    def parse(self, stream, media_type=None, parser_context=None):
        data = stream.read(20 * 1024 + 1)
        if len(data) > 20 * 1024:
            raise ApiError("REQUEST_TOO_LARGE", "Requests must be at most 20 KiB.", 413)
        try:
            result = json.loads(data.decode("utf-8"), object_pairs_hook=unique_object, parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
        except (ValueError, UnicodeError, RecursionError):
            raise ApiError("INVALID_JSON", "Send one valid JSON object.") from None
        if not isinstance(result, dict):
            raise ApiError("INVALID_JSON", "Send one valid JSON object.")
        return result
