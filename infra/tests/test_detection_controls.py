"""Synthetic category-only tests; no native, database or service operations."""
from dataclasses import FrozenInstanceError
from itertools import product
import json
import unittest

from infra.evidence_detection_controls import (
    Comparison, DetectionControlRefused, DetectionObservation,
    compare_detection_controls, parse_detection_controls,
)


def document(categories=('NOT_CLEAN', 'CLEAN', 'CLEAN')):
    return {'schema_version': 1, 'scope': 'PUBLIC_DETECTION_CONTROL_COMPARISON_ONLY',
            'completed': 3, 'controls': [
                {'id': name, 'category': category}
                for name, category in zip(
                    ('raw_upstream', 'png_strict', 'png_upstream'), categories)]}


def encode(value):
    return json.dumps(value, separators=(',', ':')).encode('utf-8')


class DetectionControlTests(unittest.TestCase):
    def refused(self, raw, returncode=0):
        try:
            parse_detection_controls(raw, returncode)
        except DetectionControlRefused as error:
            self.assertEqual(error.args, ('Detection control observation refused',))
            self.assertIsNone(error.__cause__)
            self.assertIsNone(error.__context__)
            self.assertFalse(hasattr(error, 'doc'))
            self.assertEqual(error.__dict__, {})
            return
        self.fail('Invalid observation was not refused')

    def test_all_27_triples(self):
        expected = {
            ('CLEAN', 'CLEAN', 'CLEAN'): Comparison.ALL_CLEAN_UNRESOLVED,
            ('NOT_CLEAN', 'CLEAN', 'CLEAN'): Comparison.RAW_DETECTION_PNG_CLEAN,
            ('CLEAN', 'NOT_CLEAN', 'NOT_CLEAN'): Comparison.PNG_DETECTION_OBSERVED,
            ('NOT_CLEAN', 'NOT_CLEAN', 'NOT_CLEAN'): Comparison.PNG_DETECTION_OBSERVED,
        }
        observed = refused = 0
        for triple in product(('CLEAN', 'NOT_CLEAN', 'ERROR'), repeat=3):
            with self.subTest(triple=triple):
                raw = encode(document(triple))
                if 'ERROR' in triple:
                    self.refused(raw)
                    refused += 1
                else:
                    value = parse_detection_controls(raw, 0)
                    self.assertEqual((value.raw_upstream, value.png_strict, value.png_upstream), triple)
                    self.assertIs(compare_detection_controls(value),
                                  expected.get(triple, Comparison.PNG_ENTRY_POINTS_DIFFER))
                    observed += 1
        self.assertEqual((observed, refused), (8, 19))

    def test_surrounding_json_whitespace(self):
        self.assertEqual(parse_detection_controls(b' \r\n\t' + encode(document()) + b'\n ', 0),
                         DetectionObservation('NOT_CLEAN', 'CLEAN', 'CLEAN'))

    def test_exact_byte_boundary(self):
        raw = encode(document())
        self.assertIsInstance(parse_detection_controls(raw + b' ' * (4096-len(raw)), 0), DetectionObservation)
        self.refused(raw + b' ' * (4097-len(raw)))
        self.refused(b'')

    def test_raw_input_types(self):
        for raw in (None, '', {}, [], bytearray(encode(document())), memoryview(encode(document()))):
            with self.subTest(type=type(raw).__name__):
                self.refused(raw)

    def test_exact_returncode(self):
        for code in (False, True, 0.0, '0', None, -1, 1, 256):
            with self.subTest(code=code):
                self.refused(encode(document()), code)

    def test_integer_subclasses_refused(self):
        class Integer(int):
            pass
        self.refused(encode(document()), Integer(0))

    def test_bytes_subclasses_refused(self):
        class Bytes(bytes):
            pass
        self.refused(Bytes(encode(document())))

    def test_duplicate_root_keys(self):
        self.refused(encode(document())[:-1] + b',"completed":3}')

    def test_duplicate_row_keys(self):
        self.refused(encode(document()).replace(b'"id":"raw_upstream"',
                     b'"id":"raw_upstream","id":"raw_upstream"'))

    def test_duplicate_keys_at_unknown_depth(self):
        self.refused(b'{"private":{"nested":{"canary":1,"canary":2}}}')

    def test_utf8_bom_and_invalid_bytes(self):
        for raw in (b'\xef\xbb\xbf' + encode(document()), b'\xff', b'\xc0\xaf', b'\xed\xa0\x80'):
            with self.subTest(raw_length=len(raw)):
                self.refused(raw)

    def test_nonfinite_constants(self):
        for value in (b'NaN', b'Infinity', b'-Infinity'):
            with self.subTest(value=value):
                self.refused(encode(document()).replace(b'"completed":3', b'"completed":' + value))

    def test_trailing_documents_and_content(self):
        for suffix in (b'{}', b'null', b' PRIVATE_CANARY', b'\x00'):
            with self.subTest(length=len(suffix)):
                self.refused(encode(document()) + suffix)

    def test_truncation_every_position(self):
        raw = encode(document())
        for position in range(len(raw)):
            with self.subTest(position=position):
                self.refused(raw[:position])

    def test_nonobject_documents(self):
        for value in (None, 1, True, 'PRIVATE_CANARY', [], [document()]):
            with self.subTest(type=type(value).__name__):
                self.refused(encode(value))

    def test_deep_malformed_and_nested_output(self):
        for raw in (b'[' * 2000 + b']' * 2000, b'{' * 4000,
                    encode({'controls': {'nested': document()}})):
            with self.subTest(length=len(raw)):
                self.refused(raw)

    def test_closed_root_fields(self):
        base = document()
        for key in base:
            value = document()
            del value[key]
            with self.subTest(missing=key):
                self.refused(encode(value))
        value = document()
        value['PRIVATE_CANARY'] = '/private/path'
        self.refused(encode(value))

    def test_version_and_completion_exact_integers(self):
        for key, good in (('schema_version', 1), ('completed', 3)):
            for replacement in (True, False, str(good), float(good), None, [], {}, 0, good+1):
                with self.subTest(key=key, replacement=replacement):
                    value = document()
                    value[key] = replacement
                    self.refused(encode(value))

    def test_scope_exact(self):
        for replacement in ('', 'PUBLIC_DETECTION_CONTROL_COMPARISON_ONLY ', 'PRIVATE_CANARY', None, 1, True, []):
            with self.subTest(replacement=replacement):
                value = document()
                value['scope'] = replacement
                self.refused(encode(value))

    def test_controls_container_and_partial_counts(self):
        for rows in (None, {}, 'PRIVATE_CANARY', [], document()['controls'][:2], document()['controls'] * 2):
            with self.subTest(type=type(rows).__name__, length=len(rows) if rows is not None else 0):
                value = document()
                value['controls'] = rows
                self.refused(encode(value))

    def test_control_identity_order_and_duplicates(self):
        for order in ((1, 0, 2), (0, 2, 1), (0, 0, 2), (2, 1, 0)):
            with self.subTest(order=order):
                value = document()
                rows = value['controls']
                value['controls'] = [rows[index] for index in order]
                self.refused(encode(value))

    def test_closed_row_fields(self):
        for row in (None, [], 'PRIVATE_CANARY', {'id': 'raw_upstream'}, {'category': 'CLEAN'},
                    {'id': 'raw_upstream', 'category': 'CLEAN', 'native_eligible': True}):
            with self.subTest(type=type(row).__name__):
                value = document()
                value['controls'][0] = row
                self.refused(encode(value))

    def test_categories_and_ids_deny_arbitrary_content(self):
        for key in ('id', 'category'):
            for replacement in ('PRIVATE_CANARY', '', 'clean', None, 0, True, {}, []):
                with self.subTest(key=key, type=type(replacement).__name__):
                    value = document()
                    value['controls'][0][key] = replacement
                    self.refused(encode(value))

    def test_parser_exception_privacy(self):
        for raw in (b'{"PRIVATE_CANARY":', b'"PRIVATE_CANARY" garbage',
                    b'{"PRIVATE_CANARY":"\xff"}', b'PRIVATE_CANARY'):
            self.refused(raw)

    def test_immutable_observation_and_no_alias(self):
        original = document()
        value = parse_detection_controls(encode(original), 0)
        original['controls'][0]['category'] = 'ERROR'
        self.assertEqual(value.raw_upstream, 'NOT_CLEAN')
        with self.assertRaises(FrozenInstanceError):
            value.raw_upstream = 'CLEAN'
        self.assertFalse(hasattr(value, '__dict__'))

    def test_constructor_and_comparison_revalidate(self):
        for invalid in ('ERROR', None, 0, [], 'PRIVATE_CANARY'):
            with self.subTest(type=type(invalid).__name__):
                with self.assertRaises(DetectionControlRefused):
                    DetectionObservation(invalid, 'CLEAN', 'CLEAN')
        for invalid in (None, document(), ('CLEAN',)*3):
            with self.assertRaises(DetectionControlRefused):
                compare_detection_controls(invalid)
        forged = DetectionObservation('CLEAN', 'CLEAN', 'CLEAN')
        object.__setattr__(forged, 'png_strict', 'ERROR')
        with self.assertRaises(DetectionControlRefused):
            compare_detection_controls(forged)
        with self.assertRaises(DetectionControlRefused):
            compare_detection_controls(object.__new__(DetectionObservation))


if __name__ == '__main__':
    unittest.main()
