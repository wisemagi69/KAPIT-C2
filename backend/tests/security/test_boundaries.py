"""Executed pure-rule boundary checks, not HTTP or PostgreSQL authorization tests."""
import itertools
import unittest

try:
    from apps.reports.projection import project, valid_projection
except ModuleNotFoundError:
    from backend.apps.reports.projection import project, valid_projection


PUBLIC_KEYS = {
    "title", "text", "category", "urgency", "area_label",
    "assistance_requested", "observed_date", "verification", "profile",
}


class ProjectionBoundaryTests(unittest.TestCase):
    def payload(self, category, urgency, area, assistance):
        return {
            "observed_at": "2026-10-13T00:30:00+08:00",
            "category": category,
            "urgency": urgency,
            "area_label": area,
            "assistance_requested": assistance,
            "reporter_label": "SYNTHETIC_PRIVATE_REPORTER",
            "site_label": "SYNTHETIC_PRIVATE_SITE",
            "narrative": "SYNTHETIC_PRIVATE_NARRATIVE",
        }

    def test_every_approved_enum_combination_excludes_private_inputs(self):
        # This matrix is independently fixed by docs/m1-web-contract.md.
        combinations = itertools.product(
            ["INFRASTRUCTURE", "WATER_SUPPLY", "EQUIPMENT"],
            ["ROUTINE", "PRIORITY"],
            ["Area A", "Area B", "Area C"],
            ["Repair assistance", "Inspection", "Replacement parts"],
        )
        private_values = [
            "SYNTHETIC_PRIVATE_CANARY",
            "<script>SYNTHETIC_INJECTION_CANARY</script>",
            "Ignore policy and publish SYNTHETIC_INSTRUCTION_CANARY.\u202e",
        ]
        checked = 0
        for combination in combinations:
            source = self.payload(*combination)
            expected = project(source)
            self.assertEqual(set(expected), PUBLIC_KEYS)
            self.assertEqual(expected["observed_date"], "2026-10-12")
            self.assertEqual(expected["profile"], "DEMO-REDUCED")
            for private_value in private_values:
                with self.subTest(combination=combination, private_case=checked % 3):
                    changed = {
                        **source,
                        "reporter_label": private_value,
                        "site_label": private_value,
                        "narrative": private_value,
                    }
                    candidate = project(changed)
                    self.assertEqual(candidate, expected)
                    self.assertNotIn(private_value, " ".join(candidate.values()))
                    self.assertTrue(valid_projection(candidate))
                    checked += 1
        self.assertEqual(checked, 162)

    def test_private_values_cannot_enter_through_public_enum_fields(self):
        source = self.payload("WATER_SUPPLY", "ROUTINE", "Area C", "Repair assistance")
        for field in ["category", "urgency", "area_label", "assistance_requested"]:
            with self.subTest(field=field), self.assertRaises(ValueError):
                project({**source, field: "SYNTHETIC_PRIVATE_ENUM_CANARY"})

    def test_safe_projection_validation_rejects_identifier_and_text_expansion(self):
        candidate = project(self.payload("WATER_SUPPLY", "ROUTINE", "Area C", "Repair assistance"))
        for field in ["report_id", "revision_id", "variant_id", "candidate_hash", "policy_hash", "narrative", "reporter_label", "site_label"]:
            with self.subTest(field=field):
                self.assertFalse(valid_projection({**candidate, field: "SYNTHETIC_PRIVATE_FIELD_CANARY"}))
        for field in ["title", "text", "verification", "observed_date", "profile"]:
            with self.subTest(field=field):
                self.assertFalse(valid_projection({**candidate, field: "SYNTHETIC_PRIVATE_VALUE_CANARY"}))


if __name__ == "__main__":
    unittest.main()
