from copy import deepcopy
import unittest

import support  # noqa: F401
from intelligence_hub.collect import validate_catalog

RECORD = {"cveID": "CVE-2026-99991", "dateAdded": "2026-10-27", "vulnerabilityName": "Example",
          "shortDescription": "Synthetic.", "vendorProject": "Example Vendor", "product": "Example Gateway"}


def catalog(*records):
    return {"count": len(records), "vulnerabilities": [deepcopy(record) for record in records]}


class ValidateCatalogTest(unittest.TestCase):
    def test_accepts_a_valid_catalog(self):
        validate_catalog(catalog(RECORD, {**RECORD, "cveID": "CVE-2026-99992"}))

    def test_rejects_wrong_shapes(self):
        for value in (None, [], {}, {"count": 0, "vulnerabilities": []}, {"count": 1, "vulnerabilities": {}}):
            with self.subTest(value=value), self.assertRaises(ValueError):
                validate_catalog(value)

    def test_rejects_count_mismatch(self):
        value = catalog(RECORD)
        value["count"] = 2
        with self.assertRaises(ValueError):
            validate_catalog(value)
        value["count"] = True  # a Boolean is not an integer count
        with self.assertRaises(ValueError):
            validate_catalog(value)

    def test_rejects_more_than_15000_records(self):
        value = {"count": 15001, "vulnerabilities": [RECORD] * 15001}
        with self.assertRaises(ValueError):
            validate_catalog(value)

    def test_rejects_bad_records(self):
        bad = [
            "not a record",
            {**RECORD, "cveID": "CVE-26-1"},
            {**RECORD, "cveID": "CVE-2026-99991 "},
            {**RECORD, "dateAdded": "2026-02-30"},
            {**RECORD, "dateAdded": "2026-10-27T00:00:00Z"},
            {**RECORD, "shortDescription": "x" * 12001},
            {key: value for key, value in RECORD.items() if key != "product"},
            {**RECORD, "vendorProject": 7},
        ]
        for record in bad:
            with self.subTest(record=str(record)[:60]), self.assertRaises(ValueError):
                validate_catalog({"count": 1, "vulnerabilities": [record]})


if __name__ == "__main__":
    unittest.main()
