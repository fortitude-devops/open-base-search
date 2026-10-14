import copy
import math
import tempfile
import unittest
from pathlib import Path

import integrity_demo as demo


class IntegrityDemoTests(unittest.TestCase):
    def test_four_scenarios_and_exports(self):
        with tempfile.TemporaryDirectory() as folder:
            results = demo.run_demo(folder)
            self.assertEqual([r["accepted"] for r in results], [True, False, False, False])
            self.assertEqual([r["internal_valid"] for r in results], [True, False, True, True])
            self.assertTrue((Path(folder) / "summary.csv").is_file())
            self.assertTrue((Path(folder) / "limitations.txt").is_file())

    def test_canonical_json_and_nan(self):
        self.assertEqual(demo.canonical_json({"z": 1, "a": "Я"}),
                         '{"a":"Я","z":1}'.encode("utf-8"))
        with self.assertRaises(ValueError):
            demo.canonical_json({"value": math.nan})

    def test_empty_chain_and_deleted_entire_history(self):
        self.assertTrue(demo.verify_against_checkpoint([], demo.make_checkpoint([]))["accepted"])
        chain = demo.build_chain(demo.synthetic_events())
        self.assertFalse(demo.verify_against_checkpoint([], demo.make_checkpoint(chain))["accepted"])

    def test_link_order_and_schema(self):
        chain = demo.build_chain(demo.synthetic_events())
        swapped = copy.deepcopy(chain)
        swapped[0], swapped[1] = swapped[1], swapped[0]
        self.assertFalse(demo.verify_chain(swapped)["internal_valid"])
        chain[0]["extra"] = "not allowed"
        self.assertFalse(demo.verify_chain(chain)["internal_valid"])

    def test_replacing_checkpoint_removes_guarantee(self):
        events = demo.synthetic_events()
        events[1]["version"] = 99
        rewritten = demo.build_chain(events)
        self.assertTrue(demo.verify_against_checkpoint(rewritten,
                                                     demo.make_checkpoint(rewritten))["accepted"])


if __name__ == "__main__":
    unittest.main()
