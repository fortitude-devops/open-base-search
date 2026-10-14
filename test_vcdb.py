import csv
import json
import sqlite3
import tempfile
import unittest
import zipfile
from contextlib import closing
from pathlib import Path
from collect_vcdb import DEFAULT_COMMIT, prepare


class VCDBTests(unittest.TestCase):
    def test_collisions_are_preserved_and_unknown_is_not_zero(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = root / "source.zip"
            case = {"incident_id": "shared-id", "victim": {"industry": "001"},
                    "action": {"error": {"variety": ["Misdelivery"], "notes": "omit me"}},
                    "actor": {"internal": {"name": ["omit name"], "motive": ["Unknown"]}},
                    "attribute": {"confidentiality": {"data_total": 0}}}
            with zipfile.ZipFile(archive, "w") as z:
                prefix = "VCDB-" + DEFAULT_COMMIT + "/"
                z.writestr(prefix + "LICENSE.txt", "Synthetic test fixture license")
                z.writestr(prefix + "data/json/validated/a.json", json.dumps(case))
                del case["attribute"]["confidentiality"]["data_total"]
                z.writestr(prefix + "data/json/validated/b.json", json.dumps(case))
                z.writestr(prefix + "data/json/submitted/c.json", json.dumps(case))
            out = root / "out"
            manifest = prepare(archive, out, DEFAULT_COMMIT)
            self.assertEqual(manifest["records"], 2)
            self.assertEqual(manifest["id_collision_records"], 2)
            with closing(sqlite3.connect(out / "vcdb.sqlite")) as db:
                self.assertEqual(db.execute("SELECT data_total FROM incidents ORDER BY record_id").fetchall(), [(0,), (None,)])
                self.assertEqual(db.execute("PRAGMA foreign_key_check").fetchall(), [])
                self.assertFalse(db.execute("SELECT path FROM features WHERE path LIKE '%notes%' OR path LIKE '%name%'").fetchall())
            with (out / "incidents.csv").open() as f:
                records = list(csv.DictReader(f))
            self.assertEqual(records[0]["industry"], "001")
            self.assertEqual(records[0]["action_hacking"], "")
            prepare(archive, out, DEFAULT_COMMIT)
            with closing(sqlite3.connect(out / "vcdb.sqlite")) as db:
                self.assertEqual(db.execute("SELECT COUNT(*) FROM incidents").fetchone(), (2,))


if __name__ == "__main__":
    unittest.main()
