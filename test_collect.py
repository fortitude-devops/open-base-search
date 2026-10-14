import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from collect import save_snapshot


class SnapshotTests(unittest.TestCase):
    def test_refresh_and_invalid_payload_preserve_snapshot(self):
        record = dict(Name="Synthetic", Title="Synthetic service", Domain="example.test",
                      BreachDate="2020-01-01", AddedDate="2020-02-01T00:00:00Z",
                      PwnCount=100, DataClasses=["Passwords", "Passwords"],
                      IsVerified=True, IsFabricated=False, IsSpamList=False,
                      IsMalware=False)
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            save_snapshot([record], output)
            record["PwnCount"] = 150
            save_snapshot([record], output)
            before = (output / "breaches.csv").read_bytes()
            record["PwnCount"] = -1
            with self.assertRaises(ValueError):
                save_snapshot([record], output)
            self.assertEqual(before, (output / "breaches.csv").read_bytes())
            with closing(sqlite3.connect(output / "breaches.sqlite")) as db:
                self.assertEqual(db.execute("SELECT pwn_count FROM breaches").fetchall(), [(150,)])
                self.assertEqual(db.execute("SELECT COUNT(*) FROM data_classes").fetchone(), (1,))


if __name__ == "__main__":
    unittest.main()
