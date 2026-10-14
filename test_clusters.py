import unittest
from prepare_clusters import informative


class ClusteringInputTests(unittest.TestCase):
    def test_unknown_is_not_a_known_asset(self):
        for value in (None, "", "Unknown", "S - Unknown", "NA", "null"):
            self.assertFalse(informative(value))
        for value in ("S - Database", "Personal", "Privilege abuse"):
            self.assertTrue(informative(value))


if __name__ == "__main__":
    unittest.main()
