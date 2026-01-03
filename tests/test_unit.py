import unittest
import os
import tempfile
import shutil
import json
from clonereaper.config import Config
from clonereaper.utils import format_bytes, normalize_path
from clonereaper.scanner import match_patterns

class TestUtils(unittest.TestCase):
    def test_format_bytes(self):
        self.assertEqual(format_bytes(100), "100 B")
        self.assertEqual(format_bytes(1024), "1.00 KB")
        self.assertEqual(format_bytes(1024 * 1024), "1.00 MB")

    def test_match_patterns(self):
        # Empty patterns matches everything
        self.assertTrue(match_patterns("test.txt", []))

        # Include patterns
        self.assertTrue(match_patterns("test.txt", ["*.txt"]))
        self.assertFalse(match_patterns("test.jpg", ["*.txt"]))

        # Exclude patterns
        self.assertTrue(match_patterns("test.txt", ["!*.jpg"]))
        self.assertFalse(match_patterns("test.jpg", ["!*.jpg"]))

        # Mixed
        self.assertTrue(match_patterns("test.txt", ["*.txt", "!temp*"]))
        self.assertFalse(match_patterns("temp.txt", ["*.txt", "!temp*"]))
        self.assertFalse(match_patterns("test.jpg", ["*.txt", "!temp*"]))

class TestConfig(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.config_path = os.path.join(self.temp_dir, "config.json")

    def tearDown(self):
        shutil.rmtree(self.temp_dir)

    def test_save_load_config(self):
        config = Config()
        config.directory = "/test/path"
        config.min_size = 1234
        config.file_patterns = ["*.py"]

        config.save(self.config_path)

        loaded_config = Config.load(self.config_path)
        self.assertEqual(loaded_config.directory, "/test/path")
        self.assertEqual(loaded_config.min_size, 1234)
        self.assertEqual(loaded_config.file_patterns, ["*.py"])

    def test_load_non_existent(self):
        config = Config.load("non_existent_file.json")
        self.assertIsInstance(config, Config)
        # Should have defaults
        self.assertEqual(config.min_size, 1)

if __name__ == '__main__':
    unittest.main()
