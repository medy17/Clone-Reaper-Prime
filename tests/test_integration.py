import unittest
import os
import shutil
import tempfile
from clonereaper.config import Config
from clonereaper.scanner import find_potential_duplicates_by_size, identify_duplicates_by_hash
from clonereaper.actions import perform_actions

class TestIntegration(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.config = Config()
        self.config.directory = self.test_dir
        self.config.min_size = 0
        self.config.dry_run = False
        self.config.action_mode = "delete"
        self.config.keep_strategy = "first"

    def tearDown(self):
        shutil.rmtree(self.test_dir)

    def create_file(self, filename, content):
        path = os.path.join(self.test_dir, filename)
        with open(path, "w") as f:
            f.write(content)
        return path

    def test_find_and_delete_duplicates(self):
        # Create duplicates
        self.create_file("file1.txt", "content")
        self.create_file("file2.txt", "content")
        self.create_file("file3.txt", "other content")

        # 1. Find by size
        by_size = find_potential_duplicates_by_size(self.config)
        self.assertEqual(len(by_size), 1) # Only one size group (len=7)

        # 2. Find by hash
        by_hash = identify_duplicates_by_hash(by_size, self.config)
        self.assertEqual(len(by_hash), 1)
        hash_val = list(by_hash.keys())[0]
        self.assertEqual(len(by_hash[hash_val]), 2) # file1 and file2

        # 3. Perform action (delete)
        # We need to simulate user confirmation or ensure perform_actions doesn't ask for it
        # perform_actions assumes confirmation is already done.

        processed, saved = perform_actions(by_hash, self.config)
        self.assertEqual(processed, 1)
        self.assertEqual(saved, 7)

        # Check files
        files = os.listdir(self.test_dir)
        self.assertEqual(len(files), 2) # file3 + one of (file1, file2)
        self.assertIn("file3.txt", files)

    def test_file_patterns_integration(self):
        self.config.file_patterns = ["*.txt", "!file2.txt"]

        self.create_file("file1.txt", "content")
        self.create_file("file2.txt", "content") # Excluded
        self.create_file("file3.txt", "content")
        self.create_file("image.jpg", "content") # Excluded by include pattern

        by_size = find_potential_duplicates_by_size(self.config)

        # file2.txt is excluded explicitly.
        # image.jpg is excluded because it doesn't match *.txt.
        # So only file1.txt and file3.txt remain.
        # They have same content, so they should form a group.

        # However, find_potential_duplicates_by_size returns groups > 1
        # If we only have 2 files and they are same size, we get 1 group.

        self.assertTrue(len(by_size) > 0)
        paths = list(by_size.values())[0]
        filenames = [os.path.basename(p) for p in paths]

        self.assertIn("file1.txt", filenames)
        self.assertIn("file3.txt", filenames)
        self.assertNotIn("file2.txt", filenames)
        self.assertNotIn("image.jpg", filenames)

if __name__ == '__main__':
    unittest.main()
