import os
import tempfile
import unittest
from pathlib import Path

from armour import UnsafePathError, open_beneath, read_text_beneath


@unittest.skipUnless(
    os.open in os.supports_dir_fd
    and hasattr(os, "O_NOFOLLOW")
    and hasattr(os, "O_DIRECTORY"),
    "directory-relative no-follow opens are unavailable",
)
class SafeFilesystemTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name) / "root"
        self.outside = Path(self.temp.name) / "outside"
        (self.root / "notes").mkdir(parents=True)
        self.outside.mkdir()
        (self.root / "notes" / "plan.md").write_text("safe", encoding="utf-8")
        (self.outside / "secret.txt").write_text("secret", encoding="utf-8")

    def tearDown(self):
        self.temp.cleanup()

    def test_reads_regular_file_beneath_root(self):
        self.assertEqual(read_text_beneath(self.root, "notes/plan.md"), "safe")

    def test_returned_descriptor_reads_the_opened_object(self):
        descriptor = open_beneath(self.root, "notes/plan.md")
        try:
            self.assertEqual(os.read(descriptor, 4), b"safe")
        finally:
            os.close(descriptor)

    def test_rejects_absolute_and_traversal_paths(self):
        for candidate in ("/etc/passwd", "../outside/secret.txt", "notes/../plan.md"):
            with self.subTest(candidate=candidate):
                with self.assertRaises(UnsafePathError):
                    open_beneath(self.root, candidate)

    def test_rejects_final_symlink(self):
        (self.root / "notes" / "link.txt").symlink_to(self.outside / "secret.txt")
        with self.assertRaises(UnsafePathError):
            read_text_beneath(self.root, "notes/link.txt")

    def test_rejects_intermediate_symlink(self):
        (self.root / "escape").symlink_to(self.outside, target_is_directory=True)
        with self.assertRaises(UnsafePathError):
            read_text_beneath(self.root, "escape/secret.txt")

    def test_canonicalizes_host_owned_symlink_root(self):
        alias = Path(self.temp.name) / "root-alias"
        alias.symlink_to(self.root, target_is_directory=True)
        self.assertEqual(read_text_beneath(alias, "notes/plan.md"), "safe")

    def test_rejects_non_regular_text_target(self):
        with self.assertRaises(UnsafePathError):
            read_text_beneath(self.root, "notes")


if __name__ == "__main__":
    unittest.main()
