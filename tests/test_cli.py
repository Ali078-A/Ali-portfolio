import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from .pe_fixture import minimal_pe


ROOT = Path(__file__).resolve().parents[1]
TEST_ENV = os.environ.copy()
TEST_ENV["PYTHONPATH"] = str(ROOT / "src") + os.pathsep + TEST_ENV.get("PYTHONPATH", "")


class CLITests(unittest.TestCase):
    def test_json_output(self):
        with tempfile.TemporaryDirectory() as directory:
            input_path = Path(directory) / "sample.exe"
            input_path.write_bytes(minimal_pe())
            completed = subprocess.run(
                [sys.executable, "-m", "pe_analyzer", str(input_path), "--format", "json"],
                cwd=ROOT,
                env=TEST_ENV,
                text=True,
                capture_output=True,
                check=False,
            )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(json.loads(completed.stdout)["headers"]["machine"], "x86")

    def test_html_escapes_input_path(self):
        with tempfile.TemporaryDirectory(prefix="sample&") as directory:
            input_path = Path(directory) / "sample.exe"
            input_path.write_bytes(minimal_pe())
            completed = subprocess.run(
                [sys.executable, "-m", "pe_analyzer", str(input_path), "--format", "html"],
                cwd=ROOT,
                env=TEST_ENV,
                text=True,
                capture_output=True,
                check=False,
            )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("sample&amp;", completed.stdout)
        self.assertNotIn(str(input_path), completed.stdout)

    def test_invalid_input_returns_error(self):
        with tempfile.TemporaryDirectory() as directory:
            input_path = Path(directory) / "bad.exe"
            input_path.write_bytes(b"bad")
            completed = subprocess.run(
                [sys.executable, "-m", "pe_analyzer", str(input_path)],
                cwd=ROOT,
                env=TEST_ENV,
                text=True,
                capture_output=True,
                check=False,
            )
        self.assertEqual(completed.returncode, 2)
        self.assertIn("error:", completed.stderr)

    def test_output_cannot_overwrite_input(self):
        with tempfile.TemporaryDirectory() as directory:
            input_path = Path(directory) / "sample.exe"
            original = minimal_pe()
            input_path.write_bytes(original)
            completed = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "pe_analyzer",
                    str(input_path),
                    "--output",
                    str(input_path),
                ],
                cwd=ROOT,
                env=TEST_ENV,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(input_path.read_bytes(), original)
        self.assertEqual(completed.returncode, 2)
        self.assertIn("must not overwrite", completed.stderr)


if __name__ == "__main__":
    unittest.main()
