import tempfile
import unittest
from pathlib import Path
import sys
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from pe_analyzer import PEFormatError, analyze_pe

from .pe_fixture import minimal_pe, pe_with_import


class AnalyzePETests(unittest.TestCase):
    def analyze_bytes(self, content):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sample.exe"
            path.write_bytes(content)
            return analyze_pe(path)

    def test_reads_headers_sections_and_mitigations(self):
        report = self.analyze_bytes(minimal_pe())

        self.assertEqual(report["headers"]["machine"], "x86")
        self.assertEqual(report["headers"]["bitness"], 32)
        self.assertEqual(report["headers"]["entry_point_rva"], "0x1000")
        self.assertEqual(report["sections"][0]["name"], ".text")
        self.assertEqual(report["sections"][0]["permissions"], ["read", "execute"])
        self.assertEqual(report["mitigations"], {"aslr": True, "dep": True, "cfg": False})
        self.assertEqual(len(report["findings"]), 1)
        self.assertIn("CFG compatibility", report["findings"][0]["title"])

    def test_reports_import_names(self):
        report = self.analyze_bytes(pe_with_import())

        self.assertEqual(report["imports"][0]["dll"], "KERNEL32.dll")
        self.assertEqual(report["imports"][0]["symbols"], [{"kind": "name", "hint": 7, "name": "ExitProcess"}])

    def test_flags_writable_executable_section(self):
        report = self.analyze_bytes(minimal_pe(section_characteristics=0xE0000020))
        finding = next(item for item in report["findings"] if "Writable and executable" in item["title"])
        self.assertEqual(finding["severity"], "high")
        self.assertIn("write and execute", finding["evidence"])

    def test_import_thunk_tables_have_an_aggregate_safety_limit(self):
        with patch("pe_analyzer.pe.MAX_TOTAL_IMPORT_THUNKS", 1):
            with self.assertRaisesRegex(PEFormatError, "exceed safety limit"):
                self.analyze_bytes(pe_with_import())

    def test_import_descriptor_terminator_requires_all_fields_to_be_zero(self):
        content = bytearray(pe_with_import())
        content[0x318:0x31C] = (1).to_bytes(4, "little")
        with self.assertRaises(PEFormatError):
            self.analyze_bytes(bytes(content))

    def test_rejects_non_pe_input(self):
        with self.assertRaisesRegex(PEFormatError, "MZ signature"):
            self.analyze_bytes(b"not a PE file")

    def test_rejects_truncated_section_data(self):
        content = bytearray(minimal_pe())
        content[0x98 + 0xE0 + 20 : 0x98 + 0xE0 + 24] = (0xFFFFFF00).to_bytes(4, "little")
        with self.assertRaisesRegex(PEFormatError, "extends beyond"):
            self.analyze_bytes(bytes(content))


if __name__ == "__main__":
    unittest.main()
