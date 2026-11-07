# Static PE Analyzer

A dependency-free Python MVP for read-only inspection of Windows Portable Executable (PE) files. It reports basic headers, section permissions and entropy, import names, and whether ASLR, DEP, and CFG compatibility flags are declared. It emits human-readable text, JSON, or standalone HTML.

The analyzer reads bytes as data only: it does not execute, load, modify, or extract the input. Findings are potential issues based on observable metadata, not proof of exploitability or malicious intent.

## Requirements

- Python 3.10 or newer

## Run

From the repository root:

```powershell
python -m pip install -e .
python -m pe_analyzer path\to\program.exe
python -m pe_analyzer path\to\program.exe --format json --output report.json
python -m pe_analyzer path\to\program.exe --format html --output report.html
```

The editable install also provides the `pe-analyze` command:

```powershell
pe-analyze path\to\program.exe --format json
```

The CLI exits with status 2 and reports an error for unreadable files or malformed PE structures. It refuses to overwrite the input when `--output` resolves to the same path.

## Checks and report limits

- ASLR, DEP, and CFG are inferred from the PE optional-header DLL-characteristics bits `DYNAMIC_BASE`, `NX_COMPAT`, and `GUARD_CF`.
- Writable-and-executable section findings are based on the section permission flags.
- Missing mitigation flags do not necessarily indicate a vulnerability; compatibility requirements can affect these flags.
- Import listings reflect the ordinary import directory; delay-load imports and dynamic runtime resolution are not analyzed.
- This MVP does not emulate PE loading, inspect runtime behavior, or determine whether the file is safe.

## Tests

Run the focused standard-library test suite:

```powershell
python -m unittest discover -v
```
