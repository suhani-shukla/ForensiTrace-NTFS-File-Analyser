# Setup

_Verified from a clean checkout at commit `0529dcc` on 2026-09-27 (Python 3.14.7, Linux)._

## What you can and cannot do after setup

| | Status |
|---|---|
| Install dependencies | Works |
| Run the test suite | Works — 17 pass |
| Run the analysis on fixtures | Works, from Python |
| Start the web app | **Not possible** — no ASGI app exists |
| Reproduce the forensic dataset | **Not possible** — no dataset exists |

## Prerequisites

- Python 3.11 or newer
- Git
- A Windows NTFS virtual machine — required to build the forensic dataset, which does not exist yet

Linux or macOS is fine for development and testing. Only the forensic scenario reproduction needs Windows, because the artifacts must come from a real NTFS volume.

## Install

From the repository root:

```bash
python -m venv .venv
```

Activate it:

```bash
# Linux/macOS
source .venv/bin/activate

# Windows PowerShell
.venv\Scripts\Activate.ps1
```

Then install:

```bash
python -m pip install --upgrade pip
pip install -r requirements.txt
```

This was verified working from a clean checkout. `dfir_ntfs` is pinned to version 1.1.18 and is installed from its GitHub archive, so **the first install compiles it from source and needs network access and a working C toolchain** — this is the slowest step and it is not optional.

## Dependencies

`requirements.txt` declares:

| Package | Purpose |
|---|---|
| `dfir_ntfs` 1.1.18 (GitHub archive) | `$MFT`, `$UsnJrnl`, and `$LogFile` parsing |
| `fastapi` | Planned API and dashboard server |
| `uvicorn[standard]` | ASGI server |
| `jinja2` | Planned dashboard templates |
| `pydantic` | The shared schema models |
| `pytest` | Test suite |
| `python-multipart` | Form handling for the planned dashboard |

`pydantic` is the only dependency the currently-working code actually needs — the parsers, normalizer, and analysis layer have no FastAPI or Jinja2 dependency. Installing everything is still correct, since the presentation layer is coming.

## Tests

```bash
pytest
```

Expected:

```text
17 passed
```

`pytest.ini` sets `testpaths = tests` and `pythonpath = .`. The `pythonpath` entry matters: it is what lets `import backend...` resolve when pytest runs from the repository root, and its absence was a real breakage for the whole team that is now fixed.

The suite covers the `$UsnJrnl` parser (reason-flag decoding, file-reference packing, timestamp formatting), the `$LogFile` parser's attribute-name resolution and `$STANDARD_INFORMATION` decoding, and the normalizer (fixture/schema agreement, three-source merge, USN field propagation, LogFile record skipping). **It does not cover the detection rules, scoring, or timeline** — see the limitations in [detection-rules.md](detection-rules.md).

## Running the analysis without the API

The web app cannot be started, but the analysis core can be exercised directly. From the repository root:

```bash
python -c "
import json
from backend.models.schemas import ParsedRecord
from backend.analysis.rules import run_rules
from backend.analysis.scoring import calculate_risk_scores
from backend.analysis.timeline import build_timeline

records = [ParsedRecord(**r) for r in json.load(open('fixtures/sample_parsed_records.json'))]
findings = run_rules(records, 'SCEN-001')
for s in calculate_risk_scores(findings):
    print(s.full_path, s.total_score, s.risk_level, s.triggered_rules)
for e in build_timeline(records):
    print(e.timestamp, e.source, e.event_type, e.full_path)
"
```

Each parser module also has a standalone smoke-test entry point:

```bash
python backend/parsers/usnjrnl_parser.py path/to/extracted/\$UsnJrnl_\$J
python backend/parsers/logfile_parser.py path/to/extracted/\$LogFile
```

Both print parsed records as JSON. These need real artifact extracts, which the repository does not contain.

## Running the application

The intended command is:

```bash
uvicorn backend.main:app --reload
```

**This fails.** `backend/main.py` and `backend/api/routes.py` are empty files, so there is no `app` attribute to serve. Do not include this command in a demo, a submission, or a reproduction guide until the API layer lands.

## Configuration

`config/settings.py` is an empty file. The project plan reserves a `FORENSITRACE_` prefix for environment variables, but **no configuration loader is implemented**, so no environment variable currently affects behaviour. Paths are passed directly to the parser functions. Do not document environment-variable configuration as working.

## Reproducing the forensic dataset

Not currently possible — the `dataset/` directory does not exist and no scenario has been run on a real NTFS volume. When it is built, the reproduction guide needs to cover:

1. Snapshotting a clean Windows NTFS VM before each scenario.
2. Running each scenario's specific actions.
3. Extracting `$MFT`, `$UsnJrnl:$J`, and `$LogFile` from the resulting volume.
4. Where the artifact extracts and ground-truth JSON are stored.
5. How to verify the pipeline's output against the expected ground truth.

## Handling evidence

Never commit raw disk images, credentials, VM snapshots, or sensitive forensic data. `.gitignore` already excludes `dataset/scenarios/*.raw` and `my/`. Store bulk evidence outside Git and commit only the extracts and metadata needed to reproduce findings.
