# Setup

_Last verified: 2026-09-25_

## Current limitation

The repository contains dependency and configuration placeholders, but the application, parsers, dataset, dashboard, and tests are not complete. This page distinguishes install preparation from currently runnable functionality.

## Prerequisites

- Python 3.11 or newer
- Git
- A Windows NTFS virtual machine for reproducing forensic scenarios

A Linux or macOS environment may be useful for Python development, but the planned forensic test scenarios require access to NTFS artifacts produced on Windows.

## Install dependencies

From the repository root:

```bash
python -m venv .venv
```

Activate the virtual environment:

```bash
# Linux/macOS
source .venv/bin/activate

# Windows PowerShell
.venv\Scripts\Activate.ps1
```

Install dependencies:

```bash
python -m pip install --upgrade pip
pip install -r requirements.txt
```

`requirements.txt` currently declares `dfir_ntfs` from its GitHub archive, FastAPI, Uvicorn, Jinja2, Pydantic, pytest, and python-multipart.

## Configuration

`config/settings.py` is currently an empty placeholder. The project plan names future environment variables with the `FORENSITRACE_` prefix, but no configuration loader is implemented yet. Do not assume environment-variable configuration works until it is added and documented by the owning developer.

## Tests

Run:

```bash
pytest
```

`pytest.ini` points to `tests/`, but that directory and test files are not currently present. A successful test result is therefore not available at this stage.

## Run the application

The intended command is:

```bash
uvicorn backend.main:app --reload
```

This is not currently runnable because `backend/main.py` and `backend/api/routes.py` are empty placeholders. Wait for the API implementation before using this command in setup instructions or a demo.

## Test dataset

No real `dataset/` directory or ground-truth files are currently present. The repository contains only synthetic fixtures under `fixtures/`. A future reproduction guide should document:

1. How to snapshot a clean Windows NTFS VM.
2. How to run each scenario.
3. How to extract `$MFT`, `$UsnJrnl`, and `$LogFile`.
4. Where the resulting artifacts and ground-truth JSON are stored.
5. How to verify the expected detection results.

Raw disk images and sensitive evidence should not be committed to Git.
