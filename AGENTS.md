# Repository Guidelines

## Project Structure & Module Organization

Application code lives under `src/ebpf_ransom_lab/`. The CLI entry point is
`cli.py`; collector-specific code is in `collector/`; bundled reference data
and dashboard assets are in `data/` and `static/`. Tests mirror these modules
in `tests/test_*.py`. Operational scripts are under `scripts/`, sample telemetry
is in `examples/`, and research/setup documentation belongs in `docs/`.
Generated captures, SQLite databases, models, and reports belong in ignored
locations such as `var/`, `artifacts/`, and `reports/generated/`.

## Build, Test, and Development Commands

Create the required Python 3.12 environment and install the reproducible lock:

```bash
python3.12 -m venv .venv
.venv/bin/python -m pip install --require-hashes -r requirements.lock
.venv/bin/python -m pip install --no-deps -e .
```

Run the portable quality gate with:

```bash
.venv/bin/python -m coverage run -m unittest discover -s tests -v
.venv/bin/python -m coverage report
```

Coverage is branch-aware and must remain at or above 80%. Use
`.venv/bin/ransomlab doctor --scope app` for local prerequisite checks. On the
Ubuntu 24.04 lab VM, run `scripts/ubuntu_bcc_gate.sh` after authorizing `sudo`;
do not expect live BCC collection to work on unsupported hosts.

## Coding Style & Naming Conventions

Use four-space indentation and standard PEP 8 naming: `snake_case` for modules,
functions, and variables; `PascalCase` for classes; and `UPPER_CASE` for
constants. Keep public APIs typed and prefer small, deterministic functions.
Preserve the strict JSONL contracts, schema versions, provenance checks, and
explicit error handling. No formatter or linter is configured, so match nearby
code and keep imports grouped consistently.

## Testing Guidelines

Tests use `unittest` (and may use `unittest.mock`) despite pytest-compatible
discovery. Name files `test_<module>.py` and methods `test_<behavior>`. Add
regression coverage for success and rejection paths, especially for lossy or
incomplete telemetry, artifact validation, and workload limits. Use temporary
directories; never write generated research output into tracked paths.

## Commit & Pull Request Guidelines

History uses concise, imperative subjects, often with Conventional Commit
prefixes such as `feat:` and `fix:`. Keep commits focused. Pull requests should
explain motivation and behavioral impact, list verification commands, link any
issue, and note platform-specific BCC testing. Include dashboard screenshots
only for visible UI changes.

## Security & Lab Safety

Run only `ransomlab collect` as root. Keep workloads bounded and confined to
generated disposable directories; malware samples are neither required nor
appropriate. Do not commit captures, databases, artifacts, VM images, or
secrets. Report vulnerabilities privately as described in `SECURITY.md`.
