# Milestone 2: auditable research inputs

The published corpus is pinned to upstream commit
`d5e7d3cdebf19474722a97a6238b8f737d16b7d0`. The complete CSV manifest is
[`corpus.json`](../src/ebpf_ransom_lab/data/corpus.json); the Milestone 1
reference manifest remains unchanged. Capture identities are relative paths,
and split membership comes from the published directories. The manifest
contains SHA-256, byte length, kind, capture identity, and split for all 26
capture CSVs, two feature tables, and two positive-label lists.

The frozen Windows checkout contains Git newline conversion in 17 of the
30 CSVs. The remaining 13 already contain the same bytes as their Git file
objects. To make the Milestone 2 audit portable, each manifest entry records
both the exact frozen checkout hash/size and the exact pinned Git blob
hash/size. A separate `reference_files` list records canonical Git blob
hashes/sizes for the ten Milestone 1 reference files. Verification accepts
only one of these recorded byte representations, checks the pinned commit,
and reports the observed representation. It does not normalize arbitrary
inputs. The original Milestone 1 manifest and `reference verify` behavior
are preserved.

Run the portable audit from the project root after installing the package:

```bash
ransomlab audit tmp/ebpfangel --output var/audit
```

Reports belong outside the frozen checkout. The report separates input
validation, exact label joins, and reconstructed feature comparisons. Every
feature discrepancy remains visible; passing the known label regression
does not mean that the labels are complete or that paper results were
reproduced. Upstream scripts and serialized models are research inputs and
are never executed or loaded by this audit.

The command writes `audit.json` (complete manifest, validations, history, and
experiment statuses) and `feature_differences.csv` (every changed integer cell,
missing/extra identifier or column, and column-order difference). No clock time
or absolute checkout path is included, so identical inputs produce identical
report bytes. Reports record the observed input bytes; the two supported Git
checkout representations therefore have different evidence hashes.

Exit code 0 means the pinned inputs and exact features match the documented
baseline, both label regressions pass, and no unexpected CSV, offset collision,
or byte-identical capture across splits was found. Exit code 1 means a
validation discrepancy; exit code 2 means the report could not be produced.
None of these statuses claims validated benign labels or reproduced model metrics.

## Published corpus findings

| Evidence | Training | Testing |
|---|---:|---:|
| Captures | 15 | 11 |
| Events | 639,705 | 833,626 |
| Capture/PID identities | 1,448 | 1,338 |
| Supplied feature rows | 1,448 | 1,338 |
| Listed positive labels | 32 | 21 |
| Labels joining exactly to supplied identifiers | 14 | 21 |
| Missing positive labels | 18 | 0 |
| TYPE=3 events | 0 | 72 |
| Differing reconstructed integer feature cells | 0 | 0 |

Both full tables match exactly, including identifiers, column order, operation
counts, pattern aggregates, and three-event sequence counts. The supplied
training table has 31 columns including PID; testing has 43. The difference in
observed feature columns is preserved, including testing-only encryption events.

For both splits, the supplied identifier set equals the set obtained by
adding `10000 * capture_index` to each recorded PID, with captures sorted by
filename separately inside each split. There are no within-split offset
collisions in these inputs. These findings do not make numeric identifiers
globally unique: corrected identities must retain both capture ID and PID.

The missing training labels are exactly:

```text
43763
53102 53103 53104 53105 53106 53107 53108 53109
63832
73110 73111 73112 73113 73114 73115 73116 73117
```

All 18 are absent from both the supplied training feature table and the
current capture-derived offset identifier set. Unlisted processes retain
unknown label status in the corrected track. A positive-only PID list does
not establish that every other process was independently verified benign.

## Repository history investigation

The original shallow checkout was preserved. A separate ignored bare clone
was used to inspect all 39 commits reachable from the pinned commit. Relevant
path history covers `logs/`, all four data CSVs, and
`machinelearning/dataprep.py`. Only these three commits changed those inputs:

| Commit | Evidence |
|---|---|
| [`5db71f623a911f21fc3fa59228119563e6bd7c8c`](https://github.com/TomasPhilippart/ebpfangel/commit/5db71f623a911f21fc3fa59228119563e6bd7c8c) | Introduced the original 11 captures. No data label tables existed yet. |
| [`d202d1fa51c302f3d856a7499f445f55f2cd5d97`](https://github.com/TomasPhilippart/ebpfangel/commit/d202d1fa51c302f3d856a7499f445f55f2cd5d97) | Moved two captures from training to testing without changing their bytes; introduced the feature and label tables. Exact joins were already only 10/43 training labels, versus 9/9 testing labels. All 18 currently missing labels already failed their exact training-table joins. |
| [`f01755b9b904b34844079d37c2decc31aa9fa135`](https://github.com/TomasPhilippart/ebpfangel/commit/f01755b9b904b34844079d37c2decc31aa9fa135) | Renamed all 11 existing captures with unchanged bytes, added 15 captures, and changed unsorted glob traversal to sorted filenames before applying PID offsets. Removed 15 older training labels, added four training labels and 12 testing labels, and retained the 18 unresolved labels. The resulting joins were 14/32 and 21/21. |

No later reachable commit changes these corpus files. Historical feature
tables were read as CSV, and Git rename evidence was checked without running
the historical preprocessing code.

The history suggests that capture ordering deserves scrutiny, but does not
record the historic unsorted glob order or establish a valid replacement
mapping. Numeric similarities cannot close this gap. For example, the raw
PID component `3763` occurs in both the training `3_revilog2.csv` and testing
`2_revilog1.csv`; `3832` occurs in those captures and training
`6_revilog.csv`. Several `31xx` components also recur in different training
captures. No modulo-PID or approximate label reassignment has been applied.

This investigation covers reachable published Git history, not private
annotations, uncommitted captures, deleted unreachable objects, or author
intent. The machine-readable history findings and exact missing-label list
are included in the corpus manifest so that audit reports can retain this
scope and limitation.

## Experiment identities and limits

**Upstream-compatible** reconstruction preserves sorted capture order, the
original identifier offsets, split-global time origin, truncation into
one-second periods, aggregation, and process-level sequence behavior. Its
purpose is to expose what the published preprocessing produces, including
defects. PID remains an output join key and is not a model feature.

**Corrected** processing uses explicit capture/process identities and requires
valid label provenance. The corrected published-data experiment remains
**blocked on label provenance**. Resolving that blocker requires reliable
capture-specific annotations or equivalent source evidence; a plausible PID
offset is insufficient. The independently labeled controlled-workload and
replay tracks can continue.

Milestone 2 does not reproduce training, evaluation, or the paper's reported
metrics. Feature equality, if established by the audit, is a preprocessing
result only. Any mismatched inputs, columns, identifiers, or integer feature
cells must be disclosed separately from claims about model performance.

## Verification

Portable tests cover numeric/schema rejection, duplicate identifiers, unknown
labels, PID-offset collisions, sequence order, truncation of negative timestamp
deltas, per-type pattern peaks, exact byte representations, difference exports,
CLI failures, and deterministic output. Run them with:

```bash
coverage run -m unittest discover -s tests -v
coverage report
```

The full-corpus CLI integration test is opt-in because the 26 captures are
external frozen evidence rather than test fixtures checked into this repository:

```bash
RANSOMLAB_CORPUS=/path/to/ebpfangel python -m unittest discover -s tests -p test_published_corpus.py -v
```

On PowerShell, set `$env:RANSOMLAB_CORPUS` to that checkout path before running
the Python command. The test runs the CLI twice and checks byte-identical
reports, exact feature parity, counts, and the 14/32 and 21/21 label joins.
Both the frozen Windows checkout and a local checkout with `core.autocrlf=false`
were audited. No privileged Linux collection is part of this milestone.

Validation on 2026-09-07: 49 portable tests passed with 95% first-party Python
statement/branch coverage; the optional full-corpus end-to-end test passed
separately, including its two-run byte comparison. Both checkout byte
representations returned audit exit code 0. Independent code review found two
reporting issues (canonical digest attribution and discrepancy exit status);
both were fixed and covered by regression tests. No actionable findings remained.
