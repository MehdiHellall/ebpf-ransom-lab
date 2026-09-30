# Published-data audit

The audit verifies the published `ebpfangel` inputs and reconstructs its integer
feature tables without executing upstream scripts or loading upstream models.

The reference is pinned to commit
`d5e7d3cdebf19474722a97a6238b8f737d16b7d0`. File paths, sizes, and hashes are
stored in `src/ebpf_ransom_lab/data/corpus.json`.

## Run the audit

Obtain the pinned checkout as described in
[the reference guide](../references/README.md), then run:

```bash
ransomlab audit var/reference/ebpfangel --output var/audit
```

The command writes:

- `audit.json`: input verification, label joins, feature comparisons, and
  experiment status;
- `feature_differences.csv`: changed cells, identifiers, columns, and column
  ordering.

Exit code `0` means the recorded inputs and reconstructed feature tables match.
Exit code `1` reports a validation difference, and exit code `2` reports an
execution or output error.

## Results

| Evidence | Training | Testing |
|---|---:|---:|
| Captures | 15 | 11 |
| Events | 639,705 | 833,626 |
| Feature rows | 1,448 | 1,338 |
| Listed positive labels | 32 | 21 |
| Labels matching supplied identifiers | 14 | 21 |
| Reconstructed integer feature differences | 0 | 0 |

Both published feature tables reconstruct exactly, including identifiers,
column order, operation counts, pattern aggregates, and three-event sequences.

The training label file contains 18 identifiers that do not occur in the
training feature table. The available files do not provide capture-scoped benign
labels for the remaining processes. The audit therefore preserves two separate
outcomes:

- the published preprocessing is reproducible;
- a corrected supervised experiment needs additional label provenance.

## Identifier behavior

The published preprocessing sorts captures within each split and adds
`10000 * capture_index` to each recorded PID. This reproduces the supplied
tables, but the adjusted number is not a durable process identity outside that
specific preprocessing run. Corrected processing uses capture and process
identity together.

Repository history shows that capture movement, renaming, and sorted traversal
changed how these adjusted identifiers were assigned. No approximate PID
remapping is applied by this project.

## Verification coverage

Portable tests cover schema validation, hashes and byte representations, label
joins, identifier collisions, legacy feature reconstruction, and deterministic
report output.

The complete external-corpus integration test is optional because the captures
are not stored in this repository:

```bash
RANSOMLAB_CORPUS=/path/to/ebpfangel \
  python -m unittest discover -s tests -p test_published_corpus.py -v
```

The upstream-compatible audit is a preprocessing comparison. Controlled live
collection and model evaluation use the separate workflow documented in
[TRAINING_GUIDE.md](TRAINING_GUIDE.md).
