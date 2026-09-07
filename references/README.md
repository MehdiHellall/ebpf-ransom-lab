# Frozen upstream reference

The inspiration repository is:

- Repository: <https://github.com/TomasPhilippart/ebpfangel>
- Pinned commit: `d5e7d3cdebf19474722a97a6238b8f737d16b7d0`
- Upstream license: MIT, copyright Tomás Philippart

The machine-readable manifest is packaged at
`src/ebpf_ransom_lab/data/ebpfangel.json`. It records SHA-256 hashes and byte
sizes for the detector, feature/model scripts, published feature and label
tables, and research paper used by this project.

Obtain and verify a disposable checkout with:

```bash
git clone https://github.com/TomasPhilippart/ebpfangel.git var/reference/ebpfangel
git -C var/reference/ebpfangel checkout d5e7d3cdebf19474722a97a6238b8f737d16b7d0
ransomlab reference verify var/reference/ebpfangel
```

Do not edit the upstream checkout. Implement corrected behavior in this
project's package and retain attribution when code is adapted.

Treat the checkout as untrusted research material. The verification command
hashes files and reads the Git commit; it does not import upstream Python. Do
not execute the upstream simulator or load its `*.joblib` model files, which use
Python's pickle-based serialization format.
