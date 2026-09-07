"""Opt-in end-to-end test of the real, hash-pinned research corpus.

Set RANSOMLAB_CORPUS to a verified checkout; ordinary CI uses synthetic tests.
"""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


@unittest.skipUnless(os.environ.get('RANSOMLAB_CORPUS'), 'published corpus not configured')
class PublishedCorpusTests(unittest.TestCase):
    def test_cli_exact_features_labels_and_repeatable_reports(self):
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder) / 'audit'
            command = [sys.executable, '-m', 'ebpf_ransom_lab', 'audit',
                       os.environ['RANSOMLAB_CORPUS'], '--output', str(output)]
            subprocess.run(command, check=True, capture_output=True, timeout=180)
            first = {p.name: p.read_bytes() for p in output.iterdir()}
            report = json.loads(first['audit.json'])
            self.assertTrue(report['ok'])
            self.assertEqual(30, len(report['inputs']))
            for split, events, rows, labels, matches in (
                ('training', 639705, 1448, 32, 14), ('testing', 833626, 1338, 21, 21)
            ):
                evidence = report['splits'][split]
                self.assertEqual(events, evidence['event_count'])
                self.assertEqual(rows, evidence['feature_rows'])
                self.assertEqual(labels, evidence['label_join']['total'])
                self.assertEqual(matches, evidence['label_join']['matched'])
                self.assertTrue(evidence['comparison']['match'])
                self.assertTrue(evidence['regression']['match'])
                self.assertFalse(evidence['identity_collisions'])
            self.assertEqual('blocked', report['experiments']['corrected']['status'])
            self.assertEqual('not_reproduced', report['experiments']['upstream-compatible']['paper_reproduction'])
            subprocess.run(command, check=True, capture_output=True, timeout=180)
            self.assertEqual(first, {p.name: p.read_bytes() for p in output.iterdir()})
