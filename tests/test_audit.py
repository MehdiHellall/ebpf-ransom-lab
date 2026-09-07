import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from ebpf_ransom_lab.audit import compare_features, label_join, audit_checkout, write_report
from ebpf_ransom_lab.audit_inputs import read_capture, read_features, read_labels
from ebpf_ransom_lab.legacy import FeatureTable
from ebpf_ransom_lab.audit import _inventory, _membership, _split, _reference
from ebpf_ransom_lab.reference import FileVerification, VerificationReport


class AuditTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def file(self, text):
        path = self.root / 'input.csv'
        path.write_text(text, encoding='utf-8')
        return path

    def test_label_join_preserves_unknowns(self):
        result = label_join((1, 2, 3), (2, 4))
        self.assertEqual([4], result['unmatched_labels'])
        self.assertEqual([1, 3], result['unknown_feature_ids'])
        self.assertEqual(1, result['matched'])
        self.assertEqual(2, result['total'])

    def test_integer_features_and_duplicate_identifiers(self):
        table = read_features(self.file('PID,O_sum\n1.0,2\n'))
        self.assertEqual(((1, 2),), table.rows)
        for value in ('1.5', 'NaN', 'Infinity', '-1', '1e10000'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                read_features(self.file(f'PID,O_sum\n1,{value}\n'))
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            read_features(self.file('PID,O_sum\n1,2\n1.0,3\n'))

    def test_rejects_malformed_schemas_and_rows(self):
        for text in ('', 'PID,PID\n1,1\n', 'PID,nope\n1,1\n',
                     'PID,O_sum\n1\n', 'PID,O_sum\n1,2,3\n'):
            with self.subTest(text=text), self.assertRaises(ValueError):
                read_features(self.file(text))
        with self.assertRaises(ValueError):
            read_labels(self.file('PID\n1\n1\n'))
        self.assertEqual((3,), read_labels(self.file('PID\n3\n')))

    def test_capture_schema_types_and_row_order(self):
        header = 'TS,PID,TYPE,FLAG,PATTERN,OPEN,CREATE,DELETE,ENCRYPT,FILENAME\n'
        events = read_capture(self.file(header + '9,1,0,0,0,0,0,0,0,"a,b"\n8,1,1,0,2,0,0,0,0,x\n'))
        self.assertEqual([9, 8], [event.ts for event in events])
        self.assertEqual(['O', 'C'], [event.kind for event in events])
        with self.assertRaises(ValueError):
            read_capture(self.file(header + '9,1,4,0,0,0,0,0,0,x\n'))

    def test_comparison_exports_all_cells_and_structural_differences(self):
        supplied = FeatureTable(('PID', 'O_sum', 'CCC'), ((1, 2, 0), (2, 3, 1)))
        rebuilt = FeatureTable(('PID', 'O_sum', 'DDD'), ((1, 7, 1), (3, 2, 0)))
        result = compare_features(supplied, rebuilt)
        self.assertEqual([{'pid': 1, 'feature': 'O_sum', 'supplied': 2, 'reconstructed': 7}], result['cells'])
        self.assertEqual([2], result['missing_reconstructed_ids'])
        self.assertEqual([3], result['extra_reconstructed_ids'])
        self.assertEqual(['CCC'], result['missing_reconstructed_columns'])
        self.assertFalse(result['match'])

    def test_missing_checkout_is_reported_deterministically(self):
        first = audit_checkout(self.root)
        self.assertEqual(first, audit_checkout(self.root))
        self.assertFalse(first['ok'])
        self.assertEqual('blocked', first['experiments']['corrected']['status'])
        output = self.root / 'report'
        write_report(first, output, checkout=self.root / 'upstream')
        before = (output / 'audit.json').read_bytes()
        write_report(first, output, checkout=self.root / 'upstream')
        self.assertEqual(before, (output / 'audit.json').read_bytes())
        with self.assertRaises(ValueError):
            write_report(first, self.root / 'upstream' / 'data', checkout=self.root / 'upstream')

    def test_exact_byte_representations_and_membership(self):
        import hashlib
        path = self.file('PID\n1\n')
        content = path.read_bytes()
        entry = {'path': path.name, 'sha256': '0' * 64, 'size': 999,
                 'git_blob_sha256': hashlib.sha256(content).hexdigest(),
                 'git_blob_size': len(content), 'kind': 'capture', 'split': 'training'}
        observed = _inventory(self.root, {'files': [entry]})[0]
        self.assertEqual('git_blob', observed['byte_representation'])
        self.assertEqual('match', observed['status'])
        path.write_text('PID\n2\n', encoding='utf-8')
        self.assertEqual('mismatch', _inventory(self.root, {'files': [entry]})[0]['status'])
        overlap = _membership([observed, {**observed, 'split': 'testing', 'path': 'copy.csv'}])
        self.assertEqual(1, len(overlap['exact_capture_overlap']))
        escaped = _inventory(self.root, {'files': [{**entry, 'path': '../outside.csv'}]})
        self.assertEqual('unavailable', escaped[0]['status'])

    def test_split_validates_id_collisions_and_exports_differences(self):
        data = self.root / 'data'
        data.mkdir()
        (data / 'training_data.csv').write_text('PID,O_max,O_sum,P_max,P_sum,OOO\n10001,2,2,0,0,0\n')
        (data / 'training_labels.csv').write_text('PID\n10001\n999\n')
        header = 'TS,PID,TYPE,FLAG,PATTERN,OPEN,CREATE,DELETE,ENCRYPT,FILENAME\n'
        entries = []
        for i, pid in enumerate((10001, 1)):
            path = self.root / f'{i}.csv'
            path.write_text(header + f'{i},'+f'{pid},0,0,0,0,0,0,0,x\n')
            entries.append({'path': path.name, 'capture_id': path.name, 'kind': 'capture', 'split': 'training'})
        result = _split(self.root, 'training', entries)
        self.assertEqual(1, len(result['identity_collisions']))
        self.assertFalse(result['regression']['match'])
        self.assertEqual([999], result['label_join']['unmatched_labels'])
        report = {'splits': {'training': result}}
        write_report(report, self.root / 'output', checkout=self.root / 'upstream')
        self.assertIn('missing_reconstructed_columns', (self.root / 'output/feature_differences.csv').read_text())

    def test_all_difference_types_are_written(self):
        comparison = compare_features(FeatureTable(('PID','O_sum','CCC'), ((1,1,0),(2,1,0))),
                                      FeatureTable(('PID','O_sum','DDD'), ((1,2,0),(3,1,0))))
        write_report({'splits': {'training': {'comparison': comparison}}},
                     self.root / 'out', checkout=self.root / 'upstream')
        rows = (self.root / 'out/feature_differences.csv').read_text().splitlines()
        self.assertEqual(7, len(rows))

    def test_canonical_reference_reports_the_hash_actually_verified(self):
        canonical_file = FileVerification('data/example.csv', 'match', 'b'*64, 'b'*64)
        frozen_file = FileVerification('data/example.csv', 'mismatch', 'a'*64, None)
        frozen = VerificationReport('https://example.test', 'a'*40, 'a'*40, 'match', (frozen_file,))
        canonical = VerificationReport('https://example.test', 'a'*40, 'a'*40, 'match', (canonical_file,))
        corpus = {'reference_files': [{'path': 'data/example.csv', 'git_blob_sha256': 'b'*64, 'git_blob_size': 3}]}
        with patch('ebpf_ransom_lab.audit.verify_reference', side_effect=[frozen, canonical]):
            result = _reference(self.root, corpus)
        self.assertTrue(result['ok'])
        self.assertEqual('b'*64, result['files'][0]['actual_sha256'])
        self.assertEqual('b'*64, result['files'][0]['expected_sha256'])

    def test_missing_input_report_identifies_the_file(self):
        report = audit_checkout(self.root)
        self.assertIn('logs/training/', report['splits']['training']['reason'])

    def test_feature_mismatch_and_collisions_fail_audit_acceptance(self):
        base = {'status': 'audited', 'regression': {'match': True},
                'comparison': {'match': True}, 'identity_collisions': []}
        for evidence in ({**base, 'comparison': {'match': False}},
                         {**base, 'identity_collisions': [{'adjusted_id': 1}]}):
            with self.subTest(evidence=evidence), \
                 patch('ebpf_ransom_lab.audit._reference', return_value={'ok': True}), \
                 patch('ebpf_ransom_lab.audit._inventory', return_value=[]), \
                 patch('ebpf_ransom_lab.audit._split', return_value=evidence):
                self.assertFalse(audit_checkout(self.root)['ok'])


if __name__ == '__main__':
    unittest.main()
