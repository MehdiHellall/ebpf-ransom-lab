"""Deterministic research audit; never executes upstream scripts or models."""
from __future__ import annotations

import csv
import json
from dataclasses import asdict, replace
from importlib.resources import files
from pathlib import Path

from ebpf_ransom_lab.audit_inputs import read_capture, read_features, read_labels
from ebpf_ransom_lab.legacy import FeatureTable, reconstruct
from ebpf_ransom_lab.reference import ManifestFile, load_manifest, verify_reference, _sha256_file


def label_join(feature_ids: tuple[int, ...], labels: tuple[int, ...]) -> dict:
    known = set(feature_ids) & set(labels)
    return {
        'matched': len(known), 'total': len(labels), 'matched_ids': sorted(known),
        'unmatched_labels': sorted(set(labels) - set(feature_ids)),
        'unknown_feature_ids': sorted(set(feature_ids) - set(labels)),
        'policy': 'Exact integer join only; absence is unknown in corrected experiments.',
    }


def compare_features(supplied: FeatureTable, rebuilt: FeatureTable) -> dict:
    left = {row[0]: dict(zip(supplied.columns[1:], row[1:])) for row in supplied.rows}
    right = {row[0]: dict(zip(rebuilt.columns[1:], row[1:])) for row in rebuilt.rows}
    common = sorted(set(supplied.columns[1:]) & set(rebuilt.columns[1:]))
    cells = [
        {'pid': pid, 'feature': col, 'supplied': left[pid][col], 'reconstructed': right[pid][col]}
        for pid in sorted(left.keys() & right.keys()) for col in common
        if left[pid][col] != right[pid][col]
    ]
    differences = {
        'cells': cells,
        'missing_reconstructed_ids': sorted(left.keys() - right.keys()),
        'extra_reconstructed_ids': sorted(right.keys() - left.keys()),
        'missing_reconstructed_columns': sorted(set(supplied.columns) - set(rebuilt.columns)),
        'extra_reconstructed_columns': sorted(set(rebuilt.columns) - set(supplied.columns)),
        'column_order_differs': supplied.columns != rebuilt.columns,
    }
    return {**differences, 'match': not any(differences.values())}


def _resource(name: str) -> Path:
    return Path(str(files('ebpf_ransom_lab').joinpath('data/' + name)))


def _input_path(checkout: Path, relative: str) -> Path:
    candidate = (checkout / relative).resolve()
    if not candidate.is_relative_to(checkout.resolve()):
        raise ValueError('input path escaped checkout')
    return candidate


def _inventory(checkout: Path, manifest: dict) -> list[dict]:
    result = []
    for item in manifest['files']:
        try:
            path = _input_path(checkout, item['path'])
            digest = _sha256_file(path)
            size = path.stat().st_size
            representation = _representation(item, digest, size)
            result.append({**item, 'actual_sha256': digest, 'actual_size': size,
                           'status': 'match' if representation else 'mismatch',
                           'byte_representation': representation})
        except (OSError, ValueError):
            result.append({**item, 'actual_sha256': None, 'actual_size': None, 'status': 'unavailable'})
    return result


def _representation(item: dict, digest: str, size: int) -> str | None:
    if (digest, size) == (item['sha256'], item['size']):
        return 'frozen_checkout'
    if (digest, size) == (item.get('git_blob_sha256'), item.get('git_blob_size')):
        return 'git_blob'
    return None


def _reference(checkout: Path, corpus: dict) -> dict:
    manifest = load_manifest(_resource('ebpfangel.json'))
    canonical = replace(manifest, files=tuple(
        ManifestFile(item['path'], item['git_blob_sha256'], item['git_blob_size'])
        for item in corpus['reference_files']))
    frozen = verify_reference(checkout, manifest)
    blobs = verify_reference(checkout, canonical)
    by_path = {item.path: item for item in blobs.files}
    evidence = [
        {**asdict(by_path[item.path] if by_path[item.path].status == 'match'
                  and item.status != 'match' else item),
         'status': 'match' if item.status == 'match'
          or by_path[item.path].status == 'match' else item.status,
         'byte_representation': 'frozen_checkout' if item.status == 'match'
          else 'git_blob' if by_path[item.path].status == 'match' else None}
        for item in frozen.files
    ]
    return {**asdict(frozen), 'files': evidence,
            'ok': frozen.commit_status == 'match' and all(item['status'] == 'match' for item in evidence)}


def _read_input(reader, checkout: Path, relative: str):
    try:
        return reader(_input_path(checkout, relative))
    except (OSError, ValueError, csv.Error) as error:
        reason = str(error) if isinstance(error, (ValueError, csv.Error)) else type(error).__name__
        raise ValueError(f'{relative}: {reason}') from error


def _capture_summary(item: dict, events: tuple, offset: int) -> dict:
    ids = sorted({event.pid for event in events})
    return {
        'capture_id': item['capture_id'], 'split': item['split'],
        'events': len(events), 'recorded_ids': ids, 'offset': offset,
        'adjusted_ids': [pid + offset for pid in ids],
        'process_lifecycle': 'unavailable',
        'encryption_events': sum(event.kind == 'E' for event in events),
        'timestamp_regressions': sum(b.ts < a.ts for a, b in zip(events, events[1:])),
    }


def _split(checkout: Path, split: str, inventory: list[dict]) -> dict:
    items = sorted((item for item in inventory if item['split'] == split
                    and item['kind'] == 'capture'), key=lambda item: item['path'])
    captures = tuple(_read_input(read_capture, checkout, item['path']) for item in items)
    summaries = [_capture_summary(item, events, i * 10000)
                 for i, (item, events) in enumerate(zip(items, captures))]
    supplied = _read_input(read_features, checkout, f'data/{split}_data.csv')
    labels = _read_input(read_labels, checkout, f'data/{split}_labels.csv')
    rebuilt = reconstruct(captures)
    identities = [(pid, summary['capture_id'], raw)
                  for summary in summaries
                  for pid, raw in zip(summary['adjusted_ids'], summary['recorded_ids'])]
    collisions = [
        {'adjusted_id': pid, 'identities': [{'capture_id': cap, 'recorded_id': raw}
          for adjusted, cap, raw in identities if adjusted == pid]}
        for pid in sorted({item[0] for item in identities})
        if sum(item[0] == pid for item in identities) > 1
    ]
    joined = label_join(tuple(row[0] for row in supplied.rows), labels)
    expected = (14, 32) if split == 'training' else (21, 21)
    return {
        'status': 'audited', 'captures': summaries,
        'event_count': sum(len(events) for events in captures),
        'feature_rows': len(supplied.rows), 'feature_columns': list(supplied.columns),
        'label_join': joined, 'identity_collisions': collisions,
        'regression': {'expected_matches': expected[0], 'expected_labels': expected[1],
                       'match': (joined['matched'], joined['total']) == expected},
        'comparison': compare_features(supplied, rebuilt),
    }


def _membership(inventory: list[dict]) -> dict:
    captures = [item for item in inventory if item['kind'] == 'capture']
    overlap = [
        {'training': a['path'], 'testing': b['path'], 'sha256': a['actual_sha256']}
        for a in captures if a['split'] == 'training'
        for b in captures if b['split'] == 'testing'
        if a['actual_sha256'] and a['actual_sha256'] == b['actual_sha256']
    ]
    return {'exact_capture_overlap': overlap,
            'policy': 'Published directory assignment; identity is capture path plus recorded PID.',
            'limitation': 'Different hashes do not prove independent acquisition; lifecycle metadata is unavailable.'}


def audit_checkout(checkout: Path) -> dict:
    manifest = json.loads(_resource('corpus.json').read_text(encoding='utf-8'))
    inventory = _inventory(checkout, manifest)
    reference = _reference(checkout, manifest)
    expected = {item['path'] for item in inventory}
    discovered = {path.relative_to(checkout).as_posix()
                  for folder in ('logs', 'data') for path in (checkout / folder).rglob('*.csv')}
    splits = {}
    for split in ('training', 'testing'):
        try:
            splits[split] = _split(checkout, split, inventory)
        except (OSError, ValueError, csv.Error) as error:
            splits[split] = {'status': 'invalid', 'error': type(error).__name__,
                             'reason': str(error) if isinstance(error, ValueError) else type(error).__name__}
    valid = all(value['status'] == 'audited' for value in splits.values())
    inputs_match = reference['ok'] and all(item['status'] == 'match' for item in inventory)
    regressions_match = valid and all(value['regression']['match'] for value in splits.values())
    features_match = valid and all(value['comparison']['match'] for value in splits.values())
    membership = _membership(inventory)
    return {
        'schema_version': 1, 'repository': manifest['repository'], 'commit': manifest['commit'],
        'ok': bool(inputs_match and regressions_match and features_match and not (discovered - expected)
                   and not membership['exact_capture_overlap']
                   and not any(value.get('identity_collisions') for value in splits.values())),
        'reference': reference, 'inputs': inventory,
        'unmanifested_csv_files': sorted(discovered - expected), 'splits': splits,
        'membership': membership, 'history': manifest.get('history', {}),
        'experiments': {
            'upstream-compatible': {
                'status': 'features_match' if inputs_match and features_match else 'discrepancies',
                'feature_version': 'legacy-upstream-v1', 'paper_reproduction': 'not_reproduced',
                'reason': 'Feature audit only; paper metrics and trained model results have not been reproduced.',
                'label_policy': 'Upstream fills nonmatches with zero; this is documented behavior, not validated benign truth.',
            },
            'corrected': {'status': 'blocked',
                          'reason': 'Published labels lack complete capture-scoped provenance and explicit benign labels; no approximate PID repairs.',
                          'unknown_label_policy': 'exclude; never silently label benign'},
            'controlled-workloads': {'status': 'independent_future_milestone'},
        },
    }


def write_report(report: dict, output: Path, *, checkout: Path) -> None:
    root = output.resolve()
    if root.is_relative_to(checkout.resolve()) or checkout.resolve().is_relative_to(root):
        raise ValueError('audit output must be separate from upstream checkout')
    root.mkdir(parents=True, exist_ok=True)
    for name in ('audit.json', 'feature_differences.csv'):
        if (root / name).is_symlink():
            raise ValueError('refusing symlink output')
    (root / 'audit.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n', encoding='utf-8', newline='\n')
    with (root / 'feature_differences.csv').open('w', encoding='utf-8', newline='') as stream:
        writer = csv.writer(stream, lineterminator='\n')
        writer.writerow(('split', 'kind', 'pid', 'feature', 'supplied', 'reconstructed'))
        for split, result in report['splits'].items():
            for row in _difference_rows(split, result.get('comparison', {})):
                writer.writerow(row)


def _difference_rows(split: str, comparison: dict):
    for cell in comparison.get('cells', []):
        yield (split, 'cell', cell['pid'], cell['feature'], cell['supplied'], cell['reconstructed'])
    for kind in ('missing_reconstructed_ids', 'extra_reconstructed_ids',
                 'missing_reconstructed_columns', 'extra_reconstructed_columns'):
        for value in comparison.get(kind, []):
            yield (split, kind, value if kind.endswith('ids') else '',
                   value if kind.endswith('columns') else '', '', '')
    if comparison.get('column_order_differs'):
        yield (split, 'column_order_differs', '', '', '', '')
