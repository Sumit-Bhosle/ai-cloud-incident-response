"""Create a reproducible, ground-truth-isolated CloudTrail benchmark pilot.

Uses DEVELOPMENT data only. Selection stratifies by labels, but investigator
inputs and the public manifest never contain those labels. Not a prevalence
representative or held-out evaluation sample.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import random
import subprocess
from collections import Counter
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DATA_DIR = PROJECT_ROOT / 'data/lab_evidence/cloudtrail/development'
LABEL_FIELDS = frozenset({'attack_associated', 'attack_name', 'attack_event_count',
                          'benign_event_count', 'scenario_names', 'should_sample',
                          'ground_truth', 'is_attack', 'label'})


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read_jsonl(path: Path, key: str) -> dict[str, dict]:
    result = {}
    with path.open(encoding='utf-8') as stream:
        for number, line in enumerate(stream, 1):
            if not line.strip():
                continue
            record = json.loads(line)
            if not isinstance(record, dict) or not isinstance(record.get(key), str):
                raise ValueError(f'{path.name}:{number}: invalid {key}')
            identity = record[key]
            if identity in result:
                raise ValueError(f'{path.name}:{number}: duplicate {key}: {identity}')
            result[identity] = record
    if not result:
        raise ValueError(f'{path.name}: empty')
    return result


def check_no_labels(obj, where='case'):
    if isinstance(obj, dict):
        offenders = LABEL_FIELDS.intersection(obj)
        if offenders:
            raise ValueError(f'{where}: label leakage: {sorted(offenders)}')
        for key, value in obj.items():
            check_no_labels(value, f'{where}.{key}')
    elif isinstance(obj, list):
        for index, value in enumerate(obj):
            check_no_labels(value, f'{where}[{index}]')


def bucket(count: int) -> str:
    if count == 1:
        return '1'
    if count <= 5:
        return '2-5'
    return '6+'


def diverse_positive(candidates: list[str], truth: dict, count: int, rng) -> list[str]:
    candidates = candidates.copy()
    rng.shuffle(candidates)
    chosen, covered = [], set()
    # Prefer distinct attack scenario families during the small pilot.
    while len(chosen) < count:
        with_new = [cid for cid in candidates if
                    set(truth[cid].get('scenario_names') or []) - covered]
        if not with_new:
            break
        cid = max(with_new, key=lambda item:
                  len(set(truth[item].get('scenario_names') or []) - covered))
        chosen.append(cid)
        candidates.remove(cid)
        covered.update(truth[cid].get('scenario_names') or [])
    chosen.extend(candidates[:count-len(chosen)])
    return chosen


def diverse_negative(candidates: list[str], cases: dict, count: int, rng) -> list[str]:
    candidates = candidates.copy()
    rng.shuffle(candidates)
    chosen = []
    for group in ('1', '2-5', '6+'):
        for cid in candidates:
            if bucket(len(cases[cid]['events'])) == group:
                chosen.append(cid)
                candidates.remove(cid)
                break
        if len(chosen) == count:
            return chosen
    chosen.extend(candidates[:count-len(chosen)])
    return chosen


def prepare(root: Path, *, positives=4, negatives=4, max_events=20,
            seed=20261108, output_dir: Path | None = None, check_git=True) -> dict:
    root = Path(root)
    case_path = root / 'cases.jsonl'
    truth_path = root / 'case_ground_truth.jsonl'
    cases = read_jsonl(case_path, 'case_id')
    truth = read_jsonl(truth_path, 'case_id')
    if set(cases) != set(truth):
        raise ValueError('Case and ground-truth ID sets differ')
    if positives < 1 or negatives < 1 or max_events < 1:
        raise ValueError('Positive and negative sample sizes and max_events must be >=1')

    for cid, case in cases.items():
        check_no_labels(case, cid)
        events = case.get('events')
        if not isinstance(events, list) or not events or len(events) != case.get('event_count'):
            raise ValueError(f'{cid}: event_count mismatch')
        t = truth[cid]
        attack, benign = t.get('attack_event_count'), t.get('benign_event_count')
        if (type(t.get('attack_associated')) is not bool or
            type(attack) is not int or type(benign) is not int or
            attack < 0 or benign < 0 or attack + benign != len(events) or
            t['attack_associated'] != (attack > 0)):
            raise ValueError(f'{cid}: invalid or inconsistent truth counts')

    eligible = [cid for cid in cases if len(cases[cid]['events']) <= max_events]
    pure_positive = [cid for cid in eligible if truth[cid]['attack_event_count'] > 0
                     and truth[cid]['benign_event_count'] == 0]
    pure_negative = [cid for cid in eligible if truth[cid]['attack_event_count'] == 0]
    if len(pure_positive) < positives or len(pure_negative) < negatives:
        raise ValueError('Not enough eligible pure attack/benign cases: '
                         f'attack={len(pure_positive)}, benign={len(pure_negative)}; '
                         'reduce sample size or raise --max-events')

    rng = random.Random(seed)
    ids = diverse_positive(pure_positive, truth, positives, rng)
    ids += diverse_negative(pure_negative, cases, negatives, rng)
    rng.shuffle(ids)

    if len(ids) != positives + negatives or len(set(ids)) != len(ids):
        raise AssertionError('Sampling returned duplicate or missing cases')

    output_dir = Path(output_dir or (root / 'benchmarks/pilot_01'))
    if check_git:
        result = subprocess.run(['git', 'check-ignore', '-q', str(output_dir / 'cases.jsonl')],
                                cwd=PROJECT_ROOT, capture_output=True)
        if result.returncode != 0:
            raise ValueError('Benchmark output is not protected by .gitignore')

    manifest = {
        'benchmark_id': 'cloudtrail-development-pilot-01',
        'split': 'development',
        'selection': 'stratified_pure_case_pilot_not_prevalence_representative',
        'seed': seed,
        'max_events_per_case': max_events,
        'case_count': len(ids),
        'case_ids': ids,
        'cases_source_sha256': sha256(case_path),
    }
    audit = {
        'benchmark_id': manifest['benchmark_id'],
        'case_truth_source_sha256': sha256(truth_path),
        'selection_counts': {'attack_associated': positives, 'benign': negatives},
        'selection_labels_private_do_not_feed_investigators': [
            {'case_id': cid,
             'attack_associated': truth[cid]['attack_associated'],
             'scenario_names': truth[cid].get('scenario_names') or [],
             'event_count': len(cases[cid]['events'])}
            for cid in ids
        ],
        'excluded_mixed_cases': True,
        'selection_uses_development_truth_not_valid_for_population_prevalence': True,
    }
    records = [cases[cid] for cid in ids]
    for case in records:
        check_no_labels(case)
    contents = {
        'manifest.json': json.dumps(manifest, indent=2, sort_keys=True) + '\n',
        'cases.jsonl': ''.join(json.dumps(case, sort_keys=True) + '\n' for case in records),
        'selection_audit_PRIVATE.json': json.dumps(audit, indent=2, sort_keys=True) + '\n',
    }
    # Protect existing outputs against silent overwrites.
    for name, content in contents.items():
        path = output_dir / name
        if path.exists() and path.read_text(encoding='utf-8') != content:
            raise ValueError(f'Existing benchmark artifact differs: {path}')
    output_dir.mkdir(parents=True, exist_ok=True)
    for name, content in contents.items():
        path = output_dir / name
        if not path.exists():
            path.write_text(content, encoding='utf-8')
    return {
        'output_dir': str(output_dir), 'case_count': len(ids),
        'attack_cases': positives, 'benign_cases': negatives,
        'size_buckets': dict(Counter(bucket(len(cases[cid]['events'])) for cid in ids)),
        'case_ids': ids,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--positives', type=int, default=4)
    parser.add_argument('--negatives', type=int, default=4)
    parser.add_argument('--max-events', type=int, default=20)
    parser.add_argument('--seed', type=int, default=20261108)
    args = parser.parse_args()
    result = prepare(DATA_DIR, positives=args.positives, negatives=args.negatives,
                     max_events=args.max_events, seed=args.seed)
    print('CLOUDTRAIL DEVELOPMENT PILOT PREPARED')
    print('Cases:', result['case_count'], 'Attack:', result['attack_cases'],
          'Benign:', result['benign_cases'])
    print('Event-count groups:', result['size_buckets'])
    print('Saved privately:', result['output_dir'])
    print('Labels separated from investigator inputs: YES')
    print('WARNING: Balanced pilot; NOT population-representative accuracy')


if __name__ == '__main__':
    main()
