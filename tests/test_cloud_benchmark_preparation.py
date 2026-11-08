"""Regression tests for label-isolated CloudTrail pilot cohort selection."""
import json
import tempfile
import unittest
from pathlib import Path

from src.evaluation.prepare_cloud_benchmark import prepare


def record(index, attacked=False, benign=0, events=1, scenario='S3Test'):
    cid = f'CASE-{index}'
    case = {'case_id': cid, 'event_count': events,
            'correlation_method': 'test',
            'events': [{'event_id': f'{cid}-EVT-{i}', 'action': 'GetObject'}
                       for i in range(events)]}
    t = {'case_id': cid, 'attack_associated': attacked,
         'attack_event_count': events-benign if attacked else 0,
         'benign_event_count': benign if attacked else events,
         'scenario_names': [scenario] if attacked else []}
    return case, t


class BenchmarkSelectionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.cases = []
        self.truth = []
        for i in range(6):
            self.add(*record(i, attacked=True, scenario=f'Scenario{i%3}'))
        for i in range(6, 12):
            self.add(*record(i, events=i % 3 + 1))
        self.write()

    def add(self, case, truth):
        self.cases.append(case)
        self.truth.append(truth)

    def write(self):
        for filename, records in [('cases.jsonl', self.cases),
                                  ('case_ground_truth.jsonl', self.truth)]:
            (self.root / filename).write_text(
                ''.join(json.dumps(r) + '\n' for r in records), encoding='utf-8')

    def select(self, output=None):
        return prepare(self.root, positives=3, negatives=3, max_events=3,
                       output_dir=output or self.root / 'outputs', check_git=False)

    def test_balanced_and_labels_private(self):
        result = self.select()
        self.assertEqual((result['attack_cases'], result['benign_cases']), (3, 3))
        manifest = json.loads((self.root / 'outputs/manifest.json').read_text())
        cases = (self.root / 'outputs/cases.jsonl').read_text()
        self.assertEqual(len(manifest['case_ids']), 6)
        self.assertNotIn('attack_associated', cases)
        self.assertNotIn('scenario_names', cases)
        self.assertNotIn('attack_associated', json.dumps(manifest))
        private = json.loads((self.root / 'outputs/selection_audit_PRIVATE.json').read_text())
        self.assertEqual(private['selection_counts']['attack_associated'], 3)

    def test_idempotent_repeated_run(self):
        self.select()
        before = (self.root / 'outputs/manifest.json').read_bytes()
        self.select()
        self.assertEqual(before, (self.root / 'outputs/manifest.json').read_bytes())

    def test_altered_output_is_not_overwritten(self):
        self.select()
        (self.root / 'outputs/manifest.json').write_text('{}')
        with self.assertRaisesRegex(ValueError, 'differs'):
            self.select()

    def test_duplicate_case_id_rejected(self):
        self.cases.append(self.cases[0])
        self.write()
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            self.select()

    def test_mismatched_case_and_truth_rejected(self):
        self.truth.pop()
        self.write()
        with self.assertRaisesRegex(ValueError, 'ID sets differ'):
            self.select()

    def test_source_label_leakage_rejected(self):
        self.cases[0]['events'][0]['attack_associated'] = True
        self.write()
        with self.assertRaisesRegex(ValueError, 'label leakage'):
            self.select()

    def test_insufficient_class_rejected(self):
        with self.assertRaisesRegex(ValueError, 'Not enough eligible'):
            prepare(self.root, positives=20, negatives=3, max_events=3,
                    output_dir=self.root / 'outputs', check_git=False)

    def test_mixed_case_excluded(self):
        self.add(*record(99, attacked=True, benign=1, events=3))
        self.write()
        self.select()
        manifest = json.loads((self.root / 'outputs/manifest.json').read_text())
        self.assertNotIn('CASE-99', manifest['case_ids'])

    def test_inconsistent_truth_count_rejected(self):
        self.truth[0]['benign_event_count'] = 8
        self.write()
        with self.assertRaisesRegex(ValueError, 'inconsistent truth'):
            self.select()

    def test_event_count_mismatch_rejected(self):
        self.cases[0]['event_count'] = 20
        self.write()
        with self.assertRaisesRegex(ValueError, 'event_count mismatch'):
            self.select()


if __name__ == '__main__':
    unittest.main()
