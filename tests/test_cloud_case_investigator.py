"""Unit tests for local CloudTrail case AI orchestration (no model calls)."""
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from src.investigation.cloud_case_investigator import (
    choose_case, investigate, make_payload, no_labels, select_references,
)


def case_with(n=4, diverse=True):
    events = [
        {'event_id': f'CLOUD-DEV-EVT-{i:06d}',
         'timestamp_utc': f'2026-11-04T02:{i:02d}:00Z',
         'event_source': 's3.amazonaws.com',
         'action': 'GetObject' if not diverse or i % 2 else 'PutObject',
         'actor': 'example-actor', 'source_ip': '192.0.2.1'}
        for i in range(1, n+1)
    ]
    return {'case_id': 'CLOUD-DEV-CASE-' + 'a' * 16, 'events': events,
            'event_count': n}


class CloudCaseInvestigatorTests(unittest.TestCase):
    def test_ground_truth_rejected(self):
        with self.assertRaisesRegex(ValueError, 'Ground-truth'):
            no_labels({'events': [{'event_id': 'e1', 'attack_name': 'hidden'}]})

    def test_small_diverse_case_selected_without_labels(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'cases.jsonl'
            single = case_with(1)
            single['case_id'] = 'CLOUD-DEV-CASE-' + 'b' * 16
            target = case_with(4)
            path.write_text('\n'.join([json.dumps(single), json.dumps(target)]), encoding='utf-8')
            self.assertEqual(choose_case(path)['case_id'], target['case_id'])

    def test_large_case_truncated_and_flagged(self):
        payload = make_payload(case_with(25), [], max_events=10)
        self.assertTrue(payload['evidence_is_truncated'])
        self.assertEqual(payload['total_events'], 25)
        self.assertEqual(len(payload['evidence_events']), 10)
        self.assertEqual(payload['evidence_events'][0]['event_id'], 'CLOUD-DEV-EVT-000001')
        self.assertEqual(payload['evidence_events'][-1]['event_id'], 'CLOUD-DEV-EVT-000025')

    def test_service_specific_knowledge_selection(self):
        documents = [
            {'id':'AWS-CLOUDTRAIL', 'services':['all']},
            {'id':'AWS-S3-EVENTS', 'services':['s3.amazonaws.com']},
            {'id':'AWS-IDENTITY', 'services':['iam.amazonaws.com']},
        ]
        ids = [doc['id'] for doc in select_references(case_with()['events'], documents)]
        self.assertEqual(ids, ['AWS-CLOUDTRAIL', 'AWS-S3-EVENTS'])

    def test_unknown_ai_evidence_citation_rejected(self):
        payload = make_payload(case_with(1), [])
        report = {'summary': 'Unclear', 'classification': 'insufficient_evidence',
                  'reasoning': 'Only a single API request', 'evidence_ids': ['NOT-PRESENT'],
                  'next_checks': [], 'knowledge_ids': []}
        result = {'message': {'content': json.dumps(report)}}
        with patch('src.investigation.cloud_case_investigator.urlopen') as open_mock:
            open_mock.return_value.__enter__.return_value = io.BytesIO(json.dumps(result).encode())
            with self.assertRaisesRegex(ValueError, 'Unknown evidence citations'):
                investigate(payload, 'qwen2.5:1.5b')


if __name__ == '__main__':
    unittest.main()
