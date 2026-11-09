import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from src.demo import soc_demo as s

class TestSocDemo(unittest.TestCase):
    def setUp(self):
        self.cases,self.truth,self.events=s.make_cases()

    def test_100_cases_and_distribution(self):
        self.assertEqual(len(self.cases),100)
        self.assertEqual({k:sum(t['class_label']==k for t in self.truth) for k in ('benign','suspicious','critical')}, {'benign':40,'suspicious':30,'critical':30})

    def test_no_ground_truth_exposure(self):
        s.assert_isolated(self.cases)
        self.assertNotIn('class_label',json.dumps(self.events))

    def test_event_identity_matches_wazuh(self):
        ids={e['event_id'] for c in self.cases for e in c['events']}
        self.assertEqual(ids,{e['sim_event_id'] for e in self.events})
        self.assertEqual(len(self.events),len(ids))

    def test_no_real_attack_execution(self):
        self.assertTrue(all(e['soc_demo']=='research_simulation' for e in self.events))
        self.assertTrue(all(e['source_ip'].startswith('198.51.100.') for e in self.events))

    def test_baseline_behavior(self):
        self.assertEqual(s.baseline(self.cases[0])['classification'],'benign')
        self.assertEqual(s.baseline(self.cases[4])['classification'],'suspicious')
        self.assertEqual(s.baseline(self.cases[7])['classification'],'critical')

    def test_stable_data(self):
        self.assertEqual(s.make_cases(),s.make_cases())

    def test_prepare_is_idempotent(self):
        with tempfile.TemporaryDirectory() as td:
            s.prepare(td)
            s.prepare(td)
            self.assertEqual(len(s.read_jsonl(Path(td)/'ground_truth_PRIVATE.jsonl')),100)

    def test_three_mode_case_selection(self):
        selected=s._select_demo_cases(self.cases,self.truth)
        self.assertEqual(len(selected),6)
        labels={t['case_id']:t['class_label'] for t in self.truth}
        self.assertEqual(dict(__import__('collections').Counter(labels[c['case_id']] for c in selected)),{'benign':2,'suspicious':2,'critical':2})

    def test_citation_rejects_hallucination(self):
        case=self.cases[0]
        report=s.baseline(case)
        report['evidence_ids']=['UNKNOWN']
        with self.assertRaises(ValueError):s.validate_ai(report,case,[])

    def test_llm_only_must_not_cite_knowledge(self):
        case=self.cases[0]
        report=s.baseline(case)
        report['knowledge_ids']=['MITRE-FAKE']
        with self.assertRaises(ValueError):s.validate_ai(report,case,[])

    def test_crosscheck_only_real_wazuh_alert_ids(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)
            s.prepare(p)
            alerts=p/'alerts.json'
            s.write_jsonl(alerts,[{'data':{'soc_demo':'research_simulation','sim_event_id':self.events[0]['sim_event_id'],'sim_case_id':self.events[0]['sim_case_id']}}, {'data': {'soc_demo':'research_simulation','sim_event_id':'UNKNOWN'}}])
            result=s.crosscheck(p,alerts)
            self.assertEqual(result['wazuh_alerts_matching_event_ids'],1)

    def test_executive_report_nontech(self):
        selected=s._select_demo_cases(self.cases,self.truth)
        labels={t['case_id']:t['class_label'] for t in self.truth}
        x={m:[{'case_id':c['case_id'],'prediction':'benign','summary':'No high risk confirmed', 'evidence_ids':[]} for c in selected] for m in ('baseline','llm_only','rag')}
        md=s.executive_markdown(selected,x,labels)
        self.assertIn('Executive overview',md)
        self.assertIn('No real attack was executed',md)

class TestWazuhSafeInstaller(unittest.TestCase):
    def test_insert_stanza_exactly_once(self):
        from deploy.wazuh.enable_demo import insert_stanza
        original='<ossec_config>\n</ossec_config>\n'
        first=insert_stanza(original)
        self.assertEqual(first.count('<location>/var/log/soc_demo_cloud.jsonl</location>'),1)
        self.assertEqual(insert_stanza(first),first)

    def test_insert_requires_expected_xml(self):
        from deploy.wazuh.enable_demo import insert_stanza
        with self.assertRaises(ValueError):insert_stanza('not a manager configuration')
