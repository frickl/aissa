import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from aissa.evaluate import evaluate, load_cases


class EvaluateTests(unittest.TestCase):
    def test_expectations_are_not_passed_to_classifier(self):
        with tempfile.TemporaryDirectory() as folder:
            p=Path(folder)/'sample.eml'
            raw=b'Subject: Test\n\nordinary text'
            p.write_bytes(raw)
            case=dict(id='test',group='new',expected='ham',path=p)
            rows=[]
            with patch('aissa.evaluate.analyzer.classify', return_value=dict(
                    classification='spam',confidence=.95,reason='test',elapsed_seconds=4)) as classify:
                summary=evaluate([case], 'test-model', 60, rows.append)
                classify.assert_called_once_with(raw,'test-model',60)
            self.assertEqual(summary['correct'],0)
            self.assertEqual(summary['ham_labeled_spam_or_phishing'],1)
            self.assertEqual(summary['confusion_matrix']['ham'], {'spam':1})
            self.assertEqual(rows[0]['id'],'test')

    def test_backend_errors_do_not_become_correct_uncertain(self):
        with tempfile.TemporaryDirectory() as folder:
            p=Path(folder)/'sample.eml';p.write_bytes(b'body')
            cases=[dict(id='test',group='new',expected='uncertain',path=p)]
            with patch('aissa.evaluate.analyzer.classify',side_effect=TimeoutError):
                summary=evaluate(cases,'test',1,lambda row: None)
            self.assertEqual(summary['errors'],1)
            self.assertEqual(summary['correct'],0)
            self.assertEqual(summary['confusion_matrix']['uncertain'],{'error':1})

    def test_manifest_integrity_groups_and_all_classes(self):
        root=Path(__file__).resolve().parent.parent
        manifest=root/'evaluation/manifest.json'
        cases=load_cases(manifest)
        self.assertEqual(len(cases),25)
        self.assertEqual(len(load_cases(manifest,'regression')),5)
        self.assertEqual(len(load_cases(manifest,'new')),20)
        self.assertEqual({c['expected'] for c in cases}, {'ham','bulk','spam','phishing','uncertain'})
        self.assertTrue(all(c['path'].stat().st_size>0 for c in cases))

    def test_manifest_rejects_traversal_and_duplicate_ids(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)/'evaluation';root.mkdir()
            (Path(folder)/'outside.eml').write_bytes(b'body')
            manifest=root/'manifest.json'
            case=dict(id='x',group='new',expected='ham',file='../outside.eml')
            manifest.write_text(json.dumps({'cases':[case]}))
            with self.assertRaises(ValueError): load_cases(manifest)
            (root/'mail.eml').write_bytes(b'body')
            case['file']='mail.eml'
            manifest.write_text(json.dumps({'cases':[case,case]}))
            with self.assertRaises(ValueError): load_cases(manifest)
