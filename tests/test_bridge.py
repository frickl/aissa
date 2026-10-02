
import unittest
from unittest.mock import patch

from aissa.bridge import Bridge
from aissa.service import metadata


class BridgeTests(unittest.TestCase):
    def setUp(self):
        self.bridge = Bridge({
            "max_pending": 2,
            "max_requests_per_minute": 10,
            "max_results": 1,
            "model": "test",
            "llm_timeout": 1,
        })
        self.meta = metadata({"event_id": "test:1", "account": "alice"})

    def test_result_survives_repeated_fetch_until_ack(self):
        self.assertEqual(self.bridge.submit(b"mail", self.meta)[0], 202)
        raw, meta = self.bridge.jobs.get_nowait()
        with patch("aissa.bridge.classify", return_value={
            "classification": "phishing", "confidence": 0.9,
            "elapsed_seconds": 0.1, "model": "test",
        }):
            self.bridge.process(raw, meta)
        first = self.bridge.pending_results()
        self.assertEqual(first, self.bridge.pending_results())
        self.assertEqual(self.bridge.outstanding, 1)
        self.assertEqual(self.bridge.acknowledge([first[0]["id"]]), 1)
        self.assertEqual(self.bridge.acknowledge([first[0]["id"]]), 0)
        self.assertEqual(self.bridge.outstanding, 0)
        self.assertEqual(self.bridge.pending_results(), [])

    def test_result_capacity_blocks_new_jobs(self):
        self.bridge.confirm(self.meta)
        other = {**self.meta, "event_id": "test:2"}
        self.assertEqual(self.bridge.submit(b"mail", other),
                         (429, "results_full"))

    def test_error_is_retained_as_error(self):
        self.bridge.submit(b"mail", self.meta)
        raw, meta = self.bridge.jobs.get_nowait()
        with patch("aissa.bridge.classify", side_effect=TimeoutError()):
            self.bridge.process(raw, meta)
        result = self.bridge.pending_results()[0]
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["classification"], "uncertain")

    def test_confirmation_is_separate(self):
        self.assertEqual(self.bridge.confirm(self.meta)[0], 202)
        result = self.bridge.pending_results()[0]
        self.assertEqual(result["status"], "confirmed")
        self.assertEqual(result["classification"], "confirmed")
