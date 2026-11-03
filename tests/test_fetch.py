"""fetch(): truncated bodies, per-source byte bounds and failure reasons, with no network."""
import http.client
import io
import json
import unittest
from unittest import mock
import urllib.error

import support
from intelligence_hub import collect

URL = "https://www.cisa.gov/cybersecurity-advisories/all.xml"


class FakeSocket:
    def __init__(self, data):
        self.data = data

    def makefile(self, *_args, **_kwargs):
        return io.BytesIO(self.data)


def response(raw, url=URL):
    """A real http.client response parsed from raw bytes, as urllib would return it."""
    reply = http.client.HTTPResponse(FakeSocket(raw), method="GET")
    reply.begin()
    reply.url = url
    return reply


class FakeOpener:
    def __init__(self, reply):
        self.reply = reply

    def open(self, _request, timeout=None):
        return self.reply


def serve(raw):
    return mock.patch.object(collect.urllib.request, "build_opener", return_value=FakeOpener(response(raw)))


class FetchTest(unittest.TestCase):
    def test_complete_chunked_body(self):
        with serve(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n"):
            self.assertEqual(collect.fetch(URL), b"hello world")

    def test_truncated_chunked_body_is_an_oserror(self):
        # The second chunk promises 16 bytes and the connection ends after 5.
        with serve(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n10\r\nshort"):
            with self.assertRaises(OSError) as raised:
                collect.fetch(URL)
        self.assertIn("IncompleteRead", str(raised.exception))
        self.assertIsInstance(raised.exception.__cause__, http.client.HTTPException)

    def test_short_content_length_body_is_an_oserror(self):
        with serve(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nonly twenty bytes...."):
            with self.assertRaises(OSError):
                collect.fetch(URL)

    def test_reads_use_read1(self):
        reply = response(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello")
        reply.read = mock.Mock(side_effect=AssertionError("fetch must read with read1 so its deadline binds"))
        with mock.patch.object(collect.urllib.request, "build_opener", return_value=FakeOpener(reply)):
            self.assertEqual(collect.fetch(URL), b"hello")

    def test_deadline_is_checked_between_reads(self):
        clock = iter([0.0, 1.0, 31.0])
        with serve(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n5\r\nworld\r\n0\r\n\r\n"):
            with mock.patch.object(collect.time, "monotonic", side_effect=lambda: next(clock)):
                with self.assertRaisesRegex(ValueError, "deadline"):
                    collect.fetch(URL)

    def test_response_over_its_bound(self):
        with serve(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n0123456789"):
            with self.assertRaises(collect.ResponseByteLimitExceeded):
                collect.fetch(URL, maximum=9)

    def test_bound_cannot_pass_the_fetch_ceiling(self):
        with self.assertRaises(ValueError):
            collect.fetch(URL, maximum=collect.FETCH_CEILING + 1)


class PerSourceBoundTest(unittest.TestCase):
    def test_cisa_feeds_carry_8_mib_bounds(self):
        bounds = {item["id"]: item.get("max_bytes") for item in support.sources()}
        self.assertEqual(bounds["cisa-advisories"], 8 * 1024 * 1024)
        self.assertEqual(bounds["cisa-ics-advisories"], 8 * 1024 * 1024)
        self.assertTrue(all(value is None or value <= collect.FETCH_CEILING for value in bounds.values()))
        # The two CISA responses measured 5,897,554 and 6,176,856 bytes on 2026-11-03.
        self.assertGreater(8 * 1024 * 1024, 6176856)
        self.assertLess(collect.MAX_BYTES, 5897554)

    def test_update_source_passes_its_own_bound(self):
        source = support.source("cisa-advisories")
        with mock.patch.object(collect, "fetch", side_effect=collect.ResponseByteLimitExceeded("over")) as fetch:
            result = collect.update_source(source, {})
        fetch.assert_called_once_with(source["url"], 8 * 1024 * 1024)
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["error"], collect.RESPONSE_BYTE_LIMIT_REASON)

    def test_sources_without_a_bound_use_the_default(self):
        source = support.source("cert-eu")
        with mock.patch.object(collect, "fetch", side_effect=OSError("down")) as fetch:
            collect.update_source(source, {})
        fetch.assert_called_once_with(source["url"], collect.MAX_BYTES)

    def test_registry_refuses_a_bound_over_the_ceiling(self):
        registry = json.loads((support.ROOT / "config/sources.json").read_text(encoding="utf-8"))
        registry["sources"][0]["max_bytes"] = collect.FETCH_CEILING + 1
        with self.assertRaises(ValueError):
            collect.validate_registry(registry)
        registry["sources"][0]["max_bytes"] = "8388608"
        with self.assertRaises(ValueError):
            collect.validate_registry(registry)


class FailureReasonTest(unittest.TestCase):
    def test_each_failure_names_its_cause(self):
        source = support.source("cert-eu")
        with mock.patch.object(collect, "fetch", side_effect=OSError("IncompleteRead: the publisher response ended early or was malformed")):
            result = collect.update_source(source, {})
        self.assertEqual(result["error"], "OSError: IncompleteRead: the publisher response ended early or was malformed")
        forbidden = urllib.error.HTTPError(source["url"], 403, "Forbidden", {}, io.BytesIO())
        self.addCleanup(forbidden.close)
        with mock.patch.object(collect, "fetch", side_effect=forbidden):
            self.assertEqual(collect.update_source(source, {})["error"], "HTTP 403")
        with mock.patch.object(collect, "fetch", side_effect=ValueError("Source exceeded its read deadline.")):
            self.assertEqual(collect.update_source(source, {})["error"], "ValueError: Source exceeded its read deadline.")

    def test_reason_is_bounded_single_line_text(self):
        reason = collect.failure_reason(OSError("line one\nline\ttwo\x07" + "x" * 1000), "fallback")
        self.assertTrue(reason.startswith("OSError: line one line two"))
        self.assertLessEqual(len(reason), 320)
        self.assertEqual(collect.failure_reason(OSError(), "fallback"), "OSError: fallback")

    def test_kev_failure_names_its_cause(self):
        with mock.patch.object(collect, "fetch", side_effect=OSError("RemoteDisconnected: the publisher response ended early or was malformed")):
            result = collect.update_kev({})
        self.assertEqual(result["status"], "failed")
        self.assertIn("RemoteDisconnected", result["error"])


if __name__ == "__main__":
    unittest.main()
