from __future__ import annotations

import json

import pytest

from dva.contracts.intelligence import PackageKey, ProviderError
from dva.intelligence.osv import source as source_module
from dva.intelligence.osv.source import OsvSource
from tests.support.osv_fake import FakeOsvTransport

REQUESTS = PackageKey("pypi", "requests")
LODASH = PackageKey("npm", "lodash")


def test_lookup_sends_only_ecosystem_and_name() -> None:
    transport = FakeOsvTransport()
    listed = OsvSource(transport).list_advisories([REQUESTS, LODASH, PackageKey("npm", "@a/b")])
    assert transport.batch_queries() == [
        {"package": {"ecosystem": "npm", "name": "@a/b"}},
        {"package": {"ecosystem": "npm", "name": "lodash"}},
        {"package": {"ecosystem": "PyPI", "name": "requests"}},
    ]
    assert [s.id for s in listed[REQUESTS]] == [
        "GHSA-j8r2-6x86-q33q",
        "GHSA-9wx4-h78v-vm56",
        "PYSEC-2023-74",
    ]
    assert listed[PackageKey("npm", "@a/b")] == ()
    assert all(s.modified.tzinfo is not None for s in listed[LODASH])


def test_unsupported_ecosystems_are_not_queried() -> None:
    transport = FakeOsvTransport()
    source = OsvSource(transport)
    assert not source.supports("cargo")
    assert source.list_advisories([PackageKey("cargo", "serde")]) == {}
    assert transport.requests == []


def test_pagination_follows_tokens_per_query() -> None:
    transport = FakeOsvTransport()
    transport.page_size = 1
    listed = OsvSource(transport).list_advisories([REQUESTS, LODASH])
    assert len(listed[REQUESTS]) == 3
    assert len(listed[LODASH]) == 1
    posts = [body for method, _, body in transport.requests if method == "POST"]
    assert len(posts) == 3
    assert [len(p["queries"]) for p in posts] == [2, 1, 1]
    assert posts[1]["queries"][0]["page_token"] == "1"  # noqa: S105 (a page number, not a secret)


def test_endless_pagination_is_cut_off(monkeypatch: pytest.MonkeyPatch) -> None:
    class Endless(FakeOsvTransport):
        def request(self, method: str, url: str, body: bytes | None = None) -> bytes:
            return json.dumps({"results": [{"vulns": [], "next_page_token": "again"}]}).encode()

    monkeypatch.setattr(source_module, "MAX_PAGES", 3)
    with pytest.raises(ProviderError):
        OsvSource(Endless()).list_advisories([REQUESTS])


def test_large_lookups_are_split_into_batches(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(source_module, "BATCH_SIZE", 2)
    transport = FakeOsvTransport()
    keys = [PackageKey("npm", f"pkg-{i}") for i in range(5)]
    OsvSource(transport).list_advisories(keys)
    assert [len(b["queries"]) for m, _, b in transport.requests if m == "POST"] == [2, 2, 1]


@pytest.mark.parametrize(
    "answer",
    [
        b"not json",
        b"[]",
        b'{"results": "x"}',
        b'{"results": []}',
        b'{"results": [{"vulns": "x"}]}',
        b'{"results": [{"vulns": [{"modified": "2026-01-01T00:00:00Z"}]}]}',
        b'{"results": [{"vulns": [{"id": "A", "modified": "soon"}]}]}',
        b'{"results": ["x"]}',
    ],
)
def test_malformed_batch_answers_raise(answer: bytes) -> None:
    class Broken(FakeOsvTransport):
        def request(self, method: str, url: str, body: bytes | None = None) -> bytes:
            return answer

    with pytest.raises(ProviderError):
        OsvSource(Broken()).list_advisories([REQUESTS])


def test_fetch_and_parse_a_record() -> None:
    transport = FakeOsvTransport()
    source = OsvSource(transport)
    raw = source.fetch_record("GHSA-j8r2-6x86-q33q")
    assert source.parse_record(raw).id == "GHSA-j8r2-6x86-q33q"
    assert transport.requests[0][1] == "https://api.osv.dev/v1/vulns/GHSA-j8r2-6x86-q33q"


def test_record_ids_are_escaped_in_urls() -> None:
    transport = FakeOsvTransport()
    with pytest.raises(ProviderError):
        OsvSource(transport).fetch_record("../../admin")
    assert transport.requests[0][1].endswith("/v1/vulns/..%2F..%2Fadmin")


def test_a_record_for_another_id_is_refused() -> None:
    transport = FakeOsvTransport()
    transport.records["GHSA-j8r2-6x86-q33q"] = {"id": "SOMETHING-ELSE", "modified": "x"}
    with pytest.raises(ProviderError):
        OsvSource(transport).fetch_record("GHSA-j8r2-6x86-q33q")


def test_unparsable_record_text_is_a_value_error() -> None:
    with pytest.raises(ValueError):
        OsvSource(FakeOsvTransport()).parse_record('{"id": "X"}')
    with pytest.raises(ValueError):
        OsvSource(FakeOsvTransport()).parse_record("not json")


def test_records_are_fetched_in_parallel_within_the_limit() -> None:
    import threading
    import time

    from dva.intelligence.osv.source import MAX_PARALLEL_FETCHES

    class SlowTransport(FakeOsvTransport):
        def __init__(self) -> None:
            super().__init__()
            self.active = 0
            self.peak = 0
            self.lock = threading.Lock()

        def request(self, method: str, url: str, body: bytes | None = None) -> bytes:
            with self.lock:
                self.active += 1
                self.peak = max(self.peak, self.active)
            try:
                time.sleep(0.05)
                return super().request(method, url, body)
            finally:
                with self.lock:
                    self.active -= 1

    transport = SlowTransport()
    ids = ["GHSA-35jh-r3h4-6jhm", "GHSA-j8r2-6x86-q33q", "GHSA-9wx4-h78v-vm56", "PYSEC-2023-74"]
    ids += [f"GHSA-none-{i}" for i in range(12)]  # Unknown ids: each fails on its own.
    results = OsvSource(transport).fetch_records(ids)
    assert list(results) == ids
    assert all(isinstance(results[i], str) for i in ids[:4])
    assert all(isinstance(results[i], ProviderError) for i in ids[4:])
    assert 1 < transport.peak <= MAX_PARALLEL_FETCHES
