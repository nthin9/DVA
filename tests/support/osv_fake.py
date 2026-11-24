"""A fake OSV server for tests, serving the real records in tests/fixtures/osv.

It answers ``POST /v1/querybatch`` and ``GET /v1/vulns/{id}`` the way the
live API does, records every request (so tests can check exactly what DVA
sends), and can be told to fail.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from dva.contracts.intelligence import ProviderError
from dva.intelligence.http import NotFoundError

FIXTURES = Path(__file__).parents[1] / "fixtures" / "osv"

#: Which fixture advisories the fake lists for each (OSV ecosystem, name).
DEFAULT_INDEX: dict[tuple[str, str], list[str]] = {
    ("PyPI", "requests"): ["GHSA-j8r2-6x86-q33q", "GHSA-9wx4-h78v-vm56", "PYSEC-2023-74"],
    ("npm", "lodash"): ["GHSA-35jh-r3h4-6jhm"],
}


def fixture_record(advisory_id: str) -> dict[str, Any]:
    data: dict[str, Any] = json.loads(
        (FIXTURES / f"{advisory_id}.json").read_text(encoding="utf-8")
    )
    return data


class FakeOsvTransport:
    def __init__(self, index: dict[tuple[str, str], list[str]] | None = None) -> None:
        self.index = dict(DEFAULT_INDEX if index is None else index)
        self.records: dict[str, dict[str, Any]] = {}
        self.requests: list[tuple[str, str, Any]] = []
        self.fail_batch: ProviderError | None = None
        self.fail_records: set[str] = set()
        self.page_size: int | None = None

    def record(self, advisory_id: str) -> dict[str, Any]:
        if advisory_id not in self.records:
            self.records[advisory_id] = fixture_record(advisory_id)
        return self.records[advisory_id]

    def request(self, method: str, url: str, body: bytes | None = None) -> bytes:
        payload = json.loads(body) if body else None
        self.requests.append((method, url, payload))
        if method == "POST" and url.endswith("/v1/querybatch"):
            if self.fail_batch is not None:
                raise self.fail_batch
            assert payload is not None
            return json.dumps({"results": [self._answer(q) for q in payload["queries"]]}).encode()
        if method == "GET" and "/v1/vulns/" in url:
            advisory_id = url.rsplit("/", 1)[1]
            if advisory_id in self.fail_records:
                raise ProviderError("server busy or failing (HTTP 503)")
            try:
                return json.dumps(self.record(advisory_id)).encode()
            except FileNotFoundError:
                raise NotFoundError("not found (HTTP 404)") from None
        raise AssertionError(f"unexpected request {method} {url}")

    def _answer(self, query: dict[str, Any]) -> dict[str, Any]:
        package = query["package"]
        ids = self.index.get((package["ecosystem"], package["name"]), [])
        vulns = [{"id": i, "modified": self.record(i)["modified"]} for i in ids]
        if self.page_size is None:
            return {"vulns": vulns} if vulns else {}
        start = int(query.get("page_token", "0"))
        page = vulns[start : start + self.page_size]
        answer: dict[str, Any] = {"vulns": page}
        if start + self.page_size < len(vulns):
            answer["next_page_token"] = str(start + self.page_size)
        return answer

    def batch_queries(self) -> list[dict[str, Any]]:
        return [q for method, _, body in self.requests if method == "POST" for q in body["queries"]]

    def fetched(self) -> list[str]:
        return [url.rsplit("/", 1)[1] for method, url, _ in self.requests if method == "GET"]
