"""OSV as an advisory source.

Lookups go through ``POST /v1/querybatch`` by ecosystem and package name
only, with no version, so OSV learns which packages are being checked but
not which versions a project uses. The answer lists every advisory id for
each package with its ``modified`` time; full records come from
``GET /v1/vulns/{id}`` and are only fetched when they are new or changed.

API reference: https://google.github.io/osv.dev/api/
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from typing import Any
from urllib.parse import quote

from dva.contracts.intelligence import AdvisoryStamp, PackageKey, ProviderError
from dva.domain.advisory import Advisory
from dva.intelligence.http import HttpTransport
from dva.intelligence.osv.records import (
    DVA_TO_OSV,
    InvalidRecordError,
    parse_record,
    parse_timestamp,
)

DEFAULT_BASE_URL = "https://api.osv.dev"
#: Queries per batch request. OSV doesn't publish a limit; this matches what
#: its own scanner uses.
BATCH_SIZE = 1000
#: Follow-up pages per batch before giving up; OSV pages only past 1000 results.
MAX_PAGES = 20


class OsvSource:
    provider_id = "osv"

    def __init__(self, transport: HttpTransport, base_url: str = DEFAULT_BASE_URL) -> None:
        self._transport = transport
        self._base_url = base_url.rstrip("/")

    def supports(self, ecosystem: str) -> bool:
        return ecosystem in DVA_TO_OSV

    def list_advisories(
        self, packages: Sequence[PackageKey]
    ) -> Mapping[PackageKey, tuple[AdvisoryStamp, ...]]:
        keys = sorted({p for p in packages if self.supports(p.ecosystem)})
        found: dict[PackageKey, dict[str, AdvisoryStamp]] = {key: {} for key in keys}
        for start in range(0, len(keys), BATCH_SIZE):
            self._query_batch(keys[start : start + BATCH_SIZE], found)
        return {key: tuple(stamps.values()) for key, stamps in found.items()}

    def _query_batch(
        self, keys: list[PackageKey], found: dict[PackageKey, dict[str, AdvisoryStamp]]
    ) -> None:
        pending: list[tuple[PackageKey, str | None]] = [(key, None) for key in keys]
        for _ in range(MAX_PAGES + 1):
            if not pending:
                return
            queries: list[dict[str, Any]] = []
            for key, token in pending:
                query: dict[str, Any] = {
                    "package": {"ecosystem": DVA_TO_OSV[key.ecosystem], "name": key.name}
                }
                if token:
                    query["page_token"] = token
                queries.append(query)
            body = json.dumps({"queries": queries}).encode("utf-8")
            response = _json(
                self._transport.request("POST", f"{self._base_url}/v1/querybatch", body)
            )
            results = response.get("results") if isinstance(response, dict) else None
            if not isinstance(results, list) or len(results) != len(pending):
                raise ProviderError("OSV returned a batch answer of the wrong shape")
            next_pending: list[tuple[PackageKey, str | None]] = []
            for (key, _), result in zip(pending, results, strict=True):
                token = self._read_result(result, found[key])
                if token:
                    next_pending.append((key, token))
            pending = next_pending
        raise ProviderError("OSV kept returning more pages than expected")

    @staticmethod
    def _read_result(result: object, into: dict[str, AdvisoryStamp]) -> str | None:
        if not isinstance(result, dict):
            raise ProviderError("OSV returned a batch result that is not an object")
        vulns = result.get("vulns", [])
        if not isinstance(vulns, list):
            raise ProviderError("OSV returned a batch result without a list of advisories")
        for vuln in vulns:
            if not isinstance(vuln, dict) or not isinstance(vuln.get("id"), str):
                raise ProviderError("OSV returned an advisory entry without an id")
            modified = parse_timestamp(vuln.get("modified"))
            if modified is None:
                raise ProviderError("OSV returned an advisory entry without a valid time")
            into[vuln["id"]] = AdvisoryStamp(vuln["id"], modified)
        token = result.get("next_page_token")
        return token if isinstance(token, str) and token else None

    def fetch_record(self, advisory_id: str) -> str:
        url = f"{self._base_url}/v1/vulns/{quote(advisory_id, safe='')}"
        raw = self._transport.request("GET", url)
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            raise ProviderError("OSV returned a record that is not UTF-8") from None
        record = _json(raw)
        if not isinstance(record, dict) or record.get("id") != advisory_id:
            raise ProviderError("OSV returned a record for a different advisory")
        return text

    def parse_record(self, raw: str) -> Advisory:
        try:
            decoded = json.loads(raw)
        except (ValueError, RecursionError):
            raise InvalidRecordError("record text is not valid JSON") from None
        return parse_record(decoded)


def _json(raw: bytes) -> object:
    try:
        return json.loads(raw)
    except (ValueError, RecursionError):
        raise ProviderError("OSV returned data that is not valid JSON") from None
