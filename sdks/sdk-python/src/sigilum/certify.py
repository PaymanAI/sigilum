"""One-line agent certification bindings for Python agents."""

from __future__ import annotations

import urllib.request
from typing import Any, Callable, Optional, Union

from sigilum.http_signatures import sign_http_request
from sigilum.identity_store import get_namespace_api_base, load_identity
from sigilum.types import HeaderInput, SignedRequest

Fetcher = Callable[[str, str, dict[str, str], Optional[Union[bytes, str]]], Any]


def _resolve_api_base_url(explicit: str | None) -> str:
    import os

    return explicit or os.environ.get("SIGILUM_API_URL") or "https://api.sigilum.id"


def _resolve_url(value: str, base: str) -> str:
    if value.startswith("http://") or value.startswith("https://"):
        return value
    return f"{base.rstrip('/')}/{value.lstrip('/')}"


class SigilumBindings:
    def __init__(
        self,
        *,
        namespace: str | None,
        home_dir: str | None,
        api_base_url: str | None,
        fetcher: Fetcher | None,
    ):
        self._identity = load_identity(namespace=namespace, home_dir=home_dir)
        self._api_base_url = _resolve_api_base_url(api_base_url)
        self._fetcher = fetcher

        self.namespace = self._identity.namespace
        self.did = self._identity.did
        self.key_id = self._identity.key_id
        self.public_key = self._identity.public_key
        self.certificate = self._identity.certificate
        self.api_base_url = self._api_base_url

    def sign(
        self,
        *,
        url: str,
        method: str = "GET",
        headers: HeaderInput | None = None,
        body: bytes | str | None = None,
    ) -> SignedRequest:
        return sign_http_request(
            identity=self._identity,
            url=_resolve_url(url, self._api_base_url),
            method=method,
            headers=headers,
            body=body,
        )

    def fetch(
        self,
        *,
        url: str,
        method: str = "GET",
        headers: HeaderInput | None = None,
        body: bytes | str | None = None,
    ) -> Any:
        signed = self.sign(url=url, method=method, headers=headers, body=body)
        if self._fetcher is not None:
            return self._fetcher(signed.url, signed.method, signed.headers, signed.body)

        data = None
        if isinstance(signed.body, str):
            data = signed.body.encode("utf-8")
        elif isinstance(signed.body, bytes):
            data = signed.body

        request = urllib.request.Request(
            signed.url,
            method=signed.method,
            headers=signed.headers,
            data=data,
        )
        return urllib.request.urlopen(request)

    def request(
        self,
        path: str,
        *,
        method: str = "GET",
        headers: HeaderInput | None = None,
        body: bytes | str | None = None,
    ) -> Any:
        namespace_base = get_namespace_api_base(self._api_base_url, self._identity.namespace)
        url = _resolve_url(path, namespace_base)
        return self.fetch(url=url, method=method, headers=headers, body=body)


def certify(
    agent: Any,
    *,
    namespace: str | None = None,
    home_dir: str | None = None,
    api_base_url: str | None = None,
    fetcher: Fetcher | None = None,
):
    if agent is None:
        raise ValueError("certify(agent): agent is required")

    if hasattr(agent, "sigilum"):
        return agent

    bindings = SigilumBindings(
        namespace=namespace,
        home_dir=home_dir,
        api_base_url=api_base_url,
        fetcher=fetcher,
    )

    setattr(agent, "sigilum", bindings)
    return agent
