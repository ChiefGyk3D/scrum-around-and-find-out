# SPDX-License-Identifier: Apache-2.0
"""The real transport to the vendor (docs/gemini-broker.md, "The transport to the vendor").

The destination is a constant, not a setting: a test builds the transport with a loopback endpoint through the
constructor, never through the config file. TLS verification stays on with the system store, no proxy variable is
read, the connection goes to a checked address (`netguard`), a redirect is never followed (a 3xx comes back as a
status and the pipeline makes the call ambiguous), every answer is size-capped, and the key goes in the
`x-goog-api-key` header only. The key is read for each request, from `key`, and is never formatted into a string.
One request, no retry: a failure after the request left is `TransportError`, a missed deadline `TransportTimeout`.
"""

from __future__ import annotations

import http.client
from collections.abc import Callable
from typing import Any

from safo.broker.vendor import RawReply, TransportError, TransportTimeout, VendorRequest
from safo.netguard import PinnedHTTPSConnection

VENDOR_HOST = "generativelanguage.googleapis.com"
VENDOR_PORT = 443

Factory = Callable[..., http.client.HTTPConnection]


class HttpsTransport:
    def __init__(
        self,
        key: Callable[[], str],
        *,
        host: str = VENDOR_HOST,
        port: int = VENDOR_PORT,
        factory: Factory = PinnedHTTPSConnection,
    ) -> None:
        self._key = key
        self._host = host
        self._port = port
        self._factory = factory

    def send(self, request: VendorRequest) -> RawReply:
        headers = {
            "x-goog-api-key": self._key(),
            "content-type": "application/json",
            "accept": "application/json",
            "connection": "close",
        }
        conn: Any = self._factory(self._host, self._port, timeout=request.timeout_seconds)
        try:
            conn.request("POST", request.path, body=request.body, headers=headers)
            reply = conn.getresponse()
            body = reply.read(request.max_reply_bytes + 1)
            return RawReply(reply.status, {k.lower(): v for k, v in reply.getheaders()}, body)
        except TimeoutError:
            raise TransportTimeout("deadline") from None
        except Exception:  # a reset, a short body, a TLS failure: the request may have left; nothing is quoted
            raise TransportError("connection") from None
        finally:
            conn.close()
