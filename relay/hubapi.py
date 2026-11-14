"""The relay's calls to the hub's web service: the internal channel.

Docker network only, never routed by Caddy, and every call carries the shared secret. The web
service decides everything (`hub/console/services.py`); this file only carries the question and
the answer. A call that cannot be made raises `HubUnavailable`, and every caller treats that as
"no": the relay fails closed.
"""

import logging

import aiohttp

logger = logging.getLogger("relay.hubapi")


class HubUnavailable(Exception):
    """The web service could not be asked."""


class HubApi:
    def __init__(self, config, session: aiohttp.ClientSession):
        self._config = config
        self._session = session

    async def call(self, name: str, payload: dict, *, timeout: float = 5.0) -> tuple[int, dict]:
        """POST one question. Returns (status, body). Never logs the payload: it may hold a secret."""
        url = f"{self._config.hub_url}/internal/relay/{name}"
        headers = {"Authorization": f"Bearer {self._config.internal_secret}", "Host": self._config.hub_host}
        try:
            async with self._session.post(
                url, json=payload, headers=headers, timeout=aiohttp.ClientTimeout(total=timeout), allow_redirects=False
            ) as response:
                try:
                    body = await response.json(content_type=None)
                except ValueError:
                    body = {}
                if response.status >= 500 or response.status in (301, 302, 404):
                    # 404 is what the hub answers when the secret is wrong or the feature is off.
                    raise HubUnavailable(f"{name}: the hub answered {response.status}")
                return response.status, body if isinstance(body, dict) else {}
        except (TimeoutError, aiohttp.ClientError) as exc:
            raise HubUnavailable(f"{name}: {type(exc).__name__}") from exc

    async def started(self, instance: str) -> None:
        await self.call("started", {"instance": instance})

    async def authorize_tunnel(self, credential: str) -> dict | None:
        """The gateway that holds `credential`, or None when the hub does not accept it."""
        status, body = await self.call("tunnel/authorize", {"credential": credential})
        return body if status == 200 else None

    async def tunnel_refused(self, gateway_id: str, offered: str) -> None:
        await self.call("tunnel/refused", {"gateway_id": gateway_id, "offered": offered[:200]})

    async def tunnel_opened(
        self, instance: str, gateway_id: str, *, protocol: str, software_version: str, enabled: bool
    ):
        status, _ = await self.call(
            "tunnel/opened",
            {
                "instance": instance,
                "gateway_id": gateway_id,
                "protocol": protocol,
                "software_version": software_version[:64],
                "console_enabled": enabled,
            },
        )
        return status == 200

    async def redeem_handoff(self, token: str, origin: str) -> dict | None:
        status, body = await self.call("handoff/redeem", {"token": token, "origin": origin})
        return body if status == 200 else None

    async def event(self, payload: dict) -> None:
        await self.call("event", payload)

    async def heartbeat(self, instance: str, gateways: list[dict], sessions: list[str]) -> dict:
        status, body = await self.call("heartbeat", {"instance": instance, "gateways": gateways, "sessions": sessions})
        if status != 200:
            raise HubUnavailable(f"heartbeat: the hub answered {status}")
        return body
