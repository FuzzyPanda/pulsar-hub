"""`python -m relay`: run the relay. Settings come from the environment (`relay/config.py`)."""

import asyncio
import json
import logging
import os
import signal
import sys
import time

import aiohttp
from aiohttp import web

from relay.config import ConfigError, RelayConfig
from relay.hubapi import HubApi
from relay.server import Relay


class _JsonLines(logging.Formatter):
    """One JSON object per line, like the web service's logs. Nothing secret is ever logged: no
    credential, no token, no cookie, no header and no address beyond a path-free event."""

    def format(self, record: logging.LogRecord) -> str:
        line = {
            "time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(record.created)),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            line["exception"] = self.formatException(record.exc_info)
        return json.dumps(line)


async def serve(config: RelayConfig) -> None:
    connector = aiohttp.TCPConnector(limit=20)
    async with aiohttp.ClientSession(connector=connector) as http:
        relay = Relay(config, HubApi(config, http))
        runners = []
        for app, port in (
            (relay.tunnel_app(), config.tunnel_port),
            (relay.console_app(), config.console_port),
            (relay.control_app(), config.control_port),
        ):
            # No access log: a console address can carry a secret (a reset link), and the hub
            # audits what matters. handler_cancellation lets a browser that goes away free its stream.
            runner = web.AppRunner(app, access_log=None, handler_cancellation=True)
            await runner.setup()
            await web.TCPSite(runner, "0.0.0.0", port).start()  # noqa: S104 - a container; Compose decides who can reach it
            runners.append(runner)
        await relay.start()
        stop = asyncio.Event()
        loop = asyncio.get_running_loop()
        for signame in (signal.SIGTERM, signal.SIGINT):
            loop.add_signal_handler(signame, stop.set)
        await stop.wait()
        await relay.stop()
        for runner in runners:
            await runner.cleanup()


async def serve_idle() -> None:
    """The remote console is not set up on this hub. Answer on all three ports so that Caddy and
    the health check have something to talk to, and refuse everything."""

    async def nothing(request: web.Request) -> web.Response:
        return web.json_response({"detail": "The remote console is not set up on this hub."}, status=404)

    async def health(request: web.Request) -> web.Response:
        return web.json_response({"status": "off"})

    runners = []
    for port in (8001, 8002, 8003):
        app = web.Application()
        if port == 8003:
            app.router.add_get("/control/health", health)
        app.router.add_route("*", "/{tail:.*}", nothing)
        runner = web.AppRunner(app, access_log=None)
        await runner.setup()
        await web.TCPSite(runner, "0.0.0.0", port).start()  # noqa: S104 - a container; Compose decides who can reach it
        runners.append(runner)
    stop = asyncio.Event()
    for signame in (signal.SIGTERM, signal.SIGINT):
        asyncio.get_running_loop().add_signal_handler(signame, stop.set)
    await stop.wait()
    for runner in runners:
        await runner.cleanup()


def main() -> int:
    handler = logging.StreamHandler()
    handler.setFormatter(_JsonLines())
    logging.basicConfig(level=os.environ.get("LOG_LEVEL", "info").upper(), handlers=[handler])
    logging.getLogger("aiohttp.access").disabled = True
    try:
        config = RelayConfig.from_env()
    except ConfigError as exc:
        logging.getLogger("relay").error("not starting: %s", exc)
        return 2
    if config is None:
        logging.getLogger("relay").info("CONSOLE_ORIGIN_TEMPLATE is not set: the remote console is off")
        asyncio.run(serve_idle())
        return 0
    asyncio.run(serve(config))
    return 0


if __name__ == "__main__":
    sys.exit(main())
