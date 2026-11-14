"""The conformance tool (`tools/console_conformance.py`) plays the hub for a gateway developer.
Run here against the fake gateway, so that the tool, the fake gateway and the contract cannot
drift apart: a gateway that follows the contract passes, and one that breaks it is caught."""

import argparse
import asyncio

from tests.relay.harness import async_test
from tools import console_conformance
from tools.fake_gateway import FakeGateway


def arguments(**overrides) -> argparse.Namespace:
    defaults = {
        "listen": "127.0.0.1:0",
        "credential": "hubgw_conformance_test_credential",
        "path": "/ui/echo",
        "large_path": "/ui/big?mb=2",
        "wait": 10,
        "slow": False,
        "check_revocation": True,
    }
    return argparse.Namespace(**{**defaults, **overrides})


async def run_against(gateway_options: dict, **overrides):
    args = arguments(**overrides)
    started = asyncio.Event()
    held = {}

    def listening(conformance):
        held["conformance"] = conformance
        started.set()

    checks = asyncio.create_task(console_conformance.main_async(args, on_listening=listening))
    await started.wait()
    ignore_window = gateway_options.pop("ignore_window", False)
    gateway = FakeGateway(f"http://{args.listen}", args.credential, **gateway_options)
    gateway.ignore_window = ignore_window
    runner = asyncio.create_task(gateway.run_forever())
    try:
        code = await asyncio.wait_for(checks, 55)
    finally:
        runner.cancel()
        await asyncio.gather(runner, return_exceptions=True)
        await gateway.stop()
    return code, {name: outcome for outcome, name, _ in held["conformance"].results}


@async_test
async def test_a_gateway_that_follows_the_contract_passes_every_check(capsys=None):
    code, results = await run_against({})
    failed = [name for name, outcome in results.items() if outcome == "FAIL"]
    assert code == 0 and not failed, failed
    assert sum(1 for outcome in results.values() if outcome == "PASS") >= 22
    for name in (
        "session.start is acknowledged within 5 seconds",
        "a request for a session the gateway was not told about is refused",
        "response flow control: the gateway stops at the window when no credit comes back",
        "after session.end a request for that session is refused",
        "after the hub drops the tunnel (1001) the gateway reconnects with back-off",
        "after 4003 (revoked) the gateway does not open another tunnel",
    ):
        assert results[name] == "PASS", name


@async_test
async def test_a_gateway_with_the_console_switched_off_is_told_to_switch_it_on():
    code, results = await run_against({"console_enabled": False})
    assert code == 0
    assert results["console switched off: session.start is refused with reason disabled"] == "PASS"
    assert results["everything else"] == "SKIP"


@async_test
async def test_a_gateway_that_ignores_flow_control_fails():
    code, results = await run_against({"ignore_window": True}, check_revocation=False)
    assert code == 1
    assert results["response flow control: the gateway stops at the window when no credit comes back"] == "FAIL"


@async_test
async def test_a_gateway_with_the_wrong_credential_never_gets_a_tunnel():
    args = arguments(wait=1.5)
    started = asyncio.Event()
    held = {}
    checks = asyncio.create_task(
        console_conformance.main_async(args, on_listening=lambda c: (held.update(c=c), started.set()))
    )
    await started.wait()
    gateway = FakeGateway(f"http://{args.listen}", "hubgw_someone_elses")
    runner = asyncio.create_task(gateway.run_forever())
    code = await asyncio.wait_for(checks, 20)
    await asyncio.gather(runner, return_exceptions=True)  # a 401 stops the fake gateway for good, as the contract says
    await gateway.stop()
    assert code == 1 and held["c"].results[0][0] == "FAIL" and "401" in held["c"].results[0][2]
