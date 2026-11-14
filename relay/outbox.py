"""What the relay has to tell the hub's web service, bounded by construction.

There is no queue to fill. Each thing to report has one slot, keyed by what it is about: a
gateway's tunnel closing, a session ending, a gateway's switch changing. Reporting the same thing
again replaces what was waiting. So however fast one gateway talks, it holds at most a slot of
each kind (plus one per session the hub itself started on it), and it cannot delay or push out
what another organisation's gateway has to say.

A gateway's switch gets one more limit. The hub writes an audit event each time it hears of a
change, so the relay passes on at most `console_burst` changes per gateway per
`console_seconds`, then only the latest state once that time has passed. The relay itself always
acts on the switch at once (a session is refused or ended the moment it is off); only what the hub
is told is paced.
"""

import asyncio
import logging
import time
from collections import deque

from relay.hubapi import HubUnavailable

logger = logging.getLogger("relay.outbox")

ATTEMPTS = 6  # then the report is dropped; the next heartbeat reconciles


class Outbox:
    def __init__(
        self, hub, instance: str, *, console_burst: int = 3, console_seconds: float = 60.0, capacity: int = 8192
    ):
        self._hub = hub
        self._instance = instance
        self._console_burst = console_burst
        self._console_seconds = console_seconds
        self._capacity = capacity
        self._slots: dict[tuple[str, str], dict] = {}  # in the order first reported
        self._wanted: dict[str, bool] = {}  # gateway -> a switch state the hub has not been told yet
        self._told: dict[str, bool] = {}  # gateway -> the switch state the hub was last told
        self._told_at: dict[str, deque] = {}  # gateway -> when it was told of each recent change
        self._wake = asyncio.Event()
        self._warned_at = 0.0

    def __len__(self) -> int:
        return len(self._slots) + len(self._wanted)

    # --- reporting --------------------------------------------------------------------------------

    def _put(self, kind: str, key: str, **fields) -> None:
        slot = (kind, key)
        if slot not in self._slots and len(self._slots) >= self._capacity:
            self._warn("more reports waiting than the relay keeps; the next heartbeat will reconcile")
            return
        self._slots[slot] = {"event": kind, **fields}
        self._wake.set()

    def _warn(self, message: str) -> None:
        now = time.monotonic()
        if now - self._warned_at >= 60:  # one line a minute at most, whatever is happening
            self._warned_at = now
            logger.warning(message)

    def tunnel_closed(self, gateway_id: str, tunnel_id: str, reason: str) -> None:
        self._put("tunnel.closed", gateway_id, gateway_id=gateway_id, tunnel=tunnel_id, reason=reason)

    def session_ended(self, session_id: str, reason: str) -> None:
        self._put("session.ended", session_id, session=session_id, reason=reason)

    def _may_tell(self, gateway_id: str) -> bool:
        recent = self._told_at.setdefault(gateway_id, deque())
        cutoff = time.monotonic() - self._console_seconds
        while recent and recent[0] <= cutoff:
            recent.popleft()
        return len(recent) < self._console_burst

    def _note_told(self, gateway_id: str, enabled: bool) -> None:
        if self._told.get(gateway_id) != enabled:
            self._told_at.setdefault(gateway_id, deque()).append(time.monotonic())
        self._told[gateway_id] = enabled

    def state_at_open(self, gateway_id: str, enabled: bool) -> bool:
        """The switch state to give the hub with a new tunnel: the gateway's own, unless this
        gateway has changed it (or reconnected with it changed) too often lately, in which case
        the hub keeps what it has and hears the latest when the pace allows."""
        if self._told.get(gateway_id, enabled) != enabled and not self._may_tell(gateway_id):
            self._wanted[gateway_id] = enabled
            self._wake.set()
            return self._told[gateway_id]
        self._wanted.pop(gateway_id, None)
        self._note_told(gateway_id, enabled)
        return enabled

    def console_switched(self, gateway_id: str, enabled: bool) -> None:
        if self._told.get(gateway_id) == enabled:
            self._wanted.pop(gateway_id, None)  # back to what the hub already believes
        else:
            self._wanted[gateway_id] = enabled
        self._wake.set()

    def told_state(self, gateway_id: str, live: bool) -> bool:
        """What the hub believes this gateway's switch says (for the heartbeat, so that the
        heartbeat is not a second, unpaced way of reporting changes)."""
        return self._told.get(gateway_id, live)

    def forget(self, known_gateways) -> None:
        """Drop pacing records of gateways that have no tunnel and nothing recent."""
        for gateway_id in [g for g in self._told if g not in known_gateways and g not in self._wanted]:
            if self._may_tell(gateway_id) and not self._told_at.get(gateway_id):
                self._told.pop(gateway_id, None)
                self._told_at.pop(gateway_id, None)

    # --- sending ----------------------------------------------------------------------------------

    def _next(self) -> tuple[tuple[str, str], dict] | None:
        for gateway_id, enabled in self._wanted.items():
            if self._may_tell(gateway_id):
                return ("console.switched", gateway_id), {
                    "event": "console.switched",
                    "gateway_id": gateway_id,
                    "enabled": enabled,
                }
        for slot, payload in self._slots.items():
            return slot, payload
        return None

    def _seconds_until_due(self) -> float | None:
        waits = []
        for gateway_id in self._wanted:
            recent = self._told_at.get(gateway_id)
            if recent:
                waits.append(max(0.05, recent[0] + self._console_seconds - time.monotonic()))
        return min(waits) if waits else None

    def _delivered(self, slot: tuple[str, str], payload: dict) -> None:
        kind, key = slot
        if kind == "console.switched":
            self._note_told(key, payload["enabled"])
            if self._wanted.get(key) == payload["enabled"]:
                del self._wanted[key]
        elif self._slots.get(slot) is payload:  # not replaced by something newer while it was in flight
            del self._slots[slot]

    def _give_up(self, slot: tuple[str, str], payload: dict) -> None:
        kind, key = slot
        if kind == "console.switched":
            if self._wanted.get(key) == payload["enabled"]:
                del self._wanted[key]
        elif self._slots.get(slot) is payload:
            del self._slots[slot]

    async def run(self) -> None:
        failures = 0
        while True:
            item = self._next()
            if item is None:
                self._wake.clear()
                if self._next() is None:
                    try:
                        await asyncio.wait_for(self._wake.wait(), self._seconds_until_due())
                    except TimeoutError:
                        pass
                continue
            slot, payload = item
            try:
                await self._hub.event({"instance": self._instance, **payload})
            except HubUnavailable as exc:
                failures += 1
                self._warn(f"a report to the hub was not delivered ({exc}); retrying")
                if failures >= ATTEMPTS:
                    failures = 0
                    self._give_up(slot, payload)
                    continue
                await asyncio.sleep(min(2**failures, 15))
                continue
            failures = 0
            self._delivered(slot, payload)
