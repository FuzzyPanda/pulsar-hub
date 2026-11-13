"""Structured logs: one JSON object per line in production, readable text in development.

Every record carries the request id, and the organisation and user when they are known, so one
request can be followed across the web and worker logs. Rule: nothing secret goes in a log line.
"""

import logging
from contextvars import ContextVar

from pythonjsonlogger.json import JsonFormatter as _BaseJsonFormatter

request_id_var: ContextVar[str] = ContextVar("hub_request_id", default="-")
user_ref_var: ContextVar[str] = ContextVar("hub_user_ref", default="")
org_ref_var: ContextVar[str] = ContextVar("hub_org_ref", default="")


class RequestContextFilter(logging.Filter):
    """Attach the request id, user and organisation to every record."""

    def filter(self, record: logging.LogRecord) -> bool:
        record.request_id = request_id_var.get()
        if user_ref := user_ref_var.get():
            record.user_ref = user_ref
        if org_ref := org_ref_var.get():
            record.org_ref = org_ref
        return True


class JsonFormatter(_BaseJsonFormatter):
    """JSON lines with UTC timestamps and stable key names."""

    def __init__(self, *args, **kwargs):
        kwargs.setdefault("rename_fields", {"asctime": "time", "levelname": "level", "name": "logger"})
        kwargs.setdefault("timestamp", False)
        super().__init__(*args, **kwargs)
        self.converter = __import__("time").gmtime
        self.datefmt = "%Y-%m-%dT%H:%M:%SZ"
