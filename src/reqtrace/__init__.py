"""
reqtrace
--------
Lightweight HTTP request/response logger for FastAPI.

Quickstart
----------
from fastapi import FastAPI
from reqtrace import ReqTrace
from reqtrace.middleware import ReqTraceMiddleware

rt = ReqTrace(output="terminal")

app = FastAPI()
app.add_middleware(ReqTraceMiddleware, config=rt.config)
"""

from .config import ReqTraceConfig, OutputMode, FileFormat
from .differ import DiffResult, SnapshotStore, compute_diff
from .filter import ReqTraceFilter
from .middleware import ReqTraceMiddleware

__all__ = [
    "ReqTrace",
    "ReqTraceMiddleware",
    "ReqTraceConfig",
    "ReqTraceFilter",
    "DiffResult",
    "SnapshotStore",
    "compute_diff",
]

__version__ = "0.3.0"


class ReqTrace:
    """
    Main entry point for reqtrace configuration.

    Parameters
    ----------
    output : "terminal" | "file" | "both"
        Where to send log output.
    file_path : str, optional
        Required when output is "file" or "both".
    file_format : "json" | "txt"
        Log file format. Defaults to "json".
    enabled : bool
        Master on/off switch. Defaults to True.
    diff : bool
        Auto-diff mode. Defaults to False.
    clear_key : str, optional
        Terminal clear shortcut. Defaults to "c". None to disable.
    filters : ReqTraceFilter, optional
        Filter which requests are logged. Defaults to None (log all).

    Examples
    --------
    # Terminal only
    rt = ReqTrace(output="terminal")

    # Blacklist — sembunyikan /docs dan semua GET 200
    rt = ReqTrace(
        output="terminal",
        filters=ReqTraceFilter(
            mode="blacklist",
            routes=["/docs", "/redoc", "/openapi.json"],
            methods=["GET"],
            status_codes=[200],
        )
    )

    # Whitelist — hanya log error
    rt = ReqTrace(
        output="terminal",
        filters=ReqTraceFilter(
            mode="whitelist",
            status_codes=["4xx", "5xx"],
        )
    )
    """

    def __init__(
        self,
        output: OutputMode = "terminal",
        file_path: str | None = None,
        file_format: FileFormat = "json",
        enabled: bool = True,
        diff: bool = False,
        clear_key: str | None = "c",
        filters: ReqTraceFilter | None = None,
    ) -> None:
        self.config = ReqTraceConfig(
            output=output,
            file_path=file_path,
            file_format=file_format,
            enabled=enabled,
            diff=diff,
            clear_key=clear_key,
            filters=filters,
        )
