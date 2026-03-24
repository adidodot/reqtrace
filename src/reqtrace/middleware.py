import json
import os
import select
import sys
import time
import threading
from typing import Any

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response
from starlette.types import ASGIApp

from .config import ReqTraceConfig
from .differ import SnapshotStore, compute_diff
from .formatter import format_log, format_diff
from .writer import write_log, write_diff


class ReqTraceMiddleware(BaseHTTPMiddleware):
    """
    FastAPI / Starlette middleware that logs every incoming
    request and its response.

    Usage
    -----
    rt = ReqTrace(output="both", file_path="logs/trace.json")
    app.add_middleware(ReqTraceMiddleware, config=rt.config)
    """

    def __init__(self, app: ASGIApp, config: ReqTraceConfig) -> None:
        super().__init__(app)
        self.config = config
        self._snapshots = SnapshotStore()

        if config.clear_key and config.use_terminal:
            self._start_clear_listener(config.clear_key)

    async def dispatch(self, request: Request, call_next) -> Response:  # type: ignore[override]
        if not self.config.enabled:
            return await call_next(request)

        request_body = await self._read_request_body(request)

        start = time.perf_counter()
        response = await call_next(request)
        latency_ms = (time.perf_counter() - start) * 1000

        response_body, response = await self._read_response_body(response)

        method: str = request.method
        url: str = str(request.url.path)
        status_code: int = response.status_code

        # --- cek filter sebelum log ---
        if self.config.filters is not None:
            if not self.config.filters.should_log(method, url, status_code):
                return response

        if self.config.use_terminal:
            print(
                format_log(
                    method=method,
                    url=url,
                    status_code=status_code,
                    latency_ms=latency_ms,
                    request_headers=dict(request.headers),
                    request_body=request_body,
                    response_body=response_body,
                )
            )

        if self.config.use_file and self.config.file_path is not None:
            write_log(
                file_path=self.config.file_path,
                file_format=self.config.file_format,
                method=method,
                url=url,
                status_code=status_code,
                latency_ms=latency_ms,
                request_headers=dict(request.headers),
                request_body=request_body,
                response_body=response_body,
            )

        if self.config.diff and response_body is not None:
            if self._snapshots.has(method, url):
                old_body = self._snapshots.get(method, url)
                diff_result = compute_diff(method, url, old_body, response_body)

                if self.config.use_terminal:
                    print(format_diff(diff_result))

                if self.config.use_file and self.config.file_path is not None:
                    write_diff(
                        file_path=self.config.file_path,
                        file_format=self.config.file_format,
                        diff_result=diff_result,
                    )

            self._snapshots.set(method, url, response_body)

        return response

    # ------------------------------------------------------------------
    # clear terminal listener
    # ------------------------------------------------------------------

    def _start_clear_listener(self, key: str) -> None:
        """
        Jalankan background thread yang listen input keyboard.
        Menggunakan polling non-blocking agar CTRL+C tetap berfungsi.
        """

        def _listen() -> None:
            while True:
                try:
                    if _key_available():
                        char = _read_single_char_nonblock()
                        if char and char.lower() == key.lower():
                            _clear_terminal()
                    else:
                        time.sleep(0.1)
                except Exception:
                    break

        thread = threading.Thread(target=_listen, daemon=True)
        thread.start()

    # ------------------------------------------------------------------
    # helpers
    # ------------------------------------------------------------------

    async def _read_request_body(self, request: Request) -> Any:
        raw: bytes = b""
        try:
            raw = await request.body()
            if not raw:
                return None
            request._body = raw  # type: ignore[attr-defined]
            return json.loads(raw)
        except Exception:
            return raw.decode("utf-8", errors="replace") if raw else None

    async def _read_response_body(self, response: Response) -> tuple[Any, Response]:
        body_chunks: list[bytes] = []
        async for chunk in response.body_iterator:  # type: ignore[attr-defined]
            body_chunks.append(chunk if isinstance(chunk, bytes) else chunk.encode())

        raw = b"".join(body_chunks)

        parsed: Any = None
        try:
            parsed = json.loads(raw)
        except Exception:
            parsed = raw.decode("utf-8", errors="replace") if raw else None

        new_response = Response(
            content=raw,
            status_code=response.status_code,
            headers=dict(response.headers),
            media_type=response.media_type,
        )

        return parsed, new_response


# ------------------------------------------------------------------
# Terminal utilities
# ------------------------------------------------------------------


def _clear_terminal() -> None:
    if sys.platform == "win32":
        os.system("cls")
    else:
        os.system("clear")


def _key_available() -> bool:
    if sys.platform == "win32":
        import msvcrt

        return bool(msvcrt.kbhit())
    else:
        readable, _, _ = select.select([sys.stdin], [], [], 0)
        return bool(readable)


def _read_single_char_nonblock() -> str:
    if sys.platform == "win32":
        import msvcrt

        return msvcrt.getwch()
    else:
        return sys.stdin.read(1)
