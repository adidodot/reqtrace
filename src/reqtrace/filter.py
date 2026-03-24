"""
filter.py
---------
Filter logic untuk reqtrace.

Mendukung whitelist dan blacklist berdasarkan:
- route   : string exact match atau prefix, e.g. "/users" atau "/api"
- method  : HTTP method, e.g. "GET", "POST"
- status_codes : angka spesifik (404) atau range ("4xx", "5xx")
"""

from dataclasses import dataclass, field
from typing import Literal, Union


FilterMode = Literal["whitelist", "blacklist"]
StatusCodeFilter = Union[int, str]  # e.g. 404 atau "4xx"


@dataclass
class ReqTraceFilter:
    """
    Konfigurasi filter untuk reqtrace.

    Parameters
    ----------
    mode : "whitelist" | "blacklist"
        - "whitelist" : hanya log request yang cocok dengan filter
        - "blacklist" : log semua kecuali yang cocok dengan filter

    routes : list[str], optional
        Daftar route yang difilter. Mendukung exact match ("/users")
        dan prefix match ("/api" akan cocok dengan "/api/users", "/api/products").

    methods : list[str], optional
        Daftar HTTP method yang difilter. Case-insensitive.
        Contoh: ["GET", "POST"]

    status_codes : list[int | str], optional
        Daftar status code yang difilter.
        Bisa angka spesifik (404) atau range ("4xx", "5xx").
        Contoh: [404, "5xx"] — cocok dengan 404 dan semua 5xx
    """

    mode: FilterMode = "blacklist"
    routes: list[str] = field(default_factory=list)
    methods: list[str] = field(default_factory=list)
    status_codes: list[StatusCodeFilter] = field(default_factory=list)

    def __post_init__(self) -> None:
        self._validate()
        # normalisasi methods ke uppercase
        self.methods = [m.upper() for m in self.methods]

    def _validate(self) -> None:
        if self.mode not in ("whitelist", "blacklist"):
            raise ValueError(
                f"Invalid filter mode: '{self.mode}'. "
                "Must be 'whitelist' or 'blacklist'."
            )

        for sc in self.status_codes:
            if isinstance(sc, str):
                if not (len(sc) == 3 and sc[1:] == "xx" and sc[0].isdigit()):
                    raise ValueError(
                        f"Invalid status_code filter: '{sc}'. "
                        "String format must be like '4xx', '5xx'."
                    )
            elif isinstance(sc, int):
                if not (100 <= sc <= 599):
                    raise ValueError(
                        f"Invalid status_code: {sc}. Must be between 100 and 599."
                    )
            else:
                raise ValueError(
                    f"status_codes must be int or str, got {type(sc).__name__}."
                )

    def should_log(self, method: str, route: str, status_code: int) -> bool:
        """
        Tentukan apakah request ini harus di-log berdasarkan filter.

        Returns True jika harus di-log, False jika harus di-skip.

        Perilaku filter kosong:
        - blacklist kosong : log semua (tidak ada yang diblokir)
        - whitelist kosong : tidak log apapun (tidak ada yang diizinkan)
        """
        is_empty = not self.routes and not self.methods and not self.status_codes

        if is_empty:
            # blacklist kosong = log semua, whitelist kosong = tidak log apapun
            return self.mode == "blacklist"

        matched = self._matches(method, route, status_code)

        if self.mode == "whitelist":
            return matched
        else:  # blacklist
            return not matched

    def _matches(self, method: str, route: str, status_code: int) -> bool:
        """
        Cek apakah request cocok dengan salah satu kondisi filter.
        Kondisi yang tidak diisi dianggap tidak ikut difilter.
        """
        if self.routes and self._match_route(route):
            return True
        if self.methods and method.upper() in self.methods:
            return True
        if self.status_codes and self._match_status(status_code):
            return True
        return False

    def _match_route(self, route: str) -> bool:
        """Exact match atau prefix match."""
        for pattern in self.routes:
            if route == pattern or route.startswith(pattern.rstrip("/") + "/"):
                return True
        return False

    def _match_status(self, status_code: int) -> bool:
        """Cocokkan status code dengan angka spesifik atau range (4xx, 5xx)."""
        for sc in self.status_codes:
            if isinstance(sc, int) and status_code == sc:
                return True
            if isinstance(sc, str):
                # "4xx" → cocok dengan 400-499
                prefix = int(sc[0])
                if prefix * 100 <= status_code <= prefix * 100 + 99:
                    return True
        return False
