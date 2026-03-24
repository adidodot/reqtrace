"""
Tests untuk reqtrace v0.3.0
Jalankan dengan: pytest tests/ -v
"""

import json
import os
import pytest

from reqtrace import ReqTrace
from reqtrace.config import ReqTraceConfig
from reqtrace.differ import compute_diff, SnapshotStore
from reqtrace.filter import ReqTraceFilter
from reqtrace.formatter import format_log, format_diff
from reqtrace.writer import write_log, write_diff


# ---------------------------------------------------------------
# Config
# ---------------------------------------------------------------


class TestReqTraceConfig:

    def test_default_output_is_terminal(self):
        cfg = ReqTraceConfig()
        assert cfg.output == "terminal"
        assert cfg.use_terminal is True
        assert cfg.use_file is False

    def test_file_output_requires_file_path(self):
        with pytest.raises(ValueError, match="file_path"):
            ReqTraceConfig(output="file")

    def test_both_output_requires_file_path(self):
        with pytest.raises(ValueError, match="file_path"):
            ReqTraceConfig(output="both")

    def test_valid_file_config(self):
        cfg = ReqTraceConfig(output="file", file_path="logs/trace.json")
        assert cfg.use_file is True
        assert cfg.use_terminal is False

    def test_valid_both_config(self):
        cfg = ReqTraceConfig(output="both", file_path="logs/trace.json")
        assert cfg.use_file is True
        assert cfg.use_terminal is True

    def test_invalid_output_mode(self):
        with pytest.raises(ValueError, match="Invalid output mode"):
            ReqTraceConfig(output="stdout")  # type: ignore

    def test_invalid_file_format(self):
        with pytest.raises(ValueError, match="Invalid file_format"):
            ReqTraceConfig(output="file", file_path="log.xml", file_format="xml")  # type: ignore

    def test_enabled_defaults_to_true(self):
        assert ReqTraceConfig().enabled is True

    def test_disabled_config(self):
        assert ReqTraceConfig(enabled=False).enabled is False

    def test_diff_defaults_to_false(self):
        assert ReqTraceConfig().diff is False

    def test_diff_enabled(self):
        assert ReqTraceConfig(diff=True).diff is True

    def test_clear_key_defaults_to_c(self):
        assert ReqTraceConfig().clear_key == "c"

    def test_clear_key_custom(self):
        assert ReqTraceConfig(clear_key="r").clear_key == "r"

    def test_clear_key_disabled(self):
        assert ReqTraceConfig(clear_key=None).clear_key is None

    def test_filters_defaults_to_none(self):
        assert ReqTraceConfig().filters is None

    def test_filters_with_reqtracefilter(self):
        f = ReqTraceFilter(mode="blacklist", routes=["/docs"])
        cfg = ReqTraceConfig(filters=f)
        assert cfg.filters is not None
        assert cfg.filters.mode == "blacklist"


# ---------------------------------------------------------------
# ReqTrace (public API)
# ---------------------------------------------------------------


class TestReqTrace:

    def test_creates_config(self):
        rt = ReqTrace(output="terminal")
        assert isinstance(rt.config, ReqTraceConfig)

    def test_file_mode(self):
        rt = ReqTrace(output="file", file_path="logs/test.json")
        assert rt.config.use_file is True
        assert rt.config.file_path == "logs/test.json"

    def test_both_mode(self):
        rt = ReqTrace(output="both", file_path="logs/test.txt", file_format="txt")
        assert rt.config.use_terminal is True
        assert rt.config.use_file is True
        assert rt.config.file_format == "txt"

    def test_diff_mode(self):
        rt = ReqTrace(output="terminal", diff=True)
        assert rt.config.diff is True

    def test_clear_key_none(self):
        rt = ReqTrace(output="terminal", clear_key=None)
        assert rt.config.clear_key is None

    def test_with_filter(self):
        rt = ReqTrace(
            output="terminal",
            filters=ReqTraceFilter(mode="whitelist", status_codes=["4xx", "5xx"]),
        )
        assert rt.config.filters is not None


# ---------------------------------------------------------------
# Formatter
# ---------------------------------------------------------------


class TestFormatter:

    def test_format_log_returns_string(self):
        result = format_log(
            method="GET", url="/users", status_code=200, latency_ms=12.5
        )
        assert isinstance(result, str)
        assert "GET" in result and "/users" in result and "200" in result

    def test_format_log_with_body(self):
        result = format_log(
            method="POST",
            url="/users",
            status_code=201,
            latency_ms=35.0,
            request_body={"name": "Diz", "email": "diz@mail.com"},
            response_body={"id": 3, "name": "Diz"},
        )
        assert "POST" in result and "201" in result and "Diz" in result

    def test_format_log_500(self):
        result = format_log(method="GET", url="/crash", status_code=500, latency_ms=5.0)
        assert "500" in result

    def test_format_log_with_auth_header_masked(self):
        result = format_log(
            method="GET",
            url="/users",
            status_code=200,
            latency_ms=5.0,
            request_headers={"authorization": "Bearer supersecrettoken123456"},
        )
        assert "supersecrettoken123456" not in result
        assert "Bearer" in result

    def test_format_diff_with_changes(self):
        old = {"data": [{"id": 1, "name": "Alice"}]}
        new = {"data": [{"id": 1, "name": "Alice Updated"}]}
        result = format_diff(compute_diff("GET", "/users", old, new))
        assert "DIFF" in result and "data[0].name" in result

    def test_format_diff_no_changes(self):
        body = {"status": "ok"}
        result = format_diff(compute_diff("GET", "/users", body, body))
        assert "No changes" in result


# ---------------------------------------------------------------
# Differ
# ---------------------------------------------------------------


class TestDiffer:

    def test_no_changes(self):
        body = {"status": "ok", "data": [{"id": 1}]}
        diff = compute_diff("GET", "/users", body, body)
        assert not diff.has_changes
        assert len(diff.entries) == 0

    def test_field_changed(self):
        old = {"data": [{"id": 1, "name": "Alice"}]}
        new = {"data": [{"id": 1, "name": "Alice Updated"}]}
        diff = compute_diff("GET", "/users", old, new)
        assert diff.has_changes
        assert len(diff.changed) == 1
        assert diff.changed[0].path == "data[0].name"
        assert diff.changed[0].old_value == "Alice"
        assert diff.changed[0].new_value == "Alice Updated"

    def test_field_added(self):
        old = {"data": [{"id": 1}]}
        new = {"data": [{"id": 1}, {"id": 2}]}
        diff = compute_diff("GET", "/users", old, new)
        assert len(diff.added) == 1
        assert diff.added[0].path == "data[1]"

    def test_field_removed(self):
        old = {"data": [{"id": 1}, {"id": 2}]}
        new = {"data": [{"id": 1}]}
        diff = compute_diff("GET", "/users", old, new)
        assert len(diff.removed) == 1
        assert diff.removed[0].path == "data[1]"

    def test_type_changed(self):
        diff = compute_diff("GET", "/count", {"count": "42"}, {"count": 42})
        assert diff.has_changes
        assert diff.changed[0].path == "count"

    def test_diff_result_properties(self):
        old = {"a": 1, "b": "old"}
        new = {"a": 1, "b": "new", "c": 3}
        diff = compute_diff("GET", "/test", old, new)
        assert len(diff.changed) == 1
        assert len(diff.added) == 1
        assert len(diff.removed) == 0


class TestSnapshotStore:

    def test_initially_empty(self):
        store = SnapshotStore()
        assert not store.has("GET", "/users")

    def test_set_and_get(self):
        store = SnapshotStore()
        body = {"data": [1, 2, 3]}
        store.set("GET", "/users", body)
        assert store.has("GET", "/users")
        assert store.get("GET", "/users") == body

    def test_overwrite(self):
        store = SnapshotStore()
        store.set("GET", "/users", {"v": 1})
        store.set("GET", "/users", {"v": 2})
        assert store.get("GET", "/users") == {"v": 2}

    def test_different_endpoints_isolated(self):
        store = SnapshotStore()
        store.set("GET", "/users", {"a": 1})
        store.set("POST", "/users", {"b": 2})
        assert store.get("GET", "/users") == {"a": 1}
        assert store.get("POST", "/users") == {"b": 2}

    def test_clear(self):
        store = SnapshotStore()
        store.set("GET", "/users", {"a": 1})
        store.clear()
        assert not store.has("GET", "/users")


# ---------------------------------------------------------------
# Filter
# ---------------------------------------------------------------


class TestReqTraceFilter:

    # --- validation ---

    def test_valid_config(self):
        f = ReqTraceFilter(
            mode="whitelist",
            routes=["/users"],
            methods=["GET"],
            status_codes=[404, "5xx"],
        )
        assert f.mode == "whitelist"

    def test_invalid_mode(self):
        with pytest.raises(ValueError, match="Invalid filter mode"):
            ReqTraceFilter(mode="invalid")  # type: ignore

    def test_invalid_status_string(self):
        with pytest.raises(ValueError, match="Invalid status_code filter"):
            ReqTraceFilter(status_codes=["abc"])

    def test_invalid_status_int_too_low(self):
        with pytest.raises(ValueError, match="Invalid status_code"):
            ReqTraceFilter(status_codes=[99])

    def test_invalid_status_int_too_high(self):
        with pytest.raises(ValueError, match="Invalid status_code"):
            ReqTraceFilter(status_codes=[600])

    def test_methods_normalized_to_uppercase(self):
        f = ReqTraceFilter(methods=["get", "post"])
        assert "GET" in f.methods and "POST" in f.methods

    # --- whitelist ---

    def test_whitelist_status_range(self):
        f = ReqTraceFilter(mode="whitelist", status_codes=["4xx", "5xx"])
        assert f.should_log("GET", "/users", 404)
        assert f.should_log("GET", "/users", 500)
        assert not f.should_log("GET", "/users", 200)
        assert not f.should_log("POST", "/users", 201)

    def test_whitelist_specific_status(self):
        f = ReqTraceFilter(mode="whitelist", status_codes=[404])
        assert f.should_log("GET", "/users", 404)
        assert not f.should_log("GET", "/users", 400)

    def test_whitelist_methods(self):
        f = ReqTraceFilter(mode="whitelist", methods=["POST", "PUT", "DELETE"])
        assert f.should_log("POST", "/users", 201)
        assert f.should_log("DELETE", "/users/1", 200)
        assert not f.should_log("GET", "/users", 200)

    def test_whitelist_routes_exact(self):
        f = ReqTraceFilter(mode="whitelist", routes=["/users"])
        assert f.should_log("GET", "/users", 200)
        assert not f.should_log("GET", "/products", 200)

    def test_whitelist_routes_prefix(self):
        f = ReqTraceFilter(mode="whitelist", routes=["/api"])
        assert f.should_log("GET", "/api/users", 200)
        assert f.should_log("GET", "/api/products", 200)
        assert not f.should_log("GET", "/users", 200)

    def test_whitelist_mixed_status(self):
        f = ReqTraceFilter(mode="whitelist", status_codes=[404, "5xx"])
        assert f.should_log("GET", "/users", 404)
        assert f.should_log("GET", "/users", 503)
        assert not f.should_log("GET", "/users", 200)
        assert not f.should_log("GET", "/users", 400)

    # --- blacklist ---

    def test_blacklist_routes(self):
        f = ReqTraceFilter(
            mode="blacklist", routes=["/docs", "/redoc", "/openapi.json"]
        )
        assert f.should_log("GET", "/users", 200)
        assert not f.should_log("GET", "/docs", 200)
        assert not f.should_log("GET", "/redoc", 200)

    def test_blacklist_specific_status(self):
        f = ReqTraceFilter(mode="blacklist", status_codes=[200])
        assert not f.should_log("GET", "/users", 200)
        assert f.should_log("GET", "/users", 404)
        assert f.should_log("POST", "/users", 201)

    def test_blacklist_methods_and_status(self):
        f = ReqTraceFilter(mode="blacklist", methods=["GET"], status_codes=[200])
        assert not f.should_log("GET", "/users", 404)  # GET diblacklist
        assert not f.should_log("POST", "/users", 200)  # 200 diblacklist
        assert f.should_log("POST", "/users", 201)  # tidak cocok filter apapun

    def test_blacklist_status_range(self):
        f = ReqTraceFilter(mode="blacklist", status_codes=["2xx"])
        assert not f.should_log("GET", "/users", 200)
        assert not f.should_log("POST", "/users", 201)
        assert f.should_log("GET", "/users", 404)

    # --- edge cases ---

    def test_empty_filter_logs_everything(self):
        f = ReqTraceFilter(mode="blacklist")
        assert f.should_log("GET", "/anything", 200)
        assert f.should_log("DELETE", "/users/1", 500)

    def test_empty_whitelist_logs_nothing(self):
        # whitelist kosong: tidak ada kondisi yang terpenuhi → tidak log apapun
        f = ReqTraceFilter(mode="whitelist")
        assert not f.should_log("GET", "/users", 200)


# ---------------------------------------------------------------
# Writer
# ---------------------------------------------------------------


class TestWriter:

    def test_write_log_json(self, tmp_path):
        path = str(tmp_path / "trace.json")
        write_log(path, "json", "GET", "/users", 200, 12.5, response_body={"data": []})
        with open(path) as f:
            rec = json.loads(f.readline())
        assert rec["method"] == "GET"
        assert rec["status_code"] == 200
        assert rec["url"] == "/users"

    def test_write_log_txt(self, tmp_path):
        path = str(tmp_path / "trace.txt")
        write_log(
            path, "txt", "POST", "/users", 201, 30.0, request_body={"name": "Diz"}
        )
        content = open(path).read()
        assert "POST" in content and "201" in content

    def test_write_log_appends(self, tmp_path):
        path = str(tmp_path / "trace.json")
        write_log(path, "json", "GET", "/users", 200, 10.0)
        write_log(path, "json", "POST", "/users", 201, 20.0)
        lines = open(path).readlines()
        assert len(lines) == 2

    def test_write_diff_json(self, tmp_path):
        path = str(tmp_path / "diff.json")
        old = {"data": [{"id": 1, "name": "Alice"}]}
        new = {"data": [{"id": 1, "name": "Alice Updated"}]}
        diff = compute_diff("GET", "/users", old, new)
        write_diff(path, "json", diff)
        with open(path) as f:
            rec = json.loads(f.readline())
        assert rec["type"] == "diff"
        assert rec["has_changes"] is True
        assert len(rec["changes"]["changed"]) == 1

    def test_write_diff_txt(self, tmp_path):
        path = str(tmp_path / "diff.txt")
        old = {"data": [{"id": 1}]}
        new = {"data": [{"id": 1}, {"id": 2}]}
        diff = compute_diff("GET", "/users", old, new)
        write_diff(path, "txt", diff)
        content = open(path).read()
        assert "DIFF GET /users" in content

    def test_write_diff_no_changes_json(self, tmp_path):
        path = str(tmp_path / "diff.json")
        body = {"status": "ok"}
        diff = compute_diff("GET", "/ping", body, body)
        write_diff(path, "json", diff)
        with open(path) as f:
            rec = json.loads(f.readline())
        assert rec["has_changes"] is False

    def test_write_log_creates_directory(self, tmp_path):
        path = str(tmp_path / "nested" / "dir" / "trace.json")
        write_log(path, "json", "GET", "/test", 200, 5.0)
        assert os.path.exists(path)
