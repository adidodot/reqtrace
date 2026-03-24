from dataclasses import dataclass
from typing import Literal, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from .filter import ReqTraceFilter

OutputMode = Literal["terminal", "file", "both"]
FileFormat = Literal["json", "txt"]


@dataclass
class ReqTraceConfig:
    """
    Configuration for reqtrace.

    Parameters
    ----------
    output : OutputMode
        Where to send the log output.
        - "terminal" : print colorized output to stdout (default)
        - "file"     : write to a file (requires file_path)
        - "both"     : terminal + file simultaneously

    file_path : str, optional
        Path to the output log file.
        Required when output is "file" or "both".
        Example: "logs/trace.json"

    file_format : FileFormat
        Format of the log file. Either "json" or "txt".
        Defaults to "json". Ignored when output is "terminal".

    enabled : bool
        Master switch. Set to False to disable all logging
        without removing the middleware. Useful for production.
        Defaults to True.

    diff : bool
        Auto-diff mode. When True, reqtrace automatically compares
        each response against the previous response for the same
        endpoint and displays the differences.
        Defaults to False.

    clear_key : str, optional
        Keyboard shortcut to clear the terminal while the server
        is running. Example: "c". Set to None to disable.
        Defaults to "c".

    filters : ReqTraceFilter, optional
        Filter configuration. Control which requests are logged
        based on route, method, and status code.
        Defaults to None (log everything).
    """

    output: OutputMode = "terminal"
    file_path: Optional[str] = None
    file_format: FileFormat = "json"
    enabled: bool = True
    diff: bool = False
    clear_key: Optional[str] = "c"
    filters: Optional["ReqTraceFilter"] = None

    def __post_init__(self) -> None:
        self._validate()

    def _validate(self) -> None:
        valid_outputs = ("terminal", "file", "both")
        if self.output not in valid_outputs:
            raise ValueError(
                f"Invalid output mode: '{self.output}'. "
                f"Must be one of: {valid_outputs}"
            )

        valid_formats = ("json", "txt")
        if self.file_format not in valid_formats:
            raise ValueError(
                f"Invalid file_format: '{self.file_format}'. "
                f"Must be one of: {valid_formats}"
            )

        if self.output in ("file", "both") and not self.file_path:
            raise ValueError(
                f"output='{self.output}' requires file_path to be set. "
                "Example: ReqTrace(output='file', file_path='logs/trace.json')"
            )

    @property
    def use_terminal(self) -> bool:
        return self.output in ("terminal", "both")

    @property
    def use_file(self) -> bool:
        return self.output in ("file", "both")
