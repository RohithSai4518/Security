"""
Custom ANSI-colored console logger and audit trail recorder for PySecSuite.
"""

import sys
import os
import datetime
import threading
from typing import Optional

class LogLevel:
    DEBUG = 10
    INFO = 20
    SUCCESS = 25
    WARNING = 30
    ERROR = 40
    CRITICAL = 50

    @classmethod
    def from_string(cls, level_str: str) -> int:
        levels = {
            "DEBUG": cls.DEBUG,
            "INFO": cls.INFO,
            "SUCCESS": cls.SUCCESS,
            "WARNING": cls.WARNING,
            "ERROR": cls.ERROR,
            "CRITICAL": cls.CRITICAL,
        }
        return levels.get(level_str.upper(), cls.INFO)

class SecurityLogger:
    """Thread-safe security logger with color formatting and file audit logging."""
    
    # ANSI Color escape codes
    COLOR_RESET = "\033[0m"
    COLOR_GREY = "\033[90m"
    COLOR_BLUE = "\033[94m"
    COLOR_CYAN = "\033[96m"
    COLOR_GREEN = "\033[92m"
    COLOR_YELLOW = "\033[93m"
    COLOR_RED = "\033[91m"
    COLOR_BOLD_RED = "\033[1;91m"
    COLOR_MAGENTA = "\033[95m"

    def __init__(self, name: str = "PySecSuite", log_file: Optional[str] = "secsuite_audit.log", min_level: str = "INFO"):
        self.name = name
        self.min_level = LogLevel.from_string(min_level)
        self.log_file = log_file
        self._lock = threading.Lock()
        self._enable_colors = self._check_color_support()

    def _check_color_support(self) -> bool:
        return sys.stdout.isatty() or os.environ.get("FORCE_COLOR") == "1" or os.name == "nt"

    def _format_console(self, level_name: str, message: str, color_code: str) -> str:
        now = datetime.datetime.now().strftime("%H:%M:%S")
        if self._enable_colors:
            prefix = f"{self.COLOR_GREY}[{now}]{self.COLOR_RESET} {color_code}[{level_name:^7}]{self.COLOR_RESET}"
        else:
            prefix = f"[{now}] [{level_name:^7}]"
        return f"{prefix} {message}"

    def _write_audit_file(self, level_name: str, message: str) -> None:
        if not self.log_file:
            return
        timestamp = datetime.datetime.now().isoformat()
        log_entry = f"{timestamp} | {level_name:^8} | {self.name} | {message}\n"
        try:
            with open(self.log_file, "a", encoding="utf-8") as f:
                f.write(log_entry)
        except IOError:
            pass

    def log(self, level_val: int, level_name: str, message: str, color: str):
        if level_val < self.min_level:
            return
        formatted = self._format_console(level_name, message, color)
        with self._lock:
            print(formatted)
            self._write_audit_file(level_name, message)

    def debug(self, msg: str):
        self.log(LogLevel.DEBUG, "DEBUG", msg, self.COLOR_GREY)

    def info(self, msg: str):
        self.log(LogLevel.INFO, "INFO", msg, self.COLOR_CYAN)

    def success(self, msg: str):
        self.log(LogLevel.SUCCESS, "SUCCESS", msg, self.COLOR_GREEN)

    def warning(self, msg: str):
        self.log(LogLevel.WARNING, "WARN", msg, self.COLOR_YELLOW)

    def error(self, msg: str):
        self.log(LogLevel.ERROR, "ERROR", msg, self.COLOR_RED)

    def critical(self, msg: str):
        self.log(LogLevel.CRITICAL, "CRIT", msg, self.COLOR_BOLD_RED)

logger = SecurityLogger()
