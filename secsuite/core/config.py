"""
Global Configuration and Profile Settings for PySecSuite.
"""

from dataclasses import dataclass, field
from typing import Dict, Any, List
import json
import os

@dataclass
class ScanConfig:
    default_timeout: float = 1.5
    max_threads: int = 50
    default_ports: List[int] = field(default_factory=lambda: [
        21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995,
        1433, 1521, 3306, 3389, 5432, 5900, 6379, 8000, 8080, 8443, 9200, 27017
    ])
    user_agent: str = "PySecSuite-Auditor/1.0 (+https://local.security.audit)"
    rate_limit_delay: float = 0.05
    log_level: str = "INFO"
    output_dir: str = "reports"
    banner_grab_timeout: float = 1.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "default_timeout": self.default_timeout,
            "max_threads": self.max_threads,
            "default_ports": self.default_ports,
            "user_agent": self.user_agent,
            "rate_limit_delay": self.rate_limit_delay,
            "log_level": self.log_level,
            "output_dir": self.output_dir,
            "banner_grab_timeout": self.banner_grab_timeout,
        }

    @classmethod
    def from_file(cls, path: str) -> "ScanConfig":
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
                return cls(**data)
        return cls()

GLOBAL_CONFIG = ScanConfig()
