from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List


LOG_FILE = Path("waf.log")


def log_request(
    ip: str,
    path: str,
    status: str,
    attack_type: str = "NONE",
    details: str = "",
) -> None:
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "ip": ip,
        "path": path,
        "status": status,
        "attack_type": attack_type,
        "details": details,
    }
    with LOG_FILE.open("a", encoding="utf-8") as file:
        file.write(json.dumps(entry) + "\n")


def read_logs() -> List[Dict[str, Any]]:
    if not LOG_FILE.exists():
        return []
    entries: List[Dict[str, Any]] = []
    with LOG_FILE.open("r", encoding="utf-8") as file:
        for line in file:
            line = line.strip()
            if not line:
                continue
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return entries


def clear_logs() -> None:
    if LOG_FILE.exists():
        LOG_FILE.write_text("", encoding="utf-8")
