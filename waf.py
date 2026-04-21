from __future__ import annotations

import re
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Deque, Dict, Tuple


@dataclass
class DetectionResult:
    blocked: bool
    attack_type: str
    reason: str


SQL_PATTERNS = [
    r"'\s*or\s*1=1",
    r"\bselect\b",
    r"\bdrop\b",
    r"--",
    r";",
    r"\bunion\b",
]

XSS_PATTERNS = [
    r"<\s*script\b",
    r"\balert\s*\(",
    r"\bonerror\s*=",
    r"javascript:",
]

SUSPICIOUS_CHARS = r"[<>{}\[\]\$`]"


def detect_sql_injection(user_input: str) -> Tuple[bool, str]:
    text = (user_input or "").lower()
    for pattern in SQL_PATTERNS:
        if re.search(pattern, text, flags=re.IGNORECASE):
            return True, f"Matched SQL pattern: {pattern}"
    return False, "No SQL injection pattern found"


def detect_xss(user_input: str) -> Tuple[bool, str]:
    text = (user_input or "").lower()
    for pattern in XSS_PATTERNS:
        if re.search(pattern, text, flags=re.IGNORECASE):
            return True, f"Matched XSS pattern: {pattern}"
    return False, "No XSS pattern found"


def detect_suspicious_input(user_input: str) -> Tuple[bool, str]:
    text = user_input or ""
    if len(text) > 80:
        return True, "Input length is unusually long"
    if re.search(SUSPICIOUS_CHARS, text):
        return True, "Input has unusual special characters"
    return False, "Input looks normal"


class RateLimiter:
    def __init__(self, max_requests: int = 5, window_seconds: int = 10) -> None:
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.ip_requests: Dict[str, Deque[float]] = defaultdict(deque)

    def allow_request(self, ip_address: str) -> Tuple[bool, str]:
        now = time.time()
        queue = self.ip_requests[ip_address]
        while queue and now - queue[0] > self.window_seconds:
            queue.popleft()

        if len(queue) >= self.max_requests:
            return False, (
                f"Rate limit exceeded: {len(queue)} requests in "
                f"{self.window_seconds} seconds"
            )

        queue.append(now)
        return True, "Within rate limit"
