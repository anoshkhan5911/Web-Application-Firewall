from __future__ import annotations


class Config:
    SECRET_KEY = "dev-waf-secret-key-change-me"
    RATE_LIMIT_MAX_REQUESTS = 5
    RATE_LIMIT_WINDOW_SECONDS = 10
    DASHBOARD_PAGE_SIZE = 10
