from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field, HttpUrl


class HealthResponse(BaseModel):
    status: str
    version: str
    app: str


class ErrorResponse(BaseModel):
    error: str
    detail: str


class RawEmailRequest(BaseModel):
    raw: str = Field(min_length=8, max_length=2_000_000)


class UrlAnalyzeRequest(BaseModel):
    url: str = Field(min_length=8, max_length=2048)


class RuleUpdateRequest(BaseModel):
    enabled: bool


class AnalysisListQuery(BaseModel):
    q: str | None = None
    classification: str | None = None
    severity: str | None = None
    sort: str = "created_at"
    order: str = "desc"
    page: int = 1
    page_size: int = 20
