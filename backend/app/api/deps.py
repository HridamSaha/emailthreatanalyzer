from fastapi import Header, HTTPException

from app.core.config import get_settings


def require_admin(x_admin_token: str | None = Header(default=None)) -> None:
    settings = get_settings()
    if not settings.admin_api_token:
        return
    if x_admin_token != settings.admin_api_token:
        raise HTTPException(status_code=401, detail="Administrator token required.")
