"""
Sentinel Framework Configuration and Settings.
Loads global configuration from config/settings.yaml and environment variables.
"""

import os
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml
from dotenv import load_dotenv
from pydantic import BaseModel, Field

# Load .env if present
load_dotenv()

BASE_DIR = Path(__file__).resolve().parent.parent.parent


class ScannerConfig(BaseModel):
    safe_flags: List[str] = Field(default_factory=list)
    mode: str = "baseline"
    level: str = "low"
    config: Optional[str] = None


class FrameworkSettings(BaseModel):
    name: str = "VAPT-GPT Sentinel"
    version: str = "0.1.0"
    safe_mode: bool = True
    max_retry_attempts: int = 3
    timeout_seconds: int = 300
    owner_authorized: bool = False
    llm_provider: str = "mock"
    runs_dir: Path = BASE_DIR / "runs"
    audit_log_path: Path = BASE_DIR / "runs" / "audit_log.jsonl"
    scope_path: Path = BASE_DIR / "config" / "scope.yaml"
    settings_path: Path = BASE_DIR / "config" / "settings.yaml"
    app_context_path: Path = BASE_DIR / "config" / "app_context.yaml"
    scanners: Dict[str, Any] = Field(default_factory=dict)


def load_settings() -> FrameworkSettings:
    """Loads framework settings from YAML and environment variables."""
    settings_file = BASE_DIR / "config" / "settings.yaml"
    raw_cfg: Dict[str, Any] = {}
    if settings_file.exists():
        with open(settings_file, "r", encoding="utf-8") as f:
            raw_cfg = yaml.safe_load(f) or {}

    framework_cfg = raw_cfg.get("framework", {})
    storage_cfg = raw_cfg.get("storage", {})
    scanners_cfg = raw_cfg.get("scanners", {})

    runs_dir_str = os.getenv("SENTINEL_RUNS_DIR", storage_cfg.get("runs_dir", "runs"))
    audit_log_str = os.getenv(
        "SENTINEL_AUDIT_LOG_PATH", storage_cfg.get("audit_log", "runs/audit_log.jsonl")
    )
    auth_env = os.getenv("SENTINEL_I_OWN_THIS_TARGET", "").lower() in ("true", "1", "yes")

    return FrameworkSettings(
        name=framework_cfg.get("name", "VAPT-GPT Sentinel"),
        version=framework_cfg.get("version", "0.1.0"),
        safe_mode=framework_cfg.get("safe_mode", True),
        max_retry_attempts=framework_cfg.get("max_retry_attempts", 3),
        timeout_seconds=framework_cfg.get("timeout_seconds", 300),
        owner_authorized=auth_env,
        llm_provider=os.getenv("LLM_PROVIDER", "mock").lower(),
        runs_dir=BASE_DIR / runs_dir_str,
        audit_log_path=BASE_DIR / audit_log_str,
        scope_path=BASE_DIR / "config" / "scope.yaml",
        settings_path=settings_file,
        app_context_path=BASE_DIR / "config" / "app_context.yaml",
        scanners=scanners_cfg,
    )


settings = load_settings()
