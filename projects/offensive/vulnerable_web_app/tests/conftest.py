"""Shared fixtures for BREACH test suite."""

import os
import tempfile

import pytest


@pytest.fixture(autouse=True)
def _isolate_db(tmp_path, monkeypatch):
    """Point the database and sandbox to temp dirs before any app code runs."""
    db_path = str(tmp_path / "test_breach.db")
    files_dir = str(tmp_path / "sandbox_files")

    # Patch the Settings singleton BEFORE it's used by the app
    from app.config import Settings
    test_settings = Settings.__new__(Settings)
    # Frozen dataclass — we need object.__setattr__
    for field_name in Settings.__dataclass_fields__:
        val = getattr(Settings(), field_name)
        object.__setattr__(test_settings, field_name, val)
    object.__setattr__(test_settings, "DATABASE_PATH", db_path)
    object.__setattr__(test_settings, "FILES_DIR", files_dir)

    monkeypatch.setattr("app.config.settings", test_settings)
