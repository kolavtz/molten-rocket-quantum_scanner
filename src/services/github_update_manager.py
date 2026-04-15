"""GitHub release-based self-update manager for QuantumShield.

This module checks GitHub Releases for a newer version of the package,
downloads the latest wheel or source archive, installs it with pip, and
restarts the current process.
"""

from __future__ import annotations

import importlib.metadata
import logging
import os
import re
import subprocess
import sys
import threading
import time
from typing import Any

import requests

from config import (
    APP_VERSION,
    ALLOW_AUTO_UPDATE,
    GITHUB_RELEASE_ASSET_NAME,
    GITHUB_RELEASES_API_URL,
    GITHUB_REPO_NAME,
    GITHUB_REPO_OWNER,
    GITHUB_TOKEN,
    GITHUB_UPDATE_ENABLED,
    GITHUB_UPDATE_INTERVAL_MINUTES,
    GITHUB_UPDATE_ON_START,
    GITHUB_UPDATE_SCHEDULED,
)

logger = logging.getLogger(__name__)


_VERSION_RE = re.compile(r"\d+")


def _bool_env(name: str, fallback: bool = False) -> bool:
    return os.environ.get(name, str(fallback)).strip().lower() == "true"


def _current_version() -> str:
    try:
        return importlib.metadata.version("quantumshield")
    except Exception:
        return APP_VERSION


def _version_tuple(version: str) -> tuple[int, ...]:
    numbers = [int(piece) for piece in _VERSION_RE.findall(str(version))]
    return tuple(numbers) or (0,)


def _strip_tag_prefix(tag_name: str) -> str:
    text = str(tag_name or "").strip()
    if text.lower().startswith("v") and len(text) > 1 and text[1].isdigit():
        return text[1:]
    return text


def _github_headers() -> dict[str, str]:
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "QuantumShield-Update-Manager",
    }
    if GITHUB_TOKEN:
        headers["Authorization"] = f"Bearer {GITHUB_TOKEN}"
    return headers


def _release_assets(release: dict[str, Any]) -> list[dict[str, Any]]:
    assets = release.get("assets")
    return assets if isinstance(assets, list) else []


def _select_download_url(release: dict[str, Any]) -> str:
    assets = _release_assets(release)
    preferred_name = str(GITHUB_RELEASE_ASSET_NAME or "").strip()

    if preferred_name:
        for asset in assets:
            if str(asset.get("name") or "") == preferred_name:
                return str(asset.get("browser_download_url") or "")

    wheel_assets = [asset for asset in assets if str(asset.get("name") or "").endswith(".whl")]
    if wheel_assets:
        return str(wheel_assets[0].get("browser_download_url") or "")

    archive_assets = [asset for asset in assets if str(asset.get("name") or "").endswith((".tar.gz", ".zip"))]
    if archive_assets:
        return str(archive_assets[0].get("browser_download_url") or "")

    return str(release.get("zipball_url") or release.get("tarball_url") or "")


def _fetch_latest_release() -> dict[str, Any] | None:
    if not GITHUB_REPO_OWNER or not GITHUB_REPO_NAME:
        logger.info("GitHub update manager is disabled until QSS_GITHUB_REPO_OWNER and QSS_GITHUB_REPO_NAME are set.")
        return None

    url = GITHUB_RELEASES_API_URL or f"https://api.github.com/repos/{GITHUB_REPO_OWNER}/{GITHUB_REPO_NAME}/releases/latest"
    try:
        response = requests.get(url, headers=_github_headers(), timeout=30)
        response.raise_for_status()
        payload = response.json()
        if not isinstance(payload, dict):
            logger.warning("Unexpected GitHub release payload format.")
            return None
        return payload
    except Exception as exc:
        logger.warning("Failed to fetch latest GitHub release: %s", exc)
        return None


def _download_and_install(url: str) -> bool:
    if not url:
        logger.warning("No download URL available for the latest GitHub release.")
        return False

    pip_cmd = [sys.executable, "-m", "pip", "install", "--upgrade", url]
    try:
        logger.info("Installing update from %s", url)
        result = subprocess.run(pip_cmd, cwd=os.getcwd(), capture_output=True, text=True)
        if result.returncode != 0:
            logger.warning("Package update failed: %s", result.stderr.strip() or result.stdout.strip())
            return False
        logger.info("Package update installed successfully.")
        return True
    except Exception as exc:
        logger.warning("Package update failed: %s", exc)
        return False


def check_for_update() -> dict[str, Any]:
    """Check GitHub Releases and install a newer package version when allowed."""
    current_version = _current_version()
    latest_release = _fetch_latest_release()
    if not latest_release:
        return {"updated": False, "reason": "release_unavailable", "current_version": current_version}

    latest_tag = _strip_tag_prefix(str(latest_release.get("tag_name") or latest_release.get("name") or ""))
    if not latest_tag:
        return {"updated": False, "reason": "missing_tag", "current_version": current_version}

    if _version_tuple(latest_tag) <= _version_tuple(current_version):
        return {
            "updated": False,
            "reason": "already_current",
            "current_version": current_version,
            "latest_version": latest_tag,
        }

    if not (ALLOW_AUTO_UPDATE or _bool_env("QSS_ALLOW_AUTO_PULL", False)):
        return {
            "updated": False,
            "reason": "auto_update_disabled",
            "current_version": current_version,
            "latest_version": latest_tag,
        }

    download_url = _select_download_url(latest_release)
    if not download_url:
        return {
            "updated": False,
            "reason": "download_url_missing",
            "current_version": current_version,
            "latest_version": latest_tag,
        }

    if not _download_and_install(download_url):
        return {
            "updated": False,
            "reason": "install_failed",
            "current_version": current_version,
            "latest_version": latest_tag,
        }

    return {
        "updated": True,
        "reason": "installed",
        "current_version": current_version,
        "latest_version": latest_tag,
        "download_url": download_url,
    }


def restart_process() -> None:
    """Re-exec the current process so the newly installed version is loaded."""
    os.environ["QSS_GITHUB_UPDATE_PERFORMED"] = "1"
    python = sys.executable
    os.execv(python, [python] + sys.argv)


def run_startup_update_check() -> bool:
    """Run a one-time update check during app startup."""
    if not (GITHUB_UPDATE_ENABLED or GITHUB_UPDATE_ON_START):
        return False
    if os.environ.get("QSS_GITHUB_UPDATE_PERFORMED") == "1":
        logger.info("GitHub update already applied in this process; skipping startup check.")
        return False

    result = check_for_update()
    if result.get("updated"):
        logger.info(
            "Updated QuantumShield from %s to %s via GitHub Releases; restarting.",
            result.get("current_version"),
            result.get("latest_version"),
        )
        restart_process()
        return True

    logger.info(
        "GitHub startup update check completed: %s",
        result.get("reason") or "no_update",
    )
    return False


def _scheduled_update_loop() -> None:
    interval_minutes = max(5, int(GITHUB_UPDATE_INTERVAL_MINUTES or 60))
    logger.info("GitHub scheduled update checks enabled (every %s minute(s)).", interval_minutes)
    while True:
        try:
            result = check_for_update()
            if result.get("updated"):
                logger.info(
                    "Applied GitHub update from %s to %s; restarting.",
                    result.get("current_version"),
                    result.get("latest_version"),
                )
                restart_process()
                return
            logger.debug("GitHub scheduled update check result: %s", result.get("reason") or "no_update")
        except Exception as exc:
            logger.warning("GitHub scheduled update check failed: %s", exc)

        time.sleep(interval_minutes * 60)


def start_scheduled_update_checks() -> None:
    """Start the scheduled GitHub update watcher when enabled."""
    if not (GITHUB_UPDATE_ENABLED or GITHUB_UPDATE_SCHEDULED):
        return
    if os.environ.get("QSS_GITHUB_UPDATE_SCHEDULER_STARTED") == "1":
        return

    if os.environ.get("WERKZEUG_RUN_MAIN") == "false":
        return

    os.environ["QSS_GITHUB_UPDATE_SCHEDULER_STARTED"] = "1"
    thread = threading.Thread(target=_scheduled_update_loop, name="GitHubUpdateThread", daemon=True)
    thread.start()