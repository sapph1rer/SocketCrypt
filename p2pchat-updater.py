#!/usr/bin/env python3

from __future__ import annotations

import argparse
import hashlib
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Optional
from urllib import error as urlerror
from urllib import request as urlrequest


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest().lower()


def _verify_sha256(path: Path, expected: Optional[str]) -> None:
    if not expected:
        return
    actual = _sha256_file(path)
    if actual != expected.lower():
        raise RuntimeError("Checksum mismatch for downloaded executable.")


def _download_file(url: str, dest: Path, timeout: float, *, prefix: str = "[updater]") -> None:
    req = urlrequest.Request(
        url,
        headers={
            "Cache-Control": "no-cache, no-store, max-age=0",
            "Pragma": "no-cache",
            "User-Agent": "p2pchat-updater/1.0",
        },
    )
    print(f"{prefix} Downloading {url}")
    try:
        with urlrequest.urlopen(req, timeout=timeout) as resp:
            with dest.open("wb") as out:
                while True:
                    chunk = resp.read(1024 * 1024)
                    if not chunk:
                        break
                    out.write(chunk)
    except (urlerror.URLError, TimeoutError, OSError) as exc:
        raise RuntimeError(f"Download failed: {exc}") from exc


def _is_pid_running(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        result = subprocess.run(
            ["tasklist", "/FI", f"PID eq {pid}"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        output = (result.stdout or "").lower()
        if "no tasks are running" in output:
            return False
        return str(pid) in output
    except Exception:
        try:
            os.kill(pid, 0)
        except OSError:
            return False
        return True


def _wait_for_pid_exit(pid: int, timeout: float = 180.0) -> bool:
    if pid <= 0:
        return True
    deadline = time.time() + max(timeout, 1.0)
    while time.time() < deadline:
        if not _is_pid_running(pid):
            return True
        time.sleep(0.5)
    return not _is_pid_running(pid)


def _replace_target_once(target: Path, downloaded: Path, backup: Path) -> None:
    moved_to_backup = False
    if backup.exists():
        backup.unlink()
    if target.exists():
        os.replace(str(target), str(backup))
        moved_to_backup = True

    try:
        os.replace(str(downloaded), str(target))
    except Exception:
        if moved_to_backup and backup.exists() and not target.exists():
            os.replace(str(backup), str(target))
        raise


def _replace_target_with_retry(
    target: Path,
    downloaded: Path,
    backup: Path,
    *,
    attempts: int = 60,
    delay: float = 0.5,
) -> None:
    last_error: Optional[Exception] = None
    for _ in range(max(1, attempts)):
        try:
            _replace_target_once(target, downloaded, backup)
            return
        except Exception as exc:
            last_error = exc
            time.sleep(max(0.05, delay))
    raise RuntimeError(f"Could not replace target executable: {last_error}")


def _schedule_self_cleanup(
    updater_path: Path,
    downloaded: Path,
    backup: Path,
    *,
    delete_backup: bool,
) -> None:
    script_path = Path(tempfile.gettempdir()) / f"p2pchat_updater_cleanup_{os.getpid()}.cmd"
    lines = [
        "@echo off",
        "setlocal",
        "timeout /t 2 /nobreak >nul",
        f'if exist "{downloaded}" del /f /q "{downloaded}" >nul 2>nul',
    ]
    if delete_backup:
        lines.append(f'if exist "{backup}" del /f /q "{backup}" >nul 2>nul')
    lines.extend(
        [
            f'if exist "{updater_path}" del /f /q "{updater_path}" >nul 2>nul',
            'del /f /q "%~f0" >nul 2>nul',
        ]
    )
    script_path.write_text("\n".join(lines), encoding="utf-8")
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0) | getattr(subprocess, "DETACHED_PROCESS", 0)
    subprocess.Popen(["cmd.exe", "/c", str(script_path)], creationflags=flags, close_fds=True)


def _launch_target(target: Path) -> None:
    create_console = getattr(subprocess, "CREATE_NEW_CONSOLE", 0)
    subprocess.Popen([str(target)], cwd=str(target.parent), creationflags=create_console, close_fds=True)


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="P2PChat external updater")
    parser.add_argument("--target", required=True, help="Path to executable to replace")
    parser.add_argument("--source-url", required=True, help="URL of the new executable")
    parser.add_argument("--expected-sha256", default="", help="Expected SHA256 of the new executable")
    parser.add_argument("--wait-pid", type=int, default=0, help="PID to wait for before replacing")
    parser.add_argument("--timeout", type=float, default=120.0, help="Download timeout in seconds")
    parser.add_argument("--version", default="", help="Version label for log output")
    parser.add_argument("--keep-backup", action="store_true", help="Keep .bak file after success")
    parser.add_argument("--no-launch", action="store_true", help="Do not launch target after replacing")
    return parser.parse_args()


def main() -> int:
    args = _parse_args()
    target = Path(args.target).resolve()
    if not target.parent.exists():
        print(f"[updater] Target directory does not exist: {target.parent}")
        return 1

    downloaded = target.with_name(f"{target.stem}.download{target.suffix}")
    backup = target.with_name(f"{target.stem}.bak{target.suffix}")
    updater_path = Path(sys.executable).resolve() if getattr(sys, "frozen", False) else Path(__file__).resolve()

    try:
        if args.wait_pid > 0:
            print(f"[updater] Waiting for process {args.wait_pid} to exit...")
            if not _wait_for_pid_exit(args.wait_pid):
                raise RuntimeError("Timed out waiting for running process to exit.")

        _download_file(args.source_url, downloaded, args.timeout, prefix="[updater]")
        print("[updater] Verifying package integrity...")
        _verify_sha256(downloaded, args.expected_sha256 or None)
        print("[updater] Replacing executable...")
        _replace_target_with_retry(target, downloaded, backup)

        if not args.no_launch:
            print("[updater] Starting updated application...")
            _launch_target(target)

        _schedule_self_cleanup(
            updater_path,
            downloaded,
            backup,
            delete_backup=not args.keep_backup,
        )
        version_text = f" {args.version}" if args.version else ""
        print(f"[updater] Update{version_text} complete.")
        return 0
    except Exception as exc:
        print(f"[updater] Failed: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
