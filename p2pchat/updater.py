from __future__ import annotations

import base64
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional, Tuple
from urllib import error as urlerror
from urllib import parse as urlparse
from urllib import request as urlrequest

try:
    from nacl import exceptions as nacl_exceptions
    from nacl.signing import VerifyKey
except Exception:  # pragma: no cover
    VerifyKey = None
    nacl_exceptions = None


DEFAULT_UPDATE_MANIFEST_URL = (
    "https://raw.githubusercontent.com/sapph1rer/SocketCrypt/refs/heads/main/update-manifest.json"
)
DEFAULT_UPDATE_SIGNING_PUBLIC_KEY_B64 = "j68W0xFkSa9WGKfhncx+YKMf/+xOEz+X1TLESz0DCBg="
REQUIRE_SIGNED_MANIFEST_DEFAULT = True


class UpdateError(RuntimeError):
    pass


@dataclass
class UpdateInfo:
    version: str
    notes: str
    manifest_url: str
    manifest_signed: bool
    exe_url: Optional[str]
    exe_sha256: Optional[str]
    updater_url: Optional[str]
    updater_sha256: Optional[str]


@dataclass
class UpdateApplyResult:
    message: str
    restart_required: bool


def resolve_manifest_url(explicit: Optional[str] = None) -> str:
    if explicit and explicit.strip():
        return explicit.strip()
    env_url = os.environ.get("P2PCHAT_UPDATE_MANIFEST_URL", "").strip()
    if env_url:
        return env_url
    return DEFAULT_UPDATE_MANIFEST_URL


def resolve_update_signing_public_key(explicit: Optional[str] = None) -> str:
    if explicit and explicit.strip():
        return explicit.strip()
    env_key = os.environ.get("P2PCHAT_UPDATE_SIGN_PUBKEY_B64", "").strip()
    if env_key:
        return env_key
    return DEFAULT_UPDATE_SIGNING_PUBLIC_KEY_B64.strip()


def require_signed_manifest() -> bool:
    raw = os.environ.get("P2PCHAT_REQUIRE_SIGNED_MANIFEST")
    if raw is None:
        return REQUIRE_SIGNED_MANIFEST_DEFAULT
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _canonical_json_bytes(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _verify_manifest_signature(
    payload: dict,
    signature_b64: str,
    *,
    signing_public_key_b64: str,
) -> None:
    if VerifyKey is None or nacl_exceptions is None:
        raise UpdateError("Manifest signature verification is unavailable in this runtime.")
    try:
        verify_key = VerifyKey(base64.b64decode(signing_public_key_b64.encode("ascii")))
    except Exception as exc:
        raise UpdateError("Invalid update signing public key format.") from exc
    try:
        sig_bytes = base64.b64decode(signature_b64.encode("ascii"))
    except Exception as exc:
        raise UpdateError("Invalid manifest signature encoding.") from exc
    try:
        verify_key.verify(_canonical_json_bytes(payload), sig_bytes)
    except nacl_exceptions.BadSignatureError as exc:
        raise UpdateError("Update manifest signature verification failed.") from exc


def _normalize_version(version: str) -> Tuple[int, ...]:
    clean = (version or "").strip()
    if not clean:
        return (0,)
    parts: list[int] = []
    for token in clean.replace("-", ".").split("."):
        digits = "".join(ch for ch in token if ch.isdigit())
        parts.append(int(digits or 0))
    while parts and parts[-1] == 0:
        parts.pop()
    return tuple(parts or [0])


def is_newer_version(remote_version: str, current_version: str) -> bool:
    return _normalize_version(remote_version) > _normalize_version(current_version)


def _read_manifest_payload(payload: dict, manifest_url: str, *, manifest_signed: bool) -> UpdateInfo:
    version = str(payload.get("version") or "").strip()
    if not version:
        raise UpdateError("Update manifest is missing 'version'.")
    notes = str(payload.get("notes") or payload.get("changelog") or "").strip()

    exe_cfg = payload.get("exe") if isinstance(payload.get("exe"), dict) else {}
    updater_cfg = payload.get("updater") if isinstance(payload.get("updater"), dict) else {}

    exe_url = str(payload.get("exe_url") or exe_cfg.get("url") or "").strip() or None
    exe_sha256 = str(payload.get("exe_sha256") or exe_cfg.get("sha256") or "").strip().lower() or None
    updater_url = str(payload.get("updater_url") or updater_cfg.get("url") or "").strip() or None
    updater_sha256 = (
        str(payload.get("updater_sha256") or updater_cfg.get("sha256") or "").strip().lower() or None
    )

    return UpdateInfo(
        version=version,
        notes=notes,
        manifest_url=manifest_url,
        manifest_signed=manifest_signed,
        exe_url=exe_url,
        exe_sha256=exe_sha256,
        updater_url=updater_url,
        updater_sha256=updater_sha256,
    )


def fetch_update_info(
    manifest_url: str,
    timeout: float = 20.0,
    *,
    signing_public_key_b64: Optional[str] = None,
    require_signed: Optional[bool] = None,
) -> UpdateInfo:
    sep = "&" if "?" in manifest_url else "?"
    cache_busted_url = f"{manifest_url}{sep}_ts={int(time.time())}"
    req = urlrequest.Request(
        cache_busted_url,
        headers={
            "Cache-Control": "no-cache, no-store, max-age=0",
            "Pragma": "no-cache",
            "User-Agent": "p2pchat-updater/1.0",
        },
    )
    try:
        with urlrequest.urlopen(req, timeout=timeout) as resp:
            body = resp.read()
    except (urlerror.URLError, TimeoutError, OSError) as exc:
        raise UpdateError(f"Could not fetch update manifest: {exc}") from exc

    try:
        payload = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise UpdateError("Update manifest is not valid JSON.") from exc
    if not isinstance(payload, dict):
        raise UpdateError("Update manifest must be a JSON object.")

    resolved_pubkey = resolve_update_signing_public_key(signing_public_key_b64)
    if require_signed is None:
        require_signed = require_signed_manifest()

    signature_raw = (
        str(payload.get("sig") or payload.get("signature") or "").strip()
        if isinstance(payload, dict)
        else ""
    )
    payload_obj: dict = payload
    if isinstance(payload.get("payload"), dict):
        payload_obj = payload["payload"]  # envelope format: { payload: {...}, sig: "..." }
    else:
        payload_obj = dict(payload)
        payload_obj.pop("sig", None)
        payload_obj.pop("signature", None)
        payload_obj.pop("signing", None)
        payload_obj.pop("key_id", None)

    manifest_signed = bool(signature_raw)
    if manifest_signed:
        if not resolved_pubkey:
            raise UpdateError("Signed update manifest found but no public key configured.")
        _verify_manifest_signature(payload_obj, signature_raw, signing_public_key_b64=resolved_pubkey)
    elif require_signed:
        raise UpdateError("Unsigned update manifest rejected (signed manifest required).")

    return _read_manifest_payload(payload_obj, manifest_url, manifest_signed=manifest_signed)


def check_for_update(
    *,
    current_version: str,
    manifest_url: Optional[str] = None,
    signing_public_key_b64: Optional[str] = None,
    require_signed: Optional[bool] = None,
    timeout: float = 20.0,
) -> Tuple[UpdateInfo, bool]:
    resolved = resolve_manifest_url(manifest_url)
    info = fetch_update_info(
        resolved,
        timeout=timeout,
        signing_public_key_b64=signing_public_key_b64,
        require_signed=require_signed,
    )
    return info, is_newer_version(info.version, current_version)


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
        raise UpdateError("Checksum mismatch while applying update.")


def _download_file(
    url: str,
    dest: Path,
    timeout: float,
    log: Optional[Callable[[str], None]] = None,
) -> None:
    if log:
        log(f"downloading: {url}")
    req = urlrequest.Request(
        url,
        headers={
            "Cache-Control": "no-cache, no-store, max-age=0",
            "Pragma": "no-cache",
            "User-Agent": "p2pchat-updater/1.0",
        },
    )
    try:
        with urlrequest.urlopen(req, timeout=timeout) as resp:
            with dest.open("wb") as out:
                while True:
                    chunk = resp.read(1024 * 1024)
                    if not chunk:
                        break
                    out.write(chunk)
    except (urlerror.URLError, TimeoutError, OSError) as exc:
        raise UpdateError(f"Download failed: {exc}") from exc


def _safe_temp_exe_name(version: str) -> str:
    safe = "".join(ch for ch in version if ch.isalnum() or ch in ("-", "_", ".")).strip("._-")
    if not safe:
        safe = "latest"
    return f"p2pchat-updater-{safe}.exe"


def apply_self_update(
    info: UpdateInfo,
    timeout: float = 120.0,
    log: Optional[Callable[[str], None]] = None,
) -> UpdateApplyResult:
    if not getattr(sys, "frozen", False):
        raise UpdateError("Self-update is available only in packaged .exe mode.")
    if not info.exe_url:
        raise UpdateError("No exe update URL in manifest.")
    if not info.updater_url:
        raise UpdateError("No updater URL in manifest.")

    current_exe = Path(sys.executable).resolve()
    updater_path = Path(tempfile.gettempdir()) / _safe_temp_exe_name(info.version)

    _download_file(info.updater_url, updater_path, timeout, log=log)
    _verify_sha256(updater_path, info.updater_sha256)
    if log:
        log("updater downloaded and verified")

    command = [
        str(updater_path),
        "--target",
        str(current_exe),
        "--source-url",
        info.exe_url,
        "--wait-pid",
        str(os.getpid()),
        "--timeout",
        str(timeout),
        "--version",
        info.version,
    ]
    if info.exe_sha256:
        command.extend(["--expected-sha256", info.exe_sha256])

    try:
        create_console = getattr(subprocess, "CREATE_NEW_CONSOLE", 0)
        subprocess.Popen(command, creationflags=create_console, close_fds=True)
    except OSError as exc:
        raise UpdateError(f"Failed to launch updater executable: {exc}") from exc

    return UpdateApplyResult(
        message=f"Updater launched for {info.version}. App will close and restart after update.",
        restart_required=True,
    )
