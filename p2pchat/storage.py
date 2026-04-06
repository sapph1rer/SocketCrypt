from __future__ import annotations

import base64
import hashlib
import json
import time
from pathlib import Path
from typing import Any

from nacl import exceptions as nacl_exceptions
from nacl import secret, utils

LOCAL_STATE_FILE_TYPE = 'p2pchat-local-state'
LOCAL_STATE_FILE_VERSION = 1

_STATE_KEY: bytes | None = None
_ENCRYPTED_PATHS: set[str] = set()


def _path_key(path: Path) -> str:
    return str(path.resolve()).lower()


def configure_state_encryption(key_material: str | bytes | None, encrypted_paths: list[Path] | None = None) -> None:
    global _STATE_KEY, _ENCRYPTED_PATHS
    if encrypted_paths is not None:
        _ENCRYPTED_PATHS = {_path_key(p) for p in encrypted_paths}
    if key_material is None:
        _STATE_KEY = None
        return
    if isinstance(key_material, str):
        raw = key_material.encode('utf-8')
    else:
        raw = bytes(key_material)
    if not raw:
        _STATE_KEY = None
        return
    _STATE_KEY = hashlib.blake2b(raw + b'|p2pchat-local-state-v1', digest_size=32).digest()


def state_encryption_enabled() -> bool:
    return _STATE_KEY is not None and bool(_ENCRYPTED_PATHS)


def _is_sensitive_path(path: Path) -> bool:
    if not _ENCRYPTED_PATHS:
        return False
    return _path_key(path) in _ENCRYPTED_PATHS


def _encrypt_payload(payload: Any) -> dict[str, Any]:
    if _STATE_KEY is None:
        raise ValueError('local state encryption key is not configured')
    nonce = utils.random(secret.SecretBox.NONCE_SIZE)
    box = secret.SecretBox(_STATE_KEY)
    pt = json.dumps(payload, ensure_ascii=False, separators=(',', ':')).encode('utf-8')
    ct = box.encrypt(pt, nonce).ciphertext
    return {
        'type': LOCAL_STATE_FILE_TYPE,
        'version': LOCAL_STATE_FILE_VERSION,
        'alg': 'secretbox',
        'nonce_b64': base64.b64encode(nonce).decode('ascii'),
        'ciphertext_b64': base64.b64encode(ct).decode('ascii'),
    }


def _decrypt_payload(wrapper: dict[str, Any]) -> Any:
    if _STATE_KEY is None:
        raise ValueError('local state encryption key is not configured')
    if wrapper.get('type') != LOCAL_STATE_FILE_TYPE or wrapper.get('version') != LOCAL_STATE_FILE_VERSION:
        raise ValueError('invalid local state wrapper')
    nonce_b64 = str(wrapper.get('nonce_b64', '')).strip()
    ciphertext_b64 = str(wrapper.get('ciphertext_b64', '')).strip()
    if not nonce_b64 or not ciphertext_b64:
        raise ValueError('invalid encrypted local state payload')
    try:
        nonce = base64.b64decode(nonce_b64.encode('ascii'))
        ciphertext = base64.b64decode(ciphertext_b64.encode('ascii'))
        box = secret.SecretBox(_STATE_KEY)
        pt = box.decrypt(ciphertext, nonce)
    except (ValueError, nacl_exceptions.CryptoError) as exc:
        raise ValueError('cannot decrypt local state') from exc
    return json.loads(pt.decode('utf-8'))


def load_json(path: Path, default: Any):
    if not path.exists():
        return default
    try:
        raw = json.loads(path.read_text(encoding='utf-8'))
        if _is_sensitive_path(path) and isinstance(raw, dict) and raw.get('type') == LOCAL_STATE_FILE_TYPE:
            return _decrypt_payload(raw)
        return raw
    except Exception:
        return default


def save_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload: Any = data
    if _is_sensitive_path(path) and _STATE_KEY is not None:
        payload = _encrypt_payload(data)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding='utf-8')
    try:
        path.chmod(0o600)
    except OSError:
        pass


def append_history(path: Path, event: dict[str, Any]) -> None:
    event = dict(event)
    event.setdefault('ts', int(time.time()))
    if _is_sensitive_path(path) and _STATE_KEY is not None:
        history = load_json(path, default=[])
        if not isinstance(history, list):
            history = []
        history.append(event)
        save_json(path, history)
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('a', encoding='utf-8') as f:
        f.write(json.dumps(event, ensure_ascii=False) + '\n')
    try:
        path.chmod(0o600)
    except OSError:
        pass
