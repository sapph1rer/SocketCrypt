from __future__ import annotations

import os
import sys
from pathlib import Path


def app_base_dir() -> Path:
    if getattr(sys, 'frozen', False):
        meipass = getattr(sys, '_MEIPASS', None)
        if meipass:
            return Path(meipass).resolve()
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parents[1]


APP_DIR = Path(os.environ.get('P2PCHAT_HOME', Path.home() / '.p2pchat'))
KEYS_DIR = APP_DIR / 'keys'
DB_DIR = APP_DIR / 'db'
RUNTIME_DIR = APP_DIR / 'runtime'
IDENTITY_KEY_FILE = KEYS_DIR / 'identity_signing_key.b64'
ONION_KEY_FILE = KEYS_DIR / 'onion_service_key.txt'
CONTACTS_FILE = DB_DIR / 'contacts.json'
ROOMS_FILE = DB_DIR / 'rooms.json'
HISTORY_FILE = DB_DIR / 'history.jsonl'

PROTO_VERSION = 1
VIRTUAL_PORT = 80
CONNECT_TIMEOUT = int(os.environ.get('P2PCHAT_CONNECT_TIMEOUT', '10'))


def _env_flag(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {'1', 'true', 'yes', 'on'}


ENABLE_HISTORY = _env_flag('P2PCHAT_HISTORY', default=False)
ENCRYPTED_ONLY = True
REKEY_AFTER_MESSAGES = max(1, int(os.environ.get('P2PCHAT_REKEY_AFTER_MESSAGES', '50')))
REKEY_AFTER_SECONDS = max(30, int(os.environ.get('P2PCHAT_REKEY_AFTER_SECONDS', '900')))


def get_tor_control_host() -> str:
    return os.environ.get('P2PCHAT_TOR_CONTROL_HOST', '127.0.0.1')


def get_tor_control_port() -> int:
    return int(os.environ.get('P2PCHAT_TOR_CONTROL_PORT', '9051'))


def get_tor_socks_host() -> str:
    return os.environ.get('P2PCHAT_TOR_SOCKS_HOST', '127.0.0.1')


def get_tor_socks_port() -> int:
    return int(os.environ.get('P2PCHAT_TOR_SOCKS_PORT', '9050'))


def get_tor_control_password() -> str | None:
    return os.environ.get('P2PCHAT_TOR_CONTROL_PASSWORD')


def bundled_tor_dir() -> Path:
    base = app_base_dir()
    candidates: list[Path] = [
        base / 'tor',
        base / 'tor' / 'windows-x86_64',
        base / 'vendor' / 'tor',
        base / 'vendor' / 'tor' / 'windows-x86_64',
    ]
    if getattr(sys, 'frozen', False):
        candidates.append(Path(sys.executable).resolve().parent / 'tor')
    for candidate in candidates:
        tor_exe = candidate / ('tor.exe' if os.name == 'nt' else 'tor')
        if tor_exe.exists():
            return candidate
    return candidates[-1]


def ensure_dirs() -> None:
    KEYS_DIR.mkdir(parents=True, exist_ok=True)
    DB_DIR.mkdir(parents=True, exist_ok=True)
    RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(APP_DIR, 0o700)
        os.chmod(KEYS_DIR, 0o700)
        os.chmod(DB_DIR, 0o700)
        os.chmod(RUNTIME_DIR, 0o700)
    except OSError:
        pass
