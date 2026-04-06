from __future__ import annotations

import asyncio
import atexit
import base64
import getpass
import json
import os
import shlex
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import traceback
import zlib
from collections import deque
from pathlib import Path

from .config import (
    APP_DIR,
    CONNECT_TIMEOUT,
    CONTACTS_FILE,
    ENABLE_HISTORY,
    ENCRYPTED_ONLY,
    HISTORY_FILE,
    IDENTITY_KEY_FILE,
    KEYS_DIR,
    ONION_KEY_FILE,
    ROOMS_FILE,
    REKEY_AFTER_MESSAGES,
    REKEY_AFTER_SECONDS,
    RUNTIME_DIR,
    get_tor_control_host,
    get_tor_control_password,
    get_tor_control_port,
    get_tor_socks_host,
    get_tor_socks_port,
    ensure_dirs,
)
from .contacts import Contact, ContactBook, normalize_identity_pub, normalize_onion
from .crypto import (
    SESSION_CIPHER_AEAD,
    SESSION_CIPHER_FALLBACK,
    decrypt_json_with_password,
    encrypt_json_with_password,
    identity_fingerprint,
    identity_pub_b64,
    load_or_create_signing_key,
)
from .protocol import ChatNode, Session, normalize_nick
from .storage import configure_state_encryption, load_json, save_json, state_encryption_enabled
from .tor_runtime import start_or_use_tor
from .tor_utils import create_or_resume_onion, socks5_connect
from .updater import UpdateError, apply_self_update, check_for_update

APP_VERSION = '1.0.3'
APP_BUILD = APP_VERSION

HELP = f"""=== HELP: P2P Onion Chat v{APP_VERSION} ===
Chat Basics:
  - Type plain text + Enter to send.
  - If active room exists, plain text goes to room.
  - Otherwise plain text goes to active direct session.

Core:
  /help [inline]                     open this help (window by default on Windows)
  /version                           show app version/build
  /check-update [--yes]              check signed update manifest (and apply if --yes)
  /quit | /q                         quit app
  /cls
  /clear                             clear current screen/log

Identity & Security:
  /me | /w | /whoami                 show identity, fingerprint, share code, security settings
  /nick <new_nick> | /n <new_nick>   change nick
  /sas                               show active session verify code
  /privacy [normal|hardened|paranoid|status]
                                     traffic shaping/privacy profile
  /ephemeral [on|off|status]         no local history writes when on
  /lock <set|off|status>             device startup password lock + local state encryption key
  /diag [contact_name]               local/Tor/connect diagnostics
  /panic [session|local|all]         wipe session/local/all sensitive data
  /ui [compact|full]                 switch UI density
  /wizard                            rerun first-run wizard

Contacts & Direct Chat:
  /contacts [--full]                 list contacts
  /share                             print one-line share code
  /add <name> <onion> <identity_pub_b64>
  /import <name> <share_code>        legacy share-code import (auto-trust+verify)
  /import <file.json> [--key <password>] [--name <contact_name>]
                                     encrypted contact import (password prompt if --key omitted)
  /export [--key <password>] [--out <file.json>]
                                     encrypted contact export (password prompt if --key omitted)
  /trust <name> [expected_fingerprint]
  /verify <name> <fingerprint>
  /connect [name|index]              connect to verified contact
  /reconnect [name] | /r [name]
  /part [room] | /leave              leave room, or disconnect session if no room
  /msg <text>                        legacy explicit send command

Rooms (IRC-style):
  /rooms
  /list                              alias of /rooms
  /join <room> | /j <room>           create/join room and make it active
  /invite [room]                     print room invite code (full + short)
  /names [room]                      show users in room snapshot
  /who [room|off]                    live room user updates on/off
  /topic [room] [text]               show/set/clear topic (use "-" or "--clear" to clear)

  /room create <room> [member1] [member2...]
  /room add <room> <member>
  /room del <room> <member>
  /room members <room>               legacy roster output
  /room invite <room>
  /room code [room]                  short invite code only
  /room accept <invite_code> [room]
  /room join <room>                  legacy join
  /room leave
  /room send <room> <text>
  /room queue                        pending room retry queue
  /room routes [room]                route score/health table

Local Encrypted Files:
  /save [file.json]                  save current chat transcript (encrypted)
  /cat <history.json>                open encrypted transcript (asks password)
  /backup [file.json]                encrypted full profile backup
  /restore <backup.json>             restore encrypted profile backup

Aliases:
  /h -> /help
  /w, /whoami -> /me
  /n -> /nick
  /j -> /join
  /list -> /rooms
  /leave -> /part
  /ver -> /version
  /update -> /check-update
  /traffic -> /privacy
  /r -> /reconnect
  /q -> /quit
"""


EXPORT_FILE_TYPE = 'p2pchat-contact-export'
EXPORT_FILE_VERSION = 1
HISTORY_FILE_TYPE = 'p2pchat-chat-history'
HISTORY_FILE_VERSION = 1
PROFILE_BACKUP_FILE_TYPE = 'p2pchat-profile-backup'
PROFILE_BACKUP_FILE_VERSION = 1
_USE_ANSI = False
WIZARD_DONE_FILE = RUNTIME_DIR / 'wizard.done'
ROOM_RETRY_QUEUE_FILE = RUNTIME_DIR / 'room_retry_queue.json'
RECONNECT_DELAYS = [2, 5, 10, 20, 30]
UI_IDLE_SLEEP = 0.012
UI_FULL_REDRAW_INTERVAL = 0.05
STARTUP_TOR_RETRIES = 3
STARTUP_ONION_RETRIES = 3
STARTUP_RETRY_DELAY_SECONDS = 2.0
WORKER_RESTART_DELAY_SECONDS = 1.5
ROOM_ONLINE_WINDOW_SECONDS = 120
ROOM_IDLE_WINDOW_SECONDS = 900
DEVICE_LOCK_FILE = KEYS_DIR / 'device_lock.json'
DEVICE_LOCK_FILE_TYPE = 'p2pchat-device-lock'
DEVICE_LOCK_FILE_VERSION = 1
CRASH_LOG_FILE = RUNTIME_DIR / 'crash.log'
REQUIRE_VERIFIED_CONTACTS = True


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode('ascii').rstrip('=')


def _b64url_decode(data: str) -> bytes:
    padding = '=' * (-len(data) % 4)
    return base64.urlsafe_b64decode((data + padding).encode('ascii'))


def make_share_code(onion: str, identity_pub: str) -> str:
    payload = {
        'v': 1,
        'onion': normalize_onion(onion),
        'identity_pub': normalize_identity_pub(identity_pub),
    }
    encoded = json.dumps(payload, separators=(',', ':'), sort_keys=True).encode('utf-8')
    return f'p2pchat://v1/{_b64url_encode(encoded)}'


def make_room_invite_code(
    room_name: str,
    members: list[str],
    contacts: ContactBook,
    *,
    room_peers: list[dict[str, str]] | None = None,
    inviter_name: str | None = None,
    inviter_onion: str | None = None,
    inviter_identity_pub: str | None = None,
    inviter_fingerprint: str | None = None,
    short_code: bool = False,
) -> str:
    normalized_room = _sanitize_room_name(room_name)
    if not normalized_room:
        raise ValueError('invalid room name')
    payload_members: list[dict[str, str]] = []
    inviter_identity_norm = ''
    inviter_onion_norm = ''
    if inviter_identity_pub:
        inviter_identity_norm = normalize_identity_pub(inviter_identity_pub)
        if not inviter_onion:
            raise ValueError('local onion is not ready; cannot create public room invite')
        inviter_onion_norm = normalize_onion(inviter_onion)

    for member_name in members:
        contact = contacts.by_name(member_name)
        if not contact:
            continue
        payload_members.append(
            {
                'name': contact.name,
                'onion': contact.onion,
                'identity_pub': contact.identity_pub_b64,
                'fingerprint': contact.fingerprint,
            }
        )
    for peer in room_peers or []:
        if not isinstance(peer, dict):
            continue
        name = str(peer.get('name', '')).strip()
        onion_raw = str(peer.get('onion', '')).strip()
        identity_raw = str(peer.get('identity_pub', '')).strip()
        if not name or not onion_raw or not identity_raw:
            continue
        try:
            onion = normalize_onion(onion_raw)
            identity_pub = normalize_identity_pub(identity_raw)
        except ValueError:
            continue
        if any(existing.get('identity_pub') == identity_pub for existing in payload_members):
            continue
        payload_members.append(
            {
                'name': name,
                'onion': onion,
                'identity_pub': identity_pub,
                'fingerprint': str(peer.get('fingerprint', '')).strip(),
            }
        )
    # Always include inviter as a routable peer in members list for public rooms.
    if inviter_identity_norm and inviter_onion_norm:
        if not any(existing.get('identity_pub') == inviter_identity_norm for existing in payload_members):
            payload_members.append(
                {
                    'name': (inviter_name or '').strip() or 'anon',
                    'onion': inviter_onion_norm,
                    'identity_pub': inviter_identity_norm,
                    'fingerprint': (inviter_fingerprint or '').strip(),
                }
            )
    inviter_payload: dict[str, str] | None = None
    if inviter_identity_norm:
        inviter_payload = {
            'name': (inviter_name or '').strip() or 'anon',
            'onion': inviter_onion_norm,
            'identity_pub': inviter_identity_norm,
            'fingerprint': (inviter_fingerprint or '').strip(),
        }

    payload = {'v': 1, 'room': normalized_room, 'members': payload_members, 'ts': int(time.time())}
    if inviter_payload is not None:
        payload['inviter'] = inviter_payload
    if not payload_members and 'inviter' not in payload:
        raise ValueError('room has no exportable members')
    if short_code:
        compact_members: list[dict[str, str]] = []
        for item in payload_members:
            compact_members.append(
                {
                    'n': str(item.get('name', '')).strip(),
                    'o': str(item.get('onion', '')).strip(),
                    'i': str(item.get('identity_pub', '')).strip(),
                    'f': str(item.get('fingerprint', '')).strip(),
                }
            )
        compact_payload: dict[str, object] = {
            'v': 2,
            'r': normalized_room,
            'm': compact_members,
            't': int(time.time()),
        }
        if inviter_payload is not None:
            compact_payload['iv'] = {
                'n': inviter_payload.get('name', 'anon'),
                'o': inviter_payload.get('onion', ''),
                'i': inviter_payload.get('identity_pub', ''),
                'f': inviter_payload.get('fingerprint', ''),
            }
        raw = json.dumps(compact_payload, separators=(',', ':'), sort_keys=True).encode('utf-8')
        compressed = zlib.compress(raw, level=9)
        return f'p2pr://v2/{_b64url_encode(compressed)}'

    encoded = json.dumps(payload, separators=(',', ':'), sort_keys=True).encode('utf-8')
    return f'p2proom://v1/{_b64url_encode(encoded)}'


def parse_room_invite_code(code: str) -> tuple[str, list[dict[str, str]], dict[str, str] | None]:
    cleaned = code.strip()
    payload: dict
    if cleaned.startswith('p2proom://v1/'):
        payload = json.loads(_b64url_decode(cleaned[len('p2proom://v1/'):]).decode('utf-8'))
        if payload.get('v') != 1:
            raise ValueError('unsupported room invite version')
        raw_room_name = str(payload.get('room', ''))
        raw_members = payload.get('members', [])
        inviter_raw = payload.get('inviter')
    elif cleaned.startswith('p2pr://v2/') or cleaned.startswith('p2proom://v2/'):
        token = cleaned.split('/v2/', 1)[1]
        payload_bytes = _b64url_decode(token)
        try:
            payload = json.loads(zlib.decompress(payload_bytes).decode('utf-8'))
        except Exception:
            payload = json.loads(payload_bytes.decode('utf-8'))
        if payload.get('v') != 2:
            raise ValueError('unsupported room invite version')
        raw_room_name = str(payload.get('r') or payload.get('room') or '')
        raw_members = payload.get('m', payload.get('members', []))
        inviter_raw = payload.get('iv', payload.get('inviter'))
    else:
        raise ValueError('room invite code must start with p2proom://v1/ or p2pr://v2/')

    room_name = _sanitize_room_name(raw_room_name)
    if not room_name:
        raise ValueError('invalid room name in invite')
    if not isinstance(raw_members, list):
        raise ValueError('invalid invite members')
    members: list[dict[str, str]] = []
    for item in raw_members:
        if not isinstance(item, dict):
            continue
        name = str(item.get('name', item.get('n', ''))).strip()
        onion_raw = str(item.get('onion', item.get('o', ''))).strip()
        identity_pub = str(item.get('identity_pub', item.get('i', ''))).strip()
        if not name or not identity_pub:
            continue
        try:
            identity_pub = normalize_identity_pub(identity_pub)
        except ValueError:
            continue
        onion = ''
        if onion_raw:
            try:
                onion = normalize_onion(onion_raw)
            except ValueError:
                onion = ''
        members.append(
            {
                'name': name,
                'onion': onion,
                'identity_pub': identity_pub,
                'fingerprint': str(item.get('fingerprint', item.get('f', ''))).strip(),
            }
        )
    inviter: dict[str, str] | None = None
    if isinstance(inviter_raw, dict):
        inviter_onion_raw = str(inviter_raw.get('onion', inviter_raw.get('o', ''))).strip()
        inviter_identity_raw = str(inviter_raw.get('identity_pub', inviter_raw.get('i', ''))).strip()
        if inviter_identity_raw:
            try:
                inviter_identity = normalize_identity_pub(inviter_identity_raw)
                inviter_onion = ''
                if inviter_onion_raw:
                    inviter_onion = normalize_onion(inviter_onion_raw)
                inviter = {
                    'name': str(inviter_raw.get('name', inviter_raw.get('n', ''))).strip() or 'anon',
                    'onion': inviter_onion,
                    'identity_pub': inviter_identity,
                    'fingerprint': str(inviter_raw.get('fingerprint', inviter_raw.get('f', ''))).strip(),
                }
            except ValueError:
                inviter = None
    if not members and inviter is None:
        raise ValueError('invite has no valid members')
    return room_name, members, inviter


def parse_share_code(code: str) -> tuple[str, str]:
    cleaned = code.strip()
    prefix = 'p2pchat://v1/'
    if not cleaned.startswith(prefix):
        raise ValueError('share code must start with p2pchat://v1/')
    payload = json.loads(_b64url_decode(cleaned[len(prefix):]).decode('utf-8'))
    if payload.get('v') != 1:
        raise ValueError('unsupported share code version')
    onion = normalize_onion(payload.get('onion', ''))
    identity_pub = normalize_identity_pub(payload.get('identity_pub', ''))
    return onion, identity_pub


def _clear_screen() -> None:
    if _USE_ANSI:
        print('\x1b[2J\x1b[H', end='', flush=True)
        return
    os.system('cls' if os.name == 'nt' else 'clear')


def _enable_ansi_on_windows() -> bool:
    if os.name != 'nt':
        return True
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
        if handle in (0, -1):
            return False
        mode = ctypes.c_uint()
        if kernel32.GetConsoleMode(handle, ctypes.byref(mode)) == 0:
            return False
        new_mode = mode.value | 0x0004  # ENABLE_VIRTUAL_TERMINAL_PROCESSING
        if kernel32.SetConsoleMode(handle, new_mode) == 0:
            return False
        return True
    except Exception:
        return False


def _apply_runtime_hardening() -> None:
    # Best-effort privacy hardening: disable core dumps where supported.
    try:
        import resource

        if hasattr(resource, 'RLIMIT_CORE'):
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    except Exception:
        pass

    if os.name != 'nt':
        return
    try:
        import ctypes

        sem_failcriticalerrors = 0x0001
        sem_nogpfaulterrorbox = 0x0002
        sem_noopenfileerrorbox = 0x8000
        ctypes.windll.kernel32.SetErrorMode(
            sem_failcriticalerrors | sem_nogpfaulterrorbox | sem_noopenfileerrorbox
        )
    except Exception:
        pass


def _debugger_attached() -> bool:
    if sys.gettrace() is not None:
        return True
    if os.name != 'nt':
        return False
    try:
        import ctypes

        if ctypes.windll.kernel32.IsDebuggerPresent():
            return True
        present = ctypes.c_int(0)
        current = ctypes.windll.kernel32.GetCurrentProcess()
        if ctypes.windll.kernel32.CheckRemoteDebuggerPresent(current, ctypes.byref(present)):
            return bool(present.value)
    except Exception:
        return False
    return False


def _write_crash_log(exc: BaseException) -> Path | None:
    try:
        RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
        tb_text = ''.join(traceback.format_exception(type(exc), exc, exc.__traceback__))
        lines = [
            f'[{time.strftime("%Y-%m-%d %H:%M:%S")}] unhandled exception',
            f'app_version={APP_VERSION}',
            tb_text.rstrip(),
            '',
        ]
        with CRASH_LOG_FILE.open('a', encoding='utf-8') as f:
            f.write('\n'.join(lines))
        try:
            os.chmod(CRASH_LOG_FILE, 0o600)
        except OSError:
            pass
        return CRASH_LOG_FILE
    except Exception:
        return None


async def _run_with_status(func, label: str, tick: float = 0.25):
    spinner = '|/-\\'
    task = asyncio.create_task(asyncio.to_thread(func))
    idx = 0
    while not task.done():
        print(f'\r[*] {label} {spinner[idx % len(spinner)]}', end='', flush=True)
        idx += 1
        await asyncio.sleep(tick)
    print('\r' + (' ' * 96) + '\r', end='', flush=True)
    return await task


async def _prompt_password_with_confirm(
    prompt: str,
    *,
    allow_empty: bool = False,
    mismatch_msg: str = 'password mismatch, try again',
) -> str:
    while True:
        # ensure prompt starts on fresh line, avoids "command+prompt" overlap in interactive UI
        print()
        first = (await asyncio.to_thread(getpass.getpass, prompt)).strip()
        if not first:
            if allow_empty:
                return ''
            print('[*] password cannot be empty')
            continue
        confirm = (await asyncio.to_thread(getpass.getpass, 'Confirm password: ')).strip()
        if first != confirm:
            print(f'[*] {mismatch_msg}')
            continue
        return first


async def _prompt_yes_no(prompt: str, *, default_yes: bool = True) -> bool:
    if not sys.stdin.isatty():
        return default_yes
    suffix = ' [Y/n]: ' if default_yes else ' [y/N]: '
    raw = (await asyncio.to_thread(input, prompt + suffix)).strip().lower()
    if not raw:
        return default_yes
    return raw in ('y', 'yes')


async def _prompt_password(prompt: str) -> str:
    print()
    return (await asyncio.to_thread(getpass.getpass, prompt)).strip()


def _write_device_lock(password: str) -> None:
    normalized = password.strip()
    if not normalized:
        raise ValueError('password required')
    wrapper = {
        'type': DEVICE_LOCK_FILE_TYPE,
        'version': DEVICE_LOCK_FILE_VERSION,
        'enc': encrypt_json_with_password(
            normalized,
            {
                'kind': 'device-lock',
                'created_at': int(time.time()),
            },
        ),
    }
    DEVICE_LOCK_FILE.parent.mkdir(parents=True, exist_ok=True)
    DEVICE_LOCK_FILE.write_text(json.dumps(wrapper, ensure_ascii=False, indent=2), encoding='utf-8')
    try:
        os.chmod(DEVICE_LOCK_FILE, 0o600)
    except OSError:
        pass


def _verify_device_lock(password: str) -> bool:
    if not DEVICE_LOCK_FILE.exists():
        return True
    wrapper = json.loads(DEVICE_LOCK_FILE.read_text(encoding='utf-8'))
    if wrapper.get('type') != DEVICE_LOCK_FILE_TYPE or wrapper.get('version') != DEVICE_LOCK_FILE_VERSION:
        raise ValueError('unsupported lock file format')
    enc_blob = wrapper.get('enc')
    if not isinstance(enc_blob, dict):
        raise ValueError('invalid lock file')
    payload = decrypt_json_with_password(password.strip(), enc_blob)
    return isinstance(payload, dict) and payload.get('kind') == 'device-lock'


async def _device_lock_gate() -> str | None:
    if not DEVICE_LOCK_FILE.exists():
        return None
    if not sys.stdin.isatty():
        env_pwd = os.environ.get('P2PCHAT_DEVICE_PASSWORD', '').strip()
        if not env_pwd:
            print('[*] device lock enabled but no TTY (set P2PCHAT_DEVICE_PASSWORD)')
            return ''
        try:
            if _verify_device_lock(env_pwd):
                return env_pwd
        except Exception:
            pass
        print('[*] device unlock failed in non-interactive mode')
        return ''
    print('[*] Device lock is enabled.')
    for attempt in range(1, 4):
        pwd = await _prompt_password('Unlock password: ')
        if not pwd:
            print('[*] empty password')
            continue
        try:
            if _verify_device_lock(pwd):
                print('[*] Device unlocked.')
                return pwd
        except Exception:
            pass
        print(f'[*] unlock failed ({attempt}/3)')
    print('[*] too many failed unlock attempts, exiting.')
    return ''


def _open_help_window(help_text: str) -> bool:
    if os.name != 'nt':
        return False
    try:
        temp_path = Path(tempfile.gettempdir()) / 'p2pchat-help.txt'
        temp_path.write_text(help_text, encoding='utf-8')
        flags = getattr(subprocess, 'CREATE_NEW_CONSOLE', 0)
        subprocess.Popen(['notepad.exe', str(temp_path)], creationflags=flags, close_fds=True)
        return True
    except Exception:
        return False


def _local_state_files() -> list[Path]:
    return [CONTACTS_FILE, ROOMS_FILE, ROOM_RETRY_QUEUE_FILE, HISTORY_FILE]


def _read_plain_history_jsonl(path: Path) -> list[dict]:
    rows: list[dict] = []
    if not path.exists():
        return rows
    try:
        for line in path.read_text(encoding='utf-8').splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            try:
                item = json.loads(stripped)
            except Exception:
                continue
            if isinstance(item, dict):
                rows.append(item)
    except Exception:
        return []
    return rows


def _write_plain_history_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    out_lines: list[str] = []
    for item in rows:
        if isinstance(item, dict):
            out_lines.append(json.dumps(item, ensure_ascii=False))
    path.write_text('\n'.join(out_lines) + ('\n' if out_lines else ''), encoding='utf-8')
    try:
        path.chmod(0o600)
    except OSError:
        pass


def _configure_local_state_encryption(password: str | None) -> None:
    configure_state_encryption(password, _local_state_files())

    if not password:
        return

    # One-time migration: convert legacy plaintext history jsonl into encrypted JSON list.
    try:
        raw_obj = json.loads(HISTORY_FILE.read_text(encoding='utf-8')) if HISTORY_FILE.exists() else None
        is_wrapper = isinstance(raw_obj, dict) and raw_obj.get('type') == 'p2pchat-local-state'
    except Exception:
        is_wrapper = False
    if not is_wrapper and HISTORY_FILE.exists():
        legacy_rows = _read_plain_history_jsonl(HISTORY_FILE)
        if legacy_rows:
            save_json(HISTORY_FILE, legacy_rows)


async def _auto_check_update_before_start() -> bool:
    if not sys.stdin.isatty():
        return True
    print(f'[*] Version {APP_VERSION}')
    print('[*] Checking for updates...')
    try:
        info, has_update = await asyncio.to_thread(
            check_for_update,
            current_version=APP_VERSION,
            manifest_url=None,
            require_signed=True,
            timeout=20.0,
        )
    except UpdateError as e:
        print(f'[*] update check skipped: {e}')
        return True
    except Exception as e:
        print(f'[*] update check failed: {e}')
        return True

    if not has_update:
        print(f'[*] Already latest version ({APP_VERSION})')
        return True

    print(f'[*] New version available: {info.version}')
    print(f'[*] Manifest signature: {"verified" if info.manifest_signed else "unsigned"}')
    if info.notes:
        print(f'[*] Notes: {info.notes}')
    apply_now = await _prompt_yes_no('Update now?', default_yes=True)
    if not apply_now:
        print('[*] update skipped')
        return True

    try:
        result = await asyncio.to_thread(
            apply_self_update,
            info,
            120.0,
            lambda text: print(f'[*] {text}'),
        )
    except UpdateError as e:
        print(f'[*] update failed: {e}')
        return True
    except Exception as e:
        print(f'[*] update failed: {e}')
        return True
    print(f'[*] {result.message}')
    return not result.restart_required


def _parse_cli_tokens(tokens: list[str], bool_flags: set[str] | None = None) -> tuple[list[str], dict[str, str | bool]]:
    bool_flags = bool_flags or set()
    positional: list[str] = []
    flags: dict[str, str | bool] = {}
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        if tok.startswith('--'):
            if tok in bool_flags and (i + 1 >= len(tokens) or tokens[i + 1].startswith('--')):
                flags[tok] = True
                i += 1
                continue
            if i + 1 >= len(tokens) or tokens[i + 1].startswith('--'):
                raise ValueError(f'missing value for {tok}')
            flags[tok] = tokens[i + 1]
            i += 2
        else:
            positional.append(tok)
            i += 1
    return positional, flags


def _choose_unique_name(contacts: ContactBook, preferred_name: str) -> str:
    base = preferred_name.strip() or 'friend'
    if not contacts.by_name(base):
        return base

    n = 2
    while True:
        candidate = f'{base}-{n}'
        if not contacts.by_name(candidate):
            return candidate
        n += 1


def _default_export_path(my_onion: str) -> Path:
    onion_short = normalize_onion(my_onion).split('.', 1)[0][:12]
    return Path.cwd() / f'p2pchat-contact-{onion_short}.json'


def _default_history_path() -> Path:
    return Path.cwd() / f'p2pchat-history-{time.strftime("%Y%m%d-%H%M%S")}.json'


def _default_profile_backup_path() -> Path:
    return Path.cwd() / f'p2pchat-profile-backup-{time.strftime("%Y%m%d-%H%M%S")}.json'


def _default_nick() -> str:
    raw = os.environ.get('P2PCHAT_NICK', 'anon')
    try:
        return normalize_nick(raw)
    except ValueError:
        return 'anon'


def export_contact_file(
    path: Path,
    password: str,
    onion: str,
    identity_pub: str,
    nick: str | None = None,
) -> Path:
    fingerprint = identity_fingerprint(identity_pub)
    payload = {
        'v': 1,
        'onion': normalize_onion(onion),
        'identity_pub': normalize_identity_pub(identity_pub),
        'fingerprint': fingerprint,
        'nick': nick or _default_nick(),
        'exported_at': int(time.time()),
    }
    normalized_password = password.strip()
    if not normalized_password:
        raise ValueError('password required for export')
    wrapper = {
        'type': EXPORT_FILE_TYPE,
        'version': EXPORT_FILE_VERSION,
        'enc': encrypt_json_with_password(normalized_password, payload),
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(wrapper, ensure_ascii=False, indent=2), encoding='utf-8')
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return path.resolve()


def import_contact_file(path: Path, password: str | None) -> tuple[str, str, str, str | None]:
    raw = json.loads(path.read_text(encoding='utf-8'))
    payload: dict

    if isinstance(raw, dict) and raw.get('type') == EXPORT_FILE_TYPE and raw.get('version') == EXPORT_FILE_VERSION:
        enc_blob = raw.get('enc')
        if isinstance(enc_blob, dict):
            normalized_password = (password or '').strip()
            if not normalized_password:
                raise ValueError('this file is encrypted; use /import <file.json> --key <password>')
            payload = decrypt_json_with_password(normalized_password, enc_blob)
        else:
            raise ValueError('invalid export file (encrypted payload missing)')
    elif isinstance(raw, dict):
        raise ValueError('plain import is disabled; use encrypted export/import only')
    else:
        raise ValueError('invalid export file')

    onion = normalize_onion(payload.get('onion', ''))
    identity_pub = normalize_identity_pub(payload.get('identity_pub', ''))
    fingerprint = identity_fingerprint(identity_pub)
    declared_fingerprint = payload.get('fingerprint')
    if declared_fingerprint and declared_fingerprint.lower() != fingerprint.lower():
        raise ValueError('fingerprint validation failed')
    nick_value = payload.get('nick')
    suggested_name: str | None = None
    if isinstance(nick_value, str) and nick_value.strip():
        try:
            suggested_name = normalize_nick(nick_value.strip())
        except ValueError:
            suggested_name = None
    return onion, identity_pub, fingerprint, suggested_name


def save_chat_history_file(path: Path, password: str, payload: dict) -> Path:
    normalized_password = password.strip()
    if not normalized_password:
        raise ValueError('password required')
    wrapper = {
        'type': HISTORY_FILE_TYPE,
        'version': HISTORY_FILE_VERSION,
        'enc': encrypt_json_with_password(normalized_password, payload),
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(wrapper, ensure_ascii=False, indent=2), encoding='utf-8')
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return path.resolve()


def load_chat_history_file(path: Path, password: str) -> dict:
    normalized_password = password.strip()
    if not normalized_password:
        raise ValueError('password required')
    wrapper = json.loads(path.read_text(encoding='utf-8'))
    if wrapper.get('type') != HISTORY_FILE_TYPE or wrapper.get('version') != HISTORY_FILE_VERSION:
        raise ValueError('unsupported history file format')
    enc_blob = wrapper.get('enc')
    if not isinstance(enc_blob, dict):
        raise ValueError('invalid history file')
    payload = decrypt_json_with_password(normalized_password, enc_blob)
    if not isinstance(payload, dict):
        raise ValueError('invalid history payload')
    return payload


def backup_profile_file(path: Path, password: str) -> Path:
    normalized_password = password.strip()
    if not normalized_password:
        raise ValueError('password required for profile backup')

    sources = [
        ('identity_key', 'keys/identity_signing_key.b64', IDENTITY_KEY_FILE),
        ('onion_key', 'keys/onion_service_key.txt', ONION_KEY_FILE),
        ('device_lock', 'keys/device_lock.json', DEVICE_LOCK_FILE),
        ('contacts', 'db/contacts.json', CONTACTS_FILE),
        ('rooms', 'db/rooms.json', ROOMS_FILE),
        ('history', 'db/history.jsonl', HISTORY_FILE),
        ('wizard_done', 'runtime/wizard.done', WIZARD_DONE_FILE),
        ('room_retry_queue', 'runtime/room_retry_queue.json', ROOM_RETRY_QUEUE_FILE),
    ]
    files: dict[str, dict[str, object]] = {}
    for key, rel_path, source in sources:
        if not source.exists() or not source.is_file():
            continue
        raw = source.read_bytes()
        stat = source.stat()
        files[key] = {
            'relpath': rel_path,
            'size': len(raw),
            'mtime': int(stat.st_mtime),
            'b64': base64.b64encode(raw).decode('ascii'),
        }

    payload = {
        'created_at': int(time.time()),
        'app_version': APP_VERSION,
        'files': files,
    }
    wrapper = {
        'type': PROFILE_BACKUP_FILE_TYPE,
        'version': PROFILE_BACKUP_FILE_VERSION,
        'enc': encrypt_json_with_password(normalized_password, payload),
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(wrapper, ensure_ascii=False, indent=2), encoding='utf-8')
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return path.resolve()


def restore_profile_file(path: Path, password: str) -> dict[str, object]:
    normalized_password = password.strip()
    if not normalized_password:
        raise ValueError('password required for profile restore')
    wrapper = json.loads(path.read_text(encoding='utf-8'))
    if wrapper.get('type') != PROFILE_BACKUP_FILE_TYPE or wrapper.get('version') != PROFILE_BACKUP_FILE_VERSION:
        raise ValueError('unsupported backup file format')
    enc_blob = wrapper.get('enc')
    if not isinstance(enc_blob, dict):
        raise ValueError('invalid backup file')

    payload = decrypt_json_with_password(normalized_password, enc_blob)
    if not isinstance(payload, dict):
        raise ValueError('invalid backup payload')
    files = payload.get('files', {})
    if not isinstance(files, dict):
        raise ValueError('invalid backup payload files')

    allowed_relpaths = {
        'keys/identity_signing_key.b64',
        'keys/onion_service_key.txt',
        'keys/device_lock.json',
        'db/contacts.json',
        'db/rooms.json',
        'db/history.jsonl',
        'runtime/wizard.done',
        'runtime/room_retry_queue.json',
    }
    restored = 0
    for _, item in files.items():
        if not isinstance(item, dict):
            continue
        relpath_raw = str(item.get('relpath', '')).replace('\\', '/').strip().lstrip('/')
        if relpath_raw not in allowed_relpaths:
            continue
        b64_data = str(item.get('b64', '')).strip()
        if not b64_data:
            continue
        try:
            file_bytes = base64.b64decode(b64_data.encode('ascii'))
        except Exception:
            continue
        target = (APP_DIR / relpath_raw).resolve()
        if APP_DIR.resolve() not in target.parents and target != APP_DIR.resolve():
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(file_bytes)
        try:
            os.chmod(target, 0o600)
        except OSError:
            pass
        mtime = int(item.get('mtime', 0) or 0)
        if mtime > 0:
            try:
                os.utime(target, (mtime, mtime))
            except OSError:
                pass
        restored += 1

    return {
        'restored_files': restored,
        'created_at': int(payload.get('created_at', 0) or 0),
        'backup_app_version': str(payload.get('app_version', '')).strip(),
    }


def _sanitize_contact_name(raw: str) -> str:
    name = ''.join(ch for ch in raw.strip() if ch.isalnum() or ch in ('-', '_')).strip('-_')
    return name[:24] if name else ''


def _sanitize_room_name(raw: str) -> str:
    name = ''.join(ch for ch in raw.strip().lower() if ch.isalnum() or ch in ('-', '_')).strip('-_')
    return name[:24] if name else ''


def _load_rooms_map() -> dict[str, dict]:
    raw = load_json(ROOMS_FILE, default={})
    if not isinstance(raw, dict):
        return {}
    rooms: dict[str, dict] = {}
    for room_name, room_data in raw.items():
        if not isinstance(room_name, str):
            continue
        normalized_name = _sanitize_room_name(room_name)
        if not normalized_name:
            continue
        members: list[str] = []
        peers: list[dict[str, object]] = []
        topic = ''
        if isinstance(room_data, dict):
            raw_members = room_data.get('members', [])
            if isinstance(raw_members, list):
                for item in raw_members:
                    if isinstance(item, str) and item.strip() and item.strip() not in members:
                        members.append(item.strip())
            raw_peers = room_data.get('peers', [])
            if isinstance(raw_peers, list):
                for peer_item in raw_peers:
                    if not isinstance(peer_item, dict):
                        continue
                    name = str(peer_item.get('name', '')).strip()
                    onion_raw = str(peer_item.get('onion', '')).strip()
                    identity_raw = str(peer_item.get('identity_pub', '')).strip()
                    if not name or not onion_raw or not identity_raw:
                        continue
                    try:
                        onion = normalize_onion(onion_raw)
                        identity_pub = normalize_identity_pub(identity_raw)
                    except ValueError:
                        continue
                    if any(existing.get('identity_pub') == identity_pub for existing in peers):
                        continue
                    try:
                        score = int(peer_item.get('score', 50) or 50)
                    except Exception:
                        score = 50
                    score = max(0, min(100, score))
                    def _safe_int(field: str) -> int:
                        try:
                            return max(0, int(peer_item.get(field, 0) or 0))
                        except Exception:
                            return 0
                    peers.append(
                        {
                            'name': name,
                            'onion': onion,
                            'identity_pub': identity_pub,
                            'fingerprint': str(peer_item.get('fingerprint', '')).strip(),
                            'score': score,
                            'last_ok': _safe_int('last_ok'),
                            'last_try': _safe_int('last_try'),
                            'last_fail': _safe_int('last_fail'),
                            'fail_count': _safe_int('fail_count'),
                        }
                    )
            created_at = int(room_data.get('created_at', int(time.time())) or int(time.time()))
            raw_topic = room_data.get('topic', '')
            if isinstance(raw_topic, str):
                topic = raw_topic.strip()[:180]
        else:
            created_at = int(time.time())
        rooms[normalized_name] = {
            'members': members,
            'peers': peers,
            'created_at': created_at,
            'topic': topic,
        }
    return rooms


def _save_rooms_map(rooms: dict[str, dict]) -> None:
    save_json(ROOMS_FILE, rooms)


def _load_room_retry_queue() -> list[dict]:
    raw = load_json(ROOM_RETRY_QUEUE_FILE, default=[])
    if not isinstance(raw, list):
        return []
    items: list[dict] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        room = _sanitize_room_name(str(item.get('room', '')))
        target_name = str(item.get('target_name', '')).strip()
        target_onion_raw = str(item.get('target_onion', '')).strip()
        target_identity_raw = str(item.get('target_identity_pub', '')).strip()
        text = str(item.get('text', ''))
        if not room or not target_name or not text:
            continue
        target_onion = ''
        target_identity = ''
        if target_onion_raw:
            try:
                target_onion = normalize_onion(target_onion_raw)
            except ValueError:
                target_onion = ''
        if target_identity_raw:
            try:
                target_identity = normalize_identity_pub(target_identity_raw)
            except ValueError:
                target_identity = ''
        items.append(
            {
                'room': room,
                'target_name': target_name,
                'target_onion': target_onion,
                'target_identity_pub': target_identity,
                'text': text,
                'created_at': int(item.get('created_at', int(time.time())) or int(time.time())),
                'attempts': int(item.get('attempts', 0) or 0),
                'next_try_ts': float(item.get('next_try_ts', time.time())),
                'last_error': str(item.get('last_error', '')),
            }
        )
    return items


def _save_room_retry_queue(items: list[dict]) -> None:
    save_json(ROOM_RETRY_QUEUE_FILE, items)


def _canonical_contact_query(raw: str) -> str:
    return ''.join(ch.lower() for ch in raw.strip() if ch.isalnum())


def _import_contact_into_book(contacts: ContactBook, onion: str, identity_pub: str, preferred_name: str | None) -> tuple[str, str]:
    fingerprint = identity_fingerprint(identity_pub)
    existing_identity = contacts.by_identity(identity_pub)
    if existing_identity:
        c = contacts.add(existing_identity.name, onion, identity_pub, trusted=True)
        contacts.verify(c.name)
        return c.name, f'updated and auto-verified contact: {c.name} ({c.fingerprint})'

    default_name = preferred_name or f'friend-{fingerprint.replace(":", "")[:8]}'
    contact_name = _choose_unique_name(contacts, default_name)
    c = contacts.add(contact_name, onion, identity_pub, trusted=True)
    contacts.verify(c.name)
    return c.name, f'imported and auto-verified contact: {c.name} ({c.fingerprint})'


def _resolve_contact_by_query(contacts: ContactBook, query: str) -> tuple[Contact | None, list[str]]:
    q_raw = query.strip()
    q = q_raw.lower()
    if not q_raw:
        return None, []

    entries = contacts.list()
    if q_raw.isdigit():
        idx = int(q_raw)
        if 1 <= idx <= len(entries):
            return entries[idx - 1], []

    exact = contacts.by_name(query)
    if exact:
        return exact, []

    by_name = [c for c in entries if c.name.lower() == q]
    if len(by_name) == 1:
        return by_name[0], []

    canonical_q = _canonical_contact_query(q_raw)
    by_canonical_name = [c for c in entries if _canonical_contact_query(c.name) == canonical_q]
    if len(by_canonical_name) == 1:
        return by_canonical_name[0], []

    prefix_matches = [c for c in entries if c.name.lower().startswith(q)]
    if len(prefix_matches) == 1:
        return prefix_matches[0], []

    canonical_prefix = [c for c in entries if _canonical_contact_query(c.name).startswith(canonical_q)]
    if len(canonical_prefix) == 1:
        return canonical_prefix[0], []

    substring_matches = [c for c in entries if q in c.name.lower()]
    if len(substring_matches) == 1:
        return substring_matches[0], []

    canonical_substring = [c for c in entries if canonical_q and canonical_q in _canonical_contact_query(c.name)]
    if len(canonical_substring) == 1:
        return canonical_substring[0], []

    suggestions_source = prefix_matches or canonical_prefix or substring_matches or canonical_substring
    suggestions = [c.name for c in suggestions_source[:8]]
    return None, suggestions


def _resolve_contact_by_onion_query(contacts: ContactBook, query: str) -> tuple[Contact | None, list[str]]:
    q = query.strip().lower()
    if not q:
        return None, []
    if q.endswith('.onion'):
        q = q[:-6]
    entries = contacts.list()

    exact = [c for c in entries if c.onion.lower() == (q + '.onion')]
    if len(exact) == 1:
        return exact[0], []

    prefix = [c for c in entries if c.onion.lower().startswith(q)]
    if len(prefix) == 1:
        return prefix[0], []

    suggestions = [c.name for c in prefix[:8]]
    return None, suggestions


def _trusted_contacts(contacts: ContactBook) -> list[Contact]:
    return [c for c in contacts.list() if c.trusted]


def _ready_contacts(contacts: ContactBook) -> list[Contact]:
    if REQUIRE_VERIFIED_CONTACTS:
        return [c for c in contacts.list() if c.trusted and getattr(c, 'verified', False)]
    return _trusted_contacts(contacts)


async def _disconnect_active_session(node: ChatNode) -> None:
    await node.close_session()


async def _run_first_run_wizard(node: ChatNode, contacts: ContactBook, my_id_pub: str, log_cb) -> None:
    if not sys.stdin.isatty() or WIZARD_DONE_FILE.exists():
        return

    print('\n== First-Run Setup Wizard ==')
    print('Press Enter to keep defaults, or type values to set up quickly.')

    try:
        nick_input = await asyncio.to_thread(input, f'Nick [{node.my_nick}]: ')
        if nick_input.strip():
            node.set_my_nick(nick_input.strip())
            log_cb(f'nick set to {node.my_nick}')

        export_now = (await asyncio.to_thread(input, 'Create encrypted profile export now? [Y/n]: ')).strip().lower()
        if export_now in ('', 'y', 'yes'):
            out_default = str(_default_export_path(node.my_onion))
            out_input = await asyncio.to_thread(input, f'Export file [{out_default}]: ')
            out_path = Path(out_input.strip() or out_default)
            password = await _prompt_password_with_confirm('Export password: ')
            written = export_contact_file(
                out_path,
                password,
                node.my_onion,
                my_id_pub,
                nick=node.my_nick,
            )
            log_cb(f'exported encrypted contact file: {written}')

        import_path = (await asyncio.to_thread(input, 'Import friend file now? (path or blank to skip): ')).strip()
        if import_path:
            password = await _prompt_password_with_confirm('Import file password: ')
            onion, identity_pub, _, suggested_name = import_contact_file(
                Path(import_path),
                password,
            )
            preferred = (await asyncio.to_thread(input, f'Friend name (optional) [{suggested_name or ""}]: ')).strip() or suggested_name
            _, import_msg = _import_contact_into_book(contacts, onion, identity_pub, preferred)
            log_cb(import_msg)

        connect_name = (await asyncio.to_thread(input, 'Connect now to contact name (optional): ')).strip()
        if connect_name:
            contact = contacts.by_name(connect_name)
            ready = bool(contact and contact.trusted and (contact.verified or not REQUIRE_VERIFIED_CONTACTS))
            if ready:
                try:
                    await node.connect(contact)
                    log_cb(f'connected to {connect_name}')
                except Exception as e:
                    log_cb(f'connect failed in wizard: {e}')
            else:
                log_cb('wizard connect skipped: contact missing/unverified')
    except Exception as e:
        log_cb(f'wizard error: {e}')
    finally:
        WIZARD_DONE_FILE.parent.mkdir(parents=True, exist_ok=True)
        WIZARD_DONE_FILE.write_text(str(int(time.time())), encoding='utf-8')
        log_cb('first-run wizard completed')


def _append_log(log: deque[str], text: str, prefix: str = '[*] ') -> None:
    lines = str(text).splitlines() or ['']
    for line in lines:
        log.append(f'{prefix}{line}' if prefix else line)


def _session_label(node: ChatNode) -> str:
    if not node.session:
        return 'disconnected'
    return f'connected to {node.session.peer_name} ({node.session.peer_nick})'


def _infer_peer_contact_name(node: ChatNode, contacts: ContactBook) -> str | None:
    if not node.session:
        return None
    by_identity = contacts.by_identity(node.session.peer_identity_pub_b64)
    if by_identity:
        return by_identity.name
    return node.session.peer_name


def _is_tcp_open(host: str, port: int, timeout: float = 0.8) -> tuple[bool, str]:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True, 'open'
    except OSError as e:
        return False, str(e)


def _build_diag_report(node: ChatNode, contacts: ContactBook, contact_name: str | None = None) -> list[str]:
    lines: list[str] = []

    lines.append(f'app_home: {APP_DIR}')
    lines.append(f'identity_key_exists: {IDENTITY_KEY_FILE.exists()}')
    lines.append(f'onion_key_exists: {ONION_KEY_FILE.exists()}')
    lines.append(f'contacts_file_exists: {CONTACTS_FILE.exists()}')
    lines.append(f'connect_timeout_sec: {CONNECT_TIMEOUT}')
    lines.append(f'tor_log_exists: {(RUNTIME_DIR / "tor.log").exists()}')
    lines.append(f'message_cipher_preferred: {SESSION_CIPHER_AEAD}')
    lines.append(f'message_cipher_fallback: {SESSION_CIPHER_FALLBACK}')
    lines.append(f'encrypted_only_mode: {ENCRYPTED_ONLY}')
    lines.append(f'local_state_encryption: {state_encryption_enabled()}')
    lines.append(f'require_verified_contacts: {REQUIRE_VERIFIED_CONTACTS}')
    lines.append(f'rekey_after_messages: {REKEY_AFTER_MESSAGES}')
    lines.append(f'rekey_after_seconds: {REKEY_AFTER_SECONDS}')
    lines.append(f'wizard_done: {WIZARD_DONE_FILE.exists()}')
    lines.append(f'my_onion: {node.my_onion}')
    lines.append(f'session_state: {_session_label(node)}')
    if node.session:
        lines.append(f'session_sas: {node.session.sas_code}')

    all_contacts = contacts.list()
    trusted = sum(1 for c in all_contacts if c.trusted)
    verified = sum(1 for c in all_contacts if c.trusted and getattr(c, 'verified', False))
    lines.append(f'contacts_total: {len(all_contacts)}')
    lines.append(f'contacts_trusted: {trusted}')
    lines.append(f'contacts_verified: {verified}')
    lines.append(f'contacts_untrusted: {len(all_contacts) - trusted}')

    socks_host = get_tor_socks_host()
    socks_port = get_tor_socks_port()
    control_host = get_tor_control_host()
    control_port = get_tor_control_port()
    socks_open, socks_err = _is_tcp_open(socks_host, socks_port)
    control_open, control_err = _is_tcp_open(control_host, control_port)
    lines.append(f'tor_socks: {socks_host}:{socks_port} ({socks_err if not socks_open else "open"})')
    lines.append(f'tor_control: {control_host}:{control_port} ({control_err if not control_open else "open"})')

    if control_open:
        try:
            from stem.control import Controller

            with Controller.from_port(address=control_host, port=control_port) as c:
                password = get_tor_control_password()
                if password:
                    c.authenticate(password=password)
                else:
                    c.authenticate()
                lines.append(f'tor_version: {c.get_version()}')
                bootstrap_raw = c.get_info('status/bootstrap-phase', '') or ''
                if bootstrap_raw:
                    lines.append(f'tor_bootstrap: {bootstrap_raw}')
        except Exception as e:
            lines.append(f'tor_control_auth: failed ({e})')
    else:
        lines.append('tor_control_auth: skipped (control port unreachable)')

    if contact_name:
        c, _ = _resolve_contact_by_query(contacts, contact_name)
        if not c:
            lines.append(f'contact_check: "{contact_name}" not found')
        else:
            lines.append(f'contact_check.name: {c.name}')
            lines.append(f'contact_check.onion: {c.onion}')
            lines.append(f'contact_check.trusted: {c.trusted}')
            lines.append(f'contact_check.verified: {getattr(c, "verified", False)}')
            lines.append(f'contact_check.fingerprint: {c.fingerprint}')
            if socks_open:
                try:
                    probe = socks5_connect(c.onion, 80, timeout=15)
                    probe.close()
                    lines.append('contact_check.reachability: onion reachable via Tor SOCKS')
                except Exception as e:
                    lines.append(f'contact_check.reachability: failed ({e})')
    return lines


def _render_ui(
    node: ChatNode,
    my_fp: str,
    status: str,
    connection_health: str,
    log: deque[str],
    input_buffer: str,
    cursor_pos: int | None = None,
    compact: bool = True,
) -> None:
    if _USE_ANSI:
        print('\x1b[H\x1b[J', end='')
    else:
        _clear_screen()
    cols, rows = shutil.get_terminal_size((120, 32))
    print('== P2P Onion Chat ==')
    print(f'Nick: {node.my_nick} | Session: {_session_label(node)}')
    print(f'Status: {status}')
    print(f'Connection health: {connection_health}')
    if not compact:
        print(f'Onion: {node.my_onion}')
        print(f'Fingerprint: {my_fp}')
    print('-' * min(cols, 120))

    footer_lines = 3
    header_lines = 6 if compact else 8
    max_lines = max(8, rows - header_lines - footer_lines)
    visible = list(log)[-max_lines:]
    for line in visible:
        print(line)

    print('-' * min(cols, 120))
    prompt = f'{node.my_nick}> '
    if cursor_pos is None:
        cursor_pos = len(input_buffer)
    print(prompt + input_buffer + ' ', end='', flush=True)
    if _USE_ANSI:
        move = len(prompt) + max(0, min(cursor_pos, len(input_buffer)))
        print('\r', end='')
        if move > 0:
            print(f'\x1b[{move}C', end='', flush=True)


def _redraw_prompt_line(node: ChatNode, input_buffer: str, cursor_pos: int) -> None:
    prompt = f'{node.my_nick}> '
    print('\r' + prompt + input_buffer + ' ', end='', flush=True)
    move = len(prompt) + max(0, min(cursor_pos, len(input_buffer)))
    print('\r', end='')
    if move > 0:
        print(f'\x1b[{move}C', end='', flush=True)


def _read_key_windows() -> tuple[str, str | None] | None:
    import msvcrt

    if not msvcrt.kbhit():
        return None
    ch = msvcrt.getwch()
    if ch in ('\x00', '\xe0'):
        ext = msvcrt.getwch()
        mapping = {
            'H': 'UP',
            'P': 'DOWN',
            'K': 'LEFT',
            'M': 'RIGHT',
            'G': 'HOME',
            'O': 'END',
            'S': 'DELETE',
        }
        return (mapping.get(ext, 'EXT'), None)
    if ch in ('\r', '\n'):
        return ('ENTER', None)
    if ch in ('\b', '\x08'):
        return ('BACKSPACE', None)
    if ch == '\x03':
        return ('CTRL_C', None)
    return ('CHAR', ch)


async def amain() -> None:
    print('[*] Launching P2PChat...')
    _apply_runtime_hardening()
    if _debugger_attached():
        print('[*] security warning: debugger detected in current process')
    ensure_dirs()
    unlock_password = await _device_lock_gate()
    if unlock_password == '':
        return
    _configure_local_state_encryption(unlock_password if DEVICE_LOCK_FILE.exists() else None)
    if state_encryption_enabled():
        print('[*] Local state encryption: enabled (device-lock key)')
    else:
        print('[*] Local state encryption: disabled (run /lock set to enable)')
    should_continue = await _auto_check_update_before_start()
    if not should_continue:
        return
    print('[1/4] Starting Tor network runtime...')
    managed_tor = None
    last_tor_error: Exception | None = None
    for attempt in range(1, STARTUP_TOR_RETRIES + 1):
        try:
            managed_tor = await _run_with_status(
                start_or_use_tor,
                f'Starting Tor (attempt {attempt}/{STARTUP_TOR_RETRIES})',
            )
            break
        except Exception as e:
            last_tor_error = e
            print(f'[*] Tor startup failed (attempt {attempt}/{STARTUP_TOR_RETRIES}): {e}')
            if attempt < STARTUP_TOR_RETRIES:
                await asyncio.sleep(STARTUP_RETRY_DELAY_SECONDS)
    if managed_tor is None:
        print(f'[*] Tor could not start: {last_tor_error}')
        print('[*] Please check local Tor/bundled tor files and try again.')
        return
    if managed_tor.process:
        print(f'[*] started bundled Tor on socks {managed_tor.socks_port} / control {managed_tor.control_port}')
        atexit.register(managed_tor.stop)
    else:
        print('[*] using existing local Tor instance')
    if managed_tor.bootstrap_progress is not None:
        print(f'[*] Tor bootstrap: {managed_tor.bootstrap_progress}% ({managed_tor.bootstrap_summary or "unknown"})')
    else:
        print('[*] Tor bootstrap: unknown (will continue and retry in background)')

    print('[2/4] Loading identity and contacts...')
    try:
        signing_key = load_or_create_signing_key(IDENTITY_KEY_FILE)
        contacts = ContactBook(CONTACTS_FILE)
    except Exception as e:
        print(f'[*] failed to load local identity/contacts: {e}')
        managed_tor.stop()
        return

    ui_log: deque[str] = deque(maxlen=500)
    ui_status = {'value': 'ready'}
    ui_dirty = {'value': True}
    ui_state = {'compact': True}
    ephemeral_state = {'enabled': False}
    metadata_state = {
        'profile': 'normal',
        'enabled': True,
        'cover': True,
        'jitter_ms': 120,
        'padding_max': 96,
        'cover_min_s': 22.0,
        'cover_max_s': 46.0,
        'fixed_mode': False,
        'fixed_send_delay_ms': 0,
        'fixed_pad_bytes': 0,
        'fixed_cover_interval_s': 0.0,
    }
    reconnect_state = {'target': None, 'task': None, 'enabled': True}
    rooms = _load_rooms_map()
    active_room = {'name': None}
    room_retry_queue = {'items': _load_room_retry_queue()}
    room_retry_task = {'task': None}
    room_route_refresh_task = {'task': None}
    connection_health_task = {'task': None}
    chat_transcript: list[dict] = []
    room_presence: dict[str, dict[str, dict[str, object]]] = {}
    who_live = {'room': None, 'last_signature': ''}
    connection_health = {'value': 'initializing...'}
    my_id_pub = ''
    my_fp = ''

    def set_status(text: str) -> None:
        if ui_status['value'] != text:
            ui_status['value'] = text
            ui_dirty['value'] = True

    def log_system(text: str) -> None:
        _append_log(ui_log, text, prefix='[*] ')
        set_status(text)

    def _privacy_profile_config(name: str) -> dict[str, object]:
        profile = name.strip().lower()
        if profile == 'hardened':
            return {
                'profile': 'hardened',
                'enabled': True,
                'cover': True,
                'jitter_ms': 260,
                'padding_max': 256,
                'cover_min_s': 14.0,
                'cover_max_s': 24.0,
                'fixed_mode': False,
                'fixed_send_delay_ms': 0,
                'fixed_pad_bytes': 0,
                'fixed_cover_interval_s': 0.0,
            }
        if profile == 'paranoid':
            return {
                'profile': 'paranoid',
                'enabled': True,
                'cover': True,
                'jitter_ms': 0,
                'padding_max': 0,
                'cover_min_s': 12.0,
                'cover_max_s': 12.0,
                'fixed_mode': True,
                'fixed_send_delay_ms': 180,
                'fixed_pad_bytes': 512,
                'fixed_cover_interval_s': 12.0,
            }
        return {
            'profile': 'normal',
            'enabled': True,
            'cover': True,
            'jitter_ms': 120,
            'padding_max': 96,
            'cover_min_s': 22.0,
            'cover_max_s': 46.0,
            'fixed_mode': False,
            'fixed_send_delay_ms': 0,
            'fixed_pad_bytes': 0,
            'fixed_cover_interval_s': 0.0,
        }

    def _is_local_endpoint(identity_pub: str, onion: str) -> bool:
        ident = str(identity_pub).strip()
        if not ident or ident != my_id_pub:
            return False
        try:
            my_onion_norm = normalize_onion(node.my_onion)
        except Exception:
            my_onion_norm = str(node.my_onion).strip().lower()
        try:
            onion_norm = normalize_onion(onion)
        except Exception:
            onion_norm = str(onion).strip().lower()
        if not onion_norm:
            return True
        return onion_norm == my_onion_norm

    def _listed_room_members(room_name: str) -> list[str]:
        room = rooms.get(room_name, {})
        raw_members = room.get('members', []) if isinstance(room, dict) else []
        members: list[str] = []
        if not isinstance(raw_members, list):
            return members
        for item in raw_members:
            if isinstance(item, str) and item.strip() and item.strip() not in members:
                members.append(item.strip())
        return members

    def _presence_key(identity_pub: str, nick: str) -> str:
        ident = str(identity_pub).strip()
        if ident:
            return f'id:{ident}'
        safe_nick = _sanitize_contact_name(nick).lower() or 'anon'
        return f'nick:{safe_nick}'

    def _touch_room_presence(
        room_name: str,
        nick: str,
        *,
        identity_pub: str = '',
        onion: str = '',
    ) -> bool:
        room_norm = _sanitize_room_name(room_name)
        nick_norm = _sanitize_contact_name(nick) or 'anon'
        if not room_norm:
            return False
        now = time.time()
        key = _presence_key(identity_pub, nick_norm)
        room_map = room_presence.setdefault(room_norm, {})
        existing = room_map.get(key)
        changed = existing is None
        entry = {
            'nick': nick_norm,
            'identity_pub': str(identity_pub).strip(),
            'onion': str(onion).strip(),
            'last_seen': now,
        }
        if existing:
            prev_nick = str(existing.get('nick', '')).strip()
            prev_onion = str(existing.get('onion', '')).strip()
            if prev_nick != nick_norm or (entry['onion'] and prev_onion != entry['onion']):
                changed = True
            existing.update(entry)
        else:
            room_map[key] = entry
        return changed

    def _room_presence_rows(room_name: str) -> list[dict[str, object]]:
        room_norm = _sanitize_room_name(room_name)
        now = time.time()
        rows: list[dict[str, object]] = []
        listed = _listed_room_members(room_norm)
        for peer in room_presence.get(room_norm, {}).values():
            if not isinstance(peer, dict):
                continue
            nick = str(peer.get('nick', '')).strip() or 'anon'
            last_seen = float(peer.get('last_seen', 0.0) or 0.0)
            age = max(0.0, now - last_seen)
            if age > ROOM_IDLE_WINDOW_SECONDS:
                continue
            state = 'online' if age <= ROOM_ONLINE_WINDOW_SECONDS else 'idle'
            rows.append(
                {
                    'nick': nick,
                    'state': state,
                    'age': int(age),
                    'source': 'seen',
                }
            )
        present_nicks = {str(item.get('nick', '')).strip() for item in rows}
        for member in listed:
            if member in present_nicks:
                continue
            rows.append(
                {
                    'nick': member,
                    'state': 'known',
                    'age': -1,
                    'source': 'member',
                }
            )
        if node.my_nick not in present_nicks:
            rows.append(
                {
                    'nick': node.my_nick,
                    'state': 'online',
                    'age': 0,
                    'source': 'self',
                }
            )
        rows.sort(key=lambda item: str(item.get('nick', '')).lower())
        return rows

    def _who_signature(room_name: str) -> str:
        parts: list[str] = []
        for row in _room_presence_rows(room_name):
            parts.append(f'{row.get("nick")}:{row.get("state")}')
        return '|'.join(parts)

    def _emit_who_snapshot(room_name: str, *, live: bool = False) -> None:
        room_norm = _sanitize_room_name(room_name)
        rows = _room_presence_rows(room_norm)
        if not rows:
            _append_log(ui_log, f'no users in room {room_norm}', prefix='[*] ')
            ui_dirty['value'] = True
            return
        pieces: list[str] = []
        for row in rows:
            nick = str(row.get('nick', '?'))
            state = str(row.get('state', 'known'))
            age = int(row.get('age', -1))
            if age >= 0:
                pieces.append(f'@{nick}({state},{age}s)')
            else:
                pieces.append(f'@{nick}({state})')
        head = 'who-live' if live else 'who'
        _append_log(ui_log, f'{head} {room_norm}: ' + ' '.join(pieces), prefix='[*] ')
        _append_log(ui_log, f'{len(rows)} user(s) in room {room_norm}', prefix='[*] ')
        ui_dirty['value'] = True

    def _maybe_emit_live_who(room_name: str) -> None:
        room_norm = _sanitize_room_name(room_name)
        if not room_norm or who_live.get('room') != room_norm:
            return
        signature = _who_signature(room_norm)
        if signature == who_live.get('last_signature'):
            return
        who_live['last_signature'] = signature
        _emit_who_snapshot(room_norm, live=True)

    def log_chat(nick: str, text: str) -> None:
        _append_log(ui_log, f'<{nick}> {text}', prefix='')
        if not ephemeral_state['enabled']:
            chat_transcript.append(
                {
                    'ts': int(time.time()),
                    'nick': nick,
                    'text': text,
                    'peer': _infer_peer_contact_name(node, contacts),
                    'direction': 'out' if nick == node.my_nick else 'in',
                }
            )
        ui_dirty['value'] = True

    def log_room(
        nick: str,
        room_name: str,
        text: str,
        peer_onion: str = '',
        peer_identity_pub_b64: str = '',
    ) -> None:
        identity_for_presence = peer_identity_pub_b64
        onion_for_presence = peer_onion
        if nick == node.my_nick and not identity_for_presence:
            identity_for_presence = my_id_pub
            onion_for_presence = node.my_onion
        if _touch_room_presence(
            room_name,
            nick,
            identity_pub=identity_for_presence,
            onion=onion_for_presence,
        ):
            _maybe_emit_live_who(room_name)
        _append_log(ui_log, f'[{room_name}] <{nick}> {text}', prefix='')
        if not ephemeral_state['enabled']:
            chat_transcript.append(
                {
                    'ts': int(time.time()),
                    'room': room_name,
                    'nick': nick,
                    'text': text,
                    'direction': 'out' if nick == node.my_nick else 'in',
                }
            )
        # Learn peer route from inbound room traffic so room delivery becomes bidirectional without contacts.
        if (
            peer_onion
            and peer_identity_pub_b64
            and not _is_local_endpoint(peer_identity_pub_b64, peer_onion)
            and room_name in rooms
        ):
            try:
                peer = {
                    'name': _sanitize_contact_name(nick) or 'peer',
                    'onion': normalize_onion(peer_onion),
                    'identity_pub': normalize_identity_pub(peer_identity_pub_b64),
                    'fingerprint': identity_fingerprint(peer_identity_pub_b64),
                }
                if _upsert_room_peer(room_name, peer):
                    _save_rooms_map(rooms)
            except Exception:
                pass
        ui_dirty['value'] = True

    def on_connect(session: Session) -> None:
        ui_log.clear()
        chat_transcript.clear()
        _append_log(ui_log, f'Connected: {session.peer_name} as "{session.peer_nick}"', prefix='[*] ')
        _append_log(ui_log, f'Verify code: {session.sas_code}   (check with friend via other channel)', prefix='[*] ')
        _append_log(ui_log, 'Type message and press Enter. Use /part to disconnect.', prefix='[*] ')
        set_status(f'connected to {session.peer_name} ({session.peer_nick})')

    def cancel_reconnect() -> None:
        task = reconnect_state.get('task')
        if task and not task.done():
            task.cancel()
        reconnect_state['task'] = None

    def _persist_room_queue() -> None:
        _save_room_retry_queue(room_retry_queue['items'])

    def _rewrite_local_state_now() -> None:
        contacts.save()
        _save_rooms_map(rooms)
        _save_room_retry_queue(room_retry_queue['items'])
        if not HISTORY_FILE.exists():
            return
        if state_encryption_enabled():
            history_obj = load_json(HISTORY_FILE, default=[])
            if isinstance(history_obj, list):
                save_json(HISTORY_FILE, history_obj)
                return
            legacy = _read_plain_history_jsonl(HISTORY_FILE)
            if legacy:
                save_json(HISTORY_FILE, legacy)
            return
        history_obj = load_json(HISTORY_FILE, default=[])
        if isinstance(history_obj, list):
            _write_plain_history_jsonl(HISTORY_FILE, history_obj)

    def _enqueue_room_retry(
        room_name: str,
        target_name: str,
        text: str,
        error: str,
        *,
        target_onion: str = '',
        target_identity_pub: str = '',
    ) -> None:
        for item in room_retry_queue['items']:
            if (
                item.get('room') == room_name
                and item.get('target_name') == target_name
                and item.get('text') == text
                and str(item.get('target_identity_pub', '')).strip() == target_identity_pub.strip()
            ):
                item['last_error'] = error
                item['next_try_ts'] = min(float(item.get('next_try_ts', time.time())), time.time() + 4.0)
                _persist_room_queue()
                return
        room_retry_queue['items'].append(
            {
                'room': room_name,
                'target_name': target_name,
                'target_onion': target_onion,
                'target_identity_pub': target_identity_pub,
                'text': text,
                'created_at': int(time.time()),
                'attempts': 0,
                'next_try_ts': time.time() + 4.0,
                'last_error': error,
            }
        )
        # avoid unbounded growth in long sessions
        if len(room_retry_queue['items']) > 1000:
            room_retry_queue['items'] = room_retry_queue['items'][-1000:]
        _persist_room_queue()

    async def room_retry_worker() -> None:
        while True:
            if not room_retry_queue['items']:
                await asyncio.sleep(1.5)
                continue
            now = time.time()
            updated = False
            for item in list(room_retry_queue['items']):
                if float(item.get('next_try_ts', 0.0)) > now:
                    continue
                room_name = _sanitize_room_name(str(item.get('room', '')))
                target_name = str(item.get('target_name', '')).strip()
                target_onion_raw = str(item.get('target_onion', '')).strip()
                target_identity_raw = str(item.get('target_identity_pub', '')).strip()
                text = str(item.get('text', ''))
                attempts = int(item.get('attempts', 0) or 0)
                if not room_name or not target_name or not text:
                    room_retry_queue['items'].remove(item)
                    updated = True
                    continue
                contact = None
                if target_identity_raw:
                    by_identity = contacts.by_identity(target_identity_raw)
                    if by_identity:
                        contact = by_identity
                if contact is None and target_name:
                    by_name = contacts.by_name(target_name)
                    if by_name:
                        contact = by_name
                if contact is None and target_onion_raw and target_identity_raw:
                    try:
                        normalized_onion = normalize_onion(target_onion_raw)
                        normalized_identity = normalize_identity_pub(target_identity_raw)
                        contact = Contact(
                            name=target_name or f'peer-{normalized_identity[:8]}',
                            onion=normalized_onion,
                            identity_pub_b64=normalized_identity,
                            fingerprint=identity_fingerprint(normalized_identity),
                            trusted=True,
                        )
                    except Exception:
                        contact = None
                if not contact:
                    room_retry_queue['items'].remove(item)
                    _append_log(ui_log, f'room retry dropped: {target_name} missing peer route', prefix='[*] ')
                    ui_dirty['value'] = True
                    updated = True
                    continue
                if not contact.trusted:
                    contact = Contact(
                        name=contact.name,
                        onion=contact.onion,
                        identity_pub_b64=contact.identity_pub_b64,
                        fingerprint=contact.fingerprint,
                        trusted=True,
                    )
                try:
                    await node.send_message_to_contact(contact, text, room_name)
                    _mark_room_peer_result(room_name, contact.identity_pub_b64, ok=True)
                    room_retry_queue['items'].remove(item)
                    _append_log(ui_log, f'room retry delivered: {room_name} -> {target_name}', prefix='[*] ')
                    ui_dirty['value'] = True
                    updated = True
                except Exception as e:
                    _mark_room_peer_result(room_name, contact.identity_pub_b64, ok=False, error=str(e))
                    attempts += 1
                    if attempts >= 12:
                        room_retry_queue['items'].remove(item)
                        _append_log(ui_log, f'room retry gave up: {room_name} -> {target_name}: {e}', prefix='[*] ')
                        ui_dirty['value'] = True
                        updated = True
                        continue
                    delay = min(120, 3 * attempts)
                    item['attempts'] = attempts
                    item['next_try_ts'] = time.time() + delay
                    item['last_error'] = str(e)
                    updated = True
            if updated:
                _persist_room_queue()
            await asyncio.sleep(1.0)

    async def room_route_refresh_worker() -> None:
        while True:
            await asyncio.sleep(18.0)
            room_name = active_room.get('name')
            if not room_name or room_name not in rooms:
                continue
            peers = _sorted_room_peers(room_name)
            if not peers:
                continue
            now = int(time.time())
            stale = [
                p
                for p in peers
                if max(int(p.get('last_try', 0) or 0), int(p.get('last_ok', 0) or 0)) < (now - 40)
            ]
            to_probe = stale[:2] if stale else peers[:1]
            for peer in to_probe:
                onion = str(peer.get('onion', '')).strip()
                identity_pub = str(peer.get('identity_pub', '')).strip()
                peer_name = str(peer.get('name', '')).strip() or 'peer'
                if not onion or not identity_pub:
                    continue
                try:
                    sock = await asyncio.to_thread(socks5_connect, onion, 80, 8)
                    sock.close()
                    _mark_room_peer_result(room_name, identity_pub, ok=True)
                    if _touch_room_presence(room_name, peer_name, identity_pub=identity_pub, onion=onion):
                        _maybe_emit_live_who(room_name)
                except Exception as e:
                    _mark_room_peer_result(room_name, identity_pub, ok=False, error=str(e))
            routes = len(_room_peers(room_name))
            set_status(f'room {room_name}: routes={routes} | best={_best_routes_summary(room_name)}')

    async def reconnect_worker(target_name: str) -> None:
        attempt = 0
        while reconnect_state['enabled'] and reconnect_state.get('target') == target_name and node.session is None:
            delay = RECONNECT_DELAYS[min(attempt, len(RECONNECT_DELAYS) - 1)]
            if delay > 0:
                set_status(f'auto-reconnect in {delay}s...')
                await asyncio.sleep(delay)
            contact = contacts.by_name(target_name)
            if not contact or not contact.trusted:
                log_system(f'auto-reconnect stopped: contact "{target_name}" missing/untrusted')
                reconnect_state['target'] = None
                return
            if REQUIRE_VERIFIED_CONTACTS and not getattr(contact, 'verified', False):
                log_system(f'auto-reconnect stopped: contact "{target_name}" not verified')
                reconnect_state['target'] = None
                return
            try:
                await node.connect(contact)
                log_system(f'auto-reconnected to {target_name}')
                return
            except Exception as e:
                log_system(f'auto-reconnect attempt {attempt + 1} failed: {e}')
                attempt += 1
        reconnect_state['task'] = None

    def schedule_reconnect(target_name: str) -> None:
        if not reconnect_state['enabled']:
            return
        reconnect_state['target'] = target_name
        task = reconnect_state.get('task')
        if task and not task.done():
            return
        reconnect_state['task'] = asyncio.create_task(reconnect_worker(target_name))

    def on_disconnect(session: Session) -> None:
        contact = contacts.by_identity(session.peer_identity_pub_b64)
        if not contact or not contact.trusted:
            return
        log_system(f'connection lost with {contact.name}; starting auto-reconnect')
        schedule_reconnect(contact.name)

    node = ChatNode(
        my_onion='pending.onion',
        signing_key=signing_key,
        contacts=contacts,
        history_path=HISTORY_FILE,
        my_nick=_default_nick(),
        history_enabled=ENABLE_HISTORY,
        metadata_protection=metadata_state['enabled'],
        send_jitter_max_ms=metadata_state['jitter_ms'],
        cover_traffic_enabled=metadata_state['cover'],
        cover_min_seconds=metadata_state['cover_min_s'],
        cover_max_seconds=metadata_state['cover_max_s'],
        payload_padding_max_bytes=metadata_state['padding_max'],
        fixed_traffic_shaping=metadata_state['fixed_mode'],
        fixed_send_delay_ms=metadata_state['fixed_send_delay_ms'],
        fixed_pad_bytes=metadata_state['fixed_pad_bytes'],
        fixed_cover_interval_seconds=metadata_state['fixed_cover_interval_s'],
        require_verified_contacts=REQUIRE_VERIFIED_CONTACTS,
        on_system=log_system,
        on_chat=log_chat,
        on_room=log_room,
        on_connect=on_connect,
        on_disconnect=on_disconnect,
    )

    def _apply_privacy_profile(profile_name: str, *, announce: bool = True) -> None:
        cfg = _privacy_profile_config(profile_name)
        metadata_state.update(cfg)
        node.metadata_protection = bool(metadata_state['enabled'])
        node.cover_traffic_enabled = bool(metadata_state['cover'])
        node.send_jitter_max_ms = int(metadata_state['jitter_ms'])
        node.payload_padding_max_bytes = int(metadata_state['padding_max'])
        node.cover_min_seconds = float(metadata_state['cover_min_s'])
        node.cover_max_seconds = float(metadata_state['cover_max_s'])
        node.fixed_traffic_shaping = bool(metadata_state['fixed_mode'])
        node.fixed_send_delay_ms = int(metadata_state['fixed_send_delay_ms'])
        node.fixed_pad_bytes = int(metadata_state['fixed_pad_bytes'])
        node.fixed_cover_interval_seconds = float(metadata_state['fixed_cover_interval_s'])
        if announce:
            log_system(
                'privacy profile set: '
                f'{metadata_state["profile"]} '
                f'(fixed={node.fixed_traffic_shaping}, '
                f'jitter={node.send_jitter_max_ms}ms, '
                f'pad_max={node.payload_padding_max_bytes}, '
                f'fixed_pad={node.fixed_pad_bytes})'
            )

    _apply_privacy_profile(metadata_state['profile'], announce=False)

    async def _run_resilient_worker(name: str, worker_coro) -> None:
        while True:
            try:
                await worker_coro()
                return
            except asyncio.CancelledError:
                raise
            except Exception as e:
                _append_log(ui_log, f'{name} worker crashed: {e}; restarting...', prefix='[*] ')
                ui_dirty['value'] = True
                await asyncio.sleep(WORKER_RESTART_DELAY_SECONDS)

    print('[3/4] Opening local chat listener...')
    try:
        local_port = await node.start_listener()
    except Exception as e:
        print(f'[*] failed to open local listener: {e}')
        managed_tor.stop()
        return
    print('[4/4] Publishing onion endpoint...')
    service_id = None
    last_onion_error: Exception | None = None
    for attempt in range(1, STARTUP_ONION_RETRIES + 1):
        try:
            service_id, _, _ = await _run_with_status(
                lambda: create_or_resume_onion(local_port, ONION_KEY_FILE),
                f'Publishing onion service (attempt {attempt}/{STARTUP_ONION_RETRIES})',
            )
            break
        except Exception as e:
            last_onion_error = e
            print(f'[*] onion publish failed (attempt {attempt}/{STARTUP_ONION_RETRIES}): {e}')
            if attempt < STARTUP_ONION_RETRIES:
                await asyncio.sleep(STARTUP_RETRY_DELAY_SECONDS)
    if not service_id:
        print(f'[*] could not publish onion service: {last_onion_error}')
        managed_tor.stop()
        return
    node.my_onion = f'{service_id}.onion'
    print('[*] Onion endpoint created (network propagation may take ~30-90s on fresh start)')

    my_id_pub = identity_pub_b64(signing_key)
    my_fp = identity_fingerprint(my_id_pub)

    await _run_first_run_wizard(node, contacts, my_id_pub, log_system)
    log_system('ready')
    _append_log(ui_log, 'type /help to open command reference in a separate window', prefix='[*] ')
    room_retry_task['task'] = asyncio.create_task(_run_resilient_worker('room retry', room_retry_worker))
    room_route_refresh_task['task'] = asyncio.create_task(
        _run_resilient_worker('room route refresh', room_route_refresh_worker)
    )
    pending_retry = len(room_retry_queue['items'])
    if pending_retry:
        _append_log(ui_log, f'room retry queue restored: {pending_retry} pending item(s)', prefix='[*] ')
        ui_dirty['value'] = True

    def _room_members(room_name: str) -> list[str]:
        room = rooms.get(room_name, {})
        members = room.get('members', []) if isinstance(room, dict) else []
        return [m for m in members if isinstance(m, str) and m.strip()]

    def _room_peers(room_name: str) -> list[dict[str, object]]:
        room = rooms.get(room_name, {})
        raw_peers = room.get('peers', []) if isinstance(room, dict) else []
        peers: list[dict[str, object]] = []
        if not isinstance(raw_peers, list):
            return peers
        for item in raw_peers:
            if not isinstance(item, dict):
                continue
            name = str(item.get('name', '')).strip()
            onion_raw = str(item.get('onion', '')).strip()
            identity_raw = str(item.get('identity_pub', '')).strip()
            if not name or not onion_raw or not identity_raw:
                continue
            try:
                onion = normalize_onion(onion_raw)
                identity_pub = normalize_identity_pub(identity_raw)
            except ValueError:
                continue
            if any(existing.get('identity_pub') == identity_pub for existing in peers):
                continue
            try:
                score = int(item.get('score', 50) or 50)
            except Exception:
                score = 50
            score = max(0, min(100, score))
            def _safe_int(field: str) -> int:
                try:
                    return max(0, int(item.get(field, 0) or 0))
                except Exception:
                    return 0
            peers.append(
                {
                    'name': name,
                    'onion': onion,
                    'identity_pub': identity_pub,
                    'fingerprint': str(item.get('fingerprint', '')).strip(),
                    'score': score,
                    'last_ok': _safe_int('last_ok'),
                    'last_try': _safe_int('last_try'),
                    'last_fail': _safe_int('last_fail'),
                    'fail_count': _safe_int('fail_count'),
                }
            )
        return peers

    def _upsert_room_peer(room_name: str, peer: dict[str, object]) -> bool:
        room = rooms.setdefault(room_name, {'members': [], 'peers': [], 'created_at': int(time.time()), 'topic': ''})
        if not isinstance(room.get('peers'), list):
            room['peers'] = []
        identity_pub = str(peer.get('identity_pub', '')).strip()
        if not identity_pub:
            return False
        for existing in room['peers']:
            if not isinstance(existing, dict):
                continue
            if str(existing.get('identity_pub', '')).strip() == identity_pub:
                updated = False
                for field in ('name', 'onion', 'fingerprint'):
                    value = str(peer.get(field, '')).strip()
                    if value and str(existing.get(field, '')).strip() != value:
                        existing[field] = value
                        updated = True
                for field, default in (('score', 50), ('last_ok', 0), ('last_try', 0), ('last_fail', 0), ('fail_count', 0)):
                    if field in peer:
                        try:
                            value = int(peer.get(field, default) or default)
                        except Exception:
                            value = default
                        if field == 'score':
                            value = max(0, min(100, value))
                        else:
                            value = max(0, value)
                        if int(existing.get(field, default) or default) != value:
                            existing[field] = value
                            updated = True
                existing.setdefault('score', 50)
                existing.setdefault('last_ok', 0)
                existing.setdefault('last_try', 0)
                existing.setdefault('last_fail', 0)
                existing.setdefault('fail_count', 0)
                return updated
        def _safe_int(value, default: int) -> int:
            try:
                return int(value if value is not None else default)
            except Exception:
                return default
        room['peers'].append(
            {
                'name': str(peer.get('name', '')).strip(),
                'onion': str(peer.get('onion', '')).strip(),
                'identity_pub': identity_pub,
                'fingerprint': str(peer.get('fingerprint', '')).strip(),
                'score': max(0, min(100, _safe_int(peer.get('score', 50), 50))),
                'last_ok': max(0, _safe_int(peer.get('last_ok', 0), 0)),
                'last_try': max(0, _safe_int(peer.get('last_try', 0), 0)),
                'last_fail': max(0, _safe_int(peer.get('last_fail', 0), 0)),
                'fail_count': max(0, _safe_int(peer.get('fail_count', 0), 0)),
            }
        )
        return True

    def _room_roster(room_name: str) -> list[str]:
        roster: list[str] = [f'@{node.my_nick}']
        for member_name in _room_members(room_name):
            if member_name == node.my_nick:
                continue
            if member_name not in roster:
                roster.append(member_name)
        for peer in _room_peers(room_name):
            peer_name = str(peer.get('name', '')).strip()
            if peer_name and peer_name not in roster:
                roster.append(peer_name)
        return roster

    def _sorted_room_peers(room_name: str) -> list[dict[str, object]]:
        peers = _room_peers(room_name)
        peers.sort(
            key=lambda p: (
                -int(p.get('score', 50) or 50),
                -int(p.get('last_ok', 0) or 0),
                str(p.get('name', '')).lower(),
            )
        )
        return peers

    def _mark_room_peer_result(room_name: str, identity_pub: str, *, ok: bool, error: str = '') -> None:
        room_norm = _sanitize_room_name(room_name)
        if not room_norm:
            return
        room = rooms.get(room_norm)
        if not isinstance(room, dict):
            return
        peers = room.get('peers')
        if not isinstance(peers, list):
            return
        now = int(time.time())
        changed = False
        for peer in peers:
            if not isinstance(peer, dict):
                continue
            if str(peer.get('identity_pub', '')).strip() != identity_pub:
                continue
            try:
                score = int(peer.get('score', 50) or 50)
            except Exception:
                score = 50
            try:
                fail_count = int(peer.get('fail_count', 0) or 0)
            except Exception:
                fail_count = 0
            peer['last_try'] = now
            if ok:
                peer['last_ok'] = now
                peer['fail_count'] = 0
                peer.pop('last_error', None)
                score = min(100, score + 10)
            else:
                peer['last_fail'] = now
                peer['fail_count'] = max(0, fail_count) + 1
                if error:
                    peer['last_error'] = error[:200]
                score = max(0, score - min(20, 4 + max(0, fail_count)))
            if int(peer.get('score', 50) or 50) != score:
                peer['score'] = score
            changed = True
            break
        if changed:
            _save_rooms_map(rooms)

    def _best_routes_summary(room_name: str, limit: int = 5) -> str:
        peers = _sorted_room_peers(room_name)[:limit]
        if not peers:
            return 'none'
        parts: list[str] = []
        for peer in peers:
            name = str(peer.get('name', 'peer')).strip() or 'peer'
            score = int(peer.get('score', 50) or 50)
            parts.append(f'{name}:{score}')
        return ', '.join(parts)

    def _room_topic(room_name: str) -> str:
        room = rooms.get(room_name, {})
        if not isinstance(room, dict):
            return ''
        raw = room.get('topic', '')
        if not isinstance(raw, str):
            return ''
        return raw.strip()

    def _set_room_topic(room_name: str, topic_text: str) -> str:
        room_norm = _sanitize_room_name(room_name)
        if not room_norm:
            raise ValueError('invalid room name')
        room = rooms.setdefault(room_norm, {'members': [], 'peers': [], 'created_at': int(time.time()), 'topic': ''})
        normalized = topic_text.strip()[:180]
        room['topic'] = normalized
        _save_rooms_map(rooms)
        return normalized

    def _refresh_connection_health_text() -> str:
        try:
            socks_ok, _ = _is_tcp_open(get_tor_socks_host(), get_tor_socks_port(), timeout=0.5)
        except Exception:
            socks_ok = False
        retry_count = len(room_retry_queue['items'])
        session_ok = node.session is not None
        active = active_room.get('name')
        room_peers = _room_peers(active) if active else []
        routes = len(room_peers)
        healthy_routes = sum(1 for p in room_peers if int(p.get('score', 50) or 50) >= 60)
        best_routes = _best_routes_summary(active) if active else 'none'

        score = 100
        if not socks_ok:
            score -= 55
        if session_ok:
            score += 10
        elif not active:
            score -= 8
        if active and routes == 0:
            score -= 22
        elif active and healthy_routes == 0:
            score -= 12
        if retry_count:
            score -= min(30, retry_count * 3)

        if score >= 80:
            grade = 'good'
        elif score >= 50:
            grade = 'fair'
        else:
            grade = 'poor'
        return (
            f'{grade} | tor:{"ok" if socks_ok else "down"} | '
            f'session:{"up" if session_ok else "down"} | '
            f'room_routes:{routes} ({healthy_routes} healthy) | '
            f'best:{best_routes} | retry:{retry_count}'
        )

    async def connection_health_worker() -> None:
        while True:
            health = await asyncio.to_thread(_refresh_connection_health_text)
            if health != connection_health['value']:
                connection_health['value'] = health
                ui_dirty['value'] = True
            watch_room = who_live.get('room')
            if isinstance(watch_room, str) and watch_room:
                signature = _who_signature(watch_room)
                if signature != who_live.get('last_signature'):
                    who_live['last_signature'] = signature
                    _emit_who_snapshot(watch_room, live=True)
            await asyncio.sleep(3.0)

    async def _send_to_room(room_name: str, text: str) -> tuple[int, list[str]]:
        targets_by_endpoint: dict[tuple[str, str], Contact] = {}
        skipped: list[str] = []
        for name in _room_members(room_name):
            contact = contacts.by_name(name)
            if not contact:
                skipped.append(f'missing contact: {name}')
                continue
            if REQUIRE_VERIFIED_CONTACTS and (not contact.trusted or not getattr(contact, 'verified', False)):
                skipped.append(f'unverified contact: {name}')
                continue
            if _is_local_endpoint(contact.identity_pub_b64, contact.onion):
                continue
            key = (contact.identity_pub_b64, normalize_onion(contact.onion))
            targets_by_endpoint[key] = Contact(
                name=contact.name,
                onion=contact.onion,
                identity_pub_b64=contact.identity_pub_b64,
                fingerprint=contact.fingerprint,
                trusted=True,
            )
        for peer in _sorted_room_peers(room_name):
            identity_pub = str(peer.get('identity_pub', '')).strip()
            onion = str(peer.get('onion', '')).strip()
            name = str(peer.get('name', '')).strip() or 'peer'
            if not identity_pub or not onion:
                continue
            if _is_local_endpoint(identity_pub, onion):
                continue
            onion_norm = normalize_onion(onion)
            key = (identity_pub, onion_norm)
            if key in targets_by_endpoint:
                continue
            targets_by_endpoint[key] = Contact(
                name=name,
                onion=onion,
                identity_pub_b64=identity_pub,
                fingerprint=str(peer.get('fingerprint', '')).strip() or identity_fingerprint(identity_pub),
                trusted=True,
            )

        targets = list(targets_by_endpoint.values())
        if not targets:
            return 0, skipped or ['no routable room peers']

        tasks = [node.send_message_to_contact(c, text, room_name) for c in targets]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        ok = 0
        errors = list(skipped)
        for contact, result in zip(targets, results):
            if isinstance(result, Exception):
                _mark_room_peer_result(room_name, contact.identity_pub_b64, ok=False, error=str(result))
                _enqueue_room_retry(
                    room_name,
                    contact.name,
                    text,
                    str(result),
                    target_onion=contact.onion,
                    target_identity_pub=contact.identity_pub_b64,
                )
                errors.append(f'{contact.name}: queued retry ({result})')
            else:
                _mark_room_peer_result(room_name, contact.identity_pub_b64, ok=True)
                ok += 1
        return ok, errors

    connection_health['value'] = await asyncio.to_thread(_refresh_connection_health_text)
    connection_health_task['task'] = asyncio.create_task(
        _run_resilient_worker('connection health', connection_health_worker)
    )

    async def process_line(line: str) -> bool:
        stripped = line.strip()
        if not stripped:
            return True

        lowered = stripped.lower()
        if lowered in ('/cls', '/clear'):
            ui_log.clear()
            set_status('screen cleared')
            return True

        if not stripped.startswith('/'):
            if active_room['name']:
                sent, errors = await _send_to_room(active_room['name'], stripped)
                if sent > 0:
                    log_room(node.my_nick, active_room['name'], stripped)
                    set_status(f'room {active_room["name"]}: sent to {sent} peer(s)')
                if errors:
                    for err in errors[:10]:
                        _append_log(ui_log, f'room delivery issue: {err}', prefix='[*] ')
                    ui_dirty['value'] = True
                return True
            had_session = node.session is not None
            try:
                await node.send_message(stripped)
            except Exception as e:
                log_system(f'send failed: {e}')
                return True
            if had_session and node.session is not None:
                log_chat(node.my_nick, stripped)
            return True

        try:
            parts = shlex.split(stripped)
        except ValueError as e:
            log_system(f'parse error: {e}')
            return True

        cmd = parts[0]
        alias_map = {
            '/h': '/help',
            '/w': '/me',
            '/whoami': '/me',
            '/n': '/nick',
            '/j': '/join',
            '/list': '/rooms',
            '/leave': '/part',
            '/ver': '/version',
            '/update': '/check-update',
            '/r': '/reconnect',
            '/traffic': '/privacy',
            '/q': '/quit',
        }
        cmd = alias_map.get(cmd, cmd)
        if cmd == '/help':
            inline = len(parts) > 1 and parts[1].lower() in ('inline', '--inline')
            if inline:
                _append_log(ui_log, HELP, prefix='')
                ui_dirty['value'] = True
            else:
                if _open_help_window(HELP):
                    log_system('help opened in new window')
                else:
                    _append_log(ui_log, HELP, prefix='')
                    ui_dirty['value'] = True
        elif cmd == '/version':
            _append_log(ui_log, f'version: {APP_VERSION}', prefix='[*] ')
            _append_log(ui_log, f'build: {APP_BUILD}', prefix='[*] ')
            ui_dirty['value'] = True
        elif cmd == '/check-update':
            try:
                positional, flags = _parse_cli_tokens(parts[1:], bool_flags={'--yes'})
            except ValueError as e:
                log_system(str(e))
                _append_log(ui_log, 'usage: /check-update [--yes]', prefix='[*] ')
                ui_dirty['value'] = True
                return True
            if positional:
                log_system('usage: /check-update [--yes]')
                return True
            auto_yes = bool(flags.get('--yes'))
            set_status('checking updates...')
            try:
                info, has_update = await asyncio.to_thread(
                    check_for_update,
                    current_version=APP_VERSION,
                    manifest_url=None,
                    require_signed=True,
                    timeout=20.0,
                )
            except UpdateError as e:
                log_system(f'update check failed: {e}')
                return True
            except Exception as e:
                log_system(f'update check failed: {e}')
                return True
            if not has_update:
                log_system(f'already latest version ({APP_VERSION})')
                return True

            _append_log(ui_log, f'new version available: {info.version}', prefix='[*] ')
            _append_log(
                ui_log,
                f'manifest signature: {"verified" if info.manifest_signed else "unsigned"}',
                prefix='[*] ',
            )
            if info.notes:
                _append_log(ui_log, f'notes: {info.notes}', prefix='[*] ')
            ui_dirty['value'] = True

            apply_now = auto_yes
            if not apply_now:
                print()
                apply_now = await _prompt_yes_no(f'Update to {info.version}?', default_yes=True)
            if not apply_now:
                log_system('update skipped')
                return True

            log_system('starting updater...')
            try:
                result = await asyncio.to_thread(apply_self_update, info, 120.0)
            except UpdateError as e:
                log_system(f'update failed: {e}')
                return True
            except Exception as e:
                log_system(f'update failed: {e}')
                return True
            log_system(result.message)
            if result.restart_required:
                return False
            ui_dirty['value'] = True
        elif cmd == '/me':
            _append_log(ui_log, f'nick: {node.my_nick}', prefix='[*] ')
            _append_log(ui_log, f'onion: {node.my_onion}', prefix='[*] ')
            _append_log(ui_log, f'identity_pub: {my_id_pub}', prefix='[*] ')
            _append_log(ui_log, f'fingerprint: {my_fp}', prefix='[*] ')
            _append_log(ui_log, f'message_cipher_preferred: {SESSION_CIPHER_AEAD}', prefix='[*] ')
            _append_log(ui_log, f'encrypted_only_mode: {ENCRYPTED_ONLY}', prefix='[*] ')
            _append_log(ui_log, f'metadata_protection: {node.metadata_protection}', prefix='[*] ')
            _append_log(ui_log, f'cover_traffic_enabled: {node.cover_traffic_enabled}', prefix='[*] ')
            _append_log(ui_log, f'privacy_profile: {metadata_state["profile"]}', prefix='[*] ')
            _append_log(ui_log, f'send_jitter_max_ms: {node.send_jitter_max_ms}', prefix='[*] ')
            _append_log(ui_log, f'payload_padding_max_bytes: {node.payload_padding_max_bytes}', prefix='[*] ')
            _append_log(ui_log, f'fixed_traffic_shaping: {node.fixed_traffic_shaping}', prefix='[*] ')
            _append_log(ui_log, f'fixed_send_delay_ms: {node.fixed_send_delay_ms}', prefix='[*] ')
            _append_log(ui_log, f'fixed_pad_bytes: {node.fixed_pad_bytes}', prefix='[*] ')
            _append_log(ui_log, f'fixed_cover_interval_seconds: {node.fixed_cover_interval_seconds}', prefix='[*] ')
            _append_log(ui_log, f'ephemeral_mode: {ephemeral_state["enabled"]}', prefix='[*] ')
            _append_log(ui_log, f'device_lock_enabled: {DEVICE_LOCK_FILE.exists()}', prefix='[*] ')
            _append_log(ui_log, f'local_state_encryption: {state_encryption_enabled()}', prefix='[*] ')
            _append_log(ui_log, f'require_verified_contacts: {REQUIRE_VERIFIED_CONTACTS}', prefix='[*] ')
            _append_log(ui_log, f'rekey_policy: {REKEY_AFTER_MESSAGES} msgs / {REKEY_AFTER_SECONDS}s', prefix='[*] ')
            _append_log(ui_log, f'version: {APP_VERSION}', prefix='[*] ')
            _append_log(ui_log, f'build: {APP_BUILD}', prefix='[*] ')
            _append_log(ui_log, f'share_code: {make_share_code(node.my_onion, my_id_pub)}', prefix='[*] ')
            ui_dirty['value'] = True
        elif cmd == '/ephemeral':
            if len(parts) == 1 or (len(parts) == 2 and parts[1].lower() == 'status'):
                state = 'on' if ephemeral_state['enabled'] else 'off'
                log_system(f'ephemeral mode: {state}')
                return True
            if len(parts) != 2 or parts[1].lower() not in ('on', 'off'):
                log_system('usage: /ephemeral [on|off|status]')
                return True
            enable = parts[1].lower() == 'on'
            ephemeral_state['enabled'] = enable
            node.history_enabled = (not enable) and ENABLE_HISTORY
            if enable:
                chat_transcript.clear()
                try:
                    if HISTORY_FILE.exists():
                        HISTORY_FILE.unlink()
                except OSError:
                    pass
            log_system(f'ephemeral mode {"enabled" if enable else "disabled"}')
            return True
        elif cmd == '/privacy':
            if len(parts) == 1 or (len(parts) == 2 and parts[1].lower() == 'status'):
                log_system(
                    f'privacy profile: {metadata_state["profile"]} '
                    f'(fixed={node.fixed_traffic_shaping}, '
                    f'jitter={node.send_jitter_max_ms}ms, '
                    f'pad_max={node.payload_padding_max_bytes}, fixed_pad={node.fixed_pad_bytes})'
                )
                return True
            if len(parts) != 2 or parts[1].lower() not in ('normal', 'hardened', 'paranoid'):
                log_system('usage: /privacy [normal|hardened|paranoid|status]')
                return True
            _apply_privacy_profile(parts[1].lower(), announce=True)
            return True
        elif cmd == '/lock':
            if len(parts) == 1 or (len(parts) == 2 and parts[1].lower() == 'status'):
                log_system(f'device lock: {"enabled" if DEVICE_LOCK_FILE.exists() else "disabled"}')
                log_system(f'local state encryption: {"enabled" if state_encryption_enabled() else "disabled"}')
                return True
            if len(parts) != 2 or parts[1].lower() not in ('set', 'off'):
                log_system('usage: /lock <set|off|status>')
                return True
            if parts[1].lower() == 'set':
                password = await _prompt_password_with_confirm('New lock password: ')
                if not password.strip():
                    log_system('lock cancelled: password required')
                    return True
                try:
                    _write_device_lock(password)
                except Exception as e:
                    log_system(f'lock set failed: {e}')
                    return True
                _configure_local_state_encryption(password)
                _rewrite_local_state_now()
                log_system('device lock enabled')
                log_system('local state encryption enabled')
                return True
            # off
            if not DEVICE_LOCK_FILE.exists():
                log_system('device lock already disabled')
                return True
            password = await _prompt_password('Current lock password: ')
            if not password:
                log_system('lock disable cancelled')
                return True
            try:
                if not _verify_device_lock(password):
                    log_system('invalid password')
                    return True
            except Exception:
                log_system('invalid password')
                return True
            history_snapshot: list[dict] = []
            try:
                loaded_history = load_json(HISTORY_FILE, default=[])
                if isinstance(loaded_history, list):
                    history_snapshot = [x for x in loaded_history if isinstance(x, dict)]
            except Exception:
                history_snapshot = []
            try:
                DEVICE_LOCK_FILE.unlink(missing_ok=True)
            except OSError as e:
                log_system(f'could not remove lock file: {e}')
                return True
            _configure_local_state_encryption(None)
            contacts.save()
            _save_rooms_map(rooms)
            _save_room_retry_queue(room_retry_queue['items'])
            if history_snapshot:
                _write_plain_history_jsonl(HISTORY_FILE, history_snapshot)
            log_system('device lock disabled')
            log_system('local state encryption disabled (files now plain local JSON)')
            return True
        elif cmd == '/who':
            if len(parts) > 2:
                log_system('usage: /who [room|off]')
                return True
            if len(parts) == 2 and parts[1].lower() == 'off':
                who_live['room'] = None
                who_live['last_signature'] = ''
                log_system('who live mode disabled')
                return True
            room_name = active_room['name'] if len(parts) == 1 else _sanitize_room_name(parts[1])
            if not room_name:
                log_system('no active room. usage: /who <room>')
                return True
            if room_name not in rooms:
                log_system('room not found')
                return True
            who_live['room'] = room_name
            who_live['last_signature'] = _who_signature(room_name)
            _emit_who_snapshot(room_name, live=True)
            set_status(f'who live on: {room_name}')
        elif cmd == '/topic':
            if len(parts) == 1:
                room_name = active_room['name']
                if not room_name:
                    log_system('no active room. usage: /topic [room] [text]')
                    return True
                topic = _room_topic(room_name)
                _append_log(ui_log, f'topic {room_name}: {topic or "(no topic set)"}', prefix='[*] ')
                ui_dirty['value'] = True
                return True
            if len(parts) == 2:
                maybe_room = _sanitize_room_name(parts[1])
                if maybe_room and maybe_room in rooms:
                    topic = _room_topic(maybe_room)
                    _append_log(ui_log, f'topic {maybe_room}: {topic or "(no topic set)"}', prefix='[*] ')
                    ui_dirty['value'] = True
                    return True
                room_name = active_room['name']
                if not room_name:
                    log_system('no active room. usage: /topic <room> <text>')
                    return True
                try:
                    topic_input = '' if parts[1] in ('-', '--clear') else parts[1]
                    topic = _set_room_topic(room_name, topic_input)
                except Exception as e:
                    log_system(f'topic failed: {e}')
                    return True
                log_system(f'topic set for {room_name}: {topic or "(cleared)"}')
                return True
            room_name = _sanitize_room_name(parts[1])
            if not room_name or room_name not in rooms:
                log_system('room not found')
                return True
            topic_text = ' '.join(parts[2:])
            if topic_text in ('-', '--clear'):
                topic_text = ''
            try:
                topic = _set_room_topic(room_name, topic_text)
            except Exception as e:
                log_system(f'topic failed: {e}')
                return True
            log_system(f'topic set for {room_name}: {topic or "(cleared)"}')
            try:
                sent, errors = await _send_to_room(room_name, f'[topic] {node.my_nick}: {topic or "(cleared)"}')
                if errors:
                    for err in errors[:5]:
                        _append_log(ui_log, f'topic notice issue: {err}', prefix='[*] ')
                    ui_dirty['value'] = True
                if sent > 0:
                    set_status(f'topic synced to {sent} peer(s)')
            except Exception:
                pass
        elif cmd == '/sas':
            if node.session:
                _append_log(ui_log, f'session verify code: {node.session.sas_code}', prefix='[*] ')
            else:
                _append_log(ui_log, 'no active session', prefix='[*] ')
            ui_dirty['value'] = True
        elif cmd == '/diag':
            if len(parts) > 2:
                log_system('usage: /diag [contact_name]')
                return True
            set_status('running diagnostics...')
            try:
                diag_lines = await asyncio.to_thread(_build_diag_report, node, contacts, parts[1] if len(parts) == 2 else None)
            except Exception as e:
                log_system(f'diagnostic failed: {e}')
                return True
            _append_log(ui_log, '--- diagnostics ---', prefix='[*] ')
            for line_item in diag_lines:
                _append_log(ui_log, line_item, prefix='[*] ')
            set_status('diagnostics completed')
            ui_dirty['value'] = True
        elif cmd == '/ui':
            if len(parts) == 1:
                mode = 'compact' if ui_state['compact'] else 'full'
                log_system(f'ui mode: {mode}')
                return True
            if len(parts) != 2 or parts[1].lower() not in ('compact', 'full'):
                log_system('usage: /ui [compact|full]')
                return True
            ui_state['compact'] = parts[1].lower() == 'compact'
            log_system(f'ui mode set to: {parts[1].lower()}')
            return True
        elif cmd == '/wizard':
            try:
                if WIZARD_DONE_FILE.exists():
                    WIZARD_DONE_FILE.unlink()
            except OSError:
                pass
            await _run_first_run_wizard(node, contacts, my_id_pub, log_system)
            ui_dirty['value'] = True
        elif cmd == '/nick':
            if len(parts) == 1:
                log_system(f'current nick: {node.my_nick}')
                return True
            if len(parts) != 2:
                log_system('usage: /nick <new_nick>')
                return True
            try:
                node.set_my_nick(parts[1])
            except Exception as e:
                log_system(f'invalid nick: {e}')
                return True
            if active_room['name']:
                if _touch_room_presence(active_room['name'], node.my_nick, identity_pub=my_id_pub, onion=node.my_onion):
                    _maybe_emit_live_who(active_room['name'])
            log_system(f'nick changed to: {node.my_nick}')
        elif cmd == '/share':
            _append_log(ui_log, make_share_code(node.my_onion, my_id_pub), prefix='[*] ')
            ui_dirty['value'] = True
        elif cmd == '/export':
            try:
                positional, flags = _parse_cli_tokens(parts[1:])
            except ValueError as e:
                log_system(str(e))
                _append_log(ui_log, 'usage: /export [--key <password>] [--out <file.json>]', prefix='[*] ')
                ui_dirty['value'] = True
                return True
            if positional:
                log_system('usage: /export [--key <password>] [--out <file.json>]')
                return True

            password = flags.get('--key')
            if password is not None and not isinstance(password, str):
                log_system('invalid --key value')
                return True

            out_path = Path(flags.get('--out', str(_default_export_path(node.my_onion))))
            export_password = (password or '').strip()
            if not export_password:
                export_password = await _prompt_password_with_confirm('Export password: ')
            if not export_password:
                log_system('export cancelled: password required')
                return True
            try:
                written = export_contact_file(
                    out_path,
                    export_password,
                    node.my_onion,
                    my_id_pub,
                    nick=node.my_nick,
                )
            except Exception as e:
                log_system(f'export failed: {e}')
                return True
            log_system(f'exported encrypted contact file: {written}')
        elif cmd == '/contacts':
            entries = contacts.list()
            if not entries:
                log_system('(no contacts yet)')
                return True
            full = len(parts) > 1 and parts[1].lower() in ('--full', '-f')
            for i, c in enumerate(entries, start=1):
                if c.trusted and getattr(c, 'verified', False):
                    trust = 'trusted+verified'
                elif c.trusted:
                    trust = 'trusted(unverified)'
                else:
                    trust = 'untrusted'
                if full:
                    _append_log(
                        ui_log,
                        f'[{i}] {c.name}: {c.onion} | {c.fingerprint} | {trust}',
                        prefix='[*] ',
                    )
                else:
                    _append_log(ui_log, f'[{i}] {c.name} ({trust})', prefix='[*] ')
            ui_dirty['value'] = True
        elif cmd == '/rooms':
            if not rooms:
                log_system('(no rooms yet)')
                return True
            for room_name in sorted(rooms.keys()):
                members = _room_members(room_name)
                marker = ' *active*' if active_room['name'] == room_name else ''
                topic = _room_topic(room_name)
                topic_part = f' | topic: {topic}' if topic else ''
                _append_log(ui_log, f'- {room_name}: {len(members)} member(s){marker}{topic_part}', prefix='[*] ')
            ui_dirty['value'] = True
        elif cmd == '/room':
            if len(parts) < 2:
                log_system('usage: /room <create|add|del|members|invite|accept|join|leave|send|queue|code|routes> ...')
                return True
            sub = parts[1].lower()
            if sub == 'create':
                if len(parts) < 3:
                    log_system('usage: /room create <room> [member1] [member2...]')
                    return True
                room_name = _sanitize_room_name(parts[2])
                if not room_name:
                    log_system('invalid room name')
                    return True
                members: list[str] = []
                for query in parts[3:]:
                    contact, suggestions = _resolve_contact_by_query(contacts, query)
                    if not contact:
                        if suggestions:
                            log_system(f'unknown member "{query}". try: {", ".join(suggestions)}')
                        else:
                            log_system(f'unknown member: {query}')
                        return True
                    if not contact.trusted:
                        log_system(f'member not trusted: {contact.name}')
                        return True
                    if REQUIRE_VERIFIED_CONTACTS and not getattr(contact, 'verified', False):
                        log_system(f'member not verified: {contact.name}')
                        return True
                    if contact.name not in members:
                        members.append(contact.name)
                rooms[room_name] = {
                    'members': members,
                    'peers': _room_peers(room_name),
                    'created_at': int(time.time()),
                    'topic': _room_topic(room_name),
                }
                _save_rooms_map(rooms)
                active_room['name'] = room_name
                _touch_room_presence(room_name, node.my_nick, identity_pub=my_id_pub, onion=node.my_onion)
                log_system(f'room created: {room_name} ({len(members)} member(s))')
                set_status(f'active room: {room_name}')
                _append_log(ui_log, f'joined room: {room_name} (plain text now sends to room)', prefix='[*] ')
                topic = _room_topic(room_name)
                if topic:
                    _append_log(ui_log, f'topic {room_name}: {topic}', prefix='[*] ')
                ui_dirty['value'] = True
            elif sub == 'add':
                if len(parts) != 4:
                    log_system('usage: /room add <room> <member>')
                    return True
                room_name = _sanitize_room_name(parts[2])
                room = rooms.get(room_name)
                if not room:
                    log_system('room not found')
                    return True
                contact, suggestions = _resolve_contact_by_query(contacts, parts[3])
                if not contact:
                    if suggestions:
                        log_system(f'unknown member. try: {", ".join(suggestions)}')
                    else:
                        log_system('unknown member')
                    return True
                if not contact.trusted:
                    log_system(f'member not trusted: {contact.name}')
                    return True
                if REQUIRE_VERIFIED_CONTACTS and not getattr(contact, 'verified', False):
                    log_system(f'member not verified: {contact.name}')
                    return True
                members = _room_members(room_name)
                if contact.name in members:
                    log_system('member already in room')
                    return True
                members.append(contact.name)
                room['members'] = members
                _save_rooms_map(rooms)
                log_system(f'added {contact.name} to {room_name}')
            elif sub == 'del':
                if len(parts) != 4:
                    log_system('usage: /room del <room> <member>')
                    return True
                room_name = _sanitize_room_name(parts[2])
                room = rooms.get(room_name)
                if not room:
                    log_system('room not found')
                    return True
                contact, _ = _resolve_contact_by_query(contacts, parts[3])
                member_name = contact.name if contact else parts[3]
                members = _room_members(room_name)
                if member_name not in members:
                    log_system('member not in room')
                    return True
                members = [m for m in members if m != member_name]
                room['members'] = members
                _save_rooms_map(rooms)
                log_system(f'removed {member_name} from {room_name}')
            elif sub == 'members':
                if len(parts) != 3:
                    log_system('usage: /room members <room>')
                    return True
                room_name = _sanitize_room_name(parts[2])
                room = rooms.get(room_name)
                if not room:
                    log_system('room not found')
                    return True
                roster = _room_roster(room_name)
                _append_log(ui_log, f'= {room_name} :{" ".join(roster)}', prefix='[*] ')
                _append_log(
                    ui_log,
                    f'{len(roster)} user(s) in room {room_name} | routes={len(_room_peers(room_name))}',
                    prefix='[*] ',
                )
                ui_dirty['value'] = True
            elif sub == 'invite':
                if len(parts) != 3:
                    log_system('usage: /room invite <room>')
                    return True
                room_name = _sanitize_room_name(parts[2])
                if room_name not in rooms:
                    log_system('room not found')
                    return True
                try:
                    normalize_onion(node.my_onion)
                    invite_code = make_room_invite_code(
                        room_name,
                        _room_members(room_name),
                        contacts,
                        room_peers=_room_peers(room_name),
                        inviter_name=node.my_nick,
                        inviter_onion=node.my_onion,
                        inviter_identity_pub=my_id_pub,
                        inviter_fingerprint=my_fp,
                    )
                except Exception as e:
                    log_system(f'invite failed: {e}')
                    return True
                _append_log(ui_log, f'room invite ({room_name}):', prefix='[*] ')
                _append_log(ui_log, invite_code, prefix='')
                _append_log(ui_log, f'invite routes embedded: {len(parse_room_invite_code(invite_code)[1])}', prefix='[*] ')
                try:
                    short_code = make_room_invite_code(
                        room_name,
                        _room_members(room_name),
                        contacts,
                        room_peers=_room_peers(room_name),
                        inviter_name=node.my_nick,
                        inviter_onion=node.my_onion,
                        inviter_identity_pub=my_id_pub,
                        inviter_fingerprint=my_fp,
                        short_code=True,
                    )
                    _append_log(ui_log, f'short code ({len(short_code)} chars):', prefix='[*] ')
                    _append_log(ui_log, short_code, prefix='')
                except Exception:
                    pass
                set_status(f'room invite ready: {room_name}')
                ui_dirty['value'] = True
            elif sub == 'code':
                if len(parts) not in (2, 3):
                    log_system('usage: /room code [room]')
                    return True
                room_name = active_room['name'] if len(parts) == 2 else _sanitize_room_name(parts[2])
                if not room_name:
                    log_system('no active room. use /room code <room>')
                    return True
                if room_name not in rooms:
                    log_system('room not found')
                    return True
                try:
                    normalize_onion(node.my_onion)
                    invite_code = make_room_invite_code(
                        room_name,
                        _room_members(room_name),
                        contacts,
                        room_peers=_room_peers(room_name),
                        inviter_name=node.my_nick,
                        inviter_onion=node.my_onion,
                        inviter_identity_pub=my_id_pub,
                        inviter_fingerprint=my_fp,
                        short_code=True,
                    )
                except Exception as e:
                    log_system(f'room code failed: {e}')
                    return True
                _append_log(ui_log, f'room short code ({room_name}):', prefix='[*] ')
                _append_log(ui_log, invite_code, prefix='')
                _append_log(ui_log, f'code length: {len(invite_code)}', prefix='[*] ')
                set_status(f'room code ready: {room_name}')
                ui_dirty['value'] = True
            elif sub == 'accept':
                if len(parts) not in (3, 4):
                    log_system('usage: /room accept <invite_code> [room]')
                    return True
                try:
                    invite_room_name, invite_members, inviter = parse_room_invite_code(parts[2])
                except Exception as e:
                    log_system(f'invalid invite code: {e}')
                    return True
                room_name = _sanitize_room_name(parts[3]) if len(parts) == 4 else invite_room_name
                if not room_name:
                    log_system('invalid room name')
                    return True

                if room_name not in rooms:
                    rooms[room_name] = {'members': [], 'peers': [], 'created_at': int(time.time()), 'topic': ''}
                room = rooms[room_name]
                if not isinstance(room.get('members'), list):
                    room['members'] = []
                if not isinstance(room.get('peers'), list):
                    room['peers'] = []

                accepted_items = list(invite_members)
                if inviter is not None:
                    accepted_items.append(inviter)

                mapped_contacts = 0
                peer_routes = 0
                unresolved_routes: list[str] = []
                skipped_self = 0
                for item in accepted_items:
                    identity_pub = str(item.get('identity_pub', '')).strip()
                    display_name = _sanitize_contact_name(str(item.get('name', '')).strip()) or 'peer'
                    onion_raw = str(item.get('onion', '')).strip()
                    if not identity_pub:
                        continue
                    if _is_local_endpoint(identity_pub, onion_raw):
                        skipped_self += 1
                        continue
                    contact = contacts.by_identity(identity_pub)
                    if contact:
                        if contact.name not in room['members']:
                            room['members'].append(contact.name)
                        mapped_contacts += 1
                        peer = {
                            'name': contact.name,
                            'onion': contact.onion,
                            'identity_pub': contact.identity_pub_b64,
                            'fingerprint': contact.fingerprint,
                        }
                        if _upsert_room_peer(room_name, peer):
                            peer_routes += 1
                        continue

                    if not onion_raw:
                        unresolved_routes.append(display_name)
                        continue
                    try:
                        peer = {
                            'name': display_name,
                            'onion': normalize_onion(onion_raw),
                            'identity_pub': normalize_identity_pub(identity_pub),
                            'fingerprint': str(item.get('fingerprint', '')).strip(),
                        }
                    except ValueError:
                        unresolved_routes.append(display_name)
                        continue
                    if _upsert_room_peer(room_name, peer):
                        peer_routes += 1

                _save_rooms_map(rooms)
                active_room['name'] = room_name
                _touch_room_presence(room_name, node.my_nick, identity_pub=my_id_pub, onion=node.my_onion)
                log_system(
                    f'joined room from invite: {room_name} '
                    f'(contacts mapped: {mapped_contacts}, peer routes: {peer_routes})'
                )
                if peer_routes == 0 and skipped_self > 0:
                    _append_log(
                        ui_log,
                        'invite appears to contain only this device identity/onion (self).',
                        prefix='[*] ',
                    )
                    _append_log(
                        ui_log,
                        'fix: on ONE machine run /panic all, restart, then create a NEW invite and accept again.',
                        prefix='[*] ',
                    )
                # announce join once so inviter/peers can learn reverse route immediately
                try:
                    await _send_to_room(room_name, f'[{node.my_nick} joined {room_name}]')
                except Exception:
                    pass
                if unresolved_routes:
                    _append_log(
                        ui_log,
                        'invite peers missing onion/identity route: ' + ', '.join(unresolved_routes[:10]),
                        prefix='[*] ',
                    )
                topic = _room_topic(room_name)
                if topic:
                    _append_log(ui_log, f'topic {room_name}: {topic}', prefix='[*] ')
                ui_dirty['value'] = True
            elif sub == 'join':
                if len(parts) != 3:
                    log_system('usage: /room join <room>')
                    return True
                room_name = _sanitize_room_name(parts[2])
                if room_name not in rooms:
                    log_system('room not found')
                    return True
                active_room['name'] = room_name
                _touch_room_presence(room_name, node.my_nick, identity_pub=my_id_pub, onion=node.my_onion)
                set_status(f'active room: {room_name}')
                _append_log(ui_log, f'joined room: {room_name} (plain text now sends to room)', prefix='[*] ')
                topic = _room_topic(room_name)
                if topic:
                    _append_log(ui_log, f'topic {room_name}: {topic}', prefix='[*] ')
                ui_dirty['value'] = True
            elif sub == 'leave':
                if active_room['name']:
                    if who_live.get('room') == active_room['name']:
                        who_live['room'] = None
                        who_live['last_signature'] = ''
                    log_system(f'left room: {active_room["name"]}')
                active_room['name'] = None
                return True
            elif sub == 'send':
                if len(parts) < 4:
                    log_system('usage: /room send <room> <text>')
                    return True
                room_name = _sanitize_room_name(parts[2])
                if room_name not in rooms:
                    log_system('room not found')
                    return True
                text = ' '.join(parts[3:])
                sent, errors = await _send_to_room(room_name, text)
                if sent > 0:
                    log_room(node.my_nick, room_name, text)
                    set_status(f'room {room_name}: sent to {sent} peer(s)')
                if errors:
                    for err in errors[:10]:
                        _append_log(ui_log, f'room delivery issue: {err}', prefix='[*] ')
                    ui_dirty['value'] = True
            elif sub == 'queue':
                if len(parts) != 2:
                    log_system('usage: /room queue')
                    return True
                pending = room_retry_queue['items']
                if not pending:
                    log_system('room retry queue is empty')
                    return True
                _append_log(ui_log, f'room retry queue: {len(pending)} pending item(s)', prefix='[*] ')
                now = time.time()
                for item in sorted(pending, key=lambda x: float(x.get('next_try_ts', 0.0)))[:20]:
                    wait_s = max(0, int(float(item.get('next_try_ts', 0.0)) - now))
                    _append_log(
                        ui_log,
                        f'{item.get("room")} -> {item.get("target_name")} | attempts={item.get("attempts", 0)} | retry_in={wait_s}s | last_error={item.get("last_error", "")}',
                        prefix='[*] ',
                    )
                if len(pending) > 20:
                    _append_log(ui_log, f'... and {len(pending) - 20} more', prefix='[*] ')
                ui_dirty['value'] = True
            elif sub == 'routes':
                if len(parts) not in (2, 3):
                    log_system('usage: /room routes [room]')
                    return True
                room_name = active_room['name'] if len(parts) == 2 else _sanitize_room_name(parts[2])
                if not room_name:
                    log_system('no active room. use /room routes <room>')
                    return True
                if room_name not in rooms:
                    log_system('room not found')
                    return True
                peers = _sorted_room_peers(room_name)
                if not peers:
                    log_system('no routable peers in room')
                    return True
                _append_log(ui_log, f'room routes ({room_name}): {len(peers)} peer(s)', prefix='[*] ')
                now = int(time.time())
                for peer in peers[:20]:
                    name = str(peer.get('name', 'peer')).strip() or 'peer'
                    score = int(peer.get('score', 50) or 50)
                    fail_count = int(peer.get('fail_count', 0) or 0)
                    last_ok = int(peer.get('last_ok', 0) or 0)
                    age_ok = max(0, now - last_ok) if last_ok else -1
                    ok_text = f'{age_ok}s ago' if age_ok >= 0 else 'never'
                    _append_log(
                        ui_log,
                        f'- {name}: score={score} fail_count={fail_count} last_ok={ok_text}',
                        prefix='[*] ',
                    )
                ui_dirty['value'] = True
            else:
                log_system('usage: /room <create|add|del|members|invite|accept|join|leave|send|queue|code|routes> ...')
        elif cmd == '/join':
            if len(parts) != 2:
                log_system('usage: /join <room>')
                return True
            room_name = _sanitize_room_name(parts[1])
            if not room_name:
                log_system('invalid room name')
                return True
            created = False
            if room_name not in rooms:
                rooms[room_name] = {'members': [], 'peers': [], 'created_at': int(time.time()), 'topic': ''}
                _save_rooms_map(rooms)
                created = True
            active_room['name'] = room_name
            _touch_room_presence(room_name, node.my_nick, identity_pub=my_id_pub, onion=node.my_onion)
            if created:
                _append_log(ui_log, f'created room: {room_name}', prefix='[*] ')
            set_status(f'active room: {room_name}')
            _append_log(ui_log, f'joined room: {room_name} (plain text now sends to room)', prefix='[*] ')
            topic = _room_topic(room_name)
            if topic:
                _append_log(ui_log, f'topic {room_name}: {topic}', prefix='[*] ')
            ui_dirty['value'] = True
        elif cmd == '/names':
            if len(parts) > 2:
                log_system('usage: /names [room]')
                return True
            room_name = active_room['name'] if len(parts) == 1 else _sanitize_room_name(parts[1])
            if not room_name:
                log_system('no active room. usage: /names <room>')
                return True
            if room_name not in rooms:
                log_system('room not found')
                return True
            _emit_who_snapshot(room_name, live=False)
            _append_log(
                ui_log,
                f'routes={len(_room_peers(room_name))} | best={_best_routes_summary(room_name)}',
                prefix='[*] ',
            )
            ui_dirty['value'] = True
        elif cmd == '/invite':
            if len(parts) > 2:
                log_system('usage: /invite [room]')
                return True
            room_name = active_room['name'] if len(parts) == 1 else _sanitize_room_name(parts[1])
            if not room_name:
                log_system('no active room. use /join <room> or /invite <room>')
                return True
            if room_name not in rooms:
                log_system('room not found')
                return True
            try:
                normalize_onion(node.my_onion)
                invite_code = make_room_invite_code(
                    room_name,
                    _room_members(room_name),
                    contacts,
                    room_peers=_room_peers(room_name),
                    inviter_name=node.my_nick,
                    inviter_onion=node.my_onion,
                    inviter_identity_pub=my_id_pub,
                    inviter_fingerprint=my_fp,
                )
            except Exception as e:
                log_system(f'invite failed: {e}')
                return True
            _append_log(ui_log, f'room invite ({room_name}):', prefix='[*] ')
            _append_log(ui_log, invite_code, prefix='')
            _append_log(ui_log, f'invite routes embedded: {len(parse_room_invite_code(invite_code)[1])}', prefix='[*] ')
            try:
                short_code = make_room_invite_code(
                    room_name,
                    _room_members(room_name),
                    contacts,
                    room_peers=_room_peers(room_name),
                    inviter_name=node.my_nick,
                    inviter_onion=node.my_onion,
                    inviter_identity_pub=my_id_pub,
                    inviter_fingerprint=my_fp,
                    short_code=True,
                )
                _append_log(ui_log, f'short code ({len(short_code)} chars):', prefix='[*] ')
                _append_log(ui_log, short_code, prefix='')
            except Exception:
                pass
            set_status(f'room invite ready: {room_name}')
            ui_dirty['value'] = True
        elif cmd == '/import':
            if len(parts) == 3 and parts[2].startswith('p2pchat://v1/'):
                try:
                    onion, identity_pub = parse_share_code(parts[2])
                    c = contacts.add(parts[1], onion, identity_pub, trusted=True)
                    contacts.verify(c.name)
                except Exception as e:
                    log_system(f'invalid share code: {e}')
                    return True
                _append_log(ui_log, f'imported and auto-verified {c.name} ({c.fingerprint})', prefix='[*] ')
                _append_log(ui_log, f'connect quickly with: /connect {c.name}', prefix='[*] ')
                ui_dirty['value'] = True
                return True

            try:
                positional, flags = _parse_cli_tokens(parts[1:])
            except ValueError as e:
                log_system(str(e))
                _append_log(ui_log, 'usage: /import <file.json> [--key <password>] [--name <contact_name>]', prefix='[*] ')
                ui_dirty['value'] = True
                return True
            if len(positional) != 1:
                log_system('usage: /import <file.json> [--key <password>] [--name <contact_name>]')
                return True

            password = flags.get('--key')
            if password is None:
                password = await _prompt_password_with_confirm(
                    'Import password: ',
                    allow_empty=False,
                )
            in_path = Path(positional[0])
            if not in_path.exists():
                log_system('file not found')
                return True

            try:
                onion, identity_pub, fingerprint, suggested_name = import_contact_file(
                    in_path,
                    password if isinstance(password, str) else None,
                )
            except Exception as e:
                log_system(f'import failed: {e}')
                return True

            stem_guess = _sanitize_contact_name(in_path.stem.replace('p2pchat-contact-', '').replace('contact-', ''))
            auto_guess = suggested_name or stem_guess or f'friend-{fingerprint.replace(":", "")[:8]}'
            preferred_name = flags.get('--name', auto_guess)
            imported_name, import_msg = _import_contact_into_book(contacts, onion, identity_pub, preferred_name)
            log_system(import_msg)
            reconnect_state['target'] = imported_name
            _append_log(ui_log, f'connect quickly with: /connect {imported_name}', prefix='[*] ')
            ui_dirty['value'] = True
        elif cmd == '/save':
            if len(parts) > 2:
                log_system('usage: /save [file.json]')
                return True
            if ephemeral_state['enabled']:
                log_system('save blocked in ephemeral mode')
                return True
            out_path = Path(parts[1]) if len(parts) == 2 else _default_history_path()
            password = await _prompt_password_with_confirm('Save password: ')
            if not password.strip():
                log_system('save cancelled: password required')
                return True
            payload = {
                'v': 1,
                'saved_at': int(time.time()),
                'local_nick': node.my_nick,
                'local_onion': node.my_onion,
                'local_fingerprint': my_fp,
                'session_label': _session_label(node),
                'messages': chat_transcript,
            }
            try:
                written = save_chat_history_file(out_path, password, payload)
            except Exception as e:
                log_system(f'save failed: {e}')
                return True
            log_system(f'saved encrypted history: {written}')
        elif cmd == '/backup':
            if len(parts) > 2:
                log_system('usage: /backup [file.json]')
                return True
            out_path = Path(parts[1]) if len(parts) == 2 else _default_profile_backup_path()
            password = await _prompt_password_with_confirm('Backup password: ')
            if not password.strip():
                log_system('backup cancelled: password required')
                return True
            try:
                written = backup_profile_file(out_path, password)
            except Exception as e:
                log_system(f'backup failed: {e}')
                return True
            log_system(f'saved encrypted profile backup: {written}')
        elif cmd == '/restore':
            if len(parts) != 2:
                log_system('usage: /restore <backup.json>')
                return True
            in_path = Path(parts[1])
            if not in_path.exists():
                log_system('file not found')
                return True
            password = await _prompt_password_with_confirm(
                f'Restore password for {in_path.name}: ',
                mismatch_msg='password mismatch',
            )
            if not password.strip():
                log_system('restore cancelled: password required')
                return True
            try:
                info = restore_profile_file(in_path, password)
            except Exception as e:
                log_system(f'restore failed: {e}')
                return True
            restored_files = int(info.get('restored_files', 0) or 0)
            backup_version = str(info.get('backup_app_version', '')).strip() or 'unknown'
            created_at = int(info.get('created_at', 0) or 0)
            created_at_text = (
                time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(created_at))
                if created_at > 0
                else 'unknown'
            )
            _append_log(ui_log, f'restored files: {restored_files}', prefix='[*] ')
            _append_log(ui_log, f'backup app version: {backup_version}', prefix='[*] ')
            _append_log(ui_log, f'backup created_at: {created_at_text}', prefix='[*] ')
            _append_log(ui_log, 'restart app now to fully apply restored identity/onion.', prefix='[*] ')
            set_status('restore complete (restart recommended)')
            ui_dirty['value'] = True
        elif cmd == '/cat':
            if len(parts) != 2:
                log_system('usage: /cat <history.json>')
                return True
            in_path = Path(parts[1])
            if not in_path.exists():
                log_system('file not found')
                return True
            password = await _prompt_password_with_confirm(
                f'Password for {in_path.name}: ',
                mismatch_msg='password mismatch',
            )
            if not password.strip():
                log_system('cat cancelled: password required')
                return True
            try:
                payload = load_chat_history_file(in_path, password)
            except Exception as e:
                log_system(f'cat failed: {e}')
                return True

            lines: list[str] = []
            lines.append(f'# cat {in_path.name}')
            lines.append(f'# saved_at: {time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(int(payload.get("saved_at", 0) or 0)))}')
            lines.append(f'# local: {payload.get("local_nick", "?")} ({payload.get("local_onion", "?")})')
            messages = payload.get('messages', [])
            if not isinstance(messages, list) or not messages:
                lines.append('(no chat messages)')
            else:
                for item in messages:
                    if not isinstance(item, dict):
                        continue
                    ts = int(item.get('ts', 0) or 0)
                    ts_text = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(ts))
                    nick = str(item.get('nick', '?'))
                    text = str(item.get('text', ''))
                    lines.append(f'[{ts_text}] <{nick}> {text}')
            _append_log(ui_log, '\n'.join(lines), prefix='')
            set_status(f'opened history: {in_path.name}')
            ui_dirty['value'] = True
        elif cmd == '/add':
            if len(parts) != 4:
                log_system('usage: /add <name> <onion> <identity_pub_b64>')
                return True
            try:
                c = contacts.add(parts[1], parts[2], parts[3], trusted=False)
            except Exception as e:
                log_system(f'invalid contact: {e}')
                return True
            _append_log(ui_log, f'added {c.name} ({c.fingerprint})', prefix='[*] ')
            _append_log(ui_log, 'now verify fingerprint with your friend, then /verify <name> <fingerprint>', prefix='[*] ')
            ui_dirty['value'] = True
        elif cmd == '/trust':
            if len(parts) not in (2, 3):
                log_system('usage: /trust <name> [expected_fingerprint]')
                return True
            existing, suggestions = _resolve_contact_by_query(contacts, parts[1])
            if not existing:
                if suggestions:
                    log_system(f'unknown contact. try: {", ".join(suggestions)}')
                else:
                    log_system('unknown contact')
                return True
            if len(parts) == 3 and existing.fingerprint.lower() != parts[2].lower():
                log_system('fingerprint mismatch; not trusted')
                return True
            if len(parts) == 3:
                if contacts.trust(existing.name, verified=True):
                    log_system(f'trusted+verified {existing.name}')
            else:
                if contacts.trust(existing.name, verified=False):
                    log_system(f'trusted {existing.name} (verification pending; use /verify {existing.name} <fingerprint>)')
        elif cmd == '/verify':
            if len(parts) != 3:
                log_system('usage: /verify <name> <fingerprint>')
                return True
            existing, suggestions = _resolve_contact_by_query(contacts, parts[1])
            if not existing:
                if suggestions:
                    log_system(f'unknown contact. try: {", ".join(suggestions)}')
                else:
                    log_system('unknown contact')
                return True
            if existing.fingerprint.lower() != parts[2].lower():
                log_system('fingerprint mismatch; verify aborted')
                return True
            if contacts.verify(existing.name):
                log_system(f'contact verified: {existing.name}')
        elif cmd == '/connect':
            c: Contact | None = None
            suggestions: list[str] = []

            if len(parts) == 1:
                target = reconnect_state.get('target')
                if target:
                    c, _ = _resolve_contact_by_query(contacts, target)
                if not c:
                    ready_contacts = _ready_contacts(contacts)
                    if len(ready_contacts) == 1:
                        c = ready_contacts[0]
                        log_system(f'auto-selected contact: {c.name}')
                    elif len(ready_contacts) > 1:
                        log_system('multiple contacts found. use /connect <name>')
                        _append_log(ui_log, 'ready contacts: ' + ', '.join(x.name for x in ready_contacts[:10]), prefix='[*] ')
                        ui_dirty['value'] = True
                        return True
                    else:
                        if REQUIRE_VERIFIED_CONTACTS:
                            log_system('no verified contacts. use /verify <name> <fingerprint> first')
                        else:
                            log_system('no trusted contacts. import first, then /connect')
                        return True
            elif len(parts) == 2:
                query = parts[1]
                query_candidates = [query]
                if query.lower().endswith('.json'):
                    query_candidates.append(Path(query).stem)
                if '\\' in query or '/' in query:
                    query_candidates.append(Path(query).stem)

                for candidate in query_candidates:
                    c, suggestions = _resolve_contact_by_query(contacts, candidate)
                    if c:
                        break
                if not c:
                    c, onion_suggestions = _resolve_contact_by_onion_query(contacts, query)
                    suggestions = suggestions or onion_suggestions
                if not c:
                    ready_contacts = _ready_contacts(contacts)
                    if len(ready_contacts) == 1:
                        c = ready_contacts[0]
                        log_system(f'no exact match; using only ready contact: {c.name}')
                    else:
                        if suggestions:
                            log_system(f'no exact contact. try: {", ".join(suggestions)}')
                        else:
                            if ready_contacts:
                                log_system('no such contact. use /contacts, then /connect <name> or /connect <index>')
                                _append_log(ui_log, 'ready contacts: ' + ', '.join(x.name for x in ready_contacts[:10]), prefix='[*] ')
                                ui_dirty['value'] = True
                            else:
                                log_system('no such contact')
                        return True
            else:
                log_system('usage: /connect [name]')
                return True

            if not c.trusted:
                log_system('contact not trusted yet')
                return True
            if REQUIRE_VERIFIED_CONTACTS and not getattr(c, 'verified', False):
                log_system(f'contact not verified yet. run: /verify {c.name} <fingerprint>')
                return True
            try:
                cancel_reconnect()
                await node.connect(c)
            except Exception as e:
                log_system(f'connect failed: {e}')
                reconnect_state['target'] = c.name
                schedule_reconnect(c.name)
                log_system(f'auto-reconnect scheduled for {c.name}')
                return True
            reconnect_state['target'] = c.name
            set_status('session ready')
        elif cmd == '/part':
            if len(parts) > 2:
                log_system('usage: /part [room]')
                return True
            target_room = active_room['name'] if len(parts) == 1 else _sanitize_room_name(parts[1])
            if target_room:
                if active_room['name'] != target_room:
                    log_system(f'not in room: {target_room}')
                    return True
                active_room['name'] = None
                if who_live.get('room') == target_room:
                    who_live['room'] = None
                    who_live['last_signature'] = ''
                log_system(f'left room: {target_room}')
                return True
            if node.session:
                cancel_reconnect()
                reconnect_state['target'] = None
                await _disconnect_active_session(node)
                log_system('disconnected from current session')
                return True
            log_system('no active room/session')
        elif cmd == '/reconnect':
            if len(parts) > 2:
                log_system('usage: /reconnect [name]')
                return True
            target_name = parts[1] if len(parts) == 2 else reconnect_state.get('target') or _infer_peer_contact_name(node, contacts)
            if not target_name:
                log_system('no reconnect target; use /reconnect <name>')
                return True
            contact, suggestions = _resolve_contact_by_query(contacts, target_name)
            if not contact:
                if suggestions:
                    log_system(f'no exact contact. try: {", ".join(suggestions)}')
                else:
                    log_system(f'no such contact: {target_name}')
                return True
            if not contact.trusted:
                log_system(f'contact not trusted: {target_name}')
                return True
            if REQUIRE_VERIFIED_CONTACTS and not getattr(contact, 'verified', False):
                log_system(f'contact not verified: {target_name}. use /verify first')
                return True
            cancel_reconnect()
            await _disconnect_active_session(node)
            try:
                await node.connect(contact)
            except Exception as e:
                log_system(f'reconnect failed: {e}')
                schedule_reconnect(target_name)
                return True
            reconnect_state['target'] = target_name
            set_status(f'reconnected to {target_name}')
        elif cmd == '/panic':
            if len(parts) > 2:
                log_system('usage: /panic [session|local|all]')
                return True
            mode = parts[1].lower() if len(parts) == 2 else 'session'
            if mode not in ('session', 'local', 'all'):
                log_system('usage: /panic [session|local|all]')
                return True

            cancel_reconnect()
            reconnect_state['target'] = None
            reconnect_state['enabled'] = False
            await _disconnect_active_session(node)
            node.secure_wipe_runtime()
            ui_log.clear()
            chat_transcript.clear()
            active_room['name'] = None
            who_live['room'] = None
            who_live['last_signature'] = ''
            room_presence.clear()
            room_retry_queue['items'].clear()
            _persist_room_queue()
            set_status('chat cleared by panic')

            if mode in ('local', 'all'):
                contacts.clear()
                rooms.clear()
                _save_rooms_map(rooms)
                try:
                    if RUNTIME_DIR.exists():
                        shutil.rmtree(RUNTIME_DIR)
                    RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
                except OSError:
                    pass
                try:
                    if HISTORY_FILE.exists():
                        HISTORY_FILE.unlink()
                except OSError:
                    pass
                log_system('local chat data wiped')

            if mode == 'all':
                for path in (IDENTITY_KEY_FILE, ONION_KEY_FILE, DEVICE_LOCK_FILE):
                    try:
                        if path.exists():
                            path.unlink()
                    except OSError:
                        pass
                log_system('all sensitive local keys wiped; exiting now')
                return False

            reconnect_state['enabled'] = True
            log_system(f'panic completed ({mode})')
        elif cmd == '/msg':
            if len(parts) < 2:
                log_system('usage: /msg <text>')
                return True
            text = ' '.join(parts[1:])
            try:
                await node.send_message(text)
            except Exception as e:
                log_system(f'send failed: {e}')
                return True
            if node.session is not None:
                log_chat(node.my_nick, text)
        elif cmd == '/quit':
            cancel_reconnect()
            await _disconnect_active_session(node)
            node.secure_wipe_runtime()
            return False
        else:
            log_system('unknown command. /help')

        return True

    input_buffer = ''
    cursor_pos = 0
    input_history: list[str] = []
    history_index: int | None = None
    history_draft = ''
    running = True
    ui_dirty['value'] = True
    prompt_dirty = False
    last_full_redraw = 0.0
    global _USE_ANSI
    if os.name == 'nt' and sys.stdin.isatty():
        _USE_ANSI = _enable_ansi_on_windows()

    if os.name == 'nt' and sys.stdin.isatty():
        def mark_prompt_dirty() -> None:
            nonlocal prompt_dirty
            prompt_dirty = True
            # Immediate in-line redraw keeps typing smooth while avoiding full-screen redraw.
            if _USE_ANSI and not ui_dirty['value']:
                _redraw_prompt_line(node, input_buffer, cursor_pos)
                prompt_dirty = False

        while running:
            now = time.perf_counter()
            if ui_dirty['value'] and (not _USE_ANSI or (now - last_full_redraw) >= UI_FULL_REDRAW_INTERVAL):
                _render_ui(
                    node,
                    my_fp,
                    ui_status['value'],
                    connection_health['value'],
                    ui_log,
                    input_buffer,
                    cursor_pos,
                    compact=ui_state['compact'],
                )
                ui_dirty['value'] = False
                prompt_dirty = False
                last_full_redraw = now
            elif prompt_dirty:
                if _USE_ANSI:
                    _redraw_prompt_line(node, input_buffer, cursor_pos)
                    prompt_dirty = False
                else:
                    ui_dirty['value'] = True

            key_event = _read_key_windows()
            if key_event is None:
                await asyncio.sleep(UI_IDLE_SLEEP)
                continue
            key, payload = key_event

            if key == 'EXT':
                continue

            if key == 'ENTER':
                line = input_buffer
                if line.strip():
                    if not input_history or input_history[-1] != line:
                        input_history.append(line)
                input_buffer = ''
                cursor_pos = 0
                history_index = None
                history_draft = ''
                ui_dirty['value'] = True
                try:
                    running = await process_line(line)
                except Exception as e:
                    log_system(f'unexpected error: {e}')
                continue

            if key == 'CTRL_C':
                running = False
                continue

            if key == 'BACKSPACE':
                if cursor_pos > 0:
                    input_buffer = input_buffer[:cursor_pos - 1] + input_buffer[cursor_pos:]
                    cursor_pos -= 1
                    mark_prompt_dirty()
                continue

            if key == 'DELETE':
                if cursor_pos < len(input_buffer):
                    input_buffer = input_buffer[:cursor_pos] + input_buffer[cursor_pos + 1:]
                    mark_prompt_dirty()
                continue

            if key == 'LEFT':
                if cursor_pos > 0:
                    cursor_pos -= 1
                    mark_prompt_dirty()
                continue

            if key == 'RIGHT':
                if cursor_pos < len(input_buffer):
                    cursor_pos += 1
                    mark_prompt_dirty()
                continue

            if key == 'HOME':
                if cursor_pos != 0:
                    cursor_pos = 0
                    mark_prompt_dirty()
                continue

            if key == 'END':
                if cursor_pos != len(input_buffer):
                    cursor_pos = len(input_buffer)
                    mark_prompt_dirty()
                continue

            if key == 'UP':
                if input_history:
                    if history_index is None:
                        history_draft = input_buffer
                        history_index = len(input_history) - 1
                    elif history_index > 0:
                        history_index -= 1
                    input_buffer = input_history[history_index]
                    cursor_pos = len(input_buffer)
                    mark_prompt_dirty()
                continue

            if key == 'DOWN':
                if history_index is not None:
                    if history_index < len(input_history) - 1:
                        history_index += 1
                        input_buffer = input_history[history_index]
                    else:
                        history_index = None
                        input_buffer = history_draft
                    cursor_pos = len(input_buffer)
                    mark_prompt_dirty()
                continue

            if key == 'CHAR':
                ch = payload or ''
                if ch.isprintable():
                    input_buffer = input_buffer[:cursor_pos] + ch + input_buffer[cursor_pos:]
                    cursor_pos += 1
                    mark_prompt_dirty()

            await asyncio.sleep(0)
    else:
        # Fallback for non-Windows terminals.
        while running:
            if ui_dirty['value']:
                _render_ui(
                    node,
                    my_fp,
                    ui_status['value'],
                    connection_health['value'],
                    ui_log,
                    '',
                    compact=ui_state['compact'],
                )
                ui_dirty['value'] = False
            line = await asyncio.to_thread(input, f'{node.my_nick}> ')
            try:
                running = await process_line(line)
            except Exception as e:
                log_system(f'unexpected error: {e}')
            ui_dirty['value'] = True

    retry_task = room_retry_task.get('task')
    if retry_task and not retry_task.done():
        retry_task.cancel()
        try:
            await retry_task
        except asyncio.CancelledError:
            pass

    route_task = room_route_refresh_task.get('task')
    if route_task and not route_task.done():
        route_task.cancel()
        try:
            await route_task
        except asyncio.CancelledError:
            pass

    health_task = connection_health_task.get('task')
    if health_task and not health_task.done():
        health_task.cancel()
        try:
            await health_task
        except asyncio.CancelledError:
            pass

    await _disconnect_active_session(node)
    node.secure_wipe_runtime()
    _clear_screen()
    managed_tor.stop()


def main() -> None:
    try:
        asyncio.run(amain())
    except KeyboardInterrupt:
        print('\nbye')
        sys.exit(0)
    except Exception as e:
        crash_log = _write_crash_log(e)
        print(f'[*] fatal error: {e}')
        if crash_log:
            print(f'[*] crash log: {crash_log}')
        sys.exit(1)
