from __future__ import annotations

import os
import socket
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

from stem.control import Controller

from .config import RUNTIME_DIR, bundled_tor_dir, get_tor_control_password


@dataclass
class ManagedTor:
    process: subprocess.Popen | None
    socks_port: int
    control_port: int
    tor_dir: Path | None = None
    bootstrap_progress: int | None = None
    bootstrap_summary: str | None = None

    def stop(self) -> None:
        if self.process and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=8)
            except subprocess.TimeoutExpired:
                self.process.kill()


def _free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(('127.0.0.1', 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _is_port_open(host: str, port: int) -> bool:
    try:
        with socket.create_connection((host, port), timeout=0.3):
            return True
    except OSError:
        return False


def _authenticate_controller(port: int, timeout: float = 5.0) -> tuple[bool, str]:
    deadline = time.time() + timeout
    last_err = 'unknown error'
    while time.time() < deadline:
        try:
            with Controller.from_port(address='127.0.0.1', port=port) as c:
                password = get_tor_control_password()
                if password:
                    c.authenticate(password=password)
                else:
                    c.authenticate()
                return True, 'ok'
        except Exception as e:
            last_err = str(e)
            time.sleep(0.2)
    return False, last_err


def _wait_for_controller(port: int, timeout: float = 45.0) -> None:
    _wait_for_controller_with_process(port, timeout=timeout)


def _tail_text(path: Path, max_lines: int = 30) -> str:
    if not path.exists():
        return 'no tor log captured'
    try:
        lines = path.read_text(encoding='utf-8', errors='replace').splitlines()
    except Exception as e:
        return f'failed to read tor log: {e}'
    if not lines:
        return 'tor log is empty'
    return '\n'.join(lines[-max_lines:])


def _wait_for_controller_with_process(
    port: int,
    timeout: float = 45.0,
    process: subprocess.Popen | None = None,
    log_path: Path | None = None,
) -> None:
    deadline = time.time() + timeout
    last_err: str | None = None
    while time.time() < deadline:
        if process is not None and process.poll() is not None:
            details = _tail_text(log_path) if log_path else 'tor process exited unexpectedly'
            raise RuntimeError(f'Tor exited before controller ready (code {process.returncode}).\n{details}')
        ok, err = _authenticate_controller(port, timeout=1.0)
        if ok:
            return
        last_err = err
        time.sleep(0.25)
    raise RuntimeError(f'Tor controller not ready: {last_err}')


def _bootstrap_snapshot(c: Controller) -> tuple[int | None, str]:
    raw = c.get_info('status/bootstrap-phase', '') or ''
    progress: int | None = None
    summary = raw.strip()
    for token in raw.split():
        if token.startswith('PROGRESS='):
            value = token.split('=', 1)[1].strip('"')
            if value.isdigit():
                progress = int(value)
        elif token.startswith('SUMMARY='):
            summary = token.split('=', 1)[1].strip('"')
    return progress, summary or 'unknown'


def _wait_for_bootstrap(port: int, timeout: float = 90.0) -> tuple[int | None, str]:
    deadline = time.time() + timeout
    progress: int | None = None
    summary = 'unknown'
    while time.time() < deadline:
        try:
            with Controller.from_port(address='127.0.0.1', port=port) as c:
                password = get_tor_control_password()
                if password:
                    c.authenticate(password=password)
                else:
                    c.authenticate()
                progress, summary = _bootstrap_snapshot(c)
                if progress is not None and progress >= 100:
                    return progress, summary
        except Exception:
            pass
        time.sleep(0.5)
    return progress, summary


def _tor_path(path: Path) -> str:
    return str(path.resolve())


def start_or_use_tor() -> ManagedTor:
    env_socks = int(os.environ.get('P2PCHAT_TOR_SOCKS_PORT', '9050'))
    env_control = int(os.environ.get('P2PCHAT_TOR_CONTROL_PORT', '9051'))

    if _is_port_open('127.0.0.1', env_socks) and _is_port_open('127.0.0.1', env_control):
        auth_ok, _ = _authenticate_controller(env_control, timeout=2.0)
        if auth_ok:
            progress, summary = _wait_for_bootstrap(env_control, timeout=8.0)
            return ManagedTor(
                process=None,
                socks_port=env_socks,
                control_port=env_control,
                bootstrap_progress=progress,
                bootstrap_summary=summary,
            )

    tor_dir = bundled_tor_dir()
    tor_exe = tor_dir / ('tor.exe' if os.name == 'nt' else 'tor')
    if not tor_exe.exists():
        raise RuntimeError(
            'No running Tor found and bundled tor binary is missing. '
            'Place the official Tor Expert Bundle files in the app\\tor folder.'
        )

    socks_port = _free_port()
    control_port = _free_port()
    data_dir = RUNTIME_DIR / f'tor-data-{control_port}'
    data_dir.mkdir(parents=True, exist_ok=True)
    torrc = RUNTIME_DIR / 'torrc.auto'
    tor_log = RUNTIME_DIR / 'tor.log'
    geoip = tor_dir / 'geoip'
    geoip6 = tor_dir / 'geoip6'

    torrc.write_text(
        '\n'.join([
            f'SocksPort 127.0.0.1:{socks_port}',
            f'ControlPort 127.0.0.1:{control_port}',
            'CookieAuthentication 1',
            f'DataDirectory {_tor_path(data_dir)}',
            'AvoidDiskWrites 1',
            'ClientOnly 1',
            'Log notice stdout',
            *([f'GeoIPFile {_tor_path(geoip)}'] if geoip.exists() else []),
            *([f'GeoIPv6File {_tor_path(geoip6)}'] if geoip6.exists() else []),
            '',
        ]),
        encoding='utf-8',
    )

    tor_log.parent.mkdir(parents=True, exist_ok=True)
    log_handle = tor_log.open('a', encoding='utf-8', errors='replace')
    proc = subprocess.Popen(
        [str(tor_exe), '-f', str(torrc)],
        cwd=str(tor_dir),
        stdout=log_handle,
        stderr=log_handle,
    )
    log_handle.close()
    _wait_for_controller_with_process(control_port, process=proc, log_path=tor_log)
    progress, summary = _wait_for_bootstrap(control_port, timeout=60.0)
    os.environ['P2PCHAT_TOR_SOCKS_PORT'] = str(socks_port)
    os.environ['P2PCHAT_TOR_CONTROL_PORT'] = str(control_port)
    return ManagedTor(
        process=proc,
        socks_port=socks_port,
        control_port=control_port,
        tor_dir=tor_dir,
        bootstrap_progress=progress,
        bootstrap_summary=summary,
    )
