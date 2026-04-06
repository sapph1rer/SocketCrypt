from __future__ import annotations

import os
import socket
import time
from typing import Optional

from stem.control import Controller

from .config import (
    VIRTUAL_PORT,
    get_tor_control_host,
    get_tor_control_password,
    get_tor_control_port,
    get_tor_socks_host,
    get_tor_socks_port,
)


def _recv_exact(sock: socket.socket, size: int) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    while remaining > 0:
        part = sock.recv(remaining)
        if not part:
            break
        chunks.append(part)
        remaining -= len(part)
    data = b''.join(chunks)
    if len(data) != size:
        raise RuntimeError(f'SOCKS5 short response ({len(data)}/{size} bytes)')
    return data


def _backup_bad_onion_key(onion_key_path) -> None:
    if not onion_key_path.exists():
        return
    suffix = time.strftime('%Y%m%d-%H%M%S')
    backup = onion_key_path.with_name(f'{onion_key_path.name}.bad.{suffix}')
    onion_key_path.replace(backup)


def create_or_resume_onion(local_port: int, onion_key_path) -> tuple[str, str, str]:
    with Controller.from_port(address=get_tor_control_host(), port=get_tor_control_port()) as controller:
        password = get_tor_control_password()
        if password:
            controller.authenticate(password=password)
        else:
            controller.authenticate()

        last_err: Exception | None = None
        use_saved_key = onion_key_path.exists()
        for attempt in range(1, 4):
            try:
                if use_saved_key and onion_key_path.exists():
                    raw_key = onion_key_path.read_text(encoding='utf-8').strip()
                    if ':' not in raw_key:
                        raise ValueError('invalid onion key format')
                    key_type, key_content = raw_key.split(':', 1)
                    service = controller.create_ephemeral_hidden_service(
                        {VIRTUAL_PORT: local_port},
                        key_type=key_type.strip(),
                        key_content=key_content.strip(),
                        await_publication=False,
                        detached=True,
                    )
                else:
                    service = controller.create_ephemeral_hidden_service(
                        {VIRTUAL_PORT: local_port},
                        await_publication=False,
                        detached=True,
                    )
                    onion_key_path.write_text(
                        f'{service.private_key_type}:{service.private_key}',
                        encoding='utf-8',
                    )
                    try:
                        os.chmod(onion_key_path, 0o600)
                    except OSError:
                        pass

                return service.service_id, service.private_key_type, service.private_key
            except Exception as e:
                last_err = e
                err_text = str(e).lower()
                if use_saved_key and any(token in err_text for token in ('key', 'descriptor', 'invalid', 'malformed')):
                    _backup_bad_onion_key(onion_key_path)
                    use_saved_key = False
                    continue
                if attempt < 3:
                    time.sleep(attempt)
                    continue

        raise RuntimeError(f'failed to publish onion service: {last_err}')


def socks5_connect(host: str, port: int, timeout: Optional[float] = 45) -> socket.socket:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    if timeout is not None:
        s.settimeout(timeout)
    try:
        s.connect((get_tor_socks_host(), get_tor_socks_port()))

        s.sendall(b'\x05\x01\x00')
        resp = _recv_exact(s, 2)
        if resp != b'\x05\x00':
            raise RuntimeError('SOCKS5 auth negotiation failed')

        host_bytes = host.encode('idna')
        if len(host_bytes) > 255:
            raise RuntimeError('SOCKS5 host too long')
        req = b'\x05\x01\x00\x03' + bytes([len(host_bytes)]) + host_bytes + port.to_bytes(2, 'big')
        s.sendall(req)

        resp = _recv_exact(s, 4)
        if resp[1] != 0x00:
            code = resp[1]
            code_text = {
                0x01: 'general SOCKS server failure',
                0x02: 'connection not allowed by ruleset',
                0x03: 'network unreachable',
                0x04: 'host unreachable (peer onion likely offline/unpublished)',
                0x05: 'connection refused',
                0x06: 'TTL expired',
                0x07: 'command not supported',
                0x08: 'address type not supported',
            }.get(code, 'unknown error')
            raise RuntimeError(f'SOCKS5 connect failed: 0x{code:02x} {code_text}')

        atyp = resp[3]
        if atyp == 0x01:
            _recv_exact(s, 6)
        elif atyp == 0x03:
            ln = _recv_exact(s, 1)[0]
            _recv_exact(s, ln + 2)
        elif atyp == 0x04:
            _recv_exact(s, 18)
        else:
            raise RuntimeError('SOCKS5 invalid ATYP')

        s.settimeout(None)
        return s
    except Exception:
        try:
            s.close()
        except Exception:
            pass
        raise
