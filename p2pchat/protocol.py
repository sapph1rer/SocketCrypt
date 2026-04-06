from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import os
import random
import string
import time
from collections import deque
from dataclasses import dataclass
from typing import Callable, Optional, Any

from nacl.public import PrivateKey
from nacl.signing import SigningKey

from .config import (
    CONNECT_TIMEOUT,
    ENABLE_HISTORY,
    ENCRYPTED_ONLY,
    PROTO_VERSION,
    REKEY_AFTER_MESSAGES,
    REKEY_AFTER_SECONDS,
)
from .contacts import ContactBook, Contact
from .crypto import (
    SESSION_CIPHER_AEAD,
    decrypt_for_session,
    derive_session_key,
    encrypt_for_session,
    generate_ephemeral_keypair,
    identity_pub_b64,
    sign_payload,
    verify_signature,
)
from .storage import append_history
from .tor_utils import socks5_connect

ACK_WAIT_SECONDS = 6.0
DEDUP_TTL_SECONDS = 3600
DEDUP_MAX_SIZE = 4096
MAX_RATCHET_SKIP = 2048
DEFAULT_SEND_JITTER_MS = 120
DEFAULT_COVER_MIN_SECONDS = 22.0
DEFAULT_COVER_MAX_SECONDS = 46.0
DEFAULT_PAD_BYTES = 96
DEFAULT_FIXED_SEND_DELAY_MS = 0
DEFAULT_FIXED_PAD_BYTES = 0
DEFAULT_FIXED_COVER_INTERVAL_SECONDS = 0.0


def normalize_nick(value: str) -> str:
    nick = value.strip()
    if not nick:
        raise ValueError('nick cannot be empty')
    if len(nick) > 24:
        raise ValueError('nick is too long (max 24 chars)')
    allowed = set(string.ascii_letters + string.digits + '_-')
    if any(ch not in allowed for ch in nick):
        raise ValueError('nick allows only letters, numbers, _ and -')
    return nick


@dataclass
class Session:
    peer_name: str
    peer_onion: str
    peer_identity_pub_b64: str
    peer_nick: str
    sas_code: str
    session_key: bytearray
    send_root_key: bytearray
    recv_root_key: bytearray
    send_chain_key: bytearray
    recv_chain_key: bytearray
    send_epoch: int
    send_seq: int
    recv_epoch: int
    recv_seq: int
    sent_in_epoch: int
    epoch_started_at: float
    ephemeral: bool
    pending_acks: dict[str, asyncio.Future[None]]
    seen_ids: deque[str]
    cover_task: asyncio.Task[Any] | None
    reader: asyncio.StreamReader
    writer: asyncio.StreamWriter


def _as_bytes(data: bytes | bytearray) -> bytes:
    if isinstance(data, bytearray):
        return bytes(data)
    return data


def _zeroize_secret(buf: bytearray | None) -> None:
    if buf is None:
        return
    try:
        for i in range(len(buf)):
            buf[i] = 0
    except Exception:
        pass


def _kdf32(seed: bytes | bytearray, label: bytes) -> bytes:
    return hashlib.blake2b(_as_bytes(seed) + b'|' + label, digest_size=32).digest()


def _derive_direction_roots(
    session_key: bytes,
    my_identity_pub_b64: str,
    peer_identity_pub_b64: str,
) -> tuple[bytes, bytes]:
    ordered = sorted([my_identity_pub_b64, peer_identity_pub_b64])
    low = ordered[0].encode('utf-8')
    high = ordered[1].encode('utf-8')
    low_to_high = _kdf32(session_key, b'dir-root-low-high|' + low + b'|' + high)
    high_to_low = _kdf32(session_key, b'dir-root-high-low|' + high + b'|' + low)
    if my_identity_pub_b64 == ordered[0]:
        return low_to_high, high_to_low
    return high_to_low, low_to_high


def _derive_epoch_chain_key(direction_root: bytes | bytearray, epoch: int) -> bytearray:
    label = b'epoch-chain|' + str(epoch).encode('ascii')
    return bytearray(_kdf32(direction_root, label))


def _ratchet_next_epoch(direction_root: bytearray) -> bytearray:
    return bytearray(_kdf32(direction_root, b'next-epoch'))


def _ratchet_chain_step(chain_key: bytearray) -> bytearray:
    material = hashlib.blake2b(bytes(chain_key) + b'|msg-step', digest_size=64).digest()
    chain_key[:] = material[:32]
    return bytearray(material[32:])


def build_sas_code(session_key: bytes | bytearray, my_identity_pub_b64: str, peer_identity_pub_b64: str) -> str:
    ordered = sorted([my_identity_pub_b64.encode('utf-8'), peer_identity_pub_b64.encode('utf-8')])
    digest = hashlib.blake2b(_as_bytes(session_key) + b'|' + ordered[0] + b'|' + ordered[1], digest_size=5).digest()
    return base64.b32encode(digest).decode('ascii').rstrip('=')


def _key_transcript_material(
    my_identity_pub_b64: str,
    peer_identity_pub_b64: str,
    my_eph_pub_b64: str,
    peer_eph_pub_b64: str,
) -> bytes:
    material = {
        'v': PROTO_VERSION,
        'identity_pub': sorted([my_identity_pub_b64, peer_identity_pub_b64]),
        'eph_pub': sorted([my_eph_pub_b64, peer_eph_pub_b64]),
    }
    return json.dumps(material, sort_keys=True, separators=(',', ':')).encode('utf-8')


class ChatNode:
    def __init__(
        self,
        my_onion: str,
        signing_key: SigningKey,
        contacts: ContactBook,
        history_path,
        my_nick: str = 'anon',
        history_enabled: bool = ENABLE_HISTORY,
        metadata_protection: bool = True,
        send_jitter_max_ms: int = DEFAULT_SEND_JITTER_MS,
        cover_traffic_enabled: bool = True,
        cover_min_seconds: float = DEFAULT_COVER_MIN_SECONDS,
        cover_max_seconds: float = DEFAULT_COVER_MAX_SECONDS,
        payload_padding_max_bytes: int = DEFAULT_PAD_BYTES,
        fixed_traffic_shaping: bool = False,
        fixed_send_delay_ms: int = DEFAULT_FIXED_SEND_DELAY_MS,
        fixed_pad_bytes: int = DEFAULT_FIXED_PAD_BYTES,
        fixed_cover_interval_seconds: float = DEFAULT_FIXED_COVER_INTERVAL_SECONDS,
        require_verified_contacts: bool = False,
        on_system: Callable[[str], None] | None = None,
        on_chat: Callable[[str, str], None] | None = None,
        on_room: Callable[[str, str, str, str, str], None] | None = None,
        on_connect: Callable[[Session], None] | None = None,
        on_disconnect: Callable[[Session], None] | None = None,
    ):
        self.my_onion = my_onion
        self.signing_key = signing_key
        self.contacts = contacts
        self.history_path = history_path
        self.session: Optional[Session] = None
        self.server = None
        self.my_nick = normalize_nick(my_nick)
        self.history_enabled = bool(history_enabled)
        self.metadata_protection = bool(metadata_protection)
        self.send_jitter_max_ms = max(0, int(send_jitter_max_ms))
        self.cover_traffic_enabled = bool(cover_traffic_enabled)
        self.cover_min_seconds = max(3.0, float(cover_min_seconds))
        self.cover_max_seconds = max(self.cover_min_seconds, float(cover_max_seconds))
        self.payload_padding_max_bytes = max(0, int(payload_padding_max_bytes))
        self.fixed_traffic_shaping = bool(fixed_traffic_shaping)
        self.fixed_send_delay_ms = max(0, int(fixed_send_delay_ms))
        self.fixed_pad_bytes = max(0, int(fixed_pad_bytes))
        self.fixed_cover_interval_seconds = max(0.0, float(fixed_cover_interval_seconds))
        self.require_verified_contacts = bool(require_verified_contacts)
        self.on_system = on_system
        self.on_chat = on_chat
        self.on_room = on_room
        self.on_connect = on_connect
        self.on_disconnect = on_disconnect
        self._seen_msg_keys: dict[str, float] = {}

    @property
    def my_identity_pub_b64(self) -> str:
        return identity_pub_b64(self.signing_key)

    def set_my_nick(self, nick: str) -> None:
        self.my_nick = normalize_nick(nick)

    def prompt(self) -> str:
        return f'{self.my_nick}> '

    def _emit_system(self, text: str) -> None:
        if self.on_system:
            self.on_system(text)

    def _emit_chat(self, nick: str, text: str) -> None:
        if self.on_chat:
            self.on_chat(nick, text)

    def _emit_room(self, nick: str, room: str, text: str, peer_onion: str, peer_identity_pub_b64: str) -> None:
        if self.on_room:
            self.on_room(nick, room, text, peer_onion, peer_identity_pub_b64)

    def _emit_disconnect(self, session: Session) -> None:
        if self.on_disconnect:
            self.on_disconnect(session)

    def _emit_connect(self, session: Session) -> None:
        if self.on_connect:
            self.on_connect(session)

    def _wipe_session_sensitive(self, session: Session | None) -> None:
        if not session:
            return
        self._stop_cover_traffic(session)
        for pending in list(session.pending_acks.values()):
            if pending and not pending.done():
                pending.cancel()
        session.pending_acks.clear()
        session.seen_ids.clear()
        _zeroize_secret(session.session_key)
        _zeroize_secret(session.send_root_key)
        _zeroize_secret(session.recv_root_key)
        _zeroize_secret(session.send_chain_key)
        _zeroize_secret(session.recv_chain_key)

    def secure_wipe_runtime(self) -> None:
        self._wipe_session_sensitive(self.session)
        self.session = None
        self._seen_msg_keys.clear()

    async def close_session(self) -> None:
        session = self.session
        self.session = None
        if not session:
            return
        try:
            session.writer.close()
            await session.writer.wait_closed()
        except Exception:
            pass
        self._wipe_session_sensitive(session)

    def _prepare_inbound_message_key(
        self,
        session: Session,
        pkt: dict[str, object],
    ) -> tuple[bytearray, int, int, bytearray, bytearray]:
        kepoch_raw = pkt.get('kepoch')
        kseq_raw = pkt.get('kseq')
        if not isinstance(kepoch_raw, int) or not isinstance(kseq_raw, int) or kepoch_raw < 0 or kseq_raw <= 0:
            raise RuntimeError('invalid ratchet counters')
        if kepoch_raw < session.recv_epoch:
            raise RuntimeError('stale key epoch')
        if kepoch_raw == session.recv_epoch and kseq_raw <= session.recv_seq:
            raise RuntimeError('replay/duplicate sequence')

        next_root = bytearray(session.recv_root_key)
        next_chain = bytearray(session.recv_chain_key)
        next_epoch = session.recv_epoch
        next_seq = session.recv_seq

        if kepoch_raw > next_epoch:
            jump = kepoch_raw - next_epoch
            if jump > 64:
                raise RuntimeError('key epoch jump too large')
            for _ in range(jump):
                newer_root = _ratchet_next_epoch(next_root)
                _zeroize_secret(next_root)
                next_root = newer_root
            _zeroize_secret(next_chain)
            next_chain = _derive_epoch_chain_key(next_root, kepoch_raw)
            next_epoch = kepoch_raw
            next_seq = 0

        delta = kseq_raw - next_seq
        if delta <= 0:
            raise RuntimeError('replay/duplicate sequence')
        if delta > MAX_RATCHET_SKIP:
            raise RuntimeError('ratchet sequence gap too large')

        msg_key: bytearray | None = None
        for _ in range(delta):
            if msg_key is not None:
                _zeroize_secret(msg_key)
            msg_key = _ratchet_chain_step(next_chain)
        if msg_key is None:
            raise RuntimeError('invalid ratchet state')
        return msg_key, kepoch_raw, kseq_raw, next_root, next_chain

    def _cleanup_seen_keys(self) -> None:
        if not self._seen_msg_keys:
            return
        now = time.time()
        stale = [k for k, ts in self._seen_msg_keys.items() if (now - ts) > DEDUP_TTL_SECONDS]
        for key in stale:
            self._seen_msg_keys.pop(key, None)
        if len(self._seen_msg_keys) > DEDUP_MAX_SIZE:
            ordered = sorted(self._seen_msg_keys.items(), key=lambda kv: kv[1], reverse=True)
            self._seen_msg_keys = dict(ordered[:DEDUP_MAX_SIZE])

    def _seen_message_key(self, peer_identity_pub_b64: str, msg_id: str) -> str:
        return f'{peer_identity_pub_b64}|{msg_id}'

    def _mark_message_seen(self, peer_identity_pub_b64: str, msg_id: str) -> bool:
        if not msg_id:
            return False
        self._cleanup_seen_keys()
        key = self._seen_message_key(peer_identity_pub_b64, msg_id)
        if key in self._seen_msg_keys:
            self._seen_msg_keys[key] = time.time()
            return True
        self._seen_msg_keys[key] = time.time()
        return False

    def _new_message_id(self) -> str:
        raw = (
            self.my_identity_pub_b64.encode('utf-8')
            + b'|'
            + str(time.time_ns()).encode('ascii')
            + b'|'
            + os.urandom(12)
        )
        token = hashlib.blake2b(raw, digest_size=12).digest()
        return base64.urlsafe_b64encode(token).decode('ascii').rstrip('=')

    async def _maybe_apply_send_jitter(self) -> None:
        if self.fixed_traffic_shaping and self.fixed_send_delay_ms > 0:
            await asyncio.sleep(float(self.fixed_send_delay_ms) / 1000.0)
            return
        if not self.metadata_protection or self.send_jitter_max_ms <= 0:
            return
        delay = random.uniform(0.0, float(self.send_jitter_max_ms) / 1000.0)
        if delay > 0:
            await asyncio.sleep(delay)

    def _apply_payload_padding(self, payload: dict[str, object]) -> dict[str, object]:
        if not self.metadata_protection or self.payload_padding_max_bytes <= 0:
            if not self.fixed_traffic_shaping or self.fixed_pad_bytes <= 0:
                return payload
        kind = str(payload.get('kind', '')).strip()
        # keep ack packets lean and predictable for responsiveness
        if kind in ('ack',):
            return payload
        if self.fixed_traffic_shaping and self.fixed_pad_bytes > 0:
            pad_len = self.fixed_pad_bytes
        else:
            pad_len = random.randint(0, self.payload_padding_max_bytes)
        if pad_len <= 0:
            return payload
        out = dict(payload)
        out['_pad'] = base64.b64encode(os.urandom(pad_len)).decode('ascii')
        return out

    async def _cover_traffic_worker(self, session: Session) -> None:
        while self.session is session and not session.ephemeral and self.cover_traffic_enabled:
            if self.fixed_traffic_shaping and self.fixed_cover_interval_seconds > 0:
                wait_s = self.fixed_cover_interval_seconds
            else:
                wait_s = random.uniform(self.cover_min_seconds, self.cover_max_seconds)
            await asyncio.sleep(wait_s)
            if self.session is not session:
                break
            cover_id = self._new_message_id()
            try:
                await self._send_encrypted_inner(
                    session,
                    {
                        'kind': 'cover',
                        'mid': cover_id,
                        'ts': int(time.time()),
                    },
                    count_for_rekey=False,
                )
            except Exception:
                break

    def _start_cover_traffic(self, session: Session) -> None:
        if not self.cover_traffic_enabled or session.ephemeral:
            return
        if session.cover_task and not session.cover_task.done():
            return
        session.cover_task = asyncio.create_task(self._cover_traffic_worker(session))

    def _stop_cover_traffic(self, session: Session | None) -> None:
        if not session:
            return
        task = session.cover_task
        if task and not task.done():
            task.cancel()
        session.cover_task = None

    async def start_listener(self) -> int:
        self.server = await asyncio.start_server(self._handle_inbound, host='127.0.0.1', port=0)
        return self.server.sockets[0].getsockname()[1]

    async def _handle_inbound(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        session: Session | None = None
        try:
            session = await self._server_handshake(reader, writer)
            if not session.ephemeral:
                if self.session and self.session is not session:
                    self._stop_cover_traffic(self.session)
                self.session = session
                self._emit_connect(session)
                self._emit_system(f'incoming session from {session.peer_name} as nick "{session.peer_nick}"')
                self._emit_system(f'session verify code: {session.sas_code}')
                self._start_cover_traffic(session)
            await self._receive_loop(session)
        except Exception as e:
            self._emit_system(f'inbound error: {e}')
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
            if session is not None:
                self._wipe_session_sensitive(session)

    async def connect(self, contact: Contact) -> None:
        self._emit_system(f'connecting to {contact.name} ({contact.onion}) ...')
        if self.session:
            await self.close_session()

        loop = asyncio.get_running_loop()
        last_err: Exception | None = None
        session: Session | None = None

        for attempt in range(1, 4):
            raw = None
            writer = None
            try:
                raw = await loop.run_in_executor(None, socks5_connect, contact.onion, 80, CONNECT_TIMEOUT)
                raw.setblocking(False)
                reader, writer = await asyncio.open_connection(sock=raw)
                session = await self._client_handshake(reader, writer, contact)
                break
            except Exception as e:
                last_err = e
                if writer is not None:
                    try:
                        writer.close()
                        await writer.wait_closed()
                    except Exception:
                        pass
                elif raw is not None:
                    try:
                        raw.close()
                    except Exception:
                        pass

                if attempt < 3:
                    self._emit_system(f'connect attempt {attempt}/3 failed; retrying...')
                    await asyncio.sleep(1.5 * attempt)

        if session is None:
            raise RuntimeError(
                f'failed after 3 attempts: {last_err}. '
                'Ask peer to keep app open, verify /diag and contact onion/fingerprint.'
            )

        self.session = session
        self._emit_connect(session)
        self._emit_system(f'connected to {session.peer_name} as nick "{session.peer_nick}"')
        self._emit_system(f'session verify code: {session.sas_code}')
        self._start_cover_traffic(session)
        asyncio.create_task(self._receive_loop(session))

    async def _send_encrypted_inner(
        self,
        session: Session,
        inner_payload: dict,
        *,
        count_for_rekey: bool = True,
    ) -> int:
        payload = self._apply_payload_padding(inner_payload)
        await self._maybe_apply_send_jitter()
        now = time.time()
        if (
            not session.ephemeral
            and count_for_rekey
            and (
                session.sent_in_epoch >= REKEY_AFTER_MESSAGES
                or (now - session.epoch_started_at) >= REKEY_AFTER_SECONDS
            )
        ):
            session.send_epoch += 1
            session.send_seq = 0
            session.sent_in_epoch = 0
            session.epoch_started_at = now
            next_root = _ratchet_next_epoch(session.send_root_key)
            _zeroize_secret(session.send_root_key)
            session.send_root_key = next_root
            _zeroize_secret(session.send_chain_key)
            session.send_chain_key = _derive_epoch_chain_key(session.send_root_key, session.send_epoch)
            self._emit_system(f'session key rotated (epoch {session.send_epoch})')

        session.send_seq += 1
        if count_for_rekey:
            session.sent_in_epoch += 1
        outbound_epoch = session.send_epoch
        outbound_seq = session.send_seq
        outbound_key = _ratchet_chain_step(session.send_chain_key)
        plaintext = json.dumps(payload, ensure_ascii=False, separators=(',', ':'))
        try:
            encrypted = encrypt_for_session(bytes(outbound_key), plaintext)
        finally:
            _zeroize_secret(outbound_key)
        pkt = {
            'type': 'msg',
            'kepoch': outbound_epoch,
            'kseq': outbound_seq,
            **encrypted,
        }
        session.writer.write((json.dumps(pkt) + '\n').encode('utf-8'))
        await session.writer.drain()
        return outbound_seq

    async def _send_ack(self, session: Session, msg_id: str) -> None:
        if not msg_id:
            return
        try:
            await self._send_encrypted_inner(
                session,
                {
                    'kind': 'ack',
                    'ack_for': msg_id,
                    'ts': int(time.time()),
                },
                count_for_rekey=False,
            )
        except Exception:
            pass

    async def _wait_for_ack(self, session: Session, msg_id: str, timeout: float = ACK_WAIT_SECONDS) -> bool:
        if session.ephemeral:
            return False
        loop = asyncio.get_running_loop()
        fut = loop.create_future()
        session.pending_acks[msg_id] = fut
        try:
            await asyncio.wait_for(fut, timeout=timeout)
            return True
        except asyncio.TimeoutError:
            return False
        finally:
            session.pending_acks.pop(msg_id, None)

    async def send_message_to_contact(self, contact: Contact, text: str, room: str) -> None:
        loop = asyncio.get_running_loop()
        last_err: Exception | None = None
        msg_id = self._new_message_id()
        for attempt in range(1, 4):
            raw = None
            writer = None
            session: Session | None = None
            try:
                raw = await loop.run_in_executor(None, socks5_connect, contact.onion, 80, CONNECT_TIMEOUT)
                raw.setblocking(False)
                reader, writer = await asyncio.open_connection(sock=raw)
                session = await self._client_handshake(reader, writer, contact, mode='oneshot')
                payload: dict[str, object] = {
                    'kind': 'room',
                    'room': room,
                    'nick': self.my_nick,
                    'text': text,
                    'ts': int(time.time()),
                    'mid': msg_id,
                }
                await self._send_encrypted_inner(session, payload)

                # oneshot mode waits for encrypted ACK before declaring delivery success
                ack_line = await asyncio.wait_for(reader.readline(), timeout=ACK_WAIT_SECONDS)
                if not ack_line:
                    raise RuntimeError('no ack from peer')
                ack_pkt = json.loads(ack_line.decode('utf-8'))
                if ack_pkt.get('type') != 'msg':
                    raise RuntimeError('invalid ack packet')
                inbound_key: bytearray | None = None
                next_root: bytearray | None = None
                next_chain: bytearray | None = None
                try:
                    inbound_key, next_epoch, next_seq, next_root, next_chain = self._prepare_inbound_message_key(session, ack_pkt)
                    ack_text = decrypt_for_session(
                        bytes(inbound_key),
                        ack_pkt['nonce'],
                        ack_pkt['ciphertext'],
                        ack_pkt.get('alg'),
                    )
                finally:
                    _zeroize_secret(inbound_key)
                ack_payload = json.loads(ack_text)
                if not isinstance(ack_payload, dict) or ack_payload.get('kind') != 'ack':
                    raise RuntimeError('unexpected reply (missing ack)')
                if str(ack_payload.get('ack_for', '')).strip() != msg_id:
                    raise RuntimeError('ack mismatch')
                session.recv_epoch = next_epoch
                session.recv_seq = next_seq
                if next_root is not None:
                    _zeroize_secret(session.recv_root_key)
                    session.recv_root_key = next_root
                if next_chain is not None:
                    _zeroize_secret(session.recv_chain_key)
                    session.recv_chain_key = next_chain
                return
            except Exception as e:
                last_err = e
                if attempt < 3:
                    await asyncio.sleep(1.0 * attempt)
            finally:
                if writer is not None:
                    try:
                        writer.close()
                        await writer.wait_closed()
                    except Exception:
                        pass
                elif raw is not None:
                    try:
                        raw.close()
                    except Exception:
                        pass
                if session is not None:
                    self._wipe_session_sensitive(session)

        raise RuntimeError(f'room delivery failed after retries: {last_err}')

    async def send_message(self, text: str) -> None:
        if not self.session:
            self._emit_system('no active session')
            return

        msg_id = self._new_message_id()
        payload: dict[str, object] = {
            'kind': 'chat',
            'nick': self.my_nick,
            'text': text,
            'ts': int(time.time()),
            'mid': msg_id,
        }
        await self._send_encrypted_inner(self.session, payload)
        ack_ok = await self._wait_for_ack(self.session, msg_id, timeout=ACK_WAIT_SECONDS)
        if not ack_ok:
            self._emit_system('delivery warning: no ack received yet')

        if self.history_enabled:
            append_history(
                self.history_path,
                {
                    'dir': 'out',
                    'peer': self.session.peer_name,
                    'peer_onion': self.session.peer_onion,
                    'nick': self.my_nick,
                    'text': text,
                },
            )

    async def _client_handshake(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        contact: Contact,
        mode: str | None = None,
    ) -> Session:
        eph_sk, eph_pub_b64 = generate_ephemeral_keypair()
        payload = {
            'type': 'hello',
            'v': PROTO_VERSION,
            'ts': int(time.time()),
            'from_onion': self.my_onion,
            'identity_pub': self.my_identity_pub_b64,
            'eph_pub': eph_pub_b64,
            'nick': self.my_nick,
        }
        if mode:
            payload['mode'] = mode
        signed = {**payload, 'sig': sign_payload(self.signing_key, payload)}
        writer.write((json.dumps(signed) + '\n').encode('utf-8'))
        await writer.drain()

        line = await asyncio.wait_for(reader.readline(), timeout=CONNECT_TIMEOUT)
        if not line:
            raise RuntimeError('peer closed during handshake')
        reply = json.loads(line.decode('utf-8'))
        session = self._validate_handshake(reply, expected_contact=contact, my_eph_sk=eph_sk, peer_writer=writer, peer_reader=reader)

        ack = {'type': 'ready'}
        writer.write((json.dumps(ack) + '\n').encode('utf-8'))
        await writer.drain()

        ready = await asyncio.wait_for(reader.readline(), timeout=CONNECT_TIMEOUT)
        if not ready:
            raise RuntimeError('peer did not confirm ready')
        return session

    async def _server_handshake(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> Session:
        line = await asyncio.wait_for(reader.readline(), timeout=CONNECT_TIMEOUT)
        if not line:
            raise RuntimeError('empty handshake')
        hello = json.loads(line.decode('utf-8'))

        eph_sk, eph_pub_b64 = generate_ephemeral_keypair()
        contact = self.contacts.by_identity(hello.get('identity_pub', ''))
        hello_mode = hello.get('mode') if isinstance(hello.get('mode'), str) else None

        if contact:
            if not contact.trusted:
                raise RuntimeError(f'contact {contact.name} exists but is not trusted yet')
            if self.require_verified_contacts and not getattr(contact, 'verified', False) and hello_mode != 'oneshot':
                raise RuntimeError(f'contact {contact.name} is not verified yet')
        else:
            if hello_mode != 'oneshot':
                raise RuntimeError('unknown peer; import and verify before direct chat')

        reply_payload = {
            'type': 'hello',
            'v': PROTO_VERSION,
            'ts': int(time.time()),
            'from_onion': self.my_onion,
            'identity_pub': self.my_identity_pub_b64,
            'eph_pub': eph_pub_b64,
            'nick': self.my_nick,
        }
        if hello_mode:
            reply_payload['mode'] = hello_mode
        reply = {**reply_payload, 'sig': sign_payload(self.signing_key, reply_payload)}

        temp_contact = contact or Contact(
            name=f"unknown-{hello['from_onion'][:8]}",
            onion=hello['from_onion'],
            identity_pub_b64=hello['identity_pub'],
            fingerprint='',
            trusted=False,
        )
        session = self._validate_handshake(
            hello,
            expected_contact=temp_contact,
            my_eph_sk=eph_sk,
            peer_writer=writer,
            peer_reader=reader,
            allow_untrusted_unknown=True,
        )

        writer.write((json.dumps(reply) + '\n').encode('utf-8'))
        await writer.drain()

        ready = await asyncio.wait_for(reader.readline(), timeout=CONNECT_TIMEOUT)
        if not ready:
            raise RuntimeError('peer did not send ready')
        writer.write(b'{"type":"ready"}\n')
        await writer.drain()
        return session

    def _validate_handshake(
        self,
        pkt: dict,
        expected_contact: Contact,
        my_eph_sk: PrivateKey,
        peer_writer: asyncio.StreamWriter,
        peer_reader: asyncio.StreamReader,
        allow_untrusted_unknown: bool = False,
    ) -> Session:
        required = {'type', 'v', 'ts', 'from_onion', 'identity_pub', 'eph_pub', 'sig'}
        if not required.issubset(pkt.keys()):
            raise RuntimeError('invalid handshake packet')
        if pkt['type'] != 'hello' or pkt['v'] != PROTO_VERSION:
            raise RuntimeError('protocol mismatch')

        signed_part = {k: pkt[k] for k in ['type', 'v', 'ts', 'from_onion', 'identity_pub', 'eph_pub', 'nick', 'mode'] if k in pkt}
        if not verify_signature(pkt['identity_pub'], signed_part, pkt['sig']):
            raise RuntimeError('bad handshake signature')

        if expected_contact.identity_pub_b64 != pkt['identity_pub'] and expected_contact.identity_pub_b64:
            raise RuntimeError('peer identity key mismatch')
        if expected_contact.onion != pkt['from_onion'] and expected_contact.onion:
            if expected_contact.identity_pub_b64 == pkt['identity_pub'] and expected_contact.trusted:
                old_onion = expected_contact.onion
                new_onion = pkt['from_onion']
                try:
                    self.contacts.add(expected_contact.name, new_onion, expected_contact.identity_pub_b64, trusted=True)
                    self._emit_system(f'peer onion changed, auto-updated {expected_contact.name}: {old_onion} -> {new_onion}')
                except Exception:
                    raise RuntimeError('peer onion mismatch')
            else:
                raise RuntimeError('peer onion mismatch')
        if not expected_contact.trusted and not allow_untrusted_unknown:
            raise RuntimeError('peer not trusted')

        peer_nick_raw = pkt.get('nick', expected_contact.name)
        try:
            peer_nick = normalize_nick(str(peer_nick_raw))
        except ValueError:
            peer_nick = expected_contact.name

        my_eph_pub_b64 = base64.b64encode(bytes(my_eph_sk.public_key)).decode('ascii')
        transcript = _key_transcript_material(
            self.my_identity_pub_b64,
            pkt['identity_pub'],
            my_eph_pub_b64,
            pkt['eph_pub'],
        )
        session_key = derive_session_key(my_eph_sk, pkt['eph_pub'], transcript)
        send_root_key, recv_root_key = _derive_direction_roots(
            session_key,
            self.my_identity_pub_b64,
            pkt['identity_pub'],
        )
        sas_code = build_sas_code(session_key, self.my_identity_pub_b64, pkt['identity_pub'])
        return Session(
            peer_name=expected_contact.name,
            peer_onion=pkt['from_onion'],
            peer_identity_pub_b64=pkt['identity_pub'],
            peer_nick=peer_nick,
            sas_code=sas_code,
            session_key=bytearray(session_key),
            send_root_key=bytearray(send_root_key),
            recv_root_key=bytearray(recv_root_key),
            send_chain_key=_derive_epoch_chain_key(send_root_key, 0),
            recv_chain_key=_derive_epoch_chain_key(recv_root_key, 0),
            send_epoch=0,
            send_seq=0,
            recv_epoch=0,
            recv_seq=0,
            sent_in_epoch=0,
            epoch_started_at=time.time(),
            ephemeral=(pkt.get('mode') == 'oneshot'),
            pending_acks={},
            seen_ids=deque(maxlen=1024),
            cover_task=None,
            reader=peer_reader,
            writer=peer_writer,
        )

    async def _receive_loop(self, session: Session) -> None:
        while True:
            line = await session.reader.readline()
            if not line:
                if not session.ephemeral:
                    self._emit_system('peer disconnected')
                    if self.session == session:
                        self.session = None
                    self._emit_disconnect(session)
                self._wipe_session_sensitive(session)
                return

            try:
                pkt = json.loads(line.decode('utf-8'))
            except Exception:
                self._emit_system('received malformed packet')
                continue

            if pkt.get('type') != 'msg':
                continue

            if ENCRYPTED_ONLY and pkt.get('alg') != SESSION_CIPHER_AEAD:
                self._emit_system('dropped packet: non-AES cipher in encrypted-only mode')
                continue

            prev_recv_epoch = session.recv_epoch
            inbound_key: bytearray | None = None
            next_root: bytearray | None = None
            next_chain: bytearray | None = None
            try:
                inbound_key, next_epoch, next_seq, next_root, next_chain = self._prepare_inbound_message_key(session, pkt)
                decrypted_text = decrypt_for_session(
                    bytes(inbound_key),
                    pkt['nonce'],
                    pkt['ciphertext'],
                    pkt.get('alg'),
                )
            except Exception as e:
                err_text = str(e).strip().lower()
                if 'stale key epoch' in err_text:
                    self._emit_system('dropped packet: stale key epoch')
                elif 'replay/duplicate sequence' in err_text:
                    self._emit_system('dropped packet: replay/duplicate sequence')
                elif 'ratchet sequence gap too large' in err_text:
                    self._emit_system('dropped packet: ratchet sequence gap too large')
                elif 'key epoch jump too large' in err_text:
                    self._emit_system('dropped packet: key epoch jump too large')
                else:
                    self._emit_system('failed to decrypt incoming message')
                _zeroize_secret(inbound_key)
                _zeroize_secret(next_root)
                _zeroize_secret(next_chain)
                continue
            _zeroize_secret(inbound_key)
            session.recv_epoch = next_epoch
            session.recv_seq = next_seq
            if next_root is not None:
                _zeroize_secret(session.recv_root_key)
                session.recv_root_key = next_root
            if next_chain is not None:
                _zeroize_secret(session.recv_chain_key)
                session.recv_chain_key = next_chain
            if session.recv_epoch > prev_recv_epoch:
                self._emit_system(f'peer session key rotated (epoch {session.recv_epoch})')

            peer_nick = session.peer_nick
            text = decrypted_text
            msg_id = ''
            kind = 'chat'
            room_name = 'room'

            try:
                inner = json.loads(decrypted_text)
                if isinstance(inner, dict):
                    kind = str(inner.get('kind', 'chat')).strip() or 'chat'
                    msg_id = str(inner.get('mid', '')).strip()
                    if kind == 'ack':
                        ack_for = str(inner.get('ack_for', '')).strip()
                        if ack_for:
                            pending = session.pending_acks.get(ack_for)
                            if pending and not pending.done():
                                pending.set_result(None)
                        continue
                    if kind in ('chat', 'room'):
                        text = str(inner.get('text', ''))
                        parsed_nick = inner.get('nick')
                        if parsed_nick:
                            try:
                                peer_nick = normalize_nick(str(parsed_nick))
                            except ValueError:
                                peer_nick = session.peer_nick
                        if kind == 'room':
                            room_name = str(inner.get('room', '')).strip() or 'room'
            except Exception:
                pass

            if msg_id:
                is_duplicate = self._mark_message_seen(session.peer_identity_pub_b64, msg_id)
                await self._send_ack(session, msg_id)
                if is_duplicate:
                    continue

            if kind == 'cover':
                continue

            session.peer_nick = peer_nick
            if kind == 'room':
                self._emit_room(
                    session.peer_nick,
                    room_name,
                    text,
                    session.peer_onion,
                    session.peer_identity_pub_b64,
                )
                continue

            if self.history_enabled:
                append_history(
                    self.history_path,
                    {
                        'dir': 'in',
                        'peer': session.peer_name,
                        'peer_onion': session.peer_onion,
                        'nick': session.peer_nick,
                        'text': text,
                    },
                )

            self._emit_chat(session.peer_nick, text)
