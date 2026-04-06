from __future__ import annotations

import base64
import time
from dataclasses import dataclass, asdict
from typing import Optional

from .crypto import identity_fingerprint
from .storage import load_json, save_json


@dataclass
class Contact:
    name: str
    onion: str
    identity_pub_b64: str
    fingerprint: str
    trusted: bool = False
    verified: bool = False
    verified_at: int = 0


def normalize_onion(value: str) -> str:
    onion = value.strip().lower()
    for prefix in ('http://', 'https://'):
        if onion.startswith(prefix):
            onion = onion[len(prefix):]
    if '/' in onion:
        onion = onion.split('/', 1)[0]
    if onion.endswith('.onion'):
        onion = onion[:-6]
    alphabet = set('abcdefghijklmnopqrstuvwxyz234567')
    if len(onion) != 56 or any(ch not in alphabet for ch in onion):
        raise ValueError('invalid onion address format')
    return f'{onion}.onion'


def normalize_identity_pub(identity_pub_b64_value: str) -> str:
    cleaned = identity_pub_b64_value.strip()
    try:
        raw = base64.b64decode(cleaned.encode('ascii'), validate=True)
    except Exception as e:
        raise ValueError('invalid identity public key encoding') from e
    if len(raw) != 32:
        raise ValueError('identity public key must be 32 bytes')
    return cleaned


class ContactBook:
    def __init__(self, path):
        self.path = path
        self._contacts = self._load()

    def _load(self) -> dict[str, Contact]:
        raw = load_json(self.path, default={})
        contacts: dict[str, Contact] = {}
        if not isinstance(raw, dict):
            return contacts
        for key, value in raw.items():
            if not isinstance(value, dict):
                continue
            item = dict(value)
            item.setdefault('verified', False)
            item.setdefault('verified_at', 0)
            try:
                contacts[key] = Contact(**item)
            except TypeError:
                continue
        return contacts

    def save(self) -> None:
        save_json(self.path, {k: asdict(v) for k, v in self._contacts.items()})

    def add(self, name: str, onion: str, identity_pub_b64_value: str, trusted: bool = False) -> Contact:
        normalized_onion = normalize_onion(onion)
        normalized_identity_pub = normalize_identity_pub(identity_pub_b64_value)
        existing_name = self._contacts.get(name)
        existing_identity = self.by_identity(normalized_identity_pub)
        preserved_trusted = bool(existing_name and existing_name.trusted) or bool(existing_identity and existing_identity.trusted)
        preserved_verified = bool(existing_name and existing_name.verified) or bool(existing_identity and existing_identity.verified)
        preserved_verified_at = 0
        if existing_name and existing_name.verified_at:
            preserved_verified_at = int(existing_name.verified_at)
        if existing_identity and existing_identity.verified_at:
            preserved_verified_at = max(preserved_verified_at, int(existing_identity.verified_at))
        c = Contact(
            name=name,
            onion=normalized_onion,
            identity_pub_b64=normalized_identity_pub,
            fingerprint=identity_fingerprint(normalized_identity_pub),
            trusted=trusted or preserved_trusted,
            verified=preserved_verified,
            verified_at=preserved_verified_at,
        )
        self._contacts[name] = c
        self.save()
        return c

    def by_name(self, name: str) -> Optional[Contact]:
        return self._contacts.get(name)

    def by_identity(self, identity_pub_b64_value: str) -> Optional[Contact]:
        for contact in self._contacts.values():
            if contact.identity_pub_b64 == identity_pub_b64_value:
                return contact
        return None

    def list(self) -> list[Contact]:
        return sorted(self._contacts.values(), key=lambda x: x.name.lower())

    def trust(self, name: str, *, verified: bool = False) -> bool:
        c = self.by_name(name)
        if not c:
            return False
        c.trusted = True
        if verified:
            c.verified = True
            c.verified_at = int(time.time())
        self.save()
        return True

    def verify(self, name: str) -> bool:
        c = self.by_name(name)
        if not c:
            return False
        c.trusted = True
        c.verified = True
        c.verified_at = int(time.time())
        self.save()
        return True

    def clear(self) -> None:
        self._contacts = {}
        self.save()
