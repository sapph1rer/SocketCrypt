from __future__ import annotations

import base64
import json
import os
from typing import Any

from nacl import bindings, exceptions, hash, pwhash, secret, signing
from nacl.encoding import RawEncoder
from nacl.public import PrivateKey, PublicKey
import nacl.utils

from .config import ENCRYPTED_ONLY

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except Exception:  # pragma: no cover - fallback is used when cryptography is unavailable
    AESGCM = None


SESSION_CIPHER_AEAD = "aes256gcm"
SESSION_CIPHER_FALLBACK = "secretbox"
SESSION_AAD = b"p2pchat-session-v1"


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64d(data: str) -> bytes:
    return base64.b64decode(data.encode("ascii"))


def canonical_json(obj: dict[str, Any]) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def load_or_create_signing_key(path) -> signing.SigningKey:
    if path.exists():
        return signing.SigningKey(b64d(path.read_text().strip()))
    sk = signing.SigningKey.generate()
    path.write_text(b64e(bytes(sk)))
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return sk


def identity_pub_b64(signing_key: signing.SigningKey) -> str:
    return b64e(bytes(signing_key.verify_key))


def identity_fingerprint(identity_pub_b64_value: str) -> str:
    digest = hash.blake2b(identity_pub_b64_value.encode("utf-8"), digest_size=32, encoder=RawEncoder)
    hexed = digest.hex()
    return ":".join(hexed[i:i+4] for i in range(0, len(hexed), 4))


def sign_payload(signing_key: signing.SigningKey, payload: dict[str, Any]) -> str:
    signed = signing_key.sign(canonical_json(payload))
    return b64e(signed.signature)


def verify_signature(identity_pub_b64_value: str, payload: dict[str, Any], signature_b64: str) -> bool:
    try:
        verify_key = signing.VerifyKey(b64d(identity_pub_b64_value))
        verify_key.verify(canonical_json(payload), b64d(signature_b64))
        return True
    except exceptions.BadSignatureError:
        return False


def generate_ephemeral_keypair() -> tuple[PrivateKey, str]:
    sk = PrivateKey.generate()
    return sk, b64e(bytes(sk.public_key))


def derive_session_key(my_eph_sk: PrivateKey, peer_eph_pub_b64: str, transcript: bytes) -> bytes:
    shared = bindings.crypto_scalarmult(bytes(my_eph_sk), b64d(peer_eph_pub_b64))
    return hash.blake2b(shared + transcript, digest_size=secret.SecretBox.KEY_SIZE, encoder=RawEncoder)


def _derive_aes256gcm_key(session_key: bytes) -> bytes:
    return hash.blake2b(session_key + b'|aes256gcm', digest_size=32, encoder=RawEncoder)


def encrypt_for_session(session_key: bytes, plaintext: str) -> dict[str, str]:
    plaintext_bytes = plaintext.encode("utf-8")
    if AESGCM is not None:
        nonce = os.urandom(12)
        aead = AESGCM(_derive_aes256gcm_key(session_key))
        ciphertext = aead.encrypt(nonce, plaintext_bytes, SESSION_AAD)
        return {
            "alg": SESSION_CIPHER_AEAD,
            "nonce": b64e(nonce),
            "ciphertext": b64e(ciphertext),
        }

    if ENCRYPTED_ONLY:
        raise ValueError('encrypted-only mode requires AES-256-GCM support')

    box = secret.SecretBox(session_key)
    nonce = nacl.utils.random(secret.SecretBox.NONCE_SIZE)
    ct = box.encrypt(plaintext_bytes, nonce)
    # SecretBox.encrypt returns nonce + ciphertext+mac; strip nonce to avoid storing twice
    return {
        "alg": SESSION_CIPHER_FALLBACK,
        "nonce": b64e(nonce),
        "ciphertext": b64e(ct.ciphertext),
    }


def decrypt_for_session(session_key: bytes, nonce_b64: str, ciphertext_b64: str, alg: str | None = None) -> str:
    if ENCRYPTED_ONLY and alg != SESSION_CIPHER_AEAD:
        raise ValueError('encrypted-only mode rejects non-AES packets')

    if alg in (None, SESSION_CIPHER_AEAD):
        if AESGCM is None:
            if alg == SESSION_CIPHER_AEAD:
                raise ValueError('AES-256-GCM unavailable in runtime')
        else:
            try:
                nonce = b64d(nonce_b64)
                ciphertext = b64d(ciphertext_b64)
                aead = AESGCM(_derive_aes256gcm_key(session_key))
                pt = aead.decrypt(nonce, ciphertext, SESSION_AAD)
                return pt.decode("utf-8", errors="replace")
            except Exception:
                if alg == SESSION_CIPHER_AEAD:
                    raise

    if alg not in (None, SESSION_CIPHER_FALLBACK):
        raise ValueError(f'unsupported session cipher: {alg}')

    box = secret.SecretBox(session_key)
    nonce = b64d(nonce_b64)
    ciphertext = b64d(ciphertext_b64)
    pt = box.decrypt(ciphertext, nonce)
    return pt.decode("utf-8", errors="replace")


def encrypt_json_with_password(password: str, payload: dict[str, Any]) -> dict[str, Any]:
    password_bytes = password.encode("utf-8")
    salt = nacl.utils.random(pwhash.argon2id.SALTBYTES)
    opslimit = int(pwhash.argon2id.OPSLIMIT_MODERATE)
    memlimit = int(pwhash.argon2id.MEMLIMIT_MODERATE)
    key = pwhash.argon2id.kdf(secret.SecretBox.KEY_SIZE, password_bytes, salt, opslimit=opslimit, memlimit=memlimit)
    nonce = nacl.utils.random(secret.SecretBox.NONCE_SIZE)
    box = secret.SecretBox(key)
    encrypted = box.encrypt(canonical_json(payload), nonce)
    return {
        "kdf": "argon2id",
        "salt_b64": b64e(salt),
        "opslimit": opslimit,
        "memlimit": memlimit,
        "nonce_b64": b64e(nonce),
        "ciphertext_b64": b64e(encrypted.ciphertext),
    }


def decrypt_json_with_password(password: str, blob: dict[str, Any]) -> dict[str, Any]:
    if blob.get("kdf") != "argon2id":
        raise ValueError("unsupported encryption format")

    try:
        salt = b64d(blob["salt_b64"])
        nonce = b64d(blob["nonce_b64"])
        ciphertext = b64d(blob["ciphertext_b64"])
        opslimit = int(blob["opslimit"])
        memlimit = int(blob["memlimit"])
    except Exception as e:
        raise ValueError("invalid encrypted payload") from e

    password_bytes = password.encode("utf-8")
    key = pwhash.argon2id.kdf(secret.SecretBox.KEY_SIZE, password_bytes, salt, opslimit=opslimit, memlimit=memlimit)
    box = secret.SecretBox(key)
    try:
        plaintext = box.decrypt(ciphertext, nonce)
    except exceptions.CryptoError as e:
        raise ValueError("wrong password or corrupted file") from e
    return json.loads(plaintext.decode("utf-8"))
