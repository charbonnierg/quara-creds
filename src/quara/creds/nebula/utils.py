import base64
import binascii
import ipaddress
import secrets
import time
import typing as t

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)

to_seconds = {
    "s": 1,
    "m": 60,
    "h": 3600,
    "d": 86400,
}


def parse_duration(value: str) -> int:
    """Return a duration in seconds"""
    if len(value) < 2:
        raise ValueError("Invalid value")
    duration = value[:-1]
    unit = value[-1]
    try:
        float_duration = int(duration.lower())
    except Exception as err:
        raise ValueError("Invalid value") from err
    try:
        multiplier = to_seconds[unit]
    except KeyError as err:
        raise ValueError("Invalid unit") from err
    return float_duration * multiplier


def get_relative_timestamp(duration: str) -> int:
    return int(time.time()) + parse_duration(duration)


def decode_pem(pem_data: t.Union[str, bytes], encoding: str = "utf-8") -> bytes:
    """Decode some PEM-encoded data.

    Raises ValueError when provided data is not PEM-encoded.
    """
    if isinstance(pem_data, str):
        pem_data = pem_data.encode(encoding=encoding)
    BANNER_TAG = b"-----"
    # Remove start header and stop header
    lines = pem_data.split(BANNER_TAG)
    try:
        value = b"".join(lines[2:-2])
    except IndexError as err:
        raise ValueError("Invalid PEM data") from err
    # Decode using base64
    try:
        decoded = base64.b64decode(value.strip())
    except binascii.Error as err:
        raise ValueError("Invalid PEM data") from err
    # Return decoded value
    return decoded


def encode_pem(
    value: t.Union[str, bytes], format: str, encoding: str = "utf-8"
) -> bytes:
    """Encode some bytes into PEM format.

    Data is always returned as string.
    """
    BANNER_TAG = "-----"
    if isinstance(value, str):
        value = value.encode(encoding)
    encoded_value = base64.b64encode(value).decode("utf-8")
    pem_str = f"""{BANNER_TAG}BEGIN {format}{BANNER_TAG}\n{encoded_value}\n{BANNER_TAG}END {format}{BANNER_TAG}"""
    return pem_str.encode(encoding)


def get_ed25519_public_key(bytes_value: bytes) -> Ed25519PublicKey:
    """Load a Ed25519 public key from bytes"""
    return Ed25519PublicKey.from_public_bytes(bytes_value)


def create_ed25519_private_key(seed: t.Optional[bytes] = None) -> Ed25519PrivateKey:
    if seed is None:
        seed = secrets.token_bytes(32)
    elif len(seed) != 32:
        raise ValueError("Invalid seed")
    return Ed25519PrivateKey.from_private_bytes(seed)


def create_x25519_private_key(seed: t.Optional[bytes] = None) -> X25519PrivateKey:
    if seed is None:
        seed = secrets.token_bytes(32)
    elif len(seed) != 32:
        raise ValueError("Invalid seed")
    return X25519PrivateKey.from_private_bytes(seed)


def get_x25519_public_key(bytes_value: bytes) -> X25519PublicKey:
    """Load a X25519 public key from bytes"""
    return X25519PublicKey.from_public_bytes(bytes_value)


def get_public_key_bytes(
    public_key: t.Union[X25519PublicKey, Ed25519PublicKey]
) -> bytes:
    return public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def get_private_key_bytes(
    private_key: t.Union[X25519PrivateKey, Ed25519PrivateKey]
) -> bytes:
    return private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )


def encode_ip_address(address: str) -> t.Tuple[int, int]:
    iface = ipaddress.ip_interface(address)
    return int(iface.ip), int(iface.netmask)


def decode_ip_address(address: int, mask: int) -> str:
    return str(
        ipaddress.ip_interface(
            str(ipaddress.ip_address(address)) + "/" + str(ipaddress.ip_address(mask))
        )
    )
