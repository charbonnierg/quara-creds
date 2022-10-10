import secrets
import typing as t
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey

from quara.creds.nebula.errors import InvalidPublicKeyError

from ..utils import (
    create_ed25519_private_key,
    create_x25519_private_key,
    decode_pem,
    encode_pem,
    get_private_key_bytes,
    get_public_key_bytes,
)


class SigningKeyPair:
    """SigningKeyPair are used by certificate authorities (CA).

    A SigningKeypair is composed of an ED25519 private key and its associated ED25519 public key.

    Attributes:
        private_key: An instance of `cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PrivateKey`
        public_key: An instance of `cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PublicKey`
    """

    def __init__(self, private_bytes: t.Optional[bytes] = None) -> None:
        """Create a new instance of SigningKeyPair.

        Arguments:
            private_bytes: bytes corresponding to the private key private bytes.
                When `private_bytes` is not provided or is None, random bytes will
                be generated, I.E, a new private key is generated.
        """
        if private_bytes is None:
            private_bytes = secrets.token_bytes(32)
        if len(private_bytes) == 64:
            private_bytes = private_bytes[:32]
        self.private_key = create_ed25519_private_key(private_bytes)
        self.public_key = PublicSigningKey(
            get_public_key_bytes(self.private_key.public_key())
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> "SigningKeyPair":
        """Parse keypair from bytes (potentially in PEM format)"""
        if data.startswith(b"-----"):
            decoded_data = decode_pem(data)
            return cls(decoded_data)
        else:
            return cls(data)

    @classmethod
    def from_file(cls, filepath: t.Union[str, Path]) -> "SigningKeyPair":
        """Parse keypair from a file, either holding private bytes in
        PEM format or in raw format."""
        data = Path(filepath).expanduser().read_bytes()
        return cls.from_bytes(data)

    def to_private_bytes(self) -> bytes:
        """Get private key bytes from keypair"""
        return get_private_key_bytes(self.private_key)

    def to_public_bytes(self) -> bytes:
        """Get public key bytes from keypair"""
        return self.public_key.to_public_bytes()

    def to_private_pem_data(self) -> bytes:
        """Get private key bytes encoded in PEM format"""
        return encode_pem(
            self.to_private_bytes() + self.to_public_bytes(),
            format="NEBULA ED25519 PRIVATE KEY",
        )

    def to_public_pem_data(self) -> bytes:
        """Get public key bytes encoded in PEM format"""
        return self.public_key.to_public_pem_data()

    def write_private_key(self, filepath: t.Union[str, Path]) -> Path:
        """Write private key into a file in PEM format"""
        output = Path(filepath).expanduser()
        output.write_bytes(self.to_private_pem_data())
        return output

    def write_public_key(self, filepath: t.Union[str, Path]) -> Path:
        """Write public key into a file in PEM format"""
        return self.public_key.write_public_key(filepath)

    def sign(self, data: bytes) -> bytes:
        """Sign some data"""
        return self.private_key.sign(data)

    def verify(self, signature: bytes, data: bytes) -> None:
        """Verify some data with some signature."""
        self.public_key.verify(signature, data)

    def verify_public_bytes(self, data: bytes) -> None:
        """Verify that given public bytes match keykair"""
        if self.to_public_bytes() == data:
            return None
        raise InvalidPublicKeyError("Public key does not match keypair")

    def verify_public_key(
        self, key: t.Union[Ed25519PublicKey, "PublicSigningKey"]
    ) -> None:
        """Verify that given public key match keykair"""
        if isinstance(key, PublicSigningKey):
            self.verify_public_bytes(key.to_public_bytes())
        else:
            self.verify_public_bytes(get_public_key_bytes(key))

    def __eq__(self, other: t.Any) -> bool:
        if isinstance(other, SigningKeyPair):
            return other.to_private_bytes() == self.to_private_bytes()
        return False


class EncryptionKeyPair:
    """EncryptionKeyPair are used by node certificates and nebula clients.

    An EncryptionKeyPair is composed of an X25519 private key and its associated X25519 public key.

    Attributes:
        private_key: An instance of `cryptography.hazmat.primitives.asymmetric.x25519.X25519PrivateKey`
        public_key: An instance of `cryptography.hazmat.primitives.asymmetric.x25519.X25519PublicKey`
    """

    def __init__(self, private_bytes: t.Optional[bytes] = None) -> None:
        """Create a new instance of EncryptionKeyPair.

        Arguments:
            private_bytes: bytes corresponding to the private key private bytes.
                When `private_bytes` is not provided or is None, random bytes will
                be generated, I.E, a new private key is generated.
        """
        self.private_key = create_x25519_private_key(private_bytes)
        self.public_key = PublicEncryptionKey(
            get_public_key_bytes(self.private_key.public_key())
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> "EncryptionKeyPair":
        """Parse keypair from bytes (potentially in PEM format)"""
        if data.startswith(b"-----"):
            decoded_data = decode_pem(data)
            return cls(decoded_data)
        else:
            return cls(data)

    @classmethod
    def from_file(cls, filepath: t.Union[str, Path]) -> "EncryptionKeyPair":
        """Parse keypair from file (potentially in PEM format)"""
        data = Path(filepath).expanduser().read_bytes()
        return cls.from_bytes(data)

    def to_private_bytes(self) -> bytes:
        """Get private key bytes from keypair"""
        return get_private_key_bytes(self.private_key)

    def to_public_bytes(self) -> bytes:
        """Get public key bytes from keypair"""
        return self.public_key.to_public_bytes()

    def to_private_pem_data(self) -> bytes:
        """Get private key bytes encoded in PEM format"""
        return encode_pem(self.to_private_bytes(), format="NEBULA X25519 PRIVATE KEY")

    def to_public_pem_data(self) -> bytes:
        """Get public key bytes encoded in PEM format"""
        return self.public_key.to_public_pem_data()

    def write_private_key(self, filepath: t.Union[str, Path]) -> Path:
        """Write private key into a file in PEM format"""
        output = Path(filepath).expanduser()
        output.write_bytes(self.to_private_pem_data())
        return output

    def write_public_key(self, filepath: t.Union[str, Path]) -> Path:
        """Write public key into a file in PEM format"""
        return self.public_key.write_public_key(filepath)

    def __eq__(self, other: t.Any) -> bool:
        if isinstance(other, EncryptionKeyPair):
            return other.to_private_bytes() == self.to_private_bytes()
        return False


class PublicEncryptionKey:
    """Public encryption keys are X25519 public keys.

    They are used by nebula nodes.
    """

    def __init__(self, public_bytes: bytes) -> None:
        """Create a new instance of PublicEncryptionKey"""
        self.public_key = X25519PublicKey.from_public_bytes(public_bytes)

    @classmethod
    def from_bytes(cls, data: bytes) -> "PublicEncryptionKey":
        """Create a new public key from some bytes either in raw format or PEM format."""
        if data.startswith(b"-----"):
            decoded_data = decode_pem(data)
            return cls(decoded_data)
        else:
            return cls(data)

    @classmethod
    def from_file(cls, filepath: t.Union[str, Path]) -> "PublicEncryptionKey":
        """Create a new public key from a file either in raw format or PEM format."""
        data = Path(filepath).expanduser().read_bytes()
        return cls.from_bytes(data)

    def to_public_bytes(self) -> bytes:
        """Get public bytes from public key"""
        return get_public_key_bytes(self.public_key)

    def to_public_pem_data(self) -> bytes:
        """Export public key as PEM-encoded bytes"""
        return encode_pem(self.to_public_bytes(), format="NEBULA X25519 PUBLIC KEY")

    def write_public_key(self, filepath: t.Union[str, Path]) -> Path:
        """Write public key into a file in PEM format"""
        output = Path(filepath).expanduser()
        output.write_bytes(self.to_public_pem_data())
        return output

    def __eq__(self, other: t.Any) -> bool:
        if isinstance(other, PublicEncryptionKey):
            return other.to_public_bytes() == self.to_public_bytes()
        return False


class PublicSigningKey:
    """Public signing keys are ED25519 public keys.

    They are used by certificate authorities.
    """

    def __init__(self, public_bytes: bytes) -> None:
        """Create a new instance of PublicSigningKey."""
        self.public_key = Ed25519PublicKey.from_public_bytes(public_bytes)

    def to_public_bytes(self) -> bytes:
        """Get public bytes from public key."""
        return get_public_key_bytes(self.public_key)

    @classmethod
    def from_bytes(cls, data: bytes) -> "PublicSigningKey":
        """Create a new public key from bytes, either in raw format or PEM format."""
        if data.startswith(b"-----"):
            decoded_data = decode_pem(data)
            return cls.from_bytes(decoded_data)
        else:
            return cls(data)

    @classmethod
    def from_file(cls, filepath: t.Union[str, Path]) -> "PublicSigningKey":
        """Create a new public key from a file, either in raw format or PEM format."""
        data = Path(filepath).expanduser().read_bytes()
        return cls.from_bytes(data)

    def to_public_pem_data(self) -> bytes:
        """Export public key to PEM-encoded bytes."""
        return encode_pem(self.to_public_bytes(), format="NEBULA ED25519 PUBLIC KEY")

    def write_public_key(self, filepath: t.Union[str, Path]) -> Path:
        """Write public key into a file in PEM format"""
        output = Path(filepath).expanduser()
        output.write_bytes(self.to_public_pem_data())
        return output

    def verify(self, signature: bytes, data: bytes) -> None:
        """Verify some data with some signature."""
        self.public_key.verify(signature, data)

    def verify_public_bytes(self, data: bytes) -> None:
        """Verify that given public bytes match keykair"""
        if self.to_public_bytes() == data:
            return None
        raise InvalidPublicKeyError("Public key does not match keypair")

    def verify_public_key(
        self, key: t.Union[Ed25519PublicKey, "PublicSigningKey"]
    ) -> None:
        """Verify that given public key match keykair"""
        if isinstance(key, PublicSigningKey):
            self.verify_public_bytes(key.to_public_bytes())
        else:
            self.verify_public_bytes(get_public_key_bytes(key))

    def __eq__(self, other: t.Any) -> bool:
        if isinstance(other, PublicSigningKey):
            return other.to_public_bytes() == self.to_public_bytes()
        return False
