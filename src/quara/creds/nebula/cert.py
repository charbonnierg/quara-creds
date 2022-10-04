import hashlib
import secrets
import typing as t
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey

from . import cert_pb2
from .utils import (
    create_ed25519_private_key,
    create_x25519_private_key,
    decode_ip_address,
    decode_pem,
    encode_ip_address,
    encode_pem,
    get_private_key_bytes,
    get_public_key_bytes,
    get_relative_timestamp,
)


@dataclass
class Certificate:
    """Class representing a Nebula certificate.

    This class does not use snake case, but instead use CamelCase.
    This choice was made to stay close to protobuf definition and
    JSON representation of certificates.

    Certificates can be either CA certificates or node certificates.
    """

    Name: str
    Groups: t.List[str]
    Ips: t.List[str]
    Subnets: t.List[str]
    IsCA: bool
    Issuer: str
    NotBefore: int
    NotAfter: int
    PublicKey: bytes
    Fingerprint: str
    Signature: bytes

    def get_activation_timestamp(self) -> datetime:
        """Get activation timestamp as a datetime instance.

        Activation timestamp is available as an integer through the `.NotBefore` attribute.
        Use this method to access it as a `datetime.datetime` instead.
        """
        return datetime.fromtimestamp(self.NotBefore, tz=timezone.utc)

    def get_expiration_timestamp(self) -> datetime:
        """Get expiration timestamp as a datetime instance.

        Expiration timestamp is available as an integer through the `.NotAfter` attribute.
        Use this method to access it as a `datetime.datetime` instead.
        """
        return datetime.fromtimestamp(self.NotAfter, tz=timezone.utc)

    def get_public_key(self) -> Ed25519PublicKey:
        """Get public key as cryptography Ed25519 public key instance.

        Public key is stored as a string by default. Use this method to
        access it as a `cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PublicKey`
        instead.
        """
        return Ed25519PublicKey.from_public_bytes(self.PublicKey)

    def get_ip_address(self) -> str:
        """Get certificate IP address"""
        if self.IsCA:
            raise TypeError("A CA certificate does not have an IP addess")
        return self.Ips[0]

    def verify(self, ca_crt: t.Union["Certificate", bytes]) -> None:
        """Verify that certificate is valid, I.E:
        - signature is valid
        - activation timestamp is smaller than current timestamp
        - expiration timestamps is greater than current timestmap
        """
        # Parse certificate a first time
        if not isinstance(ca_crt, Certificate):
            ca_crt = Certificate.from_bytes(ca_crt)
        # Serialize certificate to string a second time
        details = self._to_raw_cert_details().SerializeToString()
        # Verify signature
        ca_crt.get_public_key().verify(self.Signature, details)
        now = datetime.now(timezone.utc)
        # Verify activation timestamp
        if now < self.get_activation_timestamp():
            raise ValueError("Certificate is not valid yet")
        # Verify expiration timestamp
        if now >= self.get_expiration_timestamp():
            raise ValueError("Certificate is expired")

    @classmethod
    def _from_bytes(cls, data: bytes) -> "Certificate":
        """Create a new Certificate instance from bytes."""
        cert = cert_pb2.RawNebulaCertificate()
        cert.ParseFromString(data)
        is_mask = False
        address: int
        ips: t.List[str] = []
        for item in cert.Details.Ips:
            if not is_mask:
                address = item
                is_mask = True
            else:
                mask = item
                is_mask = False
                ips.append(decode_ip_address(address, mask))
        subnets: t.List[str] = []
        for item in cert.Details.Subnets:
            if not is_mask:
                address = item
                is_mask = True
            else:
                mask = item
                is_mask = False
                subnets.append(decode_ip_address(address, mask))
        return Certificate(
            Name=cert.Details.Name,
            NotAfter=cert.Details.NotAfter,
            NotBefore=cert.Details.NotBefore,
            Groups=cert.Details.Groups,
            IsCA=cert.Details.IsCA,
            Ips=ips,
            Subnets=subnets,
            Issuer=cert.Details.Issuer,
            PublicKey=cert.Details.PublicKey,
            Signature=cert.Signature,
            Fingerprint=hashlib.sha256(data).hexdigest(),
        )

    def _to_raw_cert_details(self) -> cert_pb2.RawNebulaCertificateDetails:
        """Export nebula certificate to `RawNebulaCertificate` protobuf representation.

        Those raw certificate details can then be used to generate a bytes
        representation of signed data within the certificate.
        """
        cert_details = cert_pb2.RawNebulaCertificateDetails()
        cert_details.Issuer = self.Issuer
        cert_details.Name = self.Name
        cert_details.Groups.extend(self.Groups)
        for address in self.Ips:
            cert_details.Ips.extend(encode_ip_address(address))
        for subnet in self.Subnets:
            cert_details.Subnets.extend(encode_ip_address(subnet))
        cert_details.NotBefore = self.NotBefore
        cert_details.NotAfter = self.NotAfter
        cert_details.PublicKey = self.PublicKey
        cert_details.IsCA = self.IsCA
        return cert_details

    def _to_raw_cert(self) -> cert_pb2.RawNebulaCertificate:
        """Export nebula certificate to `RawNebulaCertificate` protobuf representation.

        This raw certificate can then be used to generate a bytes
        representation of the certificate.
        """
        cert = cert_pb2.RawNebulaCertificate()
        cert_details = self._to_raw_cert_details()
        cert.Details.CopyFrom(cert_details)
        cert.Signature = self.Signature
        return cert

    @classmethod
    def _from_pem_data(
        cls, data: t.Union[str, bytes], encoding: str = "utf-8"
    ) -> "Certificate":
        """Parse a new Certificate instance from PEM-encoded data."""
        cert_bytes = decode_pem(data, encoding=encoding)
        return cls._from_bytes(cert_bytes)

    @classmethod
    def from_bytes(cls, data: bytes) -> "Certificate":
        """A convenient method to load a certificate from bytes.

        If data looks like PEM-encoded data it will be first decoded.
        """
        if data.startswith(b"-----"):
            return cls._from_pem_data(data)
        else:
            return cls._from_bytes(data)

    @classmethod
    def from_file(cls, filepath: t.Union[str, Path]) -> "Certificate":
        """Load a Certificate instance from a file"""
        return cls.from_bytes(Path(filepath).expanduser().read_bytes())

    def to_dict(self) -> t.Dict[str, t.Any]:
        """Export nebula certificate as a dictionary"""
        return asdict(self)

    def to_bytes(self) -> bytes:
        """Export nebula certificate to bytes."""
        cert = self._to_raw_cert()
        return cert.SerializeToString()

    def to_pem_data(self, encoding: str = "utf-8") -> bytes:
        """Export nebula certificate to PEM data as bytes"""
        return encode_pem(
            self.to_bytes(),
            format="NEBULA CERTIFICATE",
            encoding=encoding,
        )

    def write_pem_file(self, filepath: t.Union[str, Path]) -> Path:
        """Write certificate to file in PEM format"""
        output = Path(filepath).expanduser()
        output.write_bytes(self.to_pem_data())
        return output.resolve(True)


class SigningKeyPair:
    def __init__(self, private_bytes: t.Optional[bytes] = None) -> None:
        """Create a new instance of CAKeyPair"""
        if private_bytes is None:
            private_bytes = secrets.token_bytes(32)
        if len(private_bytes) == 64:
            private_bytes = private_bytes[:32]
        self.private_key = create_ed25519_private_key(private_bytes)
        self.public_key = self.private_key.public_key()

    def get_private_bytes(self) -> bytes:
        """Get private key bytes from keypair"""
        return get_private_key_bytes(self.private_key)

    def get_public_bytes(self) -> bytes:
        """Get public key bytes from keypair"""
        return get_public_key_bytes(self.public_key)

    @classmethod
    def _from_pem_data(cls, data: bytes) -> "SigningKeyPair":
        """Parse keypair from private bytes encoded in PEM format"""
        decoded_data = decode_pem(data)
        return cls(decoded_data)

    @classmethod
    def from_bytes(cls, data: bytes) -> "SigningKeyPair":
        """Parse keypair from bytes (potentially in PEM format)"""
        if data.startswith(b"-----"):
            return cls._from_pem_data(data)
        else:
            return cls(data)

    @classmethod
    def from_file(cls, filepath: t.Union[str, Path]) -> "SigningKeyPair":
        """Parse keypair from a file, either holding private bytes in
        PEM format or in raw format."""
        data = Path(filepath).expanduser().read_bytes()
        return cls.from_bytes(data)

    def to_private_pem_data(self) -> bytes:
        """Get private key bytes encoded in PEM format"""
        return encode_pem(
            self.get_private_bytes() + self.get_public_bytes(),
            format="NEBULA ED25519 PRIVATE KEY",
        )

    def to_public_pem_data(self) -> bytes:
        """Get public key bytes encoded in PEM format"""
        return encode_pem(self.get_public_bytes(), format="NEBULA ED25519 PUBLIC KEY")

    def write_private_key(self, filepath: t.Union[str, Path]) -> Path:
        """Write private key into a file in PEM format"""
        output = Path(filepath).expanduser()
        output.write_bytes(self.to_private_pem_data())
        return output

    def write_public_key(self, filepath: t.Union[str, Path]) -> Path:
        """Write public key into a file in PEM format"""
        output = Path(filepath).expanduser()
        output.write_bytes(self.to_public_pem_data())
        return output

    def sign(self, data: bytes) -> bytes:
        """Sign some data using private key"""
        return self.private_key.sign(data)


class EncryptionKeyPair:
    def __init__(self, private_bytes: t.Optional[bytes] = None) -> None:
        """Create a new instance of NodeKeyPair"""
        self.private_key = create_x25519_private_key(private_bytes)
        self.public_key = self.private_key.public_key()

    def get_private_bytes(self) -> bytes:
        """Get private key bytes from keypair"""
        return get_private_key_bytes(self.private_key)

    def get_public_bytes(self) -> bytes:
        """Get public key bytes from keypair"""
        return get_public_key_bytes(self.public_key)

    @classmethod
    def _from_pem_data(cls, data: bytes) -> "EncryptionKeyPair":
        """Parse keypair from bytes in PEM format"""
        decoded_data = decode_pem(data)
        return cls(decoded_data)

    @classmethod
    def from_bytes(cls, data: bytes) -> "EncryptionKeyPair":
        """Parse keypair from bytes (potentially in PEM format)"""
        if data.startswith(b"-----"):
            return cls._from_pem_data(data)
        else:
            return cls(data)

    @classmethod
    def from_file(cls, filepath: t.Union[str, Path]) -> "EncryptionKeyPair":
        """Parse keypair from file (potentially in PEM format)"""
        data = Path(filepath).expanduser().read_bytes()
        return cls.from_bytes(data)

    def to_private_pem_data(self) -> bytes:
        """Get private key bytes encoded in PEM format"""
        return encode_pem(self.get_private_bytes(), format="NEBULA X25519 PRIVATE KEY")

    def to_public_pem_data(self) -> bytes:
        """Get public key bytes encoded in PEM format"""
        return encode_pem(self.get_public_bytes(), format="NEBULA X25519 PUBLIC KEY")

    def write_private_key(self, filepath: t.Union[str, Path]) -> Path:
        """Write private key into a file in PEM format"""
        output = Path(filepath).expanduser()
        output.write_bytes(self.to_private_pem_data())
        return output

    def write_public_key(self, filepath: t.Union[str, Path]) -> Path:
        """Write public key into a file in PEM format"""
        output = Path(filepath).expanduser()
        output.write_bytes(self.to_public_pem_data())
        return output


class PublicEncryptionKey:
    """Public encryption keys are X25519 public keys.

    They are used by nebula nodes.
    """

    def __init__(self, public_bytes: bytes) -> None:
        """Create a new instance of PublicEncryptionKey"""
        self.public_key = X25519PublicKey.from_public_bytes(public_bytes)

    def get_public_bytes(self) -> bytes:
        return get_public_key_bytes(self.public_key)

    @classmethod
    def _from_pem_data(cls, data: bytes) -> "PublicEncryptionKey":
        decoded_data = decode_pem(data)
        return cls(decoded_data)

    @classmethod
    def from_bytes(cls, data: bytes) -> "PublicEncryptionKey":
        if data.startswith(b"-----"):
            return cls._from_pem_data(data)
        else:
            return cls(data)

    @classmethod
    def from_file(cls, filepath: t.Union[str, Path]) -> "PublicEncryptionKey":
        data = Path(filepath).expanduser().read_bytes()
        return cls.from_bytes(data)

    def to_pem_data(self) -> bytes:
        return encode_pem(self.get_public_bytes(), format="NEBULA X25519 PUBLIC KEY")


class PublicSigningKey:
    """Public signing keys are ED25519 public keys.

    They are used by certificate authorities.
    """

    def __init__(self, public_bytes: bytes) -> None:
        """Create a new instance of PublicSigningKey"""
        self.public_key = Ed25519PublicKey.from_public_bytes(public_bytes)

    def get_public_bytes(self) -> bytes:
        return get_public_key_bytes(self.public_key)

    @classmethod
    def _from_pem_data(cls, data: bytes) -> "PublicSigningKey":
        decoded_data = decode_pem(data)
        return cls.from_bytes(decoded_data)

    @classmethod
    def from_bytes(cls, data: bytes) -> "PublicSigningKey":
        if data.startswith(b"-----"):
            return cls._from_pem_data(data)
        else:
            return cls(data)

    @classmethod
    def from_file(cls, filepath: t.Union[str, Path]) -> "PublicSigningKey":
        data = Path(filepath).expanduser().read_bytes()
        return cls.from_bytes(data)

    def to_pem_data(self) -> bytes:
        return encode_pem(self.get_public_bytes(), format="NEBULA ED25519 PUBLIC KEY")

    def verify(self, signature: bytes, data: bytes) -> None:
        """Verify some data and some signature using the public key"""
        return self.public_key.verify(signature, data)


@dataclass
class SigningOptions:
    """Options used to sign a certificate."""

    Name: str
    Ip: str
    NotAfter: str = "8650h"
    NotBefore: str = "0s"
    Groups: t.List[str] = field(default_factory=list)
    Subnets: t.List[str] = field(default_factory=list)


@dataclass
class SigningCAOptions:
    """Options used to sign a certificate authority."""

    Name: str
    Ips: t.List[str] = field(default_factory=list)
    NotAfter: str = "25950h"
    NotBefore: str = "0s"
    Groups: t.List[str] = field(default_factory=list)
    Subnets: t.List[str] = field(default_factory=list)


def sign_cert(
    ca_crt: Certificate,
    ca_key: SigningKeyPair,
    public_key: t.Union[PublicEncryptionKey, EncryptionKeyPair],
    options: SigningOptions,
) -> Certificate:
    """Generate a nebula certificate.

    Arguments:
        ca_crt: The CA certificate used to sign the generated certificate.
        ca_key: The signing keypair used to sign the generated certificate.
        pub_key: The public key for which certificate is signed.
        options: Options used to generate the certficate.

    Returns:
        A Certificate instance.
    """
    # Create protobuf objects
    cert = cert_pb2.RawNebulaCertificate()
    cert_details = cert_pb2.RawNebulaCertificateDetails()
    # Get CA cert fingerprint
    ca_crt_fingerprint = hashlib.sha256(ca_crt.to_bytes()).digest()
    # Set certificate details
    cert_details.Name = options.Name
    cert_details.Groups.extend(options.Groups)
    cert_details.Ips.extend(encode_ip_address(options.Ip))
    for subnet in options.Subnets:
        cert_details.Subnets.extend(encode_ip_address(subnet))
    cert_details.NotBefore = get_relative_timestamp(options.NotBefore)
    cert_details.NotAfter = get_relative_timestamp(options.NotAfter)
    cert_details.Issuer = ca_crt_fingerprint
    cert_details.PublicKey = public_key.get_public_bytes()
    cert_details.IsCA = False
    # Create signature
    signature = ca_key.sign(cert_details.SerializeToString())
    # Generate cert
    cert.Details.CopyFrom(cert_details)
    cert.Signature = signature
    # First serialize to string
    crt_bytes = cert.SerializeToString()
    # Then parse the certificate instance
    return Certificate._from_bytes(crt_bytes)


def sign_ca(options: SigningCAOptions) -> t.Tuple[SigningKeyPair, Certificate]:
    """Generate a nebula CA certificate.

    Arguments:
        options: Options used to generate the CA certificate.

    Returns:
        a tuple `(keypair, cert)` holding a `SigningKeyPair` instance and a `Certificate` instance
    """
    # First generate a keypair
    ca_private_key = Ed25519PrivateKey.generate()
    # Then generate a public key
    ca_public_key = ca_private_key.public_key()
    # Extract public key bytes
    public_key_bytes = get_public_key_bytes(ca_public_key)
    # Extract private key bytes
    private_key_bytes = get_private_key_bytes(ca_private_key)
    # Initialize protobuf objects
    cert = cert_pb2.RawNebulaCertificate()
    cert_details = cert_pb2.RawNebulaCertificateDetails()
    # Set attributes on cert_details protobuf object
    cert_details.Name = options.Name
    cert_details.Groups.extend(options.Groups)
    cert_details.NotBefore = get_relative_timestamp(options.NotBefore)
    cert_details.NotAfter = get_relative_timestamp(options.NotAfter)
    cert_details.PublicKey = public_key_bytes
    cert_details.IsCA = True
    for address in options.Ips:
        cert_details.Ips.extend(encode_ip_address(address))
    for subnet in options.Subnets:
        cert_details.Subnets.extend(encode_ip_address(subnet))
    # Generate signature using cert_details string representation
    signature = ca_private_key.sign(cert_details.SerializeToString())
    # Set attributes on cert protobuf object
    cert.Details.CopyFrom(cert_details)
    cert.Signature = signature
    # Return PEM encoded certificate, public key and private key
    return (
        SigningKeyPair(private_bytes=private_key_bytes),
        Certificate._from_bytes(cert.SerializeToString()),
    )
