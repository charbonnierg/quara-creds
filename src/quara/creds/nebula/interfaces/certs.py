import hashlib
import typing as t
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from ipaddress import ip_interface
from pathlib import Path
from time import time

from quara.creds.nebula.errors import InvalidCertificateError, InvalidSigningOptionError

from ..proto import RawNebulaCertificate, RawNebulaCertificateDetails
from ..utils import (
    decode_ip_address,
    decode_pem,
    encode_ip_address,
    encode_pem,
    get_relative_timestamp,
)
from .keys import (
    EncryptionKeyPair,
    PublicEncryptionKey,
    PublicSigningKey,
    SigningKeyPair,
)
from .options import SigningCAOptions, SigningOptions

CertT = t.TypeVar("CertT", bound="Certificate")


@dataclass
class Certificate:
    """Class representing a Nebula certificate.

    This class does not use snake case, but instead use CamelCase.
    This choice was made to stay close to protobuf definition and
    JSON representation of certificates.

    Certificates can be either CA certificates or node certificates.

    Attributes:
        Name: the name of the certificate
        Groups: the groups this certificate belongs to
        Ips: list of IP addresses with CIDR notation.
            A node certificate always have a unique IP address.
            CA certificates can have zero, one or several IP addresses.
        Subnets: list of subnets this certificate is valid for.
        IsCA: boolean value indicating whether certificate is a CA certificate.
        Issuer: fingerprint of CA certificate which issued the node certificate.
            Always empty for CA certificates.
        NotBefore: certificate activation unix timestamp.
            The method `.get_activation_timestamp()` can be used to retrieve a datetime object.
        NotAfter: certificate expiration unix timestamp.
            The method `.get_expiration_timestamp()` can be used to retrieve a datetime object.
        PublicKey: public key of certificate.
        Fingerprint: hexdigest of certificate data
        Signature: signature signed using CA private key and certificate data
    """

    Name: str
    Groups: t.List[str]
    Ips: t.List[str]
    Subnets: t.List[str]
    IsCA: bool
    Issuer: bytes = field(repr=False)
    NotBefore: int
    NotAfter: int
    PublicKey: bytes = field(repr=False)
    Fingerprint: str = field(repr=False)
    Signature: bytes = field(repr=False)

    def is_ca(self) -> bool:
        """Return True if the certificate is a CA certificate."""
        return self.IsCA

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

    @classmethod
    def from_bytes(cls: t.Type[CertT], data: bytes) -> CertT:
        """A convenient method to load a certificate from bytes.

        If data looks like PEM-encoded data it will be first decoded.
        """
        if data.startswith(b"-----"):
            cert_bytes = decode_pem(data)
            return cls._from_bytes(cert_bytes)
        else:
            return cls._from_bytes(data)

    @classmethod
    def from_file(cls: t.Type[CertT], filepath: t.Union[str, Path]) -> CertT:
        """Load a Certificate instance from a file"""
        return cls.from_bytes(Path(filepath).expanduser().read_bytes())

    def to_dict(self) -> t.Dict[str, t.Any]:
        """Export nebula certificate as a dictionary"""
        data = asdict(self)
        data["PublicKey"] = self.PublicKey.hex()
        data["Signature"] = self.Signature.hex()
        data["Issuer"] = self.Issuer.hex()
        data.pop("Fingerprint", None)
        return data

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
        output.parent.mkdir(exist_ok=True, parents=True)
        output.write_bytes(self.to_pem_data())
        return output.resolve(True)

    @classmethod
    def _from_bytes(cls: t.Type[CertT], data: bytes) -> CertT:
        """Create a new Certificate instance from bytes."""
        cert = RawNebulaCertificate()
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
        return cls(
            Name=str(cert.Details.Name),
            NotAfter=int(cert.Details.NotAfter),
            NotBefore=int(cert.Details.NotBefore),
            Groups=[str(group) for group in cert.Details.Groups],
            IsCA=bool(cert.Details.IsCA),
            Ips=[str(ip) for ip in ips],
            Subnets=[str(subnet) for subnet in subnets],
            Issuer=bytes(cert.Details.Issuer),
            PublicKey=bytes(cert.Details.PublicKey),
            Signature=bytes(cert.Signature),
            Fingerprint=hashlib.sha256(data).hexdigest(),
        )

    def _to_raw_cert_details(self) -> RawNebulaCertificateDetails:
        """Export nebula certificate to `RawNebulaCertificate` protobuf representation.

        Those raw certificate details can then be used to generate a bytes
        representation of signed data within the certificate.
        """
        cert_details = RawNebulaCertificateDetails()
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

    def _to_raw_cert(self) -> RawNebulaCertificate:
        """Export nebula certificate to `RawNebulaCertificate` protobuf representation.

        This raw certificate can then be used to generate a bytes
        representation of the certificate.
        """
        cert = RawNebulaCertificate()
        cert_details = self._to_raw_cert_details()
        cert.Details.CopyFrom(cert_details)
        cert.Signature = self.Signature
        return cert


class NodeCertificate(Certificate):
    def __post_init__(self) -> None:
        if not self.IsCA:
            raise InvalidCertificateError("Certificate is a CA certificate")

    def is_ca(self) -> t.Literal[False]:
        return super().is_ca()

    def get_public_key(self) -> PublicEncryptionKey:
        """Get public key of node certificate"""
        return PublicEncryptionKey(self.PublicKey)

    def get_ip_address(self) -> str:
        """Get certificate IP address"""
        return self.Ips[0]


class CACertificate(Certificate):
    def __post_init__(self) -> None:
        if not self.IsCA:
            raise InvalidCertificateError("Certificate is not a CA certificate")

    def is_ca(self) -> t.Literal[True]:
        return super().is_ca()

    def get_public_key(self) -> PublicSigningKey:
        """Get public key as cryptography Ed25519 public key instance.

        Public key is stored as a bytes by default. Use this method to
        access it as a `cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PublicKey`
        instead.
        """
        return PublicSigningKey(self.PublicKey)

    @classmethod
    def sign_ca_certificate(
        cls, keypair: SigningKeyPair, options: SigningCAOptions
    ) -> "CACertificate":
        """Create a new CA certificate

        Arguments:
            options: Options used to generate the CA certificate.

        Returns:
            a tuple `(keypair, cert)` holding a `SigningKeyPair` instance and a `Certificate` instance
        """
        # Extract public key bytes
        public_key_bytes = keypair.to_public_bytes()
        # Initialize protobuf objects
        cert = RawNebulaCertificate()
        cert_details = RawNebulaCertificateDetails()
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
        signature = keypair.sign(cert_details.SerializeToString())
        # Set attributes on cert protobuf object
        cert.Details.CopyFrom(cert_details)
        cert.Signature = signature
        # Yeah, protobuf method is named SerializeToString but returns bytes data
        cert_data: bytes = cert.SerializeToString()
        # Parse certificate from raw bytes
        return CACertificate._from_bytes(cert_data)

    def sign_certificate(
        self,
        signing_key: SigningKeyPair,
        public_key: t.Union[PublicEncryptionKey, EncryptionKeyPair],
        options: SigningOptions,
    ) -> NodeCertificate:
        """Sign a new node certificate"""
        # Verify signing options
        self.verify_signing_options(options=options)
        # Create protobuf objects
        cert = RawNebulaCertificate()
        cert_details = RawNebulaCertificateDetails()
        # Get CA cert fingerprint
        ca_crt_fingerprint = hashlib.sha256(self.to_bytes()).digest()
        # Set certificate details
        cert_details.Name = options.Name
        cert_details.Groups.extend(options.Groups)
        cert_details.Ips.extend(encode_ip_address(options.Ip))
        for subnet in options.Subnets:
            cert_details.Subnets.extend(encode_ip_address(subnet))
        cert_details.NotBefore = get_relative_timestamp(options.NotBefore)
        cert_details.NotAfter = get_relative_timestamp(options.NotAfter)
        cert_details.Issuer = ca_crt_fingerprint
        cert_details.PublicKey = public_key.to_public_bytes()
        cert_details.IsCA = False
        # Create signature
        signature = signing_key.private_key.sign(cert_details.SerializeToString())
        # Generate cert
        cert.Details.CopyFrom(cert_details)
        cert.Signature = signature
        # Yeah, protobuf method is named SerializeToString but returns bytes data
        crt_data: bytes = cert.SerializeToString()
        # Then parse a certificate object
        return NodeCertificate._from_bytes(crt_data)

    def verify_certificate(self, crt: Certificate) -> NodeCertificate:
        """Verify a node certificate"""
        if crt.IsCA:
            raise InvalidCertificateError("Certificate is a CA certificate")
        # Serialize certificate to string a second time
        details = crt._to_raw_cert_details().SerializeToString()
        # Verify signature
        self.get_public_key().verify(crt.Signature, details)
        # Verify timestamps
        now = time()
        # Verify activation timestamp
        if now < crt.NotBefore:
            raise InvalidCertificateError("Certificate is not valid yet")
        # Verify expiration timestamp
        if now >= crt.NotAfter:
            raise InvalidCertificateError("Certificate is expired")
        # Verify groups
        for group in crt.Groups:
            if group not in self.Groups:
                raise InvalidCertificateError(
                    f"Certificate group not present in CA cert: {group}"
                )
        # Check that certificate has a single IP
        if len(crt.Ips) != 1:
            raise InvalidCertificateError(
                "A node certificate must have a single IP address"
            )
        # Check that cert IP is valid
        if self.Ips:
            for ip in self.Ips:
                iface = ip_interface(ip)
                network = iface.network
                if ip_interface(crt.Ips[0]) in network:
                    break
            else:
                raise InvalidCertificateError(
                    f"Certificate contains an ip assignment ({crt.Ips[0]}) outside the limitations of the CA: {self.Ips}"
                )
        # Check that cert subnets are valid
        for subnet in crt.Subnets:
            iface = ip_interface(subnet)
            for ca_subnet in self.Subnets:
                ca_iface = ip_interface(ca_subnet)
                network = ca_iface.network
                if iface in network:
                    break
            else:
                raise InvalidCertificateError(
                    f"Certificate contains a subnet assignment ({subnet}) outside the limitations of the CA: {self.Subnets}"
                )
        # Return a NodeCertificate instance (in case certificate was a simple Certificate)
        return NodeCertificate(**asdict(crt))

    def verify_signing_options(self, options: SigningOptions) -> None:
        """Verify that signing options match certificate constraints"""
        # Check activation timestamp
        if self.get_activation_timestamp() > options.get_activation_timestamp():
            raise InvalidSigningOptionError(
                "CA certificate is active after NotBefore signing option"
            )
        # Check expiration timestamp
        if self.get_expiration_timestamp() < options.get_expiration_timestamp():
            raise InvalidSigningOptionError(
                "CA certificate expires before NotAfter signing option. "
                f"CA expires on {self.get_expiration_timestamp().isoformat()} but "
                f"cert is expected to expire on {options.get_expiration_timestamp().isoformat()}."
            )
        # Verify groups
        for group in options.Groups:
            if group not in self.Groups:
                raise InvalidSigningOptionError(
                    f"Signing options contain a group ('{group}') assignment outside the limitation of the CA: {self.Groups}"
                )
        # Check that certificate IP is provided
        if not options.Ip:
            raise InvalidSigningOptionError("IP address must be provided")
        # Check that certificate IP is valid
        try:
            target_ip = ip_interface(options.Ip)
        except Exception as exc:
            raise InvalidSigningOptionError(
                f"Invalid IP address: {options.Ip}"
            ) from exc
        # Check that cert IP is valid
        if self.Ips:
            for ip in self.Ips:
                iface = ip_interface(ip)
                network = iface.network
                if target_ip in network:
                    break
            else:
                raise InvalidSigningOptionError(
                    f"Signing options contain an ip assignment ({options.Ip}) outside the limitations of the CA: {self.Ips}"
                )
        # Check that cert subnets are valid
        for subnet in options.Subnets:
            iface = ip_interface(subnet)
            for ca_subnet in self.Subnets:
                ca_iface = ip_interface(ca_subnet)
                network = ca_iface.network
                if iface in network:
                    break
            else:
                raise InvalidSigningOptionError(
                    f"Signing options contain a subnet assignment ({subnet}) outside the limitations of the CA: {self.Subnets}"
                )
