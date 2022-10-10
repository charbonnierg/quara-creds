import typing as t
from pathlib import Path

from quara.creds.nebula.errors import InvalidSigningOptionError

from ..interfaces import (
    CACertificate,
    Certificate,
    EncryptionKeyPair,
    NodeCertificate,
    PublicEncryptionKey,
    PublicSigningKey,
    SigningCAOptions,
    SigningKeyPair,
    SigningOptions,
)


def create_signing_options(
    name: str,
    ip: str,
    duration: t.Optional[str] = None,
    activation: t.Optional[str] = None,
    groups: t.Union[None, str, t.List[str]] = None,
    subnets: t.Union[None, str, t.List[str]] = None,
) -> SigningOptions:
    """Create signing options"""
    options: t.Dict[str, t.Any] = {"Name": name, "Ip": ip}
    if duration:
        options["NotAfter"] = duration
    if activation:
        options["NotBefore"] = activation
    if groups:
        if isinstance(groups, str):
            groups = [group.strip() for group in groups.split(",")]
        options["Groups"] = groups
    if subnets:
        if isinstance(subnets, str):
            subnets = [subnet.strip() for subnet in subnets.split(",")]
        options["Subnets"] = subnets
    # Create signing options
    return SigningOptions(**options)


def create_signing_ca_options(
    name: str,
    ips: t.Union[None, str, t.List[str]],
    duration: t.Optional[str] = None,
    activation: t.Optional[str] = None,
    groups: t.Union[None, str, t.List[str]] = None,
    subnets: t.Union[None, str, t.List[str]] = None,
) -> SigningOptions:
    """Create signing options"""
    options: t.Dict[str, t.Any] = {"Name": name}
    if ips:
        if isinstance(ips, str):
            ips = [ip.strip() for ip in ips.split(",")]
        options["Ips"] = ips
    if duration:
        options["NotAfter"] = duration
    if activation:
        options["NotBefore"] = activation
    if groups:
        if isinstance(groups, str):
            groups = [group.strip() for group in groups.split(",")]
        options["Groups"] = groups
    if subnets:
        if isinstance(subnets, str):
            subnets = [subnet.strip() for subnet in subnets.split(",")]
        options["Subnets"] = subnets
    # Create signing options
    return SigningOptions(**options)


def create_encryption_keypair() -> EncryptionKeyPair:
    """Create a new encryption keypair.

    This is equivalent to running `nebula-cert keygen` in memory.
    """
    return EncryptionKeyPair()


def create_signing_keypair() -> SigningKeyPair:
    """Create a new signing keypair.

    Creating a signing keypair only is not possible using `nebula-cert`, but
    a signing keypair is always created when using the `nebula-cert ca`
    command to create a new CA certificate.
    """
    return SigningKeyPair()


# Parse bytes


def parse_ca_certificate(data: t.Union[bytes, str]) -> CACertificate:
    """Parse a CA certificate from bytes data.

    Data can be PEM-encoded bytes or raw bytes.
    """
    if isinstance(data, str):
        data = bytes.fromhex(data)
    return CACertificate.from_bytes(data)


def parse_node_certificate(data: t.Union[bytes, str]) -> NodeCertificate:
    """Parse a node certificate from bytes data.

    Data can be PEM-encoded bytes or raw bytes.
    """
    if isinstance(data, str):
        data = bytes.fromhex(data)
    return NodeCertificate.from_bytes(data)


def parse_encryption_keypair(data: t.Union[bytes, str]) -> EncryptionKeyPair:
    """Parse an encryption keypair from private bytes.

    Data can be PEM-encoded bytes or raw bytes.
    """
    if isinstance(data, str):
        data = bytes.fromhex(data)
    return EncryptionKeyPair.from_bytes(data)


def parse_encryption_public_key(data: t.Union[str, bytes]) -> PublicEncryptionKey:
    """Parse a public encryption key from public bytes.

    Data can be PEM-encoded bytes or raw bytes.
    """
    if isinstance(data, str):
        data = bytes.fromhex(data)
    return PublicEncryptionKey.from_bytes(data)


def parse_signing_keypair(data: t.Union[bytes, str]) -> SigningKeyPair:
    """Parse a signing keypair from private bytes.

    Data can be PEM-encoded bytes or raw bytes.
    """
    if isinstance(data, str):
        data = bytes.fromhex(data)
    return SigningKeyPair.from_bytes(data)


def parse_signing_public_key(data: t.Union[bytes, str]) -> PublicSigningKey:
    """Parse a public signing key from public bytes.

    Data can be PEM-encoded bytes or raw bytes.
    """
    if isinstance(data, str):
        data = bytes.fromhex(data)
    return PublicSigningKey.from_bytes(data)


# Read files


def read_ca_certificate(path: t.Union[str, Path]) -> CACertificate:
    """Read a CA certificate from file.

    File can hold PEM-encoded data or raw bytes.
    """
    return CACertificate.from_file(path)


def read_node_certificate(path: t.Union[str, Path]) -> NodeCertificate:
    """Read a node certificate from file.

    File can hold PEM-encoded data or raw bytes.
    """
    return NodeCertificate.from_file(path)


def read_encryption_keypair(path: t.Union[str, Path]) -> EncryptionKeyPair:
    """Parse a private encryption keypair from file.

    File can hold PEM-encoded data or raw bytes.
    """
    return EncryptionKeyPair.from_file(path)


def read_encryption_public_key(path: t.Union[str, Path]) -> PublicEncryptionKey:
    """Parse a public encryption key from file.

    File can hold PEM-encoded data or raw bytes.
    """
    return PublicEncryptionKey.from_file(path)


def read_signing_keypair(path: t.Union[str, Path]) -> SigningKeyPair:
    """Parse a private signing keypair from file.

    File can hold PEM-encoded data or raw bytes.
    """
    return SigningKeyPair.from_file(path)


def read_signing_public_key(path: t.Union[str, Path]) -> PublicSigningKey:
    """Parse a public signing key from file.

    File can hold PEM-encoded data or raw bytes.
    """
    return PublicSigningKey.from_file(path)


# Verify certificates and options


def verify_certificate(
    ca_crt: t.Union[CACertificate, Path, str, bytes],
    crt: t.Union[Certificate, Path, str, bytes],
) -> NodeCertificate:
    """Verify that certificate is valid.

    This function has been adapted from the `Verify` function from the go module `github.com/slackhq/nebula/cert`:
    https://github.com/slackhq/nebula/blob/master/cert/cert.go#L255
    """
    if isinstance(crt, (str, bytes)):
        crt = parse_node_certificate(crt)
    elif isinstance(crt, Path):
        crt = read_node_certificate(crt)
    if isinstance(ca_crt, (str, bytes)):
        ca_crt = parse_ca_certificate(ca_crt)
    elif isinstance(ca_crt, Path):
        ca_crt = read_ca_certificate(ca_crt)
    return ca_crt.verify_certificate(crt)


def verify_signing_options(
    ca_crt: t.Union[CACertificate, Path, str, bytes],
    options: t.Union[SigningOptions, t.Mapping[str, t.Any]],
) -> SigningOptions:
    """Check that signing options match CA certificate constraints.

    This function has been adapted from the `Verify` function from the go module `github.com/slackhq/nebula/cert`:
    https://github.com/slackhq/nebula/blob/master/cert/cert.go#L255
    """
    if isinstance(ca_crt, (bytes, str)):
        ca_crt = parse_ca_certificate(ca_crt)
    elif isinstance(ca_crt, Path):
        ca_crt = read_ca_certificate(ca_crt)
    if not isinstance(options, SigningOptions):
        try:
            options = SigningOptions(**options)
        except Exception as exc:
            raise InvalidSigningOptionError("Failed to parse signing options") from exc
    ca_crt.verify_signing_options(options)
    return options


# Sign certificates


def sign_certificate(
    ca_crt: t.Union[str, bytes, Path, CACertificate],
    ca_key: t.Union[str, bytes, Path, SigningKeyPair],
    public_key: t.Union[str, bytes, Path, PublicEncryptionKey, EncryptionKeyPair],
    options: t.Union[SigningOptions, t.Mapping[str, t.Any]],
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
    # Parse CA crt
    if isinstance(ca_crt, (bytes, str)):
        ca_crt = parse_ca_certificate(ca_crt)
    elif isinstance(ca_crt, Path):
        ca_crt = read_ca_certificate(ca_crt)
    # Parse CA key
    if isinstance(ca_key, (bytes, str)):
        ca_key = parse_signing_keypair(ca_key)
    elif isinstance(ca_key, Path):
        ca_key = read_signing_keypair(ca_key)
    # Parse public key
    if isinstance(public_key, (bytes, str)):
        public_key = parse_encryption_public_key(public_key)
    elif isinstance(public_key, Path):
        public_key = read_encryption_public_key(public_key)
    # Parse signing options
    if not isinstance(options, SigningOptions):
        try:
            options = SigningOptions(**options)
        except Exception as exc:
            raise InvalidSigningOptionError("Failed to parse signing options") from exc
    # Sign certificate
    return ca_crt.sign_certificate(ca_key, public_key=public_key, options=options)


def sign_ca_certificate(
    options: t.Union[SigningCAOptions, t.Mapping[str, t.Any]],
) -> t.Tuple[SigningKeyPair, Certificate]:
    """Generate a nebula CA certificate.

    Arguments:
        options: Options used to generate the CA certificate.

    Returns:
        a tuple `(keypair, cert)` holding a `SigningKeyPair` instance and a `Certificate` instance
    """
    if not isinstance(options, SigningCAOptions):
        try:
            options = SigningCAOptions(**options)
        except Exception as exc:
            raise InvalidSigningOptionError(
                "Failed to parse CA signing options"
            ) from exc
    keypair = SigningKeyPair()
    ca_crt = CACertificate.sign_ca_certificate(keypair, options)
    return keypair, ca_crt
