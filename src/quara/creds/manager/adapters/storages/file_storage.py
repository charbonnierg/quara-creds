import itertools
import typing as t
from dataclasses import asdict, dataclass, replace
from json import dumps, loads
from pathlib import Path

from quara.creds.manager import errors
from quara.creds.manager.interfaces import Authorities, Store
from quara.creds.nebula.interfaces import (
    CACertificate,
    EncryptionKeyPair,
    NodeCertificate,
    PublicEncryptionKey,
    SigningOptions,
)


@dataclass
class FileStorageOptions:
    root: t.Union[str, Path] = "~/.nebula"
    authorities: t.Union[str, Path, None] = None
    keys: t.Union[str, Path, None] = None
    certificates: t.Union[str, Path, None] = None
    signing_requests: t.Union[str, Path, None] = None
    signing_certificates: t.Union[str, Path, None] = None
    signing_keys: t.Union[str, Path, None] = None


@dataclass
class FileStorageSettings:
    root: Path
    authorities: Path
    keys: Path
    certificates: Path
    signing_requests: Path
    signing_certificates: Path
    signing_keys: Path

    @classmethod
    def from_root(cls, root: t.Union[str, Path]) -> "FileStorageSettings":
        """Create a file storage settings instance from root directory.

        Arguments:
            root: Path of root repository where settings file can be found
        """
        return cls.from_options(FileStorageOptions(root=Path(root)))

    @classmethod
    def from_options(
        cls, options: t.Optional[FileStorageOptions] = None, **kwargs: t.Any
    ) -> "FileStorageSettings":
        """Create a file storage settings instance from options.

        Arguments:
            options: file storage options

        Returns:
            settings: validated file storage settings
        """
        options = (
            replace(options, **kwargs) if options else FileStorageOptions(**kwargs)
        )
        root = Path(options.root).expanduser()
        return cls(
            root=root,
            authorities=Path(options.authorities).expanduser()
            if options.authorities
            else root.joinpath("authorities.json"),
            keys=Path(options.keys) if options.keys else root.joinpath("store/keys"),
            certificates=Path(options.certificates)
            if options.certificates
            else root.joinpath("store/certificates"),
            signing_requests=Path(options.signing_requests)
            if options.signing_requests
            else root.joinpath("store/signing_requests"),
            signing_certificates=Path(options.signing_certificates)
            if options.signing_certificates
            else root.joinpath("store/signing_certificates"),
            signing_keys=Path(options.signing_keys)
            if options.signing_keys
            else root.joinpath("store/signing_keys"),
        )


class FileStorageBackend(Store):
    def __init__(self, options: FileStorageOptions) -> None:
        self.settings = FileStorageSettings.from_options(options)

    def get_authorities(self) -> Authorities:
        """Get all authorities.

        Returns:
            Authorities mapping.
        """
        authorities_file = self.settings.authorities.expanduser()
        if not authorities_file.exists():
            raise errors.AuthorityNotFoundError("No authority defined")
        return Authorities.from_json(self.settings.authorities)

    def get_keypair(self, name: str) -> EncryptionKeyPair:
        """Get a single keypair by name.

        Arguments:
            name: Name of the keypair.

        Returns:
            An encryption keypair instance.

        Raises:
            KeyPairNotFoundError: When keypair is not found.
        """
        keyfile = self.settings.keys.joinpath(f"{name}.key").expanduser()
        if not keyfile.exists():
            raise errors.KeyPairNotFoundError(keyfile)
        return EncryptionKeyPair.from_file(keyfile)

    def get_public_key(self, name: str) -> PublicEncryptionKey:
        """Get a single public key by name.

        Arguments:
            name: Name of the public key

        Returns:
            A public encryption key instance.

        Raises:
            PublicKeyNotFoundError: When public key is not found.
        """
        pubfile = self.settings.keys.joinpath(f"{name}.pub").expanduser()
        if not pubfile.exists():
            raise errors.PublicKeyNotFoundError(pubfile)
        else:
            return PublicEncryptionKey.from_file(pubfile)

    def get_signing_certificate(self, authority: str) -> CACertificate:
        """Get a single signing certificate (CA certificate) from name.

        Arguments:
            authority: Alias of the autorithy to get signing certificate for.

        Returns:
            A CACertificate instance.

        Raises:
            CertificateNotFoundError: When CA certificate is not found.
        """
        ca_crt_file = self.settings.signing_certificates.joinpath(
            f"{authority}.crt"
        ).expanduser()
        if not ca_crt_file.exists():
            raise errors.CertificateNotFoundError(ca_crt_file)
        return CACertificate.from_file(ca_crt_file)

    def get_certificate(self, authority: str, name: str) -> NodeCertificate:
        """Get a single node certificate issued by given authority with given name.

        Arguments:
            authority: Alias of the autorithy which issued the certificate.
            name: Name of the certificate to get.

        Returns:
            A NodeCertificate instance.

        Raises:
            CertificateNotFoundError: When certificate is not found.
        """
        crt_file = (
            self.settings.certificates.joinpath(authority)
            .joinpath(f"{name}.crt")
            .expanduser()
        )
        if not crt_file.exists():
            raise errors.CertificateNotFoundError(crt_file)
        return NodeCertificate.from_file(crt_file)

    def get_signing_options(self, authority: str, name: str) -> SigningOptions:
        """Get signing options for given authority and given name.

        Arguments:
            authority: Alias of the autorithy to get signing options for.
            name: Name of the certificate to get signing options for.

        Returns:
            A SigningOptions instance.

        Raises:
            SigningRequestNotFoundError: When signing request is not found.
        """
        csr_file = (
            self.settings.signing_requests.joinpath(authority)
            .joinpath(f"{name}.json")
            .expanduser()
        )
        if not csr_file.exists():
            raise errors.SigningRequestNotFoundError(csr_file)
        csr_data = loads(csr_file.read_bytes())
        return SigningOptions(**csr_data)

    def save_signing_certificate(
        self, authority: str, certificate: CACertificate
    ) -> None:
        """Save a signing certificate.

        Arguments:
            authority: Alias of the authority to save signing certificate for.
            certificate: CA certificate to save.

        Returns:
            None
        """
        output = self.settings.signing_certificates.joinpath(
            f"{authority}.crt"
        ).expanduser()
        output.parent.mkdir(exist_ok=True, parents=True)
        certificate.write_pem_file(output)

    def save_signing_options(self, authority: str, options: SigningOptions) -> None:
        """Save some signing options

        Arguments:
            authority: Alias of the authority to save signing options for.
            options: Signing options to save.

        Returns:
            None
        """
        output = (
            self.settings.signing_requests.joinpath(authority)
            .joinpath(f"{options.Name}.json")
            .expanduser()
        )
        output.parent.mkdir(exist_ok=True, parents=True)
        output.write_bytes(dumps(asdict(options), indent=2).encode("utf-8"))

    def save_certificate(self, authority: str, certificate: NodeCertificate) -> None:
        """Save a node certificate into store.

        Arguments:
            authority: Alias of the authority which issued the certificate.
            certificate: Certificate to save.

        Returns:
            None
        """
        output = (
            self.settings.certificates.joinpath(authority)
            .joinpath(f"{certificate.Name}.crt")
            .expanduser()
        )
        output.parent.mkdir(exist_ok=True, parents=True)
        certificate.write_pem_file(output)

    def save_keypair(self, name: str, keypair: EncryptionKeyPair) -> None:
        """Save a keypair into store.

        Arguments:
            name: Name of the keypair to save.
            keypair: Encryption keypair to save.

        Returns:
            None
        """
        private_output = self.settings.keys.joinpath(f"{name}.key").expanduser()
        private_output.parent.mkdir(exist_ok=True, parents=True)
        keypair.write_private_key(private_output)

    def save_public_key(self, name: str, public_key: PublicEncryptionKey) -> None:
        """Save a publickey into store.

        Arguments:
            name: Name of the public key to save.
            public_key: Public key to save.

        Returns:
            None
        """
        public_output = self.settings.keys.joinpath(f"{name}.pub").expanduser()
        public_output.parent.mkdir(exist_ok=True, parents=True)
        public_key.write_public_key(public_output)

    def delete_signing_certificate(self, authority: str) -> None:
        """Delete a signing certificate from store.

        Arguments:
            authority: Name of authority to delete signing certificate for.

        Returns:
            None
        """
        (
            self.settings.signing_certificates.joinpath(f"{authority}.crt")
            .expanduser()
            .unlink(missing_ok=True)
        )

    def delete_signing_options(self, authority: str, name: str) -> None:
        """Delete signing options from store.

        Arguments:
            authority: Name of authority associated with signing options.
            name: Name of the certificate to delete signing options for.

        Returns:
            None
        """
        (
            self.settings.signing_requests.joinpath(authority)
            .joinpath(f"{name}.json")
            .expanduser()
            .unlink(missing_ok=True)
        )

    def delete_certificate(self, authority: str, name: str) -> None:
        """Delete a node certificate from store.

        Arguments:
            authority: Name of authority which issued the certificate.
            name: Name of the certificate to delete.

        Returns:
            None
        """
        (
            self.settings.certificates.joinpath(authority)
            .joinpath(f"{name}.crt")
            .expanduser()
            .unlink(missing_ok=True)
        )

    def delete_keypair(self, name: str) -> None:
        """Delete a keypair from store.

        Arguments:
            name: Name of the keypair to delete.

        Returns:
            None
        """
        self.settings.keys.joinpath(f"{name}.key").expanduser().unlink(missing_ok=True)
        self.settings.keys.joinpath(f"{name}.pub").expanduser().unlink(missing_ok=True)

    def find_certificates(
        self,
        authorities: t.Union[str, t.Iterable[str], None] = None,
        names: t.Union[str, t.Iterable[str], None] = None,
    ) -> t.Iterator[t.Tuple[str, NodeCertificate]]:
        """Find node certificates.

        Arguments:
            authorities: When specified, only certificates issued by those authorities will be yielded.
            names: When specified, only certificates with those names will be yielded.

        Returns:
            An iterator of tuples `(authority, certificate)`.
        """
        authorities_subset: t.Optional[t.List[str]]
        if isinstance(authorities, str):
            authorities_subset = [name.strip() for name in authorities.split(",")]
        elif authorities is None:
            authorities_subset = None
        else:
            authorities_subset = list(authorities)

        names_subset: t.Optional[t.List[str]]
        if isinstance(names, str):
            names_subset = [name.strip() for name in names.split(",")]
        elif names is None:
            names_subset = None
        else:
            names_subset = list(names)

        if names_subset and authorities_subset:
            patterns = [
                f"{authority}/{name}.crt"
                for authority, name in itertools.product(
                    authorities_subset, names_subset
                )
            ]
        elif authorities_subset:
            patterns = [f"{authority}/*.crt" for authority in authorities_subset]
        elif names_subset:
            patterns = [f"**/{name}.crt" for name in names_subset]
        else:
            patterns = ["**/*.crt"]

        cert_root = self.settings.certificates.expanduser()
        for pattern in patterns:
            for file in cert_root.glob(pattern):
                yield file.parent.name, NodeCertificate.from_file(file)

    def find_signing_options(
        self,
        authorities: t.Union[str, t.Iterable[str], None] = None,
        names: t.Union[str, t.Iterable[str], None] = None,
    ) -> t.Iterator[t.Tuple[str, SigningOptions]]:
        """Find signing options

        Arguments:
            authorities: When specified, only signing options associated with those authorities will be yielded.
            names: When specified, only signing options with those names will be yielded.

        Returns:
            An iterator of tuples `(authority, options)`.
        """
        authorities_subset: t.Optional[t.List[str]]
        if isinstance(authorities, str):
            authorities_subset = [name.strip() for name in authorities.split(",")]
        elif authorities is None:
            authorities_subset = None
        else:
            authorities_subset = list(authorities)

        names_subset: t.Optional[t.List[str]]
        if isinstance(names, str):
            names_subset = [name.strip() for name in names.split(",")]
        elif names is None:
            names_subset = None
        else:
            names_subset = list(names)

        if names_subset and authorities_subset:
            patterns = [
                f"{authority}/{name}.json"
                for authority, name in itertools.product(
                    authorities_subset, names_subset
                )
            ]
        elif authorities_subset:
            patterns = [f"{authority}/*.json" for authority in authorities_subset]
        elif names_subset:
            patterns = [f"**/{name}.json" for name in names_subset]
        else:
            patterns = ["**/*.json"]

        csr_root = self.settings.signing_requests.expanduser()
        for pattern in patterns:
            for file in csr_root.glob(pattern):
                authority = file.parent.name
                csr_data = loads(file.read_bytes())
                yield authority, SigningOptions(**csr_data)

    def find_keypairs(
        self,
        names: t.Union[str, t.Iterable[str], None] = None,
    ) -> t.Iterator[t.Tuple[str, EncryptionKeyPair]]:
        """Find encryption keypairs.

        Returns:
            An iterator of tuples `(authority, options)`.
        """
        if isinstance(names, str):
            names = [name.stip() for name in names.split(",")]
        elif names is None:
            names = []
        else:
            names = list(names)
        for file in self.settings.keys.expanduser().glob("*.key"):
            name = file.stem
            if names and name not in names:
                continue
            yield name, EncryptionKeyPair.from_file(file)

    def find_public_keys(
        self,
        names: t.Union[str, t.Iterable[str], None] = None,
    ) -> t.Iterator[t.Tuple[str, PublicEncryptionKey]]:
        """Find encryption public keys.

        Returns:
            An iterator of tuples `(authority, options)`.
        """
        if isinstance(names, str):
            names = [name.stip() for name in names.split(",")]
        elif names is None:
            names = []
        else:
            names = list(names)

        matched: t.List[str] = []

        for name, keypair in self.find_keypairs(names):
            yield name, keypair.public_key

        for file in self.settings.keys.expanduser().glob("*.pub"):
            name = file.stem
            if name in matched:
                continue
            if names and name not in names:
                continue
            yield name, PublicEncryptionKey.from_file(file)
