import typing as t
from dataclasses import asdict, dataclass, replace
from json import dumps, loads
from pathlib import Path

import requests

from quara.creds.manager.interfaces.authorities import Authorities
from quara.creds.manager.interfaces.storage import Store
from quara.creds.nebula import Certificate, EncryptionKeyPair, SigningOptions


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
        """Create a file storage settings instance from root directory"""
        return cls.from_options(FileStorageOptions(root=Path(root)))

    @classmethod
    def from_options(
        cls, options: t.Optional[FileStorageOptions] = None, **kwargs: t.Any
    ) -> "FileStorageSettings":
        """Create a file storage settings instance from options"""
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
        """Get a mapping of Authority"""
        return Authorities.from_json(self.settings.authorities)

    def get_keypair(self, name: str) -> EncryptionKeyPair:
        """Get a single keypair by name"""
        keyfile = self.settings.keys.joinpath(f"{name}.key").expanduser()
        if not keyfile.exists():
            raise FileNotFoundError(keyfile)
        return EncryptionKeyPair.from_file(keyfile)

    def get_signing_certificate(self, authority: str) -> Certificate:
        """Get a single signing certificate (CA certificate) from name"""
        ca_crt_file = self.settings.signing_certificates.joinpath(
            f"{authority}.crt"
        ).expanduser()
        if not ca_crt_file.exists():
            authorities = self.get_authorities()
            if authority not in authorities:
                raise FileNotFoundError(ca_crt_file)
            authority_infos = authorities[authority]
            crt_url = authority_infos.certificate
            response = requests.get(crt_url)
            crt = Certificate.from_bytes(response.content)
            self.save_signing_certificate(authority, crt)

        return Certificate.from_file(ca_crt_file)

    def get_certificate(self, authority: str, name: str) -> Certificate:
        """Get a single node certificate issued by given authority with given name"""
        crt_file = (
            self.settings.certificates.joinpath(authority)
            .joinpath(f"{name}.crt")
            .expanduser()
        )
        if not crt_file.exists():
            raise FileNotFoundError(crt_file)
        return Certificate.from_file(crt_file)

    def get_signing_request(self, authority: str, name: str) -> SigningOptions:
        """Get a single signing certificate request for given authority with given name"""
        csr_file = (
            self.settings.signing_requests.joinpath(authority)
            .joinpath(f"{name}.json")
            .expanduser()
        )
        if not csr_file.exists():
            raise FileNotFoundError(csr_file)
        csr_data = loads(csr_file.read_bytes())
        csr_data["Name"] = name
        return SigningOptions(**csr_data)

    def save_signing_certificate(
        self, authority: str, certificate: Certificate
    ) -> None:
        """Save a signing certificate."""
        output = self.settings.signing_certificates.joinpath(
            f"{authority}.crt"
        ).expanduser()
        output.parent.mkdir(exist_ok=True, parents=True)
        certificate.write_pem_file(output)

    def save_signing_request(self, authority: str, options: SigningOptions) -> None:
        output = (
            self.settings.signing_requests.joinpath(authority)
            .joinpath(f"{options.Name}.json")
            .expanduser()
        )
        output.parent.mkdir(exist_ok=True, parents=True)
        output.write_bytes(dumps(asdict(options), indent=2).encode("utf-8"))

    def save_certificate(self, authority: str, certificate: Certificate) -> None:
        """Save a node certificate."""
        output = (
            self.settings.certificates.joinpath(authority)
            .joinpath(f"{certificate.Name}.crt")
            .expanduser()
        )
        output.parent.mkdir(exist_ok=True, parents=True)
        certificate.write_pem_file(output)

    def save_keypair(self, name: str, keypair: EncryptionKeyPair) -> None:
        private_output = self.settings.keys.joinpath(f"{name}.key").expanduser()
        private_output.parent.mkdir(exist_ok=True, parents=True)
        keypair.write_private_key(private_output)

    def iterate_certificates(
        self,
        authority: str,
    ) -> t.Iterator[Certificate]:
        for file in (
            self.settings.certificates.joinpath(authority).expanduser().glob("*.crt")
        ):
            yield Certificate.from_file(file)

    def iterate_certificate_requests(
        self,
        authority: str,
    ) -> t.Iterator[SigningOptions]:
        for file in (
            self.settings.signing_requests.joinpath(authority)
            .expanduser()
            .glob("*.json")
        ):
            csr_data = loads(file.read_bytes())
            csr_data["Name"] = file.stem
            yield SigningOptions(**csr_data)

    def iterate_keypairs(self) -> t.Iterator[t.Tuple[str, EncryptionKeyPair]]:
        for file in self.settings.keys.expanduser().glob("*.key"):
            yield file.stem, EncryptionKeyPair.from_file(file)
