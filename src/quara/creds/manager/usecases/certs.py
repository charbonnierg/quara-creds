import typing as t
from collections import defaultdict
from json import dumps
from pathlib import Path

from quara.creds.manager.errors import (
    CertificateExistsError,
    CertificateNotFoundError,
    PublicKeyNotFoundError,
)
from quara.creds.nebula.api import (
    create_encryption_keypair,
    parse_encryption_public_key,
    read_encryption_public_key,
)
from quara.creds.nebula.interfaces import NodeCertificate

if t.TYPE_CHECKING:
    from quara.creds.manager.manager import NebulaCertManager


class ManagedCertificates:
    def __init__(self, manager: "NebulaCertManager") -> None:
        self._manager = manager

    def remove(
        self,
        name: t.Optional[str] = None,
        authorities: t.Union[str, t.Iterable[str], None] = None,
    ) -> None:
        manager = self._manager
        name = name or manager.default_user
        manager.storage.delete_certificates(name=name, authorities=authorities)

    def list_by_authority(
        self,
        authorities: t.Union[str, t.Iterable[str], None] = None,
        names: t.Union[str, t.Iterable[str], None] = None,
    ) -> t.Dict[str, t.List[NodeCertificate]]:
        manager = self._manager
        certs: t.Dict[str, t.List[NodeCertificate]] = defaultdict(list)
        for authority, cert in manager.storage.find_certificates(
            authorities=authorities, names=names
        ):
            certs[authority].append(cert)
        return certs

    def list_by_names(
        self,
        authorities: t.Union[str, t.Iterable[str], None] = None,
        names: t.Union[str, t.Iterable[str], None] = None,
    ) -> t.Dict[str, t.List[t.Tuple[str, NodeCertificate]]]:
        manager = self._manager
        certs: t.Dict[str, t.List[t.Tuple[str, NodeCertificate]]] = defaultdict(list)
        for authority, cert in manager.storage.find_certificates(
            authorities=authorities, names=names
        ):
            certs[cert.Name].append((authority, cert))
        return certs

    def export(
        self,
        authorities: t.Union[str, t.Iterable[str], None] = None,
        names: t.Union[str, t.Iterable[str], None] = None,
    ) -> str:
        manager = self._manager
        certificates = manager.certificates.list_by_names(
            authorities=authorities, names=names
        )
        return dumps(
            [
                {
                    "authority": authority,
                    "user": user,
                    "certificate": cert.to_dict(),
                }
                for user, certs in certificates.items()
                for (authority, cert) in certs
            ]
        )

    def sign(
        self,
        authorities: t.Union[str, t.Iterable[str], None] = None,
        name: t.Optional[str] = None,
        public_key: t.Union[str, bytes, Path, None] = None,
        renew: bool = False,
    ) -> t.Iterator[t.Tuple[str, NodeCertificate]]:
        manager = self._manager
        name = name or manager.default_user
        authorities = manager.storage.get_authorities(authorities=authorities)
        # Try to load certificate keypair
        if public_key is None:
            try:
                pubkey = manager.storage.get_public_key(name)
            except PublicKeyNotFoundError:
                keypair = create_encryption_keypair()
                manager.storage.save_keypair(name, keypair)
                pubkey = keypair.public_key
        else:
            if Path(public_key).exists():
                pubkey = read_encryption_public_key(public_key)
            else:
                pubkey = parse_encryption_public_key(public_key)
            # Saving public key will raise an error if a different public key
            # with same name already exists
            manager.storage.save_public_key(name, pubkey)
        # Load signing requests
        for authority, authority_meta in authorities.items():
            ca_crt = manager.storage.get_signing_certificate(authority=authority)
            signing_request = manager.storage.get_signing_request(
                authority=authority, name=name
            )
            # Try to load certificate
            try:
                crt = manager.storage.get_certificate(authority, name)
            except CertificateNotFoundError:
                pass
            # If certificate is found
            else:
                # Verify certificate
                try:
                    ca_crt.verify_certificate(crt)
                except Exception:
                    pass
                # If certificate is valid
                else:
                    if not renew:
                        raise CertificateExistsError(
                            f"Certificate with name '{name}' issued by authority '{authority}' already exists"
                        )
                    else:
                        renew = True
            # Verify signing options
            ca_crt.verify_signing_options(signing_request.options)
            # Fetch CA key
            ca_key = authority_meta.get_signing_keypair()
            # Then sign certificate
            crt = ca_crt.sign_certificate(
                signing_key=ca_key,
                public_key=pubkey,
                options=signing_request.options,
            )
            # Validate certificate to make sure we did not mess up somewhere
            ca_crt.verify_certificate(crt=crt)
            # Save certificate
            manager.storage.save_certificate(
                authority=authority, certificate=crt, update=renew
            )
            # Yield authority and certificate
            yield authority, crt

    def sign_all(
        self,
        authorities: t.Union[str, t.Iterable[str], None] = None,
    ) -> t.Iterator[t.Tuple[str, NodeCertificate]]:
        for authority, signing_request in self._manager.storage.find_signing_requests(
            authorities=authorities
        ):
            for _, cert in self.sign(
                authorities=authority,
                name=signing_request.options.Name,
                renew=True,
            ):
                yield authority, cert
