import typing as t

import requests

from quara.creds.nebula.interfaces import (
    CACertificate,
    EncryptionKeyPair,
    NodeCertificate,
    SigningOptions,
)
from quara.creds.nebula.interfaces.keys import PublicEncryptionKey

from .. import errors
from .authorities import Authorities, Authority, Lighthouses
from .signing_requests import SigningRequest
from .storage_backend import StorageBackend


class Store:
    def __init__(self, backend: StorageBackend) -> None:
        self.backend = backend

    def get_authorities(
        self,
        authorities: t.Union[str, t.Iterable[str], None] = None,
    ) -> Authorities:
        """Get one or several authorities as a mapping.


        Arguments:
            name: Alias of the authorities to get. String are parsed as comma-separated lists.

        Returns:
            An Authorities mapping instance.
        """
        authorities_filter: t.Optional[t.List[str]]
        if isinstance(authorities, str):
            authorities_filter = [
                authority.strip() for authority in authorities.split(",")
            ]
        elif authorities:
            authorities_filter = list(authorities)
        else:
            authorities_filter = None
        # Query all authorities
        try:
            result = self.backend.get_authorities()
        # If there isn't any authority
        except errors.AuthorityNotFoundError:
            # Return an empty mapping
            return Authorities()
        # Return all authorities
        if not authorities_filter:
            return result
        # Filter authorities
        return Authorities(
            {
                name: infos
                for name, infos in result.items()
                if name in authorities_filter
            }
        )

    def get_lighthouses(
        self,
        authorities: t.Union[str, t.Iterable[str], None] = None,
    ) -> Lighthouses:
        """Get all lighthouses referenced by authorities.

        Arguments:
            name: Alias of the authorities to get lighthouses for. String are parsed as comma-separated lists.

        Returns:
            A Lighthouses mapping instance.
        """
        authorities = self.get_authorities(authorities=authorities)
        lighthouses = Lighthouses()
        for authority in authorities.values():
            lighthouses.update(authority.lighthouses)
        return lighthouses

    def get_authority(self, name: str) -> Authority:
        """Get an authority by name.

        Arguments:
            name: Alias of the authority to get.

        Returns:
            An authority instance

        Raises:
            AuthorityNotFoundError: When authority is not found.
        """
        authorities = self.get_authorities([name])
        try:
            return authorities[name]
        except KeyError as exc:
            raise errors.AuthorityNotFoundError from exc

    def get_keypair(self, name: str) -> EncryptionKeyPair:
        """Get a single keypair by name.

        Arguments:
            name: Name of the keypair.

        Returns:
            An encryption keypair instance.

        Raises:
            KeyPairNotFoundError: When keypair is not found.
        """
        return self.backend.get_keypair(name)

    def get_public_key(self, name: str) -> PublicEncryptionKey:
        """Get a single public key by name.

        Arguments:
            name: Name of the public key

        Returns:
            A public encryption key instance.

        Raises:
            PublicKeyNotFoundError: When public key is not found.
        """
        try:
            return self.backend.get_keypair(name).public_key
        except errors.KeyPairNotFoundError:
            pass
        return self.backend.get_public_key(name)

    def get_signing_certificate(self, authority: str) -> CACertificate:
        """Get a single signing certificate (CA certificate) from name.

        Arguments:
            authority: Alias of the autorithy to get signing certificate for.

        Returns:
            A CACertificate instance.

        Raises:
            CertificateNotFoundError: When CA certificate is not found.
        """
        try:
            return self.backend.get_signing_certificate(authority=authority)
        except errors.CertificateNotFoundError:
            authorities = self.get_authorities()
            if authority not in authorities:
                raise errors.AuthorityNotFoundError(authority)
            authority_infos = authorities[authority]
            crt_url = authority_infos.certificate
            response = requests.get(crt_url)
            try:
                response.raise_for_status()
            except requests.exceptions.HTTPError as exc:
                raise errors.CertificateNotFoundError(
                    f"CA Certificate for authority {authority} not found"
                ) from exc
            crt = CACertificate.from_bytes(response.content)
            self.save_signing_certificate(authority, crt)
            return crt

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
        return self.backend.get_certificate(authority=authority, name=name)

    def get_signing_request(self, authority: str, name: str) -> SigningRequest:
        """Get signing request for given authority and given name.

        Arguments:
            authority: Alias of the autorithy to get signing request for.
            name: Name of the certificate to get signing request for.

        Returns:
            A SigningRequest instance.

        Raises:
            SigningRequestNotFoundError: When signing request is not found.
            AuthorityNotFoundError: When CA certificate is not cached and authority is not found.
            CertificateNotFoundError: When CA certificate is not cached and cannot be fetched.
        """
        options = self.backend.get_signing_options(authority=authority, name=name)
        return SigningRequest(authority=authority, options=options)

    def save_signing_certificate(
        self,
        authority: str,
        certificate: CACertificate,
        update: bool = False,
    ) -> None:
        """Save a signing certificate.

        Arguments:
            authority: Alias of the authority to save signing certificate for.
            certificate: CA certificate to save.
            update: Overwrite existing certificate. False by default.

        Raises:
            CertificateExistsError: When update is False and certificate already exists.
        """
        try:
            crt = self.backend.get_signing_certificate(authority)
        except errors.CertificateNotFoundError:
            pass
        else:
            if crt.to_bytes() == certificate.to_bytes():
                return
            if not update:
                raise errors.CertificateExistsError(
                    f"A CA certificate for authority '{authority}' already exists"
                )
        self.backend.save_signing_certificate(authority=authority, cert=certificate)

    def save_signing_request(
        self, authority: str, options: SigningOptions, update: bool = False
    ) -> None:
        """Save a signing request.

        Arguments:
            authority: Alias of the authority to save signing request for.
            options: Signing options to save in signing request.
            update: Overwrite existing signing request. False by default.

        Returns:
            None

        Raises:
            SigningRequestExistsError: When update is False and signing request already exists.
        """
        name = options.Name
        try:
            request = self.backend.get_signing_options(authority=authority, name=name)
        except errors.SigningRequestNotFoundError:
            pass
        else:
            if request == options:
                return
            if not update:
                raise errors.SigningRequestExistsError(
                    f"A signing request for authority '{authority}' and name '{name}' already exists."
                )
        self.backend.save_signing_options(authority=authority, options=options)

    def save_certificate(
        self, authority: str, certificate: NodeCertificate, update: bool = False
    ) -> None:
        """Save a node certificate.

        Arguments:
            authority: Alias of the authority which issued the certificate.
            certificate: Certificate to save.
            update: Overwrite existing certificate. False by default.

        Returns:
            None

        Raises:
            CertificateExistsError: When update is False and certificate already exists.
        """
        name = certificate.Name
        try:
            cert = self.backend.get_certificate(authority=authority, name=name)
        except errors.CertificateNotFoundError:
            pass
        else:
            if cert.to_bytes() == certificate.to_bytes():
                return
            if not update:
                raise errors.CertificateExistsError(
                    f"A certificate issued by authority '{authority}' for name '{name}' already exists."
                )
        self.backend.save_certificate(authority=authority, certificate=certificate)

    def save_keypair(
        self, name: str, keypair: EncryptionKeyPair, update: bool = False
    ) -> None:
        """Save a keypair into the store.

        Arguments:
            name: Name of the keypair to save.
            keypair: Encryption keypair to save.
            update: Overwrite existing keypair. False by default.

        Raises:
            KeyPairExistsError: When update is False and keypair already exists.
        """
        try:
            current_keypair = self.backend.get_keypair(name)
        except errors.KeyPairNotFoundError:
            pass
        else:
            if current_keypair.to_public_bytes() == keypair.to_public_bytes():
                return
            if not update:
                raise errors.KeyPairExistsError(
                    f"A keypair named {name} already exists"
                )
            else:
                self.backend.delete_keypair(name)

        try:
            public_key = self.backend.get_public_key(name)
        except errors.PublicKeyNotFoundError:
            pass
        else:
            if public_key.to_public_bytes() != keypair.to_public_bytes():
                if not update:
                    raise errors.PublicKeyExistsError(
                        f"A public key named {name} already exists"
                    )
                else:
                    self.backend.delete_keypair(name)

        self.backend.save_keypair(name=name, keypair=keypair)

    def save_public_key(
        self, name: str, public_key: PublicEncryptionKey, update: bool = False
    ) -> None:
        """Save a public key into the store.

        Arguments:
            name: Name of the public key to save.
            public_key: Public key to save.

        Returns:
            None

        Raises:
            PublicKeyExistsError: When update is False and public key already exists.
        """
        try:
            current_keypair = self.backend.get_keypair(name)
        except errors.KeyPairNotFoundError:
            pass
        else:
            if current_keypair.to_public_bytes() == public_key.to_public_bytes():
                return
            if not update:
                raise errors.PublicKeyExistsError(
                    f"A public key named {name} already exists"
                )
            else:
                self.backend.delete_keypair(name)

        try:
            public_key = self.backend.get_public_key(name)
        except errors.PublicKeyNotFoundError:
            pass
        else:
            if public_key.to_public_bytes() == public_key.to_public_bytes():
                return
            if not update:
                raise errors.PublicKeyExistsError(
                    f"A public key named {name} already exists"
                )
            else:
                self.backend.delete_keypair(name)

        self.backend.save_public_key(name=name, public_key=public_key)

    def delete_signing_certificates(
        self, authorities: t.Union[str, t.Iterable[str], None] = None
    ) -> None:
        """Delete a signing certificate from store.

        Arguments:
            authorities: Names of authorities to delete signing certificate for.

        Returns:
            None
        """
        authorities = self.get_authorities(authorities=authorities)
        for authority in authorities:
            self.backend.delete_signing_certificate(authority=authority)

    def delete_signing_requests(
        self, name: str, authorities: t.Union[str, t.Iterable[str], None] = None
    ) -> None:
        """Delete a signing request from store.

        Arguments:
            authorities: Names of authorities to delete signing requests for.

        Returns:
            None
        """
        authorities = self.get_authorities(authorities=authorities)
        for authority in authorities:
            self.backend.delete_signing_options(authority=authority, name=name)

    def delete_certificates(
        self, name: str, authorities: t.Union[str, t.Iterable[str], None] = None
    ) -> None:
        """Delete a node certificate from store.

        Arguments:
            name: Name of certificates to delete.
            authorities: Names of authorities to delete node certificates for.

        Returns:
            None
        """
        authorities = self.get_authorities(authorities=authorities)
        for authority in authorities:
            self.backend.delete_certificate(authority=authority, name=name)

    def delete_keypair(self, name: str) -> None:
        """Delete an encryption keypair from store.

        Arguments:
            name: Name of keypair to delete.

        Returns:
            None
        """
        self.backend.delete_keypair(name=name)

    def find_certificates(
        self,
        authorities: t.Union[str, t.Iterable[str], None] = None,
        names: t.Union[str, t.Iterable[str], None] = None,
    ) -> t.Iterator[t.Tuple[str, NodeCertificate]]:
        return self.backend.find_certificates(authorities=authorities, names=names)

    def find_signing_requests(
        self,
        authorities: t.Union[str, t.Iterable[str], None] = None,
        names: t.Union[str, t.Iterable[str], None] = None,
    ) -> t.Iterator[t.Tuple[str, SigningRequest]]:
        for authority, options in self.backend.find_signing_options(
            authorities=authorities, names=names
        ):
            yield authority, SigningRequest(authority=authority, options=options)

    def find_keypairs(
        self,
        names: t.Union[str, t.Iterable[str], None] = None,
    ) -> t.Iterator[t.Tuple[str, EncryptionKeyPair]]:
        """Find encryption keypairs.

        Returns:
            An iterator of tuples `(authority, options)`.
        """
        return self.backend.find_keypairs(names)

    def find_public_keys(
        self,
        names: t.Union[str, t.Iterable[str], None] = None,
    ) -> t.Iterator[t.Tuple[str, PublicEncryptionKey]]:
        """Find encryption public keys.

        Returns:
            An iterator of tuples `(authority, options)`.
        """
        return self.backend.find_public_keys(names)
