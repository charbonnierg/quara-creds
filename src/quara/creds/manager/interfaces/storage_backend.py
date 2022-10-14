import abc
import typing as t

from quara.creds.nebula.interfaces import (
    CACertificate,
    EncryptionKeyPair,
    NodeCertificate,
    SigningOptions,
)
from quara.creds.nebula.interfaces.keys import PublicEncryptionKey

from .authorities import Authorities
from .signing_requests import SigningRequest


class StorageBackend(metaclass=abc.ABCMeta):
    """A connector to where certificates and encryption keys are stored"""

    @abc.abstractmethod
    def get_authorities(self) -> Authorities:
        """Get all authorities.

        Returns:
            Authorities mapping.
        """
        raise NotImplementedError

    @abc.abstractmethod
    def get_keypair(self, name: str) -> EncryptionKeyPair:
        """Get a single keypair by name.

        Arguments:
            name: Name of the keypair.

        Returns:
            An encryption keypair instance.

        Raises:
            KeyPairNotFoundError: When keypair is not found.
        """
        raise NotImplementedError

    @abc.abstractmethod
    def get_public_key(self, name: str) -> PublicEncryptionKey:
        """Get a single public key by name.

        Arguments:
            name: Name of the public key

        Returns:
            A public encryption key instance.

        Raises:
            PublicKeyNotFoundError: When public key is not found.
        """
        raise NotImplementedError

    @abc.abstractmethod
    def get_signing_certificate(self, authority: str) -> CACertificate:
        """Get a single signing certificate (CA certificate) from name.

        Arguments:
            authority: Alias of the autorithy to get signing certificate for.

        Returns:
            A CACertificate instance.

        Raises:
            CertificateNotFoundError: When CA certificate is not found.
        """
        raise NotImplementedError

    @abc.abstractmethod
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
        raise NotImplementedError

    @abc.abstractmethod
    def get_signing_options(self, authority: str, name: str) -> SigningRequest:
        """Get signing options for given authority and given name.

        Arguments:
            authority: Alias of the autorithy to get signing options for.
            name: Name of the certificate to get signing options for.

        Returns:
            A SigningOptions instance.

        Raises:
            SigningRequestNotFoundError: When signing request is not found.
        """
        raise NotImplementedError

    @abc.abstractmethod
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
        raise NotImplementedError

    @abc.abstractmethod
    def save_signing_options(self, authority: str, options: SigningOptions) -> None:
        """Save some signing options

        Arguments:
            authority: Alias of the authority to save signing options for.
            options: Signing options to save.

        Returns:
            None
        """
        raise NotImplementedError

    @abc.abstractmethod
    def save_certificate(self, authority: str, certificate: NodeCertificate) -> None:
        """Save a node certificate into store.

        Arguments:
            authority: Alias of the authority which issued the certificate.
            certificate: Certificate to save.

        Returns:
            None
        """
        raise NotImplementedError

    @abc.abstractmethod
    def save_keypair(self, name: str, keypair: EncryptionKeyPair) -> None:
        """Save a keypair into store.

        Arguments:
            name: Name of the keypair to save.
            keypair: Encryption keypair to save.

        Returns:
            None
        """
        raise NotImplementedError

    @abc.abstractmethod
    def save_public_key(self, name: str, public_key: PublicEncryptionKey) -> None:
        """Save a publickey into store.

        Arguments:
            name: Name of the public key to save.
            public_key: Public key to save.

        Returns:
            None
        """
        raise NotImplementedError

    @abc.abstractmethod
    def delete_signing_certificate(self, authority: str) -> None:
        """Delete a signing certificate from store.

        Arguments:
            authority: Name of authority to delete signing certificate for.

        Returns:
            None
        """
        raise NotImplementedError

    @abc.abstractmethod
    def delete_signing_options(self, authority: str, name: str) -> None:
        """Delete signing options from store.

        Arguments:
            authority: Name of authority associated with signing options.
            name: Name of the certificate to delete signing options for.

        Returns:
            None
        """
        raise NotImplementedError

    @abc.abstractmethod
    def delete_certificate(self, authority: str, name: str) -> None:
        """Delete a node certificate from store.

        Arguments:
            authority: Name of authority which issued the certificate.
            name: Name of the certificate to delete.

        Returns:
            None
        """
        raise NotImplementedError

    @abc.abstractmethod
    def delete_keypair(self, name: str) -> None:
        """Delete a keypair from store.

        Arguments:
            name: Name of the keypair to delete.

        Returns:
            None
        """
        raise NotImplementedError

    @abc.abstractmethod
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
        raise NotImplementedError

    @abc.abstractmethod
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
        raise NotImplementedError

    @abc.abstractmethod
    def find_keypairs(
        self,
        names: t.Union[str, t.Iterable[str], None] = None,
    ) -> t.Iterator[t.Tuple[str, EncryptionKeyPair]]:
        """Find encryption keypairs.

        Returns:
            An iterator of tuples `(authority, options)`.
        """
        raise NotImplementedError

    @abc.abstractmethod
    def find_public_keys(
        self,
        names: t.Union[str, t.Iterable[str], None] = None,
    ) -> t.Iterator[t.Tuple[str, PublicEncryptionKey]]:
        """Find encryption public keys.

        Returns:
            An iterator of tuples `(authority, options)`.
        """
        raise NotImplementedError
