import abc
import typing as t

from quara.creds.nebula import Certificate, EncryptionKeyPair, SigningOptions

from .authorities import Authorities, Authority, Lighthouses


class Store(metaclass=abc.ABCMeta):
    def get_authority(self, name: str) -> Authority:
        """Get an authority by name"""
        return self.get_authorities()[name]

    def get_lighthouses(
        self, authorities: t.Optional[t.List[str]] = None
    ) -> Lighthouses:
        """Get all lighthouses referenced by authorities"""
        all_authorities = self.get_authorities()
        if authorities is None:
            authorities = list(all_authorities)
        lighthouses = Lighthouses()
        for name in authorities:
            try:
                authority = all_authorities[name]
            except KeyError:
                continue
            lighthouses.update(authority.lighthouses)
        return lighthouses

    @abc.abstractmethod
    def get_authorities(self) -> Authorities:
        raise NotImplementedError

    @abc.abstractmethod
    def get_keypair(self, name: str) -> EncryptionKeyPair:
        raise NotImplementedError

    @abc.abstractmethod
    def get_signing_certificate(self, authority: str) -> Certificate:
        raise NotImplementedError

    @abc.abstractmethod
    def get_certificate(self, authority: str, name: str) -> Certificate:
        raise NotImplementedError

    @abc.abstractmethod
    def get_signing_request(self, authority: str, name: str) -> SigningOptions:
        raise NotImplementedError

    @abc.abstractmethod
    def save_signing_certificate(self, authority: str, cert: Certificate) -> None:
        raise NotImplementedError

    @abc.abstractmethod
    def save_signing_request(self, authority: str, options: SigningOptions) -> None:
        raise NotImplementedError

    @abc.abstractmethod
    def save_certificate(self, authority: str, cert: Certificate) -> None:
        raise NotImplementedError

    @abc.abstractmethod
    def save_keypair(self, name: str, keypair: EncryptionKeyPair) -> None:
        raise NotImplementedError

    @abc.abstractmethod
    def iterate_certificates(
        self,
        authority: str,
    ) -> t.Iterator[Certificate]:
        raise NotImplementedError

    @abc.abstractmethod
    def iterate_certificate_requests(
        self,
        authority: str,
    ) -> t.Iterator[SigningOptions]:
        raise NotImplementedError

    @abc.abstractmethod
    def iterate_keypairs(self) -> t.Iterator[t.Tuple[str, EncryptionKeyPair]]:
        raise NotImplementedError
