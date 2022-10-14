"""pync config gen command"""
import typing as t
from pathlib import Path

from jinja2 import Environment, FileSystemLoader

if t.TYPE_CHECKING:
    from quara.creds.manager.manager import NebulaCertManager


TEMPLATE_ROOT = Path(__file__).parent.parent / "templates"
TEMPLATE_LOADER = FileSystemLoader(searchpath=TEMPLATE_ROOT)
TEMPLATE_ENV = Environment(loader=TEMPLATE_LOADER)


class ManagedConfig:
    def __init__(self, manager: "NebulaCertManager") -> None:
        self._manager = manager

    def gen(
        self,
        authorities: t.Union[str, t.Iterable[str], None] = None,
        name: t.Union[str, t.Iterable[str], None] = None,
    ) -> str:
        manager = self._manager
        name = name or manager.default_user
        # Export certificate keypair
        pem_keypair = manager.storage.get_keypair(name).to_private_pem_data()
        pem_ca = b""
        pem_certificate = b""
        # Export CA certificates and node certificates
        for authority_name, certificates in manager.certificates.list_by_authority(
            authorities=authorities, names=name
        ).items():
            ca_crt = manager.storage.get_signing_certificate(authority_name)
            pem_ca = b"\n".join([pem_ca, ca_crt.to_pem_data()])
            for crt in certificates:
                # Verify certificate just to be sure that configuration will be valid
                ca_crt.verify_certificate(crt)
                pem_certificate = b"\n".join([pem_certificate, crt.to_pem_data()])
        return self.render_template(
            template="config",
            lighthouses=manager.storage.get_lighthouses(authorities=authorities),
            ca_cert=pem_ca.decode("utf-8"),
            cert=pem_certificate.decode("utf-8"),
            key=pem_keypair.decode("utf-8"),
        )

    def render_template(
        self,
        template: str,
        lighthouses: t.Dict[str, t.Union[str, t.List[str]]],
        ca_cert: t.Optional[str] = None,
        ca_cert_file: t.Optional[str] = None,
        cert: t.Optional[str] = None,
        cert_file: t.Optional[str] = None,
        key: t.Optional[str] = None,
        key_file: t.Optional[str] = None,
        preferred_ranges: t.Optional[t.List[str]] = None,
        am_relay: bool = False,
        use_relays: bool = True,
        device: str = "nebula1",
    ) -> str:
        """
        Arguments:
            lighouses: A mapping a lighthouses. Keys are nebula IP addresses. Values are lists of public IP addresses.
            ca_cert: the CA certificate to use in config as a PEM-encoded string.
            ca_cert_file: the CA certificate to use in config as a filepath.
            cert: the node certificate to use in config as PEM-encoded string.
            cert_file: the node certificate to use in config as a filepath.
            key: the node public key to use in config as PEM-encoded string.
            key_file: the node public key to use in config as a filepath.
            preferred_ranges: A list of networks with CIDR notation.
            am_relay: boolean flag indicating if nebula node should act as a relay node.
            use_relays: boolean flag indicating if nebula node can connect to relay nodes.
            device: name of the network interface managed by nebula.

        Returns:
            A nebula YAML configuration file as a string.
        """
        template = TEMPLATE_ENV.get_template(template + ".yml.j2")
        static_host_map = {
            key: [value] if isinstance(value, str) else value
            for key, value in lighthouses.items()
        }
        lighthouse_hosts = list(static_host_map)
        return template.render(
            static_host_map=static_host_map,
            lighthouse_hosts=lighthouse_hosts,
            preferred_ranges=preferred_ranges,
            ca_cert=ca_cert,
            ca_cert_file=ca_cert_file,
            cert=cert,
            cert_file=cert_file,
            key=key,
            key_file=key_file,
            am_relay=am_relay,
            use_relays=use_relays,
            device=device,
        )
