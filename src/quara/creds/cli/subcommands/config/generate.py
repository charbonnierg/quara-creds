"""pync config gen command"""
import typing as t
from pathlib import Path

import typer
from jinja2 import Environment, FileSystemLoader

from quara.creds.cli.utils import get_manager
from quara.creds.nebula.api import create_encryption_keypair

TEMPLATE_ROOT = Path(__file__).parent / "data"
TEMPLATE_LOADER = FileSystemLoader(searchpath=TEMPLATE_ROOT)
TEMPLATE_ENV = Environment(loader=TEMPLATE_LOADER)


def generate_cmd(
    root: t.Optional[str] = typer.Option(
        None, "--root", "-r", help="Nebula root directory", envvar="PYNC_NEBULA_ROOT"
    ),
    config: t.Optional[str] = typer.Option(
        None,
        "--config",
        "-c",
        help="pync configuration file",
        envvar="PYNC_NEBULA_CONFIG",
    ),
    name: t.Optional[str] = typer.Option(
        None, "--name", "-n", help="Name of keypair to use in configuration"
    ),
    ca: t.Optional[str] = typer.Option(
        None, "--ca", help="Certificate authority to use"
    ),
) -> None:
    manager = get_manager(config, root)

    if ca:
        authorities = [ca]
    else:
        authorities = list(manager.authorities)
    name = name or manager.default_user
    try:
        keypair = manager.storage.get_keypair(name)
    except FileNotFoundError:
        keypair = create_encryption_keypair()
        manager.storage.save_keypair(name, keypair)
    # Merge authorities and certificates
    ca_crt = b""
    crt = b""
    for authority in authorities:
        authority_crt = manager.storage.get_signing_certificate(authority=authority)
        if not ca_crt:
            ca_crt = authority_crt.to_pem_data()
        else:
            ca_crt = b"\n".join([ca_crt, authority_crt.to_pem_data()])
        # Merge certificates
        try:
            certificate = manager.storage.get_certificate(
                authority=authority, name=name
            )
        except FileNotFoundError:
            typer.echo(
                f"No certificate issued by authority {authority} for user {name}"
            )
            raise typer.Exit(1)
        if certificate.get_public_key().to_public_bytes() != keypair.to_public_bytes():
            typer.echo(
                "Error: certificate public key does not match user public key.",
                err=True,
            )
            typer.echo(
                f"You can regenerate the certificate using `pync cert sign -n {name}` command.",
                err=True,
            )
            raise typer.Exit(1)
        if not crt:
            crt = certificate.to_pem_data()
        else:
            crt = b"\n".join([crt, certificate.to_pem_data()])

    options: t.Dict[str, t.Any] = {
        "lighthouses": manager.storage.get_lighthouses(authorities),
    }
    # Check wheter pki options should be inlined
    options["ca_cert"] = ca_crt.decode("utf8")
    options["cert"] = crt.decode("utf-8")
    options["key"] = keypair.to_private_pem_data().decode("utf-8")
    # Render config
    config = render_template(name="default", **options)
    typer.echo(config)
    # Exit successfully
    raise typer.Exit(0)


def render_template(
    name: str,
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
    template = TEMPLATE_ENV.get_template(name + ".yml.j2")
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
