"""pync cert show command"""
import typing as t

import typer
from rich.console import Console
from rich.table import Table

from quara.creds.cli.utils import get_manager

console = Console()


def show_cmd(
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
    authorities: t.Optional[str] = typer.Option(
        None, "--ca", help="Name of CA used to sign the certificate"
    ),
    name: t.Optional[str] = typer.Option(None, "--name", "-n", help="Certificate name"),
    pem: bool = typer.Option(
        False,
        "--pem",
        help="Display certificate in PEM format",
    ),
) -> None:
    """Describe a nebula node certificate.

    When --raw option is provided, the raw certificate bytes are printed.

    When --json option is provided, the certificate is printed in PEM format.
    """
    manager = get_manager(config, root)
    name = name or manager.default_user
    certificates = manager.certificates.list_by_names(
        authorities=authorities, names=name
    )
    found = False
    for certs in certificates.values():
        for authority, cert in certs:
            found = True
            if pem:
                typer.echo(cert.to_pem_data().decode("utf-8"))
                continue
            else:
                table = Table(title=f"Nebula node certificate (authority={authority})")
                table.add_column("Field")
                table.add_column("Value")
                for key, value in cert.to_dict().items():
                    if key == "IsCA":
                        continue
                    elif key == "Signature":
                        continue
                    elif key == "NotAfter":
                        key = "Expiration"
                        value = cert.get_expiration_timestamp().isoformat()
                    elif key == "NotBefore":
                        key = "Activation"
                        value = cert.get_activation_timestamp().isoformat()
                    table.add_row(key, str(value))
                table.add_section()
                table.add_row("Signature", cert.Signature.hex())
                console.print(table)
    if not found:
        typer.echo(f"Certificate not found: {name}", err=True)
        raise typer.Exit(1)

    raise typer.Exit(0)
