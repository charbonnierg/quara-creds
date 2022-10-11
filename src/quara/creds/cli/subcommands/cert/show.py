"""pync cert show command"""
import typing as t
from json import dumps

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
    authority: t.Optional[str] = typer.Option(
        None, "--ca", help="Name of CA used to sign the certificate"
    ),
    name: t.Optional[str] = typer.Option(None, "--name", "-n", help="Certificate name"),
    pem: bool = typer.Option(
        False,
        "--pem",
        help="Display certificate in PEM format",
    ),
    raw: bool = typer.Option(False, "--raw", help="Display raw certificate"),
    json: bool = typer.Option(False, "--json", help="Display JSON certificate"),
) -> None:
    """Describe a nebula node certificate.

    When --raw option is provided, the raw certificate bytes are printed.

    When --json option is provided, the certificate is printed in PEM format.
    """
    manager = get_manager(config, root)

    if authority is None:
        authorities = list(manager.authorities)
    else:
        authorities = [authority]
    name = name or manager.default_user
    found = False
    json_result: t.List[t.Dict[str, t.Any]] = []
    for authority in authorities:
        try:
            cert = manager.storage.get_certificate(authority=authority, name=name)
        except FileNotFoundError:
            continue
        else:
            found = True
        if pem:
            typer.echo(cert.to_pem_data().decode("utf-8"))
            continue
        elif raw:
            typer.echo(cert.to_bytes().hex())
            continue
        elif json:
            json_result.append(cert.to_dict())
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
    if json_result:
        console.print(dumps(json_result, indent=2))
    if not found:
        typer.echo(f"Certificate not found: {name}", err=True)
        raise typer.Exit(1)

    raise typer.Exit(0)
