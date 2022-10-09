"""pync nebula key show CLI command"""
import typing as t

import typer

from quara.creds.cli.utils import get_manager


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
    name: str = typer.Option(None, "--name", "-n", help="Name of key to show"),
    raw: bool = typer.Option(
        None, "--raw", help="Show raw public bytes instead of PEM encoded key"
    ),
    private: bool = typer.Option(
        False, "--private", help="Show private key instead of public key"
    ),
) -> None:
    """Show a single key"""
    manager = get_manager(config, root)

    name = name or manager.default_user
    try:
        keypair = manager.storage.get_keypair(name)
    except FileNotFoundError:
        typer.echo(f"No private key found for user: {name or manager.default_user}")
        raise typer.Exit(1)
    if raw:
        if not private:
            typer.echo(keypair.get_public_bytes().hex())
        else:
            typer.echo(keypair.get_private_bytes().hex())
    else:
        if not private:
            typer.echo(keypair.to_public_pem_data().decode("utf-8"))
        else:
            typer.echo(keypair.to_private_pem_data().decode("utf-8"))
    raise typer.Exit(0)
