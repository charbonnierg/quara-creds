"""pync nebula key show CLI command"""
import subprocess
import typing as t

import typer

from quara.creds.cli.utils import get_manager
from quara.creds.nebula import EncryptionKeyPair


def scp_cmd(
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
    host: str = typer.Argument(..., help="Host where key should be copied"),
    local_name: str = typer.Option(..., "--name", "-n", help="Name of key to show"),
    remote_name: t.Optional[str] = typer.Option(
        None, "--remote-name", help="Name used to store key on remote system"
    ),
    check: bool = typer.Option(
        False, "--check", help="Check if remote host alreay have this key"
    ),
) -> None:
    """Copy a key to a remote host using scp (SSH)"""
    manager = get_manager(config, root)

    remote_name = remote_name or local_name
    keyfile, keypair = manager.storage.get_keypair(local_name)
    # Check key on remote host
    if check:
        check_cmd = [
            "ssh",
            host,
            "cat",
            f"~/.nebula/keys/{remote_name}.key",
        ]
        try:
            output = subprocess.check_output(check_cmd)
        except subprocess.CalledProcessError:
            typer.echo("Key does not exist on host")
            raise typer.Exit(1)
        remote_keypair = EncryptionKeyPair.from_bytes(output)
        if remote_keypair != keypair:
            typer.echo("Local and remote keys do not match")
            raise typer.Exit(1)
        # Simply exit if key is identital
        raise typer.Exit(0)
    mkdir_cmd = [
        "ssh",
        host,
        "mkdir",
        "-p",
        "~/.nebula/keys",
    ]
    try:
        subprocess.check_call(mkdir_cmd)
    except subprocess.CalledProcessError:
        typer.echo("Failed create keystore directory on remote host", error=True)
        raise typer.Exit(1)
    copy_cmd = ["scp", keyfile.as_posix(), f"{host}:~/.nebula/keys/{remote_name}.key"]
    try:
        subprocess.check_call(copy_cmd)
    except subprocess.CalledProcessError:
        typer.echo("Failed to copy key", err=True)
        raise typer.Exit(1)
    raise typer.Exit(0)
