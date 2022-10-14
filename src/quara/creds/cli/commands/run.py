import shutil
import subprocess
import typing as t
from pathlib import Path
from tempfile import TemporaryDirectory

import typer

from quara.creds.cli.utils import get_manager


def run_cmd(
    root: t.Optional[str] = typer.Option(
        None, "--root", "-r", help="pync root directory", envvar="PYNC_NEBULA_ROOT"
    ),
    config: t.Optional[str] = typer.Option(
        None,
        "--config",
        help="pync configuration file",
        envvar="PYNC_NEBULA_CONFIG",
    ),
    authorities: str = typer.Option(
        None,
        "--ca",
        help="Name of authority used to sign the certificate. By default all authorities are used.",
    ),
    name: t.Optional[str] = typer.Option(
        None,
        "--name",
        "-n",
        help="Name of certificate",
    ),
    elevate: bool = False,
) -> None:
    manager = get_manager(config=config, root=root)
    nebula = shutil.which("nebula")
    if nebula is None:
        # TODO: Bootstrap nebula
        typer.echo(
            "Nebula does not seem to be installed. Please make sure nebula is installed and available from PATH environment variable.",
            err=True,
        )
        raise typer.Exit(1)

    with TemporaryDirectory() as tmpdir:
        tmppath = Path(tmpdir)
        config_path = tmppath / "config.yml"
        config_path.write_text(
            manager.nebula_config.gen(authorities=authorities, name=name)
        )
        cmd = [nebula, "-config", config_path.as_posix()]
        if elevate:
            cmd = ["sudo"] + cmd
        try:
            subprocess.run(cmd)
        except KeyboardInterrupt:
            typer.echo("Stopped nebula daemon. Bye bye...")
