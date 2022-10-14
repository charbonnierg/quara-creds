import typer

from .commands import env_cmd, init_cmd, run_cmd, version
from .subcommands import authorities_app, ca_app, cert_app, config_app, csr_app, key_app

app = typer.Typer(
    name="nebula",
    add_completion=False,
    no_args_is_help=True,
    help="Manage nebula certificates, keys and CA certificates",
)


@app.callback()
def common(
    ctx: typer.Context,
    version: bool = typer.Option(
        None, "--version", "-v", callback=version.version_callback, is_eager=True
    ),
):
    return None


app.add_typer(authorities_app)
app.add_typer(cert_app)
app.add_typer(ca_app)
app.add_typer(config_app)
app.add_typer(csr_app)
app.add_typer(key_app)

app.command("env")(env_cmd)
app.command("init")(init_cmd)
app.command("nebula")(run_cmd)
