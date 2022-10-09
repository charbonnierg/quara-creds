import typer

from .list import list_cmd
from .show import show_cmd
from .sign import sign_cmd
from .verify import verify_cmd

app = typer.Typer(
    name="cert",
    no_args_is_help=True,
    add_completion=False,
    help="Manager nebula certificates",
)


app.command("sign")(sign_cmd)
app.command("show")(show_cmd)
app.command("list")(list_cmd)
app.command("verify")(verify_cmd)
