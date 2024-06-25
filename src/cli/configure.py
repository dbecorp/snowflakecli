import typer

from core.config.sfcli import ensure_config_file

app = typer.Typer(no_args_is_help=True)


@app.command()
def cli():
    """Configure SnowflakeCLI"""
    ensure_config_file()
    return
