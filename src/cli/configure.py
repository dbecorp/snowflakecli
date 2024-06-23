import typer

from core.config import ensure_config_file

app = typer.Typer()


@app.command()
def cli():
    """Configure Snowflake CLI"""
    ensure_config_file()
    return
