import typer

from core.config import ensure_config_file

app = typer.Typer(no_args_is_help=True)


@app.command()
def test():
    """Test SnowflakeCLI connection to your Snowflake account"""
    print("Running connection test")
    return


@app.command()
def add():
    """Add a named Snowflakecli connection"""
    print("Adding a named Snowflakecli connection")
    return
