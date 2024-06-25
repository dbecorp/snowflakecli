import typer
from rich import print

app = typer.Typer(no_args_is_help=True)


@app.command()
def test(ctx: typer.Context):
    """Test SnowflakeCLI connection to your Snowflake account"""
    print("Running connection test")
    cursor = ctx.obj.cursor
    result = cursor.execute("select true as connected").fetchone()
    print("[green]SnowflakeCLI connection test successful[/green]")
    return True


@app.command()
def add():
    """Add a named Snowflakecli connection"""
    raise NotImplementedError
    return
