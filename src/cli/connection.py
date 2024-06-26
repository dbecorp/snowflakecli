import typer
from rich import print

from cli.core.logging import logger

app = typer.Typer(no_args_is_help=True)


@app.command()
def test(ctx: typer.Context):
    """Test SnowflakeCLI connection to your Snowflake account"""
    print("⚠️  Running connection test ⚠️")
    try:
        cursor = ctx.obj.cursor
        if not cursor:
            logger.debug("no connection established, failing test")
            print("❌ SnowflakeCLI connection test failed ❌")
            return False
        else:
            result = cursor.execute("select true as connected").fetchone()
            print("✨✨ SnowflakeCLI connection test successful ✨✨")
            return True
    except Exception as e:
        logger.debug(e)
        print("❌ SnowflakeCLI connection test failed ❌")
        return False


@app.command()
def add():
    """Add a named Snowflakecli connection"""
    raise NotImplementedError
    return
