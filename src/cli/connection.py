import typer


app = typer.Typer(no_args_is_help=True)


@app.command()
def test(ctx: typer.Context):
    """Test SnowflakeCLI connection to your Snowflake account"""
    print("Running connection test")
    cursor = ctx.obj.cursor
    result = cursor.execute("select true as connected").fetchone()
    if not result["CONNECTED"]:
        print("Connection failed")
        return False
    print("Connection succeeded")
    return True


@app.command()
def add():
    """Add a named Snowflakecli connection"""
    raise NotImplementedError
    return
