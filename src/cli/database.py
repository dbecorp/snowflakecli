import typer

app = typer.Typer(no_args_is_help=True)


@app.command()
def list():
    """List all Snowflake databases"""
    return


@app.command()
def create():
    """Create a Snowflake database"""
    return


@app.command()
def delete(name: str):
    """Delete a Snowflake database"""
    return


@app.command()
def stats(database: str):
    """Get statistics about a Snowflake database"""
    return
