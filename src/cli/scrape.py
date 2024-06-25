import typer


app = typer.Typer(no_args_is_help=True)


@app.command()
def all():
    """Generate vector embeddings from Snowflake metadata, statistics, and schemata"""
    return


@app.command()
def statistics():
    """Generate vector embeddings from Snowflake statistics"""
    return


@app.command()
def metadata():
    """Generate vector embeddings from Snowflake metadata"""
    return


@app.command()
def schemata():
    """Generate vector embeddings from Snowflake schemata"""
    return
