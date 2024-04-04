import typer

app = typer.Typer()


@app.command()
def all():
    """Scrape all metadata, statistics, and schemata from Snowflake"""
    return


@app.command()
def statistics():
    """Scrape just statistics from Snowflake"""
    return


@app.command()
def metadata():
    """Scrape just metadata from Snowflake"""
    return


@app.command()
def schemata():
    """Scrape just schemata from Snowflake"""
    return
