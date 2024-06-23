import typer

app = typer.Typer()


@app.command()
def optimizations():
    """Recommend optimizations for your Snowflake account, such as using DuckDB or DataFusion instead of Snowflake"""
    return


@app.command()
def resizing():
    """Recommend resizing operations for your Snowflake resources"""
    return
