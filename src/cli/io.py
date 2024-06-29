import typer

app = typer.Typer(no_args_is_help=True)


@app.command(name="import")
def bulk_import():
    """Quickly import data to Snowflake from a local path or object storage"""
    return


@app.command(name="export")
def bulk_export():
    """Export data from Snowflake to a local path or object storage"""
    return
