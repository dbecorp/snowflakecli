from cli.core.security.types import AuditDefinition
from cli.core.logging import logger
from cli.core.snowflake.connection import SnowflakeCursor
from cli.core.snowflake.query import query_all, tabulate_to_stdout


# TODO -> add an audit definition parser so this can be pointed at a json file


def run_audit(
    cursor: SnowflakeCursor, definition: AuditDefinition, audit_name: str = None
):
    """Run a security audit and output the results to stdout or a file."""
    for query in definition.audit_queries:
        msg = f"Running audit query: {query.name}"
        logger.debug(msg)
        results = query_all(cursor, query.query)
        tabulate_to_stdout(results)
        print("\n\n")
    pass
