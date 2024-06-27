from rich import print

from cli.core.security.types import HuntingDefinition
from cli.core.logging import logger
from cli.core.snowflake.connection import SnowflakeCursor
from cli.core.snowflake.query import query_all, tabulate_to_stdout
from cli.core.security.hunt_definitions.snowflake_unc5537_breach import (
    UNC5537_BREACH_DEFINITION,
)


def run_threat_hunt(
    cursor: SnowflakeCursor, definition: HuntingDefinition = UNC5537_BREACH_DEFINITION
):
    """Run a threat hunt and output the results to a terminal or file"""
    msg = f"Running threat hunt {definition.name}"
    print(msg)
    logger.debug(msg)
    for query in definition.hunting_queries:
        msg = f"Running threat hunt query {query.name}"
        print(msg)
        logger.debug(msg)
        results = query_all(cursor, query.query)
        tabulate_to_stdout(results)
