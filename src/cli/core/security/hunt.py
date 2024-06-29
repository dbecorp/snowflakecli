from rich import print

from cli.core.security.types import HuntDefinition
from cli.core.logging import logger
from cli.core.snowflake.connection import SnowflakeCursor
from cli.core.snowflake.query import query_all, tabulate_to_stdout
from cli.core.security.hunt_definitions.snowflake_unc5537_breach import (
    UNC5537_BREACH_DEFINITION,
)


def run_threat_hunt(
    cursor: SnowflakeCursor,
    definition: HuntDefinition = UNC5537_BREACH_DEFINITION,
    query_name: str = None,
):
    """Run a threat hunt and output the results to a terminal or file"""
    msg = f"Hunting with definition: {definition.name}"
    print("#" * 80)
    print(msg)
    print("#" * 80)
    logger.debug(msg)
    if query_name:
        query = definition.get_query(query_name)
        msg = f"Running query: {query.name}"
        print(
            f"[NAME] {query.name}" + f"\n[DESCRIPTION] {query.description}"
            f"\n[SEVERITY] {query.severity}"
        )
        logger.debug(msg)
        results = query_all(cursor, query.query)
        tabulate_to_stdout(results)
        print("\n\n")
        return
    for query in definition.hunting_queries:
        msg = f"Running query: {query.name}"
        print(
            f"[NAME] {query.name}" + f"\n[DESCRIPTION] {query.description}"
            f"\n[SEVERITY] {query.severity}"
        )
        logger.debug(msg)
        results = query_all(cursor, query.query)
        tabulate_to_stdout(results)
        print("\n\n")
