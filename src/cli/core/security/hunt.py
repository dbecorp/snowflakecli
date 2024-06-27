from dataclasses import dataclass

from rich import print

from cli.core.snowflake.sql import Sql
from cli.core.logging import logger
from cli.core.snowflake.query import query_all, tabulate_to_stdout
from cli.core.security.hunt_definitions.snowflake_unc5537_breach import (
    UNC5537_BREACH_DEFINITION,
)


@dataclass
class HuntingQuery:
    name: str
    description: str
    query: Sql
    severity: int
    mitre_id: str = None


@dataclass
class HuntingDefinition:
    name: str
    hunting_queries: list[HuntingQuery]


def run_threat_hunt(definition: HuntingDefinition = UNC5537_BREACH_DEFINITION):
    """Run a threat hunt and output the results to a terminal or file"""
    msg = f"Running threat hunt {definition.name}"
    print(msg)
    logger.debug(msg)
    for query in definition.hunting_queries:
        msg = f"Running threat hunt query {query.name}"
        print(msg)
        log.debug(msg)
        results = query_all(query.query)
        tabulate_to_stdout(results)
