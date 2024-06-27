from dataclasses import dataclass

from cli.core.snowflake.sql import Sql


@dataclass
class HuntingQuery:
    name: str
    description: str
    query: Sql
    severity: int = None
    mitre_id: str = None


@dataclass
class HuntingDefinition:
    name: str
    hunting_queries: list[HuntingQuery]
