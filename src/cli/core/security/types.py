from dataclasses import dataclass
from functools import cached_property

from cli.core.snowflake.sql import Sql


@dataclass
class SecurityQuery:
    name: str
    description: str
    query: Sql


@dataclass
class AuditQuery(SecurityQuery):
    control: str
    severity: int = None


@dataclass
class AuditDefinition:
    name: str
    audit_queries: list[AuditQuery]


@dataclass
class HuntQuery(SecurityQuery):
    severity: int = None
    mitre_id: str = None
    followup: str = None


@dataclass
class HuntDefinition:
    name: str
    hunting_queries: list[HuntQuery]

    @cached_property
    def named_queries(self) -> dict[str, HuntQuery]:
        return {query.name: query for query in self.hunting_queries}

    def get_query(self, name: str) -> HuntQuery:
        return self.named_queries[name]


@dataclass
class HuntResult:

    query: HuntQuery
    results: list[dict]
