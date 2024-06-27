from dataclasses import dataclass
from cli.core.snowflake.sql import Sql


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


UNC5537_BREACH_DEFINITION = HuntingDefinition(
    name="unc-5537",
    hunting_queries=[
        HuntingQuery(
            name="select_all_without_where",
            description="select * queries that don't contain a where predicate",
            query=Sql(
                statement="""SELECT query_id, user_name, query_text FROM snowflake.account_usage.query_history WHERE query_text ILIKE 'SELECT *' AND query_text NOT ILIKE '%WHERE%';"""
            ),
        ),
        HuntingQuery(
            name="copy_into_select_all",
            description="COPY INTO and select * in a single query.",
            query=Sql(
                statement="""SELECT query_id, user_name, query_text FROM snowflake.account_usage.query_history WHERE query_text ILIKE 'COPY INTO%' AND query_text ILIKE 'SELECT *%';"""
            ),
        ),
    ],
)


def run_threat_hunt(definition: HuntingDefinition = UNC5537_BREACH_DEFINITION):
    """Run a threat hunt and output the results to a terminal or file"""
    pass
