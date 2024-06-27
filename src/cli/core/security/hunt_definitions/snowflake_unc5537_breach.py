from cli.core.security.hunt import HuntingDefinition, HuntingQuery


UNC5537_BREACH_DEFINITION = HuntingDefinition(
    name="UNC5537 Snowflake Breach",
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
        HuntingQuery(
            name="show_tables_executed",
            description="Instances of a SHOW TABLES query being executed",
            query=Sql(
                statement="""SELECT query_id, user_name, query_text FROM snowflake.account_usage.query_history WHERE query_text ILIKE '%SHOW TABLES%';"""
            ),
        ),
        HuntingQuery(
            name="dbeaver_used",
            description="dbeaver usage",
            query=Sql(
                statement="""SELECT created_on, user_name, authentication_method, PARSE_JSON(client_environment) :APPLICATION :: STRING AS client_application, PARSE_JSON(client_environment) :OS :: STRING AS client_os, PARSE_JSON(client_environment) :OS_VERSION :: STRING AS client_os_version, session_id FROM snowflake.account_usage.sessions, WHERE PARSE_JSON(CLIENT_ENVIRONMENT):APPLICATION ilike '%DBeaver_DBeaverUltimate%' ORDER BY CREATED_ON;"""
            ),
        ),
        # HuntingQuery(name="", description="", query=Sql(statement="""""")),
        # HuntingQuery(name="", description="", query=Sql(statement="""""")),
        # HuntingQuery(name="", description="", query=Sql(statement="""""")),
        # HuntingQuery(name="", description="", query=Sql(statement="""""")),
        # HuntingQuery(name="", description="", query=Sql(statement="""""")),
        # HuntingQuery(name="", description="", query=Sql(statement="""""")),
        # HuntingQuery(name="", description="", query=Sql(statement="""""")),
        # HuntingQuery(name="", description="", query=Sql(statement="""""")),
        # HuntingQuery(name="", description="", query=Sql(statement="""""")),
        # HuntingQuery(name="", description="", query=Sql(statement="""""")),
        # HuntingQuery(name="", description="", query=Sql(statement="""""")),
        # HuntingQuery(name="", description="", query=Sql(statement="""""")),
        # HuntingQuery(name="", description="", query=Sql(statement="""""")),
    ],
)
