from cli.core.security.types import HuntDefinition, HuntQuery
from cli.core.snowflake.sql import Sql


UNC5537_BREACH_DEFINITION = HuntDefinition(
    name="UNC5537 Snowflake Breach",
    hunting_queries=[
        HuntQuery(
            name="select_all_without_where",
            description="select * queries that don't contain a where predicate",
            query=Sql(
                statement="""SELECT query_id, user_name, query_text FROM snowflake.account_usage.query_history WHERE query_text ILIKE 'SELECT *' AND query_text NOT ILIKE '%WHERE%';"""
            ),
        ),
        HuntQuery(
            name="copy_into_select_all",
            description="COPY INTO and select * in a single query.",
            query=Sql(
                statement="""SELECT query_id, user_name, query_text FROM snowflake.account_usage.query_history WHERE query_text ILIKE 'COPY INTO%' AND query_text ILIKE 'SELECT *%';"""
            ),
        ),
        HuntQuery(
            name="show_tables_executed",
            description="Instances of a SHOW TABLES query being executed",
            query=Sql(
                statement="""SELECT query_id, start_time, user_name, query_text FROM snowflake.account_usage.query_history WHERE query_text ILIKE '%SHOW TABLES%' order by start_time desc;"""
            ),
        ),
        HuntQuery(
            name="dbeaver_used",
            description="dbeaver usage",
            query=Sql(
                statement="""SELECT created_on, user_name, authentication_method, PARSE_JSON(client_environment) :APPLICATION :: STRING AS client_application, PARSE_JSON(client_environment) :OS :: STRING AS client_os, PARSE_JSON(client_environment) :OS_VERSION :: STRING AS client_os_version, session_id FROM snowflake.account_usage.sessions, WHERE PARSE_JSON(CLIENT_ENVIRONMENT):APPLICATION ilike '%DBeaver_DBeaverUltimate%' ORDER BY CREATED_ON;"""
            ),
        ),
        HuntQuery(
            name="brute_force_on_user_past_month",
            description="Identify instances of mass failed login attempts",
            mitre_id="T1110",
            query=Sql(
                statement="""select CLIENT_IP, USER_NAME, REPORTED_CLIENT_TYPE, count(*) as FAILED_ATTEMPTS, min(EVENT_TIMESTAMP) as FIRST_EVENT, max(EVENT_TIMESTAMP) as LAST_EVENT from SNOWFLAKE.ACCOUNT_USAGE.LOGIN_HISTORY where IS_SUCCESS = 'NO' and ERROR_MESSAGE in ('INCORRECT_USERNAME_PASSWORD', 'USER_LOCKED_TEMP') and FIRST_AUTHENTICATION_FACTOR='PASSWORD' and EVENT_TIMESTAMP >= DATEADD(MONTH, -1, CURRENT_TIMESTAMP()) group by 1,2,3 having FAILED_ATTEMPTS >= 5 order by 4 desc;"""
            ),
            followup="""For each result check if the source IP successfully logged in as the target user after the lastEvent time""",
        ),
        HuntQuery(
            name="failed_login_on_disabled_user",
            description="Identify user logins that have failed due to the user being disabled",
            mitre_id="T1110",
            query=Sql(
                statement="""select * from SNOWFLAKE.ACCOUNT_USAGE.LOGIN_HISTORY where IS_SUCCESS = 'NO' and  ERROR_MESSAGE  = 'USER_ACCESS_DISABLED'"""
            ),
        ),
        HuntQuery(
            name="login_attempt_blocked_by_network_policy",
            description="Identify user logins that have failed due to the user being blocked by the network ip policy",
            query=Sql(
                statement="""select * from SNOWFLAKE.ACCOUNT_USAGE.LOGIN_HISTORY where IS_SUCCESS = 'NO' and  ERROR_MESSAGE  = 'INCOMING_IP_BLOCKED' and EVENT_TIMESTAMP >= DATEADD(HOUR, -24, CURRENT_TIMESTAMP());"""
            ),
        ),
        HuntQuery(
            name="recently_created_shares_past_month",
            description="Identify instances of newly-created shares in the past month",
            mitre_id="T1537",
            query=Sql(
                statement="""select query_id, start_time, user_name, query_text from SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY where (QUERY_TEXT ilike '%create%share%' and QUERY_TEXT NOT ILIKE '%account_usage%') and START_TIME>= DATEADD(HOUR, -24, CURRENT_TIMESTAMP());"""
            ),
        ),
        HuntQuery(
            name="stages_created_past_24_hours",
            description="Identify all stages created in the last 24 hours",
            mitre_id="T1537",
            query=Sql(
                statement="""select * from SNOWFLAKE.ACCOUNT_USAGE.STAGES where CREATED>= DATEADD(HOUR, -24, CURRENT_TIMESTAMP());"""
            ),
        ),
        HuntQuery(
            name="tasks_created_past_24_hours",
            description="Identify all tasks created in the last 24 hours",
            query=Sql(
                statement="""select * from SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY where QUERY_TEXT ilike '%create%task%' and QUERY_TEXT not ilike '%SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY%' and START_TIME >= DATEADD(HOUR, -24, CURRENT_TIMESTAMP());"""
            ),
        ),
        HuntQuery(
            name="procedures_created_past_24_hours",
            description="Identify all stored procedures created in the last 24 hours",
            query=Sql(
                statement="""select * from SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY where QUERY_TEXT ilike '%create%procedure%' and QUERY_TEXT not ilike '%SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY%' and START_TIME >= DATEADD(HOUR, -24, CURRENT_TIMESTAMP());"""
            ),
        ),
        HuntQuery(
            name="login_failure_statistics",
            description="Summarize login failure statistics by user",
            query=Sql(
                statement="""WITH error_stats AS (SELECT START_TIME::date as date, USER_NAME, COUNT(*) AS error_count FROM SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY WHERE error_code != 'NULL' GROUP BY date, USER_NAME), total_queries AS (SELECT START_TIME::date as date, USER_NAME, COUNT(*) AS total_queries FROM SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY GROUP BY date, USER_NAME), final_stats AS (SELECT tq.date, tq.USER_NAME, tq.total_queries,  COALESCE(es.error_count, 0) AS error_count, (COALESCE(es.error_count, 0) / tq.total_queries) * 100 AS daily_error_percentage FROM total_queries tq LEFT JOIN error_stats es ON tq.date = es.date AND tq.USER_NAME = es.USER_NAME) SELECT * FROM final_stats order by date desc, user_name;"""
            ),
        ),
        # HuntQuery(name="", description="", query=Sql(statement="""""")),
        # HuntQuery(name="", description="", query=Sql(statement="""""")),
        # HuntQuery(name="", description="", query=Sql(statement="""""")),
        # HuntQuery(name="", description="", query=Sql(statement="""""")),
        # HuntQuery(name="", description="", query=Sql(statement="""""")),
        # HuntQuery(name="", description="", query=Sql(statement="""""")),
    ],
)
