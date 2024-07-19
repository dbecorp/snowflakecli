from cli.core.snowflake.sql import Sql
from cli.core.security.types import SecurityPlaybook, SecurityTask, SecurityReference


CIS_BENCHMARK_PLAYBOOK = SecurityPlaybook(
    name="CIS Benchmarks",
    description="CIS Snowflake Foundations Benchmarks",
    tasks=[
        SecurityTask(
            name="sso_configured_security_integrations",
            description="Federated authentication enables users to connect to Snowflake using secure SSO (single sign-on). With SSO enabled, users authenticate through an external (SAML 2.0- compliant or OAuth 2.0) identity provider (IdP). Once authenticated by an IdP, users can access their Snowflake account for the duration of their IdP session without having to authenticate to Snowflake again. Users can choose to initiate their sessions from within the interface provided by the IdP or directly in Snowflake.",
            control="CIS",
            control_id="1.1",
            queries=[
                Sql(statement="SHOW SECURITY INTEGRATIONS;"),
                Sql(
                    statement="""SELECT * FROM TABLE(RESULT_SCAN(LAST_QUERY_ID())) WHERE ("type" LIKE 'EXTERNAL_OAUTH%' OR "type" LIKE 'SAML2') AND "enabled" = TRUE;"""
                ),
            ],
            required_privileges="""Requires USAGE privilege on every security integration in your Snowflake account.""",
            results_expected=True,
            remediation="""The steps for configuring an IdP differ depending on whether you choose SAML2 or OAuth. They further differ depending on what identity provider you choose: Okta, AD FS, Ping Identity, Azure AD, or custom. For specific instructions, see Snowflake documentation on SAML and External OAuth. Note: If your SAML integration is configured using the deprecated account parameter SAML_IDENTITY_PROVIDER, you should migrate to creating a security integration using the system$migrate_saml_idp_registration function. For more information, see the Migrating to a SAML2 Security Integration documentation.""",
        ),
        SecurityTask(
            name="ensure_scim_integration",
            description="The System for Cross-domain Identity Management (SCIM) is an open specification designed to help facilitate the automated management of user identities and groups (i.e. roles) in cloud applications using RESTful APIs. Snowflake supports SCIM 2.0 integration with Okta, Microsoft Azure AD and custom identity providers. Users and groups from the identity provider can be provisioned into Snowflake, which functions as the service provider.",
            control="CIS",
            control_id="1.2",
            queries=[
                Sql(statement="SHOW SECURITY INTEGRATIONS;"),
                Sql(
                    statement="""SELECT * FROM TABLE(result_scan(last_query_id())) WHERE ("type" like 'SCIM%') AND "enabled" = true;"""
                ),
            ],
            required_privileges="""Requires USAGE privilege on every security integration in an account.""",
            results_expected=True,
        ),
        SecurityTask(
            name="ensure_snowflake_password_unset",
            description="Ensure that Snowflake password is unset for SSO users.",
            rationale="""Allowing users to sign in with Snowflake passwords in the presence of a configured third-party identity provider SSO may undermine mandatory security controls configured on the SSO and degrade the security posture of the account. For example, the SSO sign-in flow may be configured to require multi-factor authentication (MFA), whereas the Snowflake password sign-in flow may not.""",
            control="CIS",
            control_id="1.3",
            queries=[
                Sql(
                    statement="""SELECT NAME, CREATED_ON, HAS_PASSWORD, HAS_RSA_PUBLIC_KEY FROM SNOWFLAKE.ACCOUNT_USAGE.USERS WHERE HAS_PASSWORD AND DELETED_ON IS NULL AND NOT DISABLED AND NAME NOT LIKE 'SNOWFLAKE';"""
                )
            ],
            required_privileges="""Requires the SECURITY_VIEWER role on the Snowflake database.""",
            results_expected=False,
            references=[
                SecurityReference(
                    url="https://docs.snowflake.com/en/sql-reference/sql/create-user",
                    name="Snowflake documentation on CREATE USER",
                ),
                SecurityReference(
                    url="https://docs.snowflake.com/en/user-guide/scim-okta#features",
                    name="Snowflake documentation on Okta SCIM integration",
                ),
                SecurityReference(
                    url="https://docs.snowflake.com/en/user-guide/key-pair-auth",
                    name="Snowflake documentation on key pair authentication",
                ),
                SecurityReference(
                    url="https://community.snowflake.com/s/article/FAQ-User-and-Password-Management",
                    name="Snowflake documentation on user and password management",
                ),
            ],
        ),
    ],
)


UNC5537_BREACH_PLAYBOOK = SecurityPlaybook(
    name="UNC5537 Snowflake Breach",
    description="Playbook for the UNC5537 breach threat hunting",
    tasks=[
        SecurityTask(
            name="select_all_without_where",
            description="select * queries that don't contain a where predicate",
            queries=[
                Sql(
                    statement="""SELECT query_id, user_name, query_text FROM snowflake.account_usage.query_history WHERE query_text ILIKE '%SELECT *%' AND query_text NOT ILIKE '%WHERE%';"""
                )
            ],
        ),
        SecurityTask(
            name="copy_into_select_all",
            description="COPY INTO and select * in a single query.",
            queries=[
                Sql(
                    statement="""SELECT query_id, user_name, query_text FROM snowflake.account_usage.query_history WHERE query_text ILIKE '%COPY INTO%' AND query_text ILIKE '%SELECT *%' and query_text not ilike '%account_usage.query_history%';"""
                )
            ],
        ),
        SecurityTask(
            name="show_tables_executed",
            description="Instances of a SHOW TABLES query being executed",
            queries=[
                Sql(
                    statement="""SELECT query_id, start_time, user_name, query_text FROM snowflake.account_usage.query_history WHERE query_text ILIKE '%SHOW TABLES%' and query_text not ilike '%account_usage.query_history%'order by start_time desc;"""
                )
            ],
        ),
        SecurityTask(
            name="dbeaver_used",
            description="dbeaver usage",
            queries=[
                Sql(
                    statement="""SELECT created_on, user_name, authentication_method, PARSE_JSON(client_environment) :APPLICATION :: STRING AS client_application, PARSE_JSON(client_environment) :OS :: STRING AS client_os, PARSE_JSON(client_environment) :OS_VERSION :: STRING AS client_os_version, session_id FROM snowflake.account_usage.sessions, WHERE PARSE_JSON(CLIENT_ENVIRONMENT):APPLICATION ilike '%DBeaver_DBeaverUltimate%' ORDER BY CREATED_ON;"""
                )
            ],
        ),
        SecurityTask(
            name="create_temp_storage",
            description="Attackers often create a temp storage location as a staging location",
            queries=[
                Sql(
                    statement="""SELECT query_id, user_name, query_text FROM snowflake.account_usage.query_history WHERE query_text ilike '%create%temp%' and query_text not ilike '%account_usage.query_history%';"""
                )
            ],
        ),
        SecurityTask(
            name="10_largest_queries",
            description="Returns the 10 largest queries by rows produced. These queries should be reviewed.",
            queries=[
                Sql(
                    statement="""SELECT query_id, user_name, query_text, rows_produced FROM snowflake.account_usage.query_history WHERE rows_produced > 2000 ORDER BY rows_produced DESC LIMIT 10;"""
                )
            ],
        ),
        SecurityTask(
            name="grants_on_accountadmin_past_week",
            description="Grants to ACCOUNTADMIN (sudo) in the past week. These grants should be reviewed.",
            queries=[
                Sql(
                    statement="""select query_id, start_time, user_name || ' granted the ' || role_name || ' role on ' || end_time ||' [' || query_text ||']' as Grants from snowflake.account_usage.query_history where start_time >= current_timestamp() - interval '1 week' and execution_status = 'SUCCESS' and query_type = 'GRANT' and query_text ilike '%grant%accountadmin%to%' order by end_time desc;"""
                )
            ],
        ),
        SecurityTask(
            name="impactful_modifications_past_week",
            description="A list of all impactful modifications to the Snowflake account. These modifications should be reviewed for suspicious activity.",
            queries=[
                Sql(
                    statement="""SELECT start_time, user_name, role_name, query_type, query_text FROM snowflake.account_usage.query_history WHERE start_time >= current_timestamp() - interval '1 week' and execution_status = 'SUCCESS' AND query_type NOT in ('SELECT') AND query_type NOT in ('SHOW') AND query_type NOT in ('DESCRIBE') AND (query_text ILIKE '%create role%' OR query_text ILIKE '%manage grants%' OR query_text ILIKE '%create integration%' OR query_text ILIKE '%alter integration%' OR query_text ILIKE '%create share%' OR query_text ILIKE '%create account%' OR query_text ILIKE '%moni or usage%' OR query_text ILIKE '%ownership%' OR query_text ILIKE '%drop table%' OR query_text ILIKE '%drop database%' OR query_text ILIKE '%create stage%' OR query_text ILIKE '%drop stage%' OR query_text ILIKE '%alter stage%' OR query_text ILIKE '%create user%' OR query_text ILIKE '%alter user%' OR query_text ILIKE '%drop user%' OR query_text ILIKE '%create_network_policy%' OR query_text ILIKE '%alter_network_policy%' OR query_text ILIKE '%drop_network_policy%' OR query_text ILIKE '%copy%') and query_text not ilike '%account_usage.query_history%' ORDER BY end_time desc;"""
                )
            ],
        ),
        SecurityTask(
            name="copy_http",
            description="All instances of COPY INTO being run with an HTTP destination. Review for suspicious activity.",
            queries=[
                Sql(
                    statement="""SELECT *, FROM snowflake.account_usage.query_history where query_text ilike '%copy%into%http%' and query_text not ilike '%account_usage.query_history%';"""
                )
            ],
        ),
        SecurityTask(
            name="get_file_from_stage",
            description="",
            queries=[
                Sql(
                    statement="""select query_id, start_time, user_name, query_text from snowflake.account_usage.query_history where query_text ilike '%get%file%' and query_text not ilike '%account_usage.query_history%' and user_name not ilike '%worksheets_app_user%' and query_text not ilike '%worksheet_data/metadata%';"""
                )
            ],
        ),
        SecurityTask(
            name="least_common_applications_used_past_week",
            description="",
            queries=[
                Sql(
                    statement="""select count(*) as client_app_count, PARSE_JSON(client_environment) :APPLICATION :: STRING AS client_application, PARSE_JSON(client_environment) :OS :: STRING AS client_os, PARSE_JSON(client_environment) :OS_VERSION :: STRING AS client_os_version FROM snowflake.account_usage.sessions sessions WHERE created_on >= current_timestamp() - interval '1 week' group by all order by 1 asc limit 10;"""
                )
            ],
        ),
        SecurityTask(
            name="brute_force_on_user_past_month",
            description="Identify instances of mass failed login attempts",
            control="MITRE ATT&CK",
            control_id="T1110",
            queries=[
                Sql(
                    statement="""select CLIENT_IP, USER_NAME, REPORTED_CLIENT_TYPE, count(*) as FAILED_ATTEMPTS, min(EVENT_TIMESTAMP) as FIRST_EVENT, max(EVENT_TIMESTAMP) as LAST_EVENT from SNOWFLAKE.ACCOUNT_USAGE.LOGIN_HISTORY where IS_SUCCESS = 'NO' and ERROR_MESSAGE in ('INCORRECT_USERNAME_PASSWORD', 'USER_LOCKED_TEMP') and FIRST_AUTHENTICATION_FACTOR='PASSWORD' and EVENT_TIMESTAMP >= DATEADD(MONTH, -1, CURRENT_TIMESTAMP()) group by 1,2,3 having FAILED_ATTEMPTS >= 5 order by 4 desc;"""
                )
            ],
            remediation="""For each result check if the source IP successfully logged in as the target user after the lastEvent time""",
        ),
        SecurityTask(
            name="failed_login_on_disabled_user",
            description="Identify user logins that have failed due to the user being disabled",
            control="MITRE ATT&CK",
            control_id="T1110",
            queries=[
                Sql(
                    statement="""select * from SNOWFLAKE.ACCOUNT_USAGE.LOGIN_HISTORY where IS_SUCCESS = 'NO' and  ERROR_MESSAGE  = 'USER_ACCESS_DISABLED'"""
                )
            ],
        ),
        SecurityTask(
            name="login_attempt_blocked_by_network_policy",
            description="Identify user logins that have failed due to the user being blocked by the network ip policy",
            queries=[
                Sql(
                    statement="""select * from SNOWFLAKE.ACCOUNT_USAGE.LOGIN_HISTORY where IS_SUCCESS = 'NO' and  ERROR_MESSAGE  = 'INCOMING_IP_BLOCKED' and EVENT_TIMESTAMP >= DATEADD(HOUR, -24, CURRENT_TIMESTAMP());"""
                )
            ],
        ),
        SecurityTask(
            name="recently_created_shares_past_month",
            description="Identify instances of newly-created shares in the past month",
            control="MITRE ATT&CK",
            control_id="T1537",
            queries=[
                Sql(
                    statement="""select query_id, start_time, user_name, query_text from SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY where (QUERY_TEXT ilike '%create%share%' and QUERY_TEXT NOT ILIKE '%account_usage%') and START_TIME>= DATEADD(HOUR, -24, CURRENT_TIMESTAMP());"""
                )
            ],
        ),
        SecurityTask(
            name="stages_created_past_24_hours",
            description="Identify all stages created in the last 24 hours",
            control="MITRE ATT&CK",
            control_id="T1537",
            queries=[
                Sql(
                    statement="""select * from SNOWFLAKE.ACCOUNT_USAGE.STAGES where CREATED>= DATEADD(HOUR, -24, CURRENT_TIMESTAMP());"""
                )
            ],
        ),
        SecurityTask(
            name="tasks_created_past_24_hours",
            description="Identify all tasks created in the last 24 hours",
            queries=[
                Sql(
                    statement="""select * from SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY where QUERY_TEXT ilike '%create%task%' and QUERY_TEXT not ilike '%SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY%' and START_TIME >= DATEADD(HOUR, -24, CURRENT_TIMESTAMP());"""
                )
            ],
        ),
        SecurityTask(
            name="procedures_created_past_24_hours",
            description="Identify all stored procedures created in the last 24 hours",
            queries=[
                Sql(
                    statement="""select * from SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY where QUERY_TEXT ilike '%create%procedure%' and QUERY_TEXT not ilike '%SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY%' and START_TIME >= DATEADD(HOUR, -24, CURRENT_TIMESTAMP());"""
                )
            ],
        ),
        SecurityTask(
            name="login_failure_statistics",
            description="Summarize login failure statistics by user",
            queries=[
                Sql(
                    statement="""WITH error_stats AS (SELECT START_TIME::date as date, USER_NAME, COUNT(*) AS error_count FROM SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY WHERE error_code != 'NULL' GROUP BY date, USER_NAME), total_queries AS (SELECT START_TIME::date as date, USER_NAME, COUNT(*) AS total_queries FROM SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY GROUP BY date, USER_NAME), final_stats AS (SELECT tq.date, tq.USER_NAME, tq.total_queries,  COALESCE(es.error_count, 0) AS error_count, (COALESCE(es.error_count, 0) / tq.total_queries) * 100 AS daily_error_percentage FROM total_queries tq LEFT JOIN error_stats es ON tq.date = es.date AND tq.USER_NAME = es.USER_NAME) SELECT * FROM final_stats order by date desc, user_name;"""
                )
            ],
        ),
    ],
)
