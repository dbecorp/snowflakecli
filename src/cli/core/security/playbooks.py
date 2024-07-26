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
        SecurityTask(
            name="ensure_mfa_enabled_for_password_users",
            description="Multi-factor authentication (MFA) is a security control used to add an additional layer of login security. It works by requiring the user to present two or more proofs (factors) of user identity. An MFA example would be requiring a password and a verification code delivered to the user's phone during user sign-in.",
            control="CIS",
            control_id="1.4",
            queries=[
                Sql(
                    statement="SELECT NAME, EXT_AUTHN_DUO AS MFA_ENABLED FROM SNOWFLAKE.ACCOUNT_USAGE.USERS WHERE DELETED_ON IS NULL AND NOT DISABLED AND HAS_PASSWORD;"
                ),
            ],
            required_privileges="""Requires the SECURITY_VIEWER role on the Snowflake database.""",
            results_expected=True,
            remediation="",
            references=[
                SecurityReference(
                    url="https://docs.snowflake.com/en/user-guide/ui-snowsight-profile#enrolling-in-mfa-multi-factor-authentication",
                    name="Snowflake documentation for enrolling in multi-factor authentication",
                )
            ],
        ),
        SecurityTask(
            name="ensure_minimum_password_length_policy",
            description="Multi-factor authentication (MFA) is a security control used to add an additional layer of login security. It works by requiring the user to present two or more proofs (factors) of user identity. An MFA example would be requiring a password and a verification code delivered to the user's phone during user sign-in.",
            control="CIS",
            control_id="1.5",
            queries=[
                Sql(
                    statement="WITH PWDS_WITH_MIN_LEN AS (SELECT ID FROM SNOWFLAKE.ACCOUNT_USAGE.PASSWORD_POLICIES WHERE PASSWORD_MIN_LENGTH >= 14 AND DELETED IS NULL)SELECT A.* FROM SNOWFLAKE.ACCOUNT_USAGE.POLICY_REFERENCES AS A LEFT JOIN PWDS_WITH_MIN_LEN AS B ON A.POLICY_ID = B.ID WHERE A.REF_ENTITY_DOMAIN = 'ACCOUNT' AND A.POLICY_KIND = 'PASSWORD_POLICY' AND A.POLICY_STATUS = 'ACTIVE' AND B.ID IS NOT NULL;"
                ),
            ],
            required_privileges="""Requires the SECURITY_VIEWER role on the Snowflake database.""",
            results_expected=True,
            remediation="",
            references=[
                SecurityReference(
                    url="https://docs.snowflake.com/en/user-guide/admin-user-management#password-policies",
                    name="Snowflake documentation for password policies",
                )
            ],
        ),
        SecurityTask(
            name="ensure_service_accounts_keypair_authentication",
            description="Password-based authentication has a set of disadvantages that increase probability of a security incident, especially when used without MFA. Using key-based authentication for service accounts helps to mitigate these risks.",
            control="CIS",
            control_id="1.6",
            queries=[
                # NOTE! This is not a complete list of service accounts and should be reviewed.
                Sql(
                    statement="select name, created_on, has_password, has_rsa_public_key, disabled from snowflake.account_usage.users where (has_password = true or has_rsa_public_key = false) and disabled = false and (name ilike '%svc%' or name ilike '%service%' or name ilike '%dbt%' or name ilike '%airflow%' or name ilike '%airbyte%' or name ilike '%fivetran%');"
                ),
            ],
            required_privileges="""Requires the SECURITY_VIEWER role on the Snowflake database.""",
            results_expected=False,
            remediation="",
            references=[
                SecurityReference(
                    url="https://docs.snowflake.com/en/user-guide/key-pair-auth.html",
                    name="Snowflake documentation for key pair authentication",
                )
            ],
        ),
        SecurityTask(
            name="ensure_keypair_rotation_180_days",
            description="Snowflake supports using RSA key pair authentication as an alternative to password authentication and as a primary way to authenticate service accounts. Snowflake supports two active authentication key pairs to allow for uninterrupted key rotation. Rotate and replace your authentication key pairs based on the expiration schedule at least once every 180 days.",
            control="CIS",
            control_id="1.7",
            queries=[
                Sql(
                    statement="WITH FILTERED_QUERY_HISTORY AS (SELECT END_TIME AS SET_TIME, UPPER(SPLIT_PART(QUERY_TEXT, ' ', 3)) AS PROCESSED_USERNAME, QUERY_TEXT FROM SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY WHERE EXECUTION_STATUS = 'SUCCESS' AND QUERY_TYPE IN ('ALTER_USER', 'CREATE_USER') AND TO_DATE(SET_TIME) < DATEADD(day, -180, CURRENT_DATE()) AND (QUERY_TEXT ILIKE '%rsa_public_key%' OR QUERY_TEXT ILIKE '%rsa_public_key_2%')), EXTRACTED_KEYS AS (SELECT SET_TIME, PROCESSED_USERNAME, CASE WHEN POSITION('rsa_public_key' IN LOWER(QUERY_TEXT)) > 0 THEN 'rsa_public_key' WHEN POSITION('rsa_public_key_2' IN LOWER(QUERY_TEXT)) > 0 THEN 'rsa_public_key_2' ELSE NULL END AS RSA_KEY_NAME FROM FILTERED_QUERY_HISTORY WHERE POSITION('rsa_public_key' IN LOWER(QUERY_TEXT)) > 0 OR POSITION('rsa_public_key_2' IN LOWER(QUERY_TEXT)) > 0), RECENT_KEYS AS ( SELECT EK.SET_TIME, EK.PROCESSED_USERNAME AS USERNAME, EK.RSA_KEY_NAME AS RSA_PUBLIC_KEY, ROW_NUMBER() OVER (PARTITION BY ek.processed_username, ek.rsa_key_name ORDER BY ek.set_time DESC) AS rnum FROM EXTRACTED_KEYS EK INNER JOIN SNOWFLAKE.ACCOUNT_USAGE.USERS AU ON EK.PROCESSED_USERNAME = AU.NAME WHERE AU.DELETED_ON IS NULL AND AU.DISABLED = FALSE AND EK.RSA_KEY_NAME IS NOT NULL) SELECT SET_TIME, USERNAME, RSA_PUBLIC_KEY FROM RECENT_KEYS WHERE RNUM = 1;"
                ),
            ],
            required_privileges="""Requires SECURITY_VIEWER and GOVERNANCE_VIEWER roles on the Snowflake database.""",
            results_expected=False,
            remediation="",
            references=[
                SecurityReference(
                    url="https://docs.snowflake.com/en/user-guide/key-pair-auth.html#configuring-key-pair-rotation",
                    name="Snowflake documentation for configuring key pair rotation",
                )
            ],
        ),
        SecurityTask(
            name="ensure_disabled_after_90_days_without_login",
            description="Access grants tend to accumulate over time unless explicitly set to expire. Regularly revoking unused access grants and disabling inactive user accounts is a good countermeasure to this dynamic.",
            control="CIS",
            control_id="1.8",
            queries=[
                Sql(statement="SHOW USERS;"),
                Sql(
                    statement="""SELECT "name", "created_on", "last_success_login", "disabled" FROM TABLE(result_scan(last_query_id())) WHERE "last_success_login" < CURRENT_TIMESTAMP() - interval '90 days' and "disabled" = false"""
                ),
            ],
            required_privileges="""Requires USERADMIN role""",
            results_expected=False,
            remediation="Run the following query after 90 days of inactivity: ALTER USER <user_name> SET DISABLED = true;",
            references=[
                SecurityReference(
                    url="https://docs.snowflake.com/en/user-guide/admin-user-management.html#disabling-enabling-a-user",
                    name="Snowflake documentation for disabling a user",
                )
            ],
        ),
        SecurityTask(
            name="ensure_idle_session_timeout_for_privileged_roles",
            description=" session is maintained indefinitely with continued user activity. After a period of inactivity in the session, known as the idle session timeout, the user must authenticate to Snowflake again. Session policies can be used to modify the idle session timeout period. The idle session timeout has a maximum value of four hours. Tightening up the idle session timeout reduces sensitive data exposure risk when users forget to sign out of Snowflake and an unauthorized person gains access to their device.",
            control="CIS",
            control_id="1.9",
            queries=[
                Sql(
                    statement="WITH PRIV_USERS AS (SELECT DISTINCT GRANTEE_NAME FROM SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_USERS WHERE DELETED_ON IS NULL AND ROLE IN ('ACCOUNTADMIN','SECURITYADMIN') AND DELETED_ON IS NULL), POLICY_REFS AS (SELECT * FROM SNOWFLAKE.ACCOUNT_USAGE.POLICY_REFERENCES AS A LEFT JOIN SNOWFLAKE.ACCOUNT_USAGE.SESSION_POLICIES AS B ON A.POLICY_ID = B.ID WHERE A.POLICY_KIND = 'SESSION_POLICY' AND A.POLICY_STATUS = 'ACTIVE' AND A.REF_ENTITY_DOMAIN = 'USER' AND B.DELETED IS NULL AND B.SESSION_IDLE_TIMEOUT_MINS <= 15) SELECT A.*, B.POLICY_ID, B.POLICY_KIND, B.POLICY_STATUS, B.SESSION_IDLE_TIMEOUT_MINS FROM PRIV_USERS AS A LEFT JOIN POLICY_REFS AS B ON A.GRANTEE_NAME = B.REF_ENTITY_NAME WHERE B.POLICY_ID IS NULL;"
                ),
            ],
            required_privileges="""Requires USERADMIN role""",
            results_expected=False,
            remediation="Run the following query after 90 days of inactivity: ALTER USER <user_name> SET DISABLED = true;",
            references=[
                SecurityReference(
                    url="https://docs.snowflake.com/en/user-guide/session-policies",
                    name="Snowflake documentation for session policies",
                ),
                SecurityReference(
                    url="https://docs.snowflake.com/en/user-guide/session-policies#step-3-create-a-new-session-policy",
                    name="Snowflake documentation for creating session policies",
                ),
            ],
        ),
        SecurityTask(
            name="limit_users_with_accountadmin_and_securityadmin",
            description="By default, ACCOUNTADMIN is the most powerful role in a Snowflake account. Users with the SECURITYADMIN role grant can trivially escalate their privileges to that of ACCOUNTADMIN. Following the principle of least privilege that prescribes limiting user's privileges to those that are strictly required to do their jobs, the ACCOUNTADMIN and SECURITYADMIN roles should be assigned to a limited number of designated users (e.g., less than 10, but at least 2 to ensure that access can be recovered if one ACCOUNTAMIN user is having login difficulties).",
            control="CIS",
            control_id="1.10",
            queries=[
                Sql(
                    statement="SELECT DISTINCT A.GRANTEE_NAME AS NAME, A.ROLE FROM SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_USERS AS A LEFT JOIN SNOWFLAKE.ACCOUNT_USAGE.USERS AS B ON A.GRANTEE_NAME = B.NAME WHERE A.ROLE IN ('ACCOUNTADMIN', 'SECURITYADMIN') AND A.DELETED_ON IS NULL AND B.DELETED_ON IS NULL AND NOT B.DISABLED ORDER BY A.ROLE;"
                ),
            ],
            required_privileges="""Requires SECURITY_VIEWER role on the Snowflake databases.""",
            results_expected=True,
            remediation="Run the following query after 90 days of inactivity: ALTER USER <user_name> SET DISABLED = true;",
            references=[
                SecurityReference(
                    url="https://docs.snowflake.com/en/user-guide/security-access-control-considerations.html",
                    name="Snowflake documentation for access control considerations",
                )
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
