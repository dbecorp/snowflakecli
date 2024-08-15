from cli.core.snowflake.sql import Sql
from cli.core.security.types import (
    SecurityPlaybook,
    SecurityTask,
    SecurityReference,
    SecurityRemediation,
)


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
            remediation=[
                SecurityRemediation(
                    description="Configure a security integration",
                    action="The steps for configuring an IdP differ depending on whether you choose SAML2 or OAuth. They further differ depending on what identity provider you choose: Okta, AD FS, Ping Identity, Azure AD, or custom. For specific instructions, see Snowflake documentation on SAML and External OAuth. Note: If your SAML integration is configured using the deprecated account parameter SAML_IDENTITY_PROVIDER, you should migrate to creating a security integration using the system$migrate_saml_idp_registration function. For more information, see the Migrating to a SAML2 Security Integration documentation.",
                )
            ],
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
            remediation=[
                SecurityRemediation(),
            ],
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
            remediation=[
                SecurityRemediation(),
            ],
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
            remediation=[
                SecurityRemediation(),
            ],
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
            results_expected=False,
            remediation="Run the following query after 90 days of inactivity: ALTER USER <user_name> SET DISABLED = true;",
            references=[
                SecurityReference(
                    url="https://docs.snowflake.com/en/user-guide/security-access-control-considerations.html",
                    name="Snowflake documentation for access control considerations",
                )
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
            required_privileges="""Requires SECURITY_VIEWER role on the Snowflake database.""",
            results_expected=True,
            remediation="REVOKE ROLE ACCOUNTADMIN FROM USER <username> or REVOKE ROLE SECURITYADMIN FROM USER <username>",
            references=[
                SecurityReference(
                    url="https://docs.snowflake.com/en/user-guide/security-access-control-considerations.html",
                    name="Snowflake documentation for access control considerations",
                )
            ],
        ),
        SecurityTask(
            name="ensure_accountadmin_have_email_address",
            description="Every Snowflake user can be assigned an email address. The email addresses assigned to ACCOUNTADMIN users are used by Snowflake to notify administrators about important events related to their accounts. For example, ACCOUNTADMIN users are notified about impending expiration of SAML2 certificates or SCIM access tokens.",
            control="CIS",
            control_id="1.11",
            queries=[
                Sql(
                    statement="""SELECT DISTINCT a.grantee_name as name, b.email FROM snowflake.account_usage.grants_to_users AS a LEFT JOIN snowflake.account_usage.users AS b ON a.grantee_name = b.name WHERE a.role = 'ACCOUNTADMIN' AND a.deleted_on IS NULL AND b.email IS NULL AND b.deleted_on IS NULL AND NOT b.disabled;"""
                ),
            ],
            required_privileges="Requires SECURITY_VIEWER role on the SNOWFLAKE database.",
            results_expected=False,
            remediation=[
                SecurityRemediation(
                    description="Add email address to ACCOUNTADMIN user.",
                    action="ALTER USER <username> SET EMAIL = <email_address>;",
                )
            ],
            references=[
                SecurityReference(
                    url="https://docs.snowflake.com/en/user-guide/admin-user-management.html#resetting-the-password-for-an-administrator",
                    name="Snowflake docs for modifying administrator accounts",
                )
            ],
        ),
        SecurityTask(
            name="ensure_no_users_have_accountadmin_or_security_admin_as_default",
            description="The ACCOUNTADMIN system role is the most powerful role in a Snowflake account and is intended for performing initial setup and managing account-level objects. SECURITYADMIN role can trivially escalate their privileges to that of ACCOUNTADMIN. Neither of these roles should be used for performing daily non-administrative tasks in a Snowflake account.",
            control="CIS",
            control_id="1.12",
            queries=[
                Sql(
                    statement="SELECT NAME, DEFAULT_ROLE FROM SNOWFLAKE.ACCOUNT_USAGE.USERS WHERE DEFAULT_ROLE IN ('ACCOUNTADMIN', 'SECURITYADMIN') AND DELETED_ON IS NULL AND NOT DISABLED;"
                ),
            ],
            required_privileges="Requires SECURITY_VIEWER role on the Snowflake database.",
            results_expected=False,
            remediation="ALTER USER <user_name> SET DEFAULT_ROLE = <job_appropriate_role>;",
            references=[
                SecurityReference(
                    url="https://docs.snowflake.com/en/user-guide/security-access-control-configure.html",
                    name="Snowflake documentation for access control configuration",
                )
            ],
        ),
        SecurityTask(
            name="ensure_custom_roles_not_granted_accountadmin_securityadmin",
            description="The principle of least privilege requires that every identity is only given privileges that are necessary to complete its tasks. The ACCOUNTADMIN system role is the most powerful role in a Snowflake account and is intended for performing initial setup and managing account-level objects. SECURITYADMIN role can trivially escalate their privileges to that of ACCOUNTADMIN. Neither of these roles should be used for performing daily non-administrative tasks in a Snowflake account.",
            control="CIS",
            control_id="1.13",
            queries=[
                Sql(
                    statement="""SELECT GRANTEE_NAME, PRIVILEGE AS GRANTED_PRIVILEGE, NAME AS GRANTED_ROLE FROM SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_ROLES WHERE GRANTED_ON = 'ROLE' AND NAME IN ('ACCOUNTADMIN','SECURITYADMIN') AND GRANTEE_NAME NOT IN ('ACCOUNTADMIN') AND DELETED_ON IS NULL;"""
                ),
            ],
            required_privileges="Requires SECURITY_VIEWER role on the Snowflake database.",
            results_expected=False,
            remediation=[
                SecurityRemediation(
                    description="Revoke ACCOUNTADMIN or SECURITYADMIN from custom role(s)",
                    action="REVOKE SECURITYADMIN ON ACCOUNT FROM ROLE <custom_role>; REVOKE ACCOUNTADMIN ON ACCOUNT FROM ROLE <custom_role>;",
                )
            ],
            references=[
                SecurityReference(
                    url="https://docs.snowflake.com/en/user-guide/security-access-control-configure.html",
                    name="Snowflake documentation for access control configuration",
                )
            ],
        ),
        SecurityTask(
            name="ensure_tasks_not_owned_by_accountadmin_securityadmin",
            description="The ACCOUNTADMIN system role is the most powerful role in a Snowflake account and is intended for performing initial setup and managing account-level objects. SECURITYADMIN role can trivially escalate their privileges to that of ACCOUNTADMIN. Neither of these roles should be used for running Snowflake tasks. A task should be running using a custom role containing only those privileges that are necessary for successful execution of the task. Snowflake executes tasks with the privileges of the task owner. The role that has OWNERSHIP privilege on the task owns the task.",
            control="CIS",
            control_id="1.14",
            queries=[
                Sql(
                    statement="SELECT NAME AS STORED_PROCEDURE_NAME, GRANTED_TO, GRANTEE_NAME AS ROLE_NAME, PRIVILEGE FROM SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_ROLES WHERE GRANTED_ON = 'TASK' AND DELETED_ON IS NULL AND GRANTED_TO = 'ROLE' AND PRIVILEGE = 'OWNERSHIP' AND GRANTEE_NAME IN ('ACCOUNTADMIN' , 'SECURITYADMIN');"
                ),
            ],
            required_privileges="Requires SECURITY_VIEWER role on the Snowflake database.",
            results_expected=False,
            remediation=[
                SecurityRemediation(
                    description="Create and assign a task-specific role to overprivileged tasks",
                    action="CREATE ROLE <task_specific_role>; GRANT OWNERSHIP ON TASK <task_name> TO ROLE <task_specific_role>;",
                ),
                SecurityRemediation(
                    description="Revoke elevated privileges from tasks",
                    action="REVOKE ALL PRIVILEGES ON TASK <task_name> FROM ROLE ACCOUNTADMIN; REVOKE ALL PRIVILEGES ON TASK <task_name> FROM ROLE SECURITYADMIN;",
                ),
            ],
            references=[
                SecurityReference(
                    url="https://docs.snowflake.com/en/user-guide/tasks-intro.html#task-security",
                    name="Snowflake documentation for task security",
                ),
                SecurityReference(
                    url="https://docs.snowflake.com/en/user-guide/security-access-control-configure.html",
                    name="Snowflake documentation for access control configuration",
                ),
                SecurityReference(
                    url="https://docs.snowflake.com/en/user-guide/security-access-control-considerations.html",
                    name="Snowflake documentation for access control considerations",
                ),
            ],
        ),
        SecurityTask(
            name="ensure_tasks_do_not_run_with_accountadmin_securityadmin",
            description="The ACCOUNTADMIN system role is the most powerful role in a Snowflake account and is intended for performing initial setup and managing account-level objects. SECURITYADMIN role can trivially escalate their privileges to that of ACCOUNTADMIN. Neither of these roles should be used for running Snowflake tasks. A task should be running using a custom role containing only those privileges that are necessary for successful execution of the task.",
            control="CIS",
            control_id="1.15",
            queries=[
                Sql(
                    statement="""SELECT NAME, GRANTED_TO, GRANTEE_NAME, PRIVILEGE FROM SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_ROLES WHERE GRANTED_ON = 'TASK' AND DELETED_ON IS NULL AND GRANTED_TO = 'ROLE' AND GRANTEE_NAME IN ('ACCOUNTADMIN' , 'SECURITYADMIN');""",
                ),
            ],
            required_privileges="Requires the SECURITY_VIEWER role on the Snowflake database.",
            results_expected=False,
            remediation=[
                SecurityRemediation(
                    description="Create and assign a task-specific role to overprivileged tasks",
                    action="CREATE ROLE <task_specific_role>; GRANT OWNERSHIP ON TASK <task_name> TO ROLE <task_specific_role>;",
                ),
                SecurityRemediation(
                    description="Revoke elevated privileges from tasks",
                    action="REVOKE ALL PRIVILEGES ON TASK <task_name> FROM ROLE ACCOUNTADMIN; REVOKE ALL PRIVILEGES ON TASK <task_name> FROM ROLE SECURITYADMIN;",
                ),
            ],
            references=[
                SecurityReference(
                    url="https://docs.snowflake.com/en/user-guide/tasks-intro.html#task-security",
                    name="Snowflake documentation for task security",
                ),
                SecurityReference(
                    url="https://docs.snowflake.com/en/user-guide/security-access-control-configure.html",
                    name="Snowflake documentation for access control configuration",
                ),
                SecurityReference(
                    url="https://docs.snowflake.com/en/user-guide/security-access-control-considerations.html",
                    name="Snowflake documentation for access control considerations",
                ),
            ],
        ),
        SecurityTask(
            name="ensure_stored_procedures_not_owned_by_accountadmin_securityadmin",
            description="The ACCOUNTADMIN system role is the most powerful role in a Snowflake account and is intended for performing initial setup and managing account-level objects. SECURITYADMIN role can trivially escalate their privileges to that of ACCOUNTADMIN. Neither of these roles should be used for running Snowflake stored procedures. A stored procedure should be running using a custom role containing only those privileges that are necessary for successful execution of the stored procedure.",
            control="CIS",
            control_id="1.16",
            queries=[
                Sql(
                    statement="SELECT * FROM SNOWFLAKE.ACCOUNT_USAGE.PROCEDURES WHERE DELETED IS NULL AND PROCEDURE_OWNER IN ('ACCOUNTADMIN','SECURITYADMIN');"
                ),
            ],
            required_privileges="Requires the SECURITY_VIEWER role on the Snowflake database.",
            results_expected=False,
            remediation=[
                SecurityRemediation(
                    description="For each stored procedure <procedure_name> that runs with ACCOUNTADMIN or SECURITYADMIN privileges, create a new role <procedure_specific_role> and assign it to the stored procedure.",
                    action="CREATE ROLE <procedure_specific_role>; GRANT OWNERSHIP ON PROCEDURE <procedure_name> TO ROLE <procedure_specific_role>;",
                ),
                SecurityRemediation(
                    description="After creating a new role and granting ownership of each stored procedure to it, for each stored procedure that is owned by ACCOUNTADMIN or SECURITYADMIN roles, ensure all privileges on the stored procedure are revoked from the roles.",
                    action="REVOKE ALL PRIVILEGES ON PROCEDURE <procedure_name> FROM ROLE ACCOUNTADMIN; REVOKE ALL PRIVILEGES ON PROCEDURE <procedure_name> FROM ROLE SECURITYADMIN;",
                ),
            ],
            references=[
                SecurityReference(
                    url="https://docs.snowflake.com/en/sql-reference/stored-procedures-rights",
                    name="Snowflake documentation for stored procedure rights",
                ),
                SecurityReference(
                    url="https://docs.snowflake.com/en/user-guide/security-access-control-configure.html",
                    name="Snowflake documentation for access control configuration",
                ),
                SecurityReference(
                    url="https://docs.snowflake.com/en/user-guide/security-access-control-considerations.html",
                    name="Snowflake documentation for access control considerations",
                ),
            ],
        ),
        SecurityTask(
            name="ensure_stored_procedures_do_not_run_with_accountadmin_securityadmin",
            description="The ACCOUNTADMIN system role is the most powerful role in a Snowflake account; it is intended for performing initial setup and managing account-level objects. Users and stored procedures with the SECURITYADMIN role can escalate their privileges to ACCOUNTADMIN. Snowflake stored procedures should not run with the ACCOUNTADMIN or SECURITYADMIN roles. Instead, stored procedures should be run using a custom role containing only those privileges that are necessary for successful execution of the stored procedure.",
            control="CIS",
            control_id="1.17",
            queries=[
                Sql(
                    statement="SELECT NAME, GRANTED_TO, GRANTEE_NAME FROM SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_ROLES WHERE GRANTED_ON = 'PROCEDURE' AND DELETED_ON IS NULL AND GRANTED_TO = 'ROLE' AND GRANTEE_NAME IN ('ACCOUNTADMIN' , 'SECURITYADMIN');"
                ),
            ],
            required_privileges="Requires the SECURITY_VIEWER role on the Snowflake database.",
            results_expected=False,
            remediation=[
                SecurityRemediation(
                    description="Create and assign a task-specific role to overprivileged tasks",
                    action="CREATE ROLE <task_specific_role>; GRANT OWNERSHIP ON TASK <task_name> TO ROLE <task_specific_role>;",
                ),
                SecurityRemediation(
                    description="Revoke elevated privileges from tasks",
                    action="REVOKE ALL PRIVILEGES ON TASK <task_name> FROM ROLE ACCOUNTADMIN; REVOKE ALL PRIVILEGES ON TASK <task_name> FROM ROLE SECURITYADMIN;",
                ),
            ],
            references=[
                SecurityReference(
                    url="https://docs.snowflake.com/en/user-guide/tasks-intro.html#task-security",
                    name="Snowflake documentation for task security",
                ),
                SecurityReference(
                    url="https://docs.snowflake.com/en/user-guide/security-access-control-configure.html",
                    name="Snowflake documentation for access control configuration",
                ),
                SecurityReference(
                    url="https://docs.snowflake.com/en/user-guide/security-access-control-considerations.html",
                    name="Snowflake documentation for access control considerations",
                ),
            ],
        ),
    ],
)
