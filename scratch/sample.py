SELECT NAME, GRANTED_TO, GRANTEE_NAME FROM SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_ROLES WHERE GRANTED_ON = 'PROCEDURE' AND DELETED_ON IS NULL AND GRANTED_TO = 'ROLE' AND GRANTEE_NAME IN ('ACCOUNTADMIN' , 'SECURITYADMIN');


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
                    name="Create and assign a task-specific role to overprivileged tasks",
                    action="CREATE ROLE <task_specific_role>; GRANT OWNERSHIP ON TASK <task_name> TO ROLE <task_specific_role>;",
                ),
                SecurityRemediation(
                    name="Revoke elevated privileges from tasks",
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
            name="",
            description="",
            control="CIS",
            control_id="",
            queries=[
                Sql(
                    statement=""
                ),
            ],
            required_privileges="""""",
            results_expected=False,
            remediation=[
                SecurityRemediation(
                    name="",
                    action="",
                )
            ],
            references=[
                SecurityReference(
                    url="",
                    name="",
                )
            ],
        ),
