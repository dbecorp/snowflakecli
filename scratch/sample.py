
        SecurityTask(
            name="ensure_monitoring_for_accountadmin_securityadmin_grants",
            description="Following the principle of least privilege that prescribes limiting user's privileges to those that are strictly required to do their jobs, the ACCOUNTADMIN and SECURITYADMIN roles should be assigned to a limited number of designated users. Any new ACCOUNTADMIN and SECURITYADMIN role grants should be scrutinized.",
            control="CIS",
            control_id="2.1",
            queries=[
                Sql(
                    statement="SELECT CREATED_ON, GRANTEE_NAME, GRANTED_TO, GRANTED_BY FROM SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_ROLES WHERE NAME IN ('ACCOUNTADMIN', 'SECURITYADMIN') AND GRANTEE_NAME NOT IN ('ACCOUNTADMIN', 'SECURITYADMIN') AND DELETED_ON IS NULL ORDER BY CREATED_ON DESC;"
                ),
            ],
            required_privileges="Requires the SECURITY_VIEWER role on the Snowflake database.",
            results_expected=False,
            remediation=[
                SecurityRemediation(
                    name="Revoke ACCOUNTADMIN or SECURITYADMIN from custom role(s) if they were mistakenly granted such privileges.",
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
