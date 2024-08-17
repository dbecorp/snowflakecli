I'm very pleased to open up a project I've been working on - a DuckDB-powered CLI for Snowflake security, governance, operations, and cost optimization.


After continually seeing common patterns with mature Snowflake implementations, it was time to release tooling to help organizations move towards a safer, more-efficient data warehousing future. How does Snowflakecli help with this?


Key/Pair Management


Command-line tools from Snowflake default to username/password-based auth and don't require MFA. Snowflakecli not only requires you to use key/pair auth, it also helps the user generate a proper public/private keypair with a single command. So usersyou can start secure and stay secure.



Security Threat Hunting


Still dealing with the fallout of the UNC5537 breach and don't know where to start? Snowflakecli includes onboard threat hunting capabilities and defaults to a UNC5537 threat hunt. But allows you to definite and execute your own threat hunts.


Security Auditing


While the Snowflake Security and Trust Center allows you tol "cron" a periodic CIS audit, Snowflakecli goes further. It defaults to common foundational audits but allows you to write and execute your own security audits.







