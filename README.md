# What is Snowflakecli?

Snowflakecli is a [DuckDB](https://duckdb.org/)-powered command line interface for [Snowflake](https://www.snowflake.com/en/) **security**, **governance**, **operations**, and **cost optimization**.


![snowflakecli](img/snowflakecli.png)


# Installation

    $ pip install snowflakecli
    

# Who is Snowflakecli for?


**Snowflakecli is built for:**

* Security threat-hunting teams **still dealing with the [fallout of the UNC5537 breach](https://cloud.google.com/blog/topics/threat-intelligence/unc5537-snowflake-data-theft-extortion).**
* Data and Ops teams looking to **proactively improve and continuously monitor their security posture**.
* Operations teams looking to **optimize their [virtual warehouses](https://docs.snowflake.com/en/user-guide/warehouses) and workloads.**
* Data engineers looking to **grasp the complexities of their Snowflake account.**


# What does Snowflakecli do?


**Snowflakecli includes:**

* Key-Pair utilities so you can ***establish and maintain secure access to your Snowflake account***.
* Customizable security threat hunting, with the [UNC5537](https://cloud.google.com/blog/topics/threat-intelligence/unc5537-snowflake-data-theft-extortion) threat hunt being the default.
* Customizable security and auditing benchmarks, with well-known industry standards being the default.
* CLI-based SQL execution
* Simplified SQL migration management - think a lightweight, Python-based [Flyway](https://www.red-gate.com/products/flyway/community/)
* Configuration management
* Connection management


**Snowflakecli is quickly growing to include:**

* Data loading and unloading tools
* Account snapshotting and state diff-ing
* Declarative, idempotent resource management [with fewer dangerous surprises](https://github.com/Snowflake-Labs/terraform-provider-snowflake/issues?q=is%3Aopen+is%3Aissue+label%3Abug)
* ACL exploration - "Can user X access Y? How?"
* Virtual warehouse utilization and workload optimization tools
* Tiered compute so local queries don't have to use a virtual warehouse to do local analytics
* AI-powered PII governance
* AI-powered account recommendations


# Why are we building it?

We first adopted Snowflake in 2017 and it was absolutely game-changing. The separation of compute and storage allowed our data teams to quickly implement analytical systems that would have taken months (or years) to roll out.

But a series of common patterns have since emerged across industry:

### Snowflake accounts often fail to implement best-in-class security and data security practices...

Which has lead to unfortunate situations like [UNC5537](https://cloud.google.com/blog/topics/threat-intelligence/unc5537-snowflake-data-theft-extortion).

### Snowflake usage and activity often goes unaudited...

Which leads to a lack of insight into what is actually happening to an organizations data resources.

### Snowflake accounts often have [runaway costs](https://www.reddit.com/r/snowflake/comments/197mszg/solutions_to_manage_runaway_snowflake_costs/)...

Which means either a dedicated hire (who quickly pays for themselves) or onboarding third-party software like [Select](https://select.dev/) or [Keebo](https://keebo.ai/).


# Why are we the right people to build it?


* Taught [Snowflake courses on O'Reilly](https://www.oreilly.com/live-events/building-a-modern-data-platform-with-snowflake/0636920414971/)
* Contributed heavily to [Snowflake The Definitive Guide](https://www.amazon.com/Snowflake-Definitive-Architecting-Designing-Deploying/dp/1098103823)
* Built [Okta's next-gen SIEM on Snowflake](https://www.youtube.com/watch?v=h3MMQMyiXcw)
* [Reduced Snowflake costs](https://www.youtube.com/watch?v=TrmJilG4GXk) by hundreds of thousands of dollars using embedded OLAP
* ..and helped many companies along the way


# Documentation

We'll be publishing full documentation shortly so please stay tuned.

In the meantime, `snowflakecli` is entirely self-documenting thanks to great tools like [Typer](https://typer.tiangolo.com/) and [Rich](https://github.com/Textualize/rich).


# Q&A


### Can I contribute?

Please do!

We are readily accepting new contributions and understand the power of collective, collaborative knowledge. If you have thoughts, ideas, suggestions, or innovative use cases please create an issue and let's start the conversation. Or just pull a PR 😀. Or find one of us on LinkedIn 😀.


### Is it secure?


Yes. The codebase is entirely open, MIT-licensed, and built with best-in-class Python tooling.

Unlike [other](https://docs.snowflake.com/en/user-guide/snowsql) [tools](https://docs.snowflake.com/en/developer-guide/snowflake-cli-v2/index) from Snowflake which facilitate insecure practices such as username and password-based authentication without MFA, Snowflakecli ***explicitly mandates key-pair authentication***.


### Can it be used to keep my Snowflake account more secure?


Yes.

Data security has never been more important and Snowflakecli was explicitly built to help Snowflake customers enhance the security of their accounts.

Many Snowflake accounts have been set up quickly with less-than-ideal configuration. As these accounts grow they usually store increasingly-sensitive information and become targets for malicious activity.

Snowflakecli helps automate the process of ***establishing and maintaining secure accounts.***


# License


[MIT](https://opensource.org/license/mit)
