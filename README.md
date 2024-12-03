# Contents

* [Censeye](#censeye)
  * [Introduction](#introduction)
  * [Setup](#setup)
  * [How?](#how)
  * [Warning](#warning)
  * [Usage](#usage)
  * [Reporting](#reporting)
  * [Auto Pivoting](#auto-pivoting)
  * [Historical Certificates](#historical-certificates)
  * [Query Prefix Filtering](#query-prefix-filtering)
  * [Saving reports](#saving-reports)
  * [Configuration](#configuration)
    * [Configuring Rarity](#configuring-rarity)
    * [Configuring Fields](#configuring-fields)
      * [Ignoring field values](#ignoring-field-values)
      * [Field weights](#field-weights)
      * [Value-only fields](#value-only-fields)
  * [Workspaces](#workspaces)

# Censeye

## Introduction

This tool is designed to help researchers identify hosts with characteristics similar to a given target. For instance, if you come across a suspicious host, the tool enables you to determine the most effective CenQL search terms for discovering related infrastructure. Once those search terms are identified, the utility can automatically query the Censys API to fetch hosts matching those criteria, download the results, and repeat the analysis on the newly found hosts.

Censeye was hacked together over the course of a few weeks to automate routine tasks performed by our research team. While it has proven useful in streamlining daily workflows, its effectiveness may vary depending on specific use cases.

## Setup

Using python virtual-env, we can do the following to set everything up:

```shell
python -m venv .venv && source .venv/bin/activate  
pip install -r requirements.txt 
python ./censeye.py --help
```

**Note**: Censeye requires the latest version of [censys-python](https://github.com/censys/censys-python) and a Censys API key, this is configured via the `censys` command-line tool:

```shell
$ censys config

Censys API ID: XXX
Censys API Secret: XXX
Do you want color output? [y/n]: y

Successfully authenticated for your@email.com
```

## How?

![diagram](./static/diag.png)

<BS>
The visual representation above outlines how Censeye operates. In textual form, the tool follows a straightforward workflow:

1. **Fetch Initial Host Data**  
   Use the Censys Host API to retrieve data for a specified host.

2. **Generate CenQL Queries**  
   For each [keyword](https://search.censys.io/search/definitions?resource=hosts) found in the host data (see: [Configuration](#configuration)), generate a valid CenQL query that matches the corresponding key-value pair.  
   Example:  
   `services.ssh.server_host_key.fingerprint_sha256=531a33202a58e4437317f8086d1847a6e770b2017b34b6676a033e9dc30a319c`

3. **Aggregate Data Using Reporting API**  
   Leverage the Censys Reporting API to generate aggregate reports for each CenQL query, using `ip` as the "breakdown" with a bucket count of `1`. The `total` value is used to determine the number of hosts matching each query.

4. **Identify "Interesting" Queries**  
   CenQL queries with a host count (aka: [rarity](#configuring-rarity) ) between 2 and a configurable maximum are tagged as as "interesting." These queries represent CenQL terms observed on the host that are also found in a limited number of other hosts.

5. **Recursive Pivoting (Optional)**  
   If the `--depth` flag is set to a value greater than zero, the tool uses the Censys Search API to fetch a list of hosts matching the "interesting" CenQL queries. It then loops back to Step 1 for these newly discovered hosts, repeating the process until the specified depth is reached.  

   **Note:** Queries are never reused across different depths. For example, a query identified at depth 1 will not be applied at depths 2 or beyond.

Censeye includes multiple layers of caching and filtering, all of which can be adjusted to suit specific requirements.

## Warning

This tool is not intended for correlating vast numbers of hosts. Instead, it focuses on identifying connections using unique search key/value pairs. If your goal is to explore questions like "What other services do servers running Apache also host?" this is not the right tool.

Additionally, Censeye can be quite query-intensive. The auto-pivoting feature, in particular, requires a significant number of queries, making it less practical for those with limited query access (e.g., users outside of Censys).

**Use this tool at your own discretion. We are not responsible for any depletion of your quotas resulting from its use.**

## Usage

```plain
Usage: censeye.py [OPTIONS] [IP]

Options:
  -d, --depth INTEGER             [auto-pivoting] search depth (0 is single host, 1 is all the hosts that host found, etc...)
  --workers INTEGER               number of workers to run queries in parallel
  -w, --workspace TEXT            directory for caching results (defaults to XDG configuration path)
  -m, --max-search-results N      maximum number of censys search results to process
  -ll, --log-level TEXT           set the logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
  -s, --save TEXT                 save report to a file
  -p, --pivot-threshold INTEGER   maximum number of hosts for a search term that will trigger a pivot (default: 120)
  -a, --at-time [%Y-%m-%d %H:%M:%S|%Y-%m-%d]
                                  historical host data at_time.
  -q, --query-prefix TEXT         prefix to add to all queries (useful for filtering, the ' and ' is added automatically)
  --input-workers INTEGER         number of parallel workers to process inputs (e.g., only has an effect on stdin inputs)
  -qp, --query-prefix-count       If the --query-prefix is set, this will return a count of hosts for both the filtered and
                                  unfiltered results.
  --vt                            Lookup IPs in VirusTotal
  -c, --config TEXT               configuration file path
  -mp, -M, --min-pivot-weight N   [auto-pivoting] only pivot into fields with a weight greater-than or equal-to this number (see configuration)
  --fast                          [auto-pivoting] alias for --min-pivot-weight 1.0
  --slow                          [auto-pivoting] alias for --min-pivot-weight 0.0
```

These options will all override the settings in the [configuration](#configuration) file.

If an IP is not specified in the arguments, the default behavior is to read IPs from stdin. This enables integration with other tools to seed input for this utility. For example:

```shell
censys search labels=c2 | jq '.[].ip' | python censeye.py
```

## Reporting

![simple screenshot](./static/2024-11-26_13-19.png)

Above is a screenshot of a very simple report generated by Censeye for a single host. Each row contains three columns:

1. The number of matching hosts for the given field.
2. The key.
3. The value of the key.

If your terminal supports it, each row is clickable and will navigate to the Censys website for the corresponding datapoint.

The next report, labeled `Interesting search terms`, is an aggregate list of all CenQL statements that fall within the [rarity](#configuring-rarity) threshold—also referred to as "Interesting search terms."

## Auto Pivoting

Like web crawlers discover websites, Censeye can be used to crawl Censys!

When the `--depth` argument is set to a value greater than zero, the "interesting" fields are used to query the Censys Search API to retrieve lists of matching hosts. These hosts are then fed back into Censeye as input to generate additional reports.

Furthermore, the output will include a new section labeled the `Pivot Tree`. For example:

```plain
Pivot Tree:
5.188.87.38
├── 5.178.1.11      (via: services.ssh.server_host_key.fingerprint_sha256="f95812cbb46f0a664a8f2200592369b105d17dfe8255054963aac4e2df53df51") ['remote-access']
├── 147.78.46.112   (via: services.ssh.server_host_key.fingerprint_sha256="f95812cbb46f0a664a8f2200592369b105d17dfe8255054963aac4e2df53df51") ['remote-access']
├── 179.60.149.209  (via: services.ssh.server_host_key.fingerprint_sha256="f95812cbb46f0a664a8f2200592369b105d17dfe8255054963aac4e2df53df51") ['remote-access']
│   ├── 5.161.114.184   (via: services.ssh.server_host_key.fingerprint_sha256="6278464bcad66259d2cd62deeb11c8488f170a1a650d5748bd7a8610026ca634") ['remote-access']
│   ├── 185.232.67.15   (via: services.ssh.server_host_key.fingerprint_sha256="6278464bcad66259d2cd62deeb11c8488f170a1a650d5748bd7a8610026ca634") ['remote-access']
│   │   ├── 193.29.13.183   (via: services.ssh.server_host_key.fingerprint_sha256="bd613b3be57f18c3bceb0aaf86a28ad8b6df7f9bccacf58044f1068d1787f8a5") ['remote-access']
│   │   ├── 45.227.252.245  (via: services.ssh.server_host_key.fingerprint_sha256="bd613b3be57f18c3bceb0aaf86a28ad8b6df7f9bccacf58044f1068d1787f8a5") ['remote-access']
│   │   ├── 45.145.20.211   (via: services.ssh.server_host_key.fingerprint_sha256="bd613b3be57f18c3bceb0aaf86a28ad8b6df7f9bccacf58044f1068d1787f8a5") ['remote-access']
│   │   ├── 193.142.30.165  (via: services.ssh.server_host_key.fingerprint_sha256="bd613b3be57f18c3bceb0aaf86a28ad8b6df7f9bccacf58044f1068d1787f8a5") ['remote-access']
│   ├── 77.220.213.90   (via: services.ssh.server_host_key.fingerprint_sha256="6278464bcad66259d2cd62deeb11c8488f170a1a650d5748bd7a8610026ca634") ['remote-access']
... snip snip ...
```

Here, our initial input was the host `5.188.87.38`. Using the host details from this IP, we identified an SSH fingerprint that appeared on a limited number of other hosts. Censeye then fetched those matching hosts and generated reports for them.

One of the matching hosts was `179.60.149.209`, and you can see how Censeye discovered that host through the `via:` statement in the report:

```plain
├── 179.60.149.209  (via: services.ssh.server_host_key.fingerprint_sha256="f95812cbb46f0a664a8f2200592369b105d17dfe8255054963aac4e2df53df51")
```

* `179.60.149.209` was found using the search query `services.ssh.server_host_key.fingerprint_sha256="f95812cbb46f0a664a8f2200592369b105d17dfe8255054963aac4e2df53df51"` that was found on `5.188.87.38`
* `185.232.67.15` was found using the search query `services.ssh.server_host_key.fingerprint_sha256="6278464bcad66259d2cd62deeb11c8488f170a1a650d5748bd7a8610026ca634"` which was found running on `179.60.149.209`
* `193.29.13.183` was found using the search query `services.ssh.server_host_key.fingerprint_sha256="bd613b3be57f18c3bceb0aaf86a28ad8b6df7f9bccacf58044f1068d1787f8a5"` which was found running on `185.232.67.15`

## Historical Certificates

There are some special cases for reporting, one of which involves TLS certificate fingerprints. If a certificate is found on a host and it is unique to that host (i.e., only observed on the current host being analyzed), Censeye will query historical data in Censys and report all hosts in the past that have used this certificate.

![tls history](./static/cert_history.png)

In this screenshot, we see that `113.250.188.15` has a TLS fingerprint `e426a94594510a5c2adb1f0ba062ed2c76756416dfe22b83121e5351031a5e1b` which is unique to this IP at present. However, the certificate has been observed on other hosts in the past. Notice the count column presented as `1 (+2)`. This indicates that there is only one current host with this certificate, but historical data reveals two additional hosts.

Historical certificate observations are also displayed as a tree beneath the main table. Each of these fields is clickable (if supported by your terminal) and links to the corresponding host on the given date.

These historical hosts are also included in [auto-pivoting](#Auto_Pivoting) if the `--depth` argument is set to a value greater than zero. In this case, the tool will use the host data from the time the certificate was observed to guide the crawler.

## Query Prefix Filtering

One of the things we use this tool here at Censys for is to use hosts that we already know are malicious to find other hosts that may be malicious that we have not labeled as such. For example:

```shell
censys search 'labels=c2' | jq '.[].ip' | python censeye.py --query-prefix 'not labels=c2'
```

This `--query-prefix` flag tells Censeye that for every aggregation report that it generates, add the `not labels=c2` to the query. The goal here is to look at hosts already labeled as a `c2` to find other hosts not labeled as `c2`.

![query prefix example](./static/query_prefix_01.png)

In the above example under "Interesting search terms" we can see the resulting CenQL terms that matched our rarity configuration. Note that there are several rows that have a count of `0`, this is because those fields were _only_ found on hosts already labeled `c2`.

## Saving reports

If you wish to save the report as an HTML file, simply pass the `--save` flag with an output filename, and the whole thing is there.

## Configuration

Censeye ships with a built-in configuration file that defines the general settings along with the [keyword definitions](https://search.censys.io/search/definitions?resource=hosts) that are used to generate reports. But this can be overloaded by using the `--config` argument. The following is a snippet of this configuration file:

```yaml
rarity:
  min: 2               # minimum host count for a field to be treated as "interesting"
  max: 120             # maximum host count for a field to be treated as "interesting"

fields:
  - field: services.ssh.server_host_key.fingerprint_sha256
    weight: 1.0
  - field: services.http.response.body_hash
    weight: 1.0
    ignore:
      - "sha1:4dcf84abb6c414259c1d5aec9a5598eebfcea842"
      - "sha256:036bacf3bd34365006eac2a78e4520a953a6250e9550dcf9c9d4b0678c225b4c"
  - field: services.tls.certificates.leaf_data.issuer_dn
    weight: 1.0
    ignore:
      - "C=US, O=DigiCert Inc, CN=DigiCert Global G2 TLS RSA SHA256 2020 CA1"
  - field: services.tls.certificates.leaf_data.subject.organization
    weight: 1.0
  - field: ~services.tls.certificates.leaf_data.subject.organization
    weight: 0.5
    ignore:
      - "Cloudflare, Inc."
  - field: services.http.response.html_tags
    weight: 0.9
    ignore:
      - "<title>301 Moved Permanently</title>"
      - "<title>403 Forbidden</title>"
      - "<title> 403 Forbidden </title>"
  - field: services.http.response.headers
    weight: 0.8
    ignore:
      - "Location": ["*/"]
      - "Vary": ["Accept-Encoding"]
      - "Content-Type":
          - "text/html"
          - "text/html; charset=UTF-8"
          - "text/html;charset=UTF-8"
          - "text/html; charset=utf-8"
      - "Connection":
          - "close"
          - "keep-alive"
          - "Keep-Alive"
```

### Configuring Rarity

The rarity setting defines what constitutes an "interesting" CenQL term. Once an aggregation report is fetched for a given CenQL statement, the term is flagged as "interesting" if the number of matching hosts is greater than `min` but less than `max`.

If the `--depth` flag is set, these "interesting" search terms are used to pivot and discover _other_ hosts. Otherwise, the final report for the host will "feature" these search terms in two ways:

1. The report will include different colors and highlighting for the matching rows.
2. The final output will contain an aggregate list of "interesting search terms."

### Configuring Fields

Censeye does not generate aggregate reports for every single field in a host result, as some fields are more useful than others. Instead, it focuses on fields explicitly defined as relevant for reporting.

Each field definition includes two configurable options:

1. **Ignored Values**: Specific values within the field that should be excluded from the report.
2. **Weight**: The relative importance of the field, which can influence prioritization in reporting and analysis.

#### Ignoring field values

The `ignored` configuration tells the utility to exclude certain values from generating reports. For example, the `services.http.response.body_hash` field in the configuration may specify two values to ignore:

* `"sha1:4dcf84abb6c414259c1d5aec9a5598eebfcea842"`
* `"sha256:036bacf3bd34365006eac2a78e4520a953a6250e9550dcf9c9d4b0678c225b4c"`

When analyzing a host's result, if the _value_ of that field matches one of these configured values, a report will not be generated for that _specific_ field.

HTTP response headers are handled slightly differently. Instead of ignoring individual values, the configuration defines an array of key-value pairs to ignore. If the response header key-value pairs on a host match any of those defined in the configuration, a report will not be generated.

The goal of this feature is to optimize the tool's performance by reducing processing time and pre-filtering well-known CenQL statements that are unlikely to provide useful insights.

#### Field weights

Field weights influence how Censeye pivots during its analysis and are directly tied to the `--min-pivot-weight` argument (default: `0.0`).

Each field is assigned a weight ranging from `0.0` to `1.0`, with a default of `0.0`. When the `--depth` flag is set, fields with a weight below the specified `--min-pivot-weight` value will be excluded from pivoting. In other words, these fields will not be used to identify other matching hosts for further reporting.

This allows users to prioritize certain fields over others, tailoring the analysis to focus on more relevant or significant fields.

**Note**: the argument `--fast` is an alias for `--min-pivot-weight 1.0` and `--slow` is an alias for `--min-pivot-weight 0.0`.

#### Value-only fields

In the above configuration, some fields are prefixed with a `~` character, for example:

```yaml
  - field: ~services.tls.certificates.leaf_data.subject.organization
    weight: 0.5
    ignore:
      - "Cloudflare, Inc."
```

In this case, if a host includes the `services.tls.certificates.leaf_data.subject.organization` field in its data, the value is used as a wildcard search in Censys. The resulting CenQL statement will resemble the following:

```dsl
(not services.tls.certificates.leaf_data.subject.organization=$VALUE) and "$VALUE"
```

The idea is to determine the number of hosts where that value is found anywhere in the data, not just within the specific field itself.

## Workspaces

Censeye caches almost everything it does to avoid running the same queries for the same data repeatedly—which would be inefficient and time-consuming. A "workspace" is essentially a directory where the cache is stored. It is recommended to use a unique workspace (configured via the `--workspace` flag) and stick with it for as long as possible. Once you begin a hunt, continue using the same workspace to leverage the cache and minimize round-trip times (RTT).

If, for some reason, you want all data to be fetched fresh from the API, you can use the `--no-cache` option. However, this is generally not recommended unless absolutely necessary.