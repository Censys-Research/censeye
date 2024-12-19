import asyncio
import logging
import sys
import urllib.parse
from collections import defaultdict
from typing import Optional

import click
from appdirs import user_cache_dir
from dateutil import parser as dateutil_parser
from rich import box
from rich.console import Console
from rich.style import Style
from rich.table import Table
from rich.tree import Tree

from . import censeye
from .__version__ import __version__
from .config import Config
from .const import DEFAULT_MAX_SEARCH_RESULTS
from .gadget import GADGET_NAMESPACE, Gadget
from .gadgets import unarmed_gadgets

console = Console(record=True, soft_wrap=True)


async def run_censeye(
    ip,
    depth=0,
    cache_dir=None,
    console=console,
    at_time=None,
    query_prefix=None,
    duo_reporting=False,
    config: Optional[Config] = None,
    gadgets: Optional[set[Gadget]] = None,
):
    if config is None:
        config = Config()

    if cache_dir is None:
        cache_dir = user_cache_dir("censys/censeye")
        logging.debug(f"Using cache dir: {cache_dir}")

    if gadgets is None:
        gadgets = set()

    c = censeye.Censeye(
        depth=depth,
        cache_dir=cache_dir,
        at_time=at_time,
        query_prefix=query_prefix,
        duo_reporting=duo_reporting,
        config=config,
        armed_gadgets=gadgets,
    )

    result, searches = await c.run(ip)
    searches = sorted(searches)
    seen_hosts = set()

    # TODO: make these configurable, e.g., themes.
    style_bold = Style(bold=True)
    style_gadget = Style(bold=False, color="#5696CC")
    style_gadget_bold = Style(bold=True, color="#9FC3E2")

    for host in result:
        if host["ip"] in seen_hosts:
            continue

        seen_hosts.add(host["ip"])
        if host["depth"] > depth:
            # these are just empty anyway.
            continue

        sres = sorted(host["report"], key=lambda x: x["hosts"], reverse=True)
        link = f"https://search.censys.io/hosts/{host['ip']}"

        if "at_time" in host and host["at_time"] is not None:
            try:
                at_encoded = urllib.parse.quote(
                    host["at_time"].isoformat(timespec="milliseconds") + "Z"
                )
                link = f"{link}?at_time={at_encoded}"
            except Exception:
                pass

        title = (
            f"[link={link}]{host['ip']}[/link] (depth: {host['depth']}) (Via:"
            f" {host['parent_ip']} -- {host['found_via']} -- {host['labels']})"
        )

        table = Table(
            title=title,
            min_width=20,
            title_justify="left",
            box=box.SIMPLE_HEAVY,
        )

        table.add_column("Hosts", justify="right", style="magenta")
        table.add_column("Key", justify="left", style="cyan", no_wrap=False)
        table.add_column(
            "Val", justify="left", style="green", no_wrap=False, overflow="fold"
        )

        seen_rows = set()
        hist_obs = dict()

        for r in sres:
            key = r["key"]
            if key.startswith("services."):
                key = key[len("services.") :]
            elif key.startswith("~services."):
                key = key[len("~services.") :]
                key = f"{key} (VALUE ONLY)"

            if key.startswith("parsed."):
                key = key[len("parsed.") :]
            elif key.startswith("~parsed."):
                key = key[len("~parsed.") :]
                key = f"{key} (VALUE ONLY)"

            row = (key, r["val"])

            host_count = f"{r['hosts']}"
            hist_count = 0

            urlenc_query = urllib.parse.quote(r["query"])
            key = f"[link=https://search.censys.io/search?resource=hosts&q={urlenc_query}]{key}[/link]"

            if "historical_observations" in r:
                hist_count = len(r["historical_observations"])
                hkey = f"{r['key']}={r['val']}"
                if hkey not in hist_obs:
                    hist_obs[hkey] = r["historical_observations"]

            if row not in seen_rows:
                row_style = None
                count_col = ""

                if (
                    r["hosts"] <= config.max_host_count
                    and (r["hosts"] + hist_count) > 1
                ):
                    if r["key"].endswith(f".{GADGET_NAMESPACE}"):
                        row_style = style_gadget_bold
                    else:
                        row_style = style_bold

                    if hist_count:
                        count_col = f"{host_count} (+{hist_count})"
                    else:
                        count_col = f"{host_count}"
                else:
                    if r["key"].endswith(f".{GADGET_NAMESPACE}"):
                        row_style = style_gadget
                    count_col = f"{host_count}"

                if "noprefix_hosts" in r:
                    count_col = f"{count_col} / {r['noprefix_hosts']}"

                table.add_row(count_col, key, r["val"], style=row_style)
                seen_rows.add(row)

        console.print(table)

        if len(hist_obs) > 0:
            htree = Tree(f"Historical Certificate Observations: {len(hist_obs)}")

            for k, v in hist_obs.items():
                sorted_v = dict(
                    sorted(
                        v.items(),
                        key=lambda item: dateutil_parser.isoparse(item[1]),
                        reverse=False,
                    )
                )

                node = htree.add(k)

                for hip, at_time in sorted_v.items():
                    if host["ip"] != hip:
                        lnk = f"https://search.censys.io/hosts/{hip}?at_time={at_time}"
                        node.add(f"{at_time}: [link={lnk}]{hip}[/link]")

            console.print(htree)
            console.print()

    console.print(f"Interesting search terms: {len(searches)}")
    for s in searches:
        # urlencode "s"
        ul = urllib.parse.quote(s)
        console.print(
            f" - [link=https://search.censys.io/search?resource=hosts&q={ul}]{s}[/link]"
        )

    console.print()
    if depth > 0:
        ipmap = defaultdict(list)
        root = None
        seen = set()

        for host in result:
            parent = host["parent_ip"]
            nfo = (
                host["ip"],
                host["found_via"],
                host["labels"],
                host.get("at_time", None),
            )

            if parent is None:
                root = host["ip"]

            ipmap[parent].append(nfo)

        def _build_tree(ip, parent_tree):
            if ip in seen:
                return

            seen.add(ip)

            for cip, via, labels, at_time in ipmap[ip]:
                cip_fmt = f"{cip:<15}"
                via_str = f"via: [i]{via}[/i]"

                if at_time:
                    via_str = f"{via_str} @ {at_time}"

                lnk = (
                    f"[link=https://search.censys.io/hosts/{cip}][b]{cip_fmt}[/b][/link]"
                    f" ({via_str}) {labels}"
                )

                child_tree = parent_tree.add(lnk)
                _build_tree(cip, child_tree)

        if root is None:
            return

        tree = Tree(f"[link=https://search.censys.io/hosts/{root}][b]{root}[/b][/link]")
        _build_tree(root, tree)

        console.print("Pivot Tree:")
        console.print(tree)

    console.print(f"Total queries used: {c.get_num_queries()}")


@click.command(
    context_settings=dict(max_content_width=125, help_option_names=["-h", "--help"])
)
@click.argument(
    "ip",
    required=False,
)
@click.option(
    "--depth",
    "-d",
    default=0,
    help=(
        "[auto-pivoting] search depth (0 is single host, 1 is all the hosts that host"
        " found, etc...)"
    ),
)
@click.option(
    "--workers",
    default=4,
    help="number of workers to run queries in parallel",
)
@click.option(
    "--workspace",
    "-w",
    default=None,
    help="directory for caching results (defaults to XDG configuration path)",
)
@click.option(
    "--max-search-results",
    "-m",
    default=DEFAULT_MAX_SEARCH_RESULTS,
    help="maximum number of censys search results to process",
)
@click.option(
    "--log-level",
    "-ll",
    default=None,
    help="set the logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)",
)
@click.option("--save", "-s", default=None, help="save report to a file")
@click.option(
    "--pivot-threshold",
    "-p",
    default=128,
    help=(
        "maximum number of hosts for a search term that will trigger a pivot (default:"
        " 128)"
    ),
)
@click.option(
    "--at-time",
    "-a",
    type=click.DateTime(formats=["%Y-%m-%d %H:%M:%S", "%Y-%m-%d"]),
    help="historical host data at_time.",
)
@click.option(
    "--query-prefix",
    "-q",
    default=None,
    help=(
        "prefix to add to all queries (useful for filtering, the ' and ' is added"
        " automatically)"
    ),
)
@click.option(
    "--input-workers",
    default=2,
    help=(
        "number of parallel workers to process inputs (e.g., only has an effect on"
        " stdin inputs)"
    ),
)
@click.option(
    "--query-prefix-count",
    "-qp",
    is_flag=True,
    default=False,
    help=(
        "If the --query-prefix is set, this will return a count of hosts for both the"
        " filtered and unfiltered results."
    ),
)
@click.option(
    "--config",
    "-c",
    "cfgfile_",
    default=None,
    help="configuration file path",
)
@click.option(
    "--min-pivot-weight",
    "-mp",
    "-M",
    type=float,
    help=(
        "[auto-pivoting] only pivot into fields with a weight greater-than or equal-to"
        " this number (see configuration)"
    ),
)
@click.option(
    "--fast", is_flag=True, help="[auto-pivoting] alias for --min-pivot-weight 1.0"
)
@click.option(
    "--slow", is_flag=True, help="[auto-pivoting] alias for --min-pivot-weight 0.0"
)
@click.option(
    "--gadget",
    "-g",
    "-G",
    multiple=True,
    help="list of gadgets to load",
)
@click.option("--list-gadgets", is_flag=True, help="list available gadgets")
@click.version_option(__version__)
def main(
    ip,
    depth,
    workers,
    workspace,
    max_search_results,
    log_level,
    save,
    pivot_threshold,
    at_time,
    query_prefix,
    input_workers,
    query_prefix_count,
    cfgfile_,
    min_pivot_weight,
    fast,
    slow,
    gadget,
    list_gadgets,
):
    if sum([fast, slow]) > 1:
        print("Only one of --fast or --slow can be set.")
        sys.exit(1)

    cfg = Config(cfgfile_)

    if workers:
        cfg.workers = workers

    if max_search_results:
        cfg.max_search_res = max_search_results

    if pivot_threshold:
        cfg.max_host_count = pivot_threshold

    if min_pivot_weight:
        cfg.min_pivot_weight = min_pivot_weight

    if fast:
        cfg.min_pivot_weight = 1.0

    if slow:
        cfg.min_pivot_weight = 0.0

    for g in gadget:
        cfg.gadgets.enable(g)

    armed_gadgets = set()

    for g in cfg.gadgets.enabled():
        if g.name not in unarmed_gadgets:
            raise ValueError(f"gadget {g} not loaded!")

        loaded_gadget = unarmed_gadgets[g.name]
        loaded_gadget.config = g.config
        armed_gadgets.add(loaded_gadget)

    def _parse_ip(d):
        period_replacements = ["[.]", ".]", "[."]
        remove = ['"', ","]

        for r in period_replacements:
            d = d.replace(r, ".")
        for r in remove:
            d = d.replace(r, "")
        return d.strip()

    logging.captureWarnings(True)

    if log_level:
        llevel = getattr(logging, log_level.upper(), None)

        if not isinstance(llevel, int):
            raise ValueError(f"Invalid log level: {log_level}")

        logging.basicConfig(
            level=llevel,
            format=(
                "%(asctime)s [%(filename)s:%(lineno)d] - %(levelname)s - %(message)s"
            ),
        )
    else:
        logging.basicConfig(
            level=logging.CRITICAL,
            format=(
                "%(asctime)s [%(filename)s:%(lineno)d] - %(levelname)s - %(message)s"
            ),
        )

    console = Console(record=True, soft_wrap=True)

    if list_gadgets:
        table = Table(title="available gadgets", box=box.MINIMAL_DOUBLE_HEAD)
        table.add_column("name", no_wrap=True)
        table.add_column("aliases", no_wrap=True)
        table.add_column("desc", no_wrap=False)

        for name, g in unarmed_gadgets.items():
            table.add_row(
                f"[bold]{name}[/bold]", f"[i]{', '.join(g.aliases)}[/i]", g.__doc__
            )

        console.print(table)
        sys.exit(0)

    async def _run_worker(queue):
        while not queue.empty():
            ip = await queue.get()
            logging.debug(
                f"processing {ip} - max_search_results: {max_search_results} -"
                f" pivot_threshold: {pivot_threshold} - query_prefix: {query_prefix} -"
                f" cache_dir: {workspace} - workers: {workers} - at_time: {at_time} -"
                f" depth: {depth} - save: {save} min_pivot_weight: {min_pivot_weight}"
            )
            await run_censeye(
                ip,
                duo_reporting=query_prefix_count,
                query_prefix=query_prefix,
                cache_dir=workspace,
                at_time=at_time,
                depth=depth,
                console=console,
                config=cfg,
                gadgets=armed_gadgets,
            )
            queue.task_done()

    async def _run_stdin():
        wqueue = asyncio.Queue()
        for line in sys.stdin:
            ip = line.strip()
            if ip:
                await wqueue.put(_parse_ip(ip))

        tasks = []
        for _ in range(input_workers):
            tasks.append(_run_worker(wqueue))

        await asyncio.gather(*tasks)

    if ip == "-" or not ip:
        logging.info("processing IPs from stdin")
        asyncio.run(_run_stdin())
    else:
        asyncio.run(
            run_censeye(
                _parse_ip(ip),
                duo_reporting=query_prefix_count,
                query_prefix=query_prefix,
                cache_dir=workspace,
                at_time=at_time,
                depth=depth,
                console=console,
                config=cfg,
                gadgets=armed_gadgets,
            )
        )

    if save:
        console.save_html(save)


if __name__ == "__main__":
    main()
