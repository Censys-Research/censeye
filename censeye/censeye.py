import asyncio
import hashlib
import logging
import os
import pickle
from typing import Optional

from censys.search import CensysHosts

from .aggregator import Aggregator
from .config import Config
from .const import USER_AGENT
from .gadget import Gadget, HostLabelerGadget


class Censeye:
    QUEUE_TYPE_HOST = 0
    QUEUE_TYPE_SEARCH = 1

    def __init__(
        self,
        depth=0,
        cache_dir=None,
        at_time=None,
        query_prefix=None,
        duo_reporting=False,
        config: Optional[Config] = None,
        armed_gadgets: Optional[set[Gadget]] = None,
    ):
        if config is None:
            config = Config()
        self.config = config
        self.workers = config.workers
        self.client = CensysHosts(user_agent=USER_AGENT)
        if armed_gadgets is None:
            armed_gadgets = set()
        self.find = Aggregator(
            cache_dir=cache_dir,
            query_prefix=query_prefix,
            duo_reporting=duo_reporting,
            config=config,
            armed_gadgets=armed_gadgets,
        )
        self.seen_hosts: set[str] = set()
        self.depth = depth
        self.cache_dir = cache_dir
        self.at_time = at_time
        self.query_prefix = (
            query_prefix  # this gets appended to every report and search
        )
        self.num_queries = 0
        self.in_transit: set[str] = set()
        self.search_buckets: dict[int, set[str]] = dict()
        self.lock = asyncio.Lock()
        self.duo_reporting = duo_reporting
        self.gadgets = armed_gadgets

        if self.cache_dir:
            os.makedirs(self.cache_dir, exist_ok=True)

        logging.info(
            f"max_host_count: {self.config.max_host_count}, min_host_count:"
            f" {self.config.min_host_count}, max_service_count:"
            f" {self.config.max_serv_count} workers: {self.config.workers} depth:"
            f" {self.depth} cache_dir: {self.cache_dir}"
        )

    def _get_cache_filename(self, input_data, at_time=None, other=None):
        fmt = f"{input_data}_{self.config.max_search_res}"

        if at_time:
            fmt = f"{fmt}_{at_time}"

        if other:
            fmt = f"{fmt}_{other}"

        input_hash = hashlib.md5(fmt.encode("utf-8")).hexdigest()

        return (
            os.path.join(self.cache_dir, f"{input_hash}.pkl")
            if self.cache_dir
            else None
        )

    def _load_from_cache(self, input_data, at_time=None, other=None):
        cache_file = self._get_cache_filename(input_data, at_time, other)

        if cache_file and os.path.exists(cache_file):
            with open(cache_file, "rb") as f:
                logging.debug(
                    f"Loaded cached data {cache_file} for input: {input_data}"
                )
                return pickle.load(f)

        return None

    def _save_to_cache(self, input_data, data, at_time=None, other=None):
        cache_file = self._get_cache_filename(input_data, at_time, other)

        if cache_file:
            with open(cache_file, "wb") as f:
                pickle.dump(data, f)
                logging.debug(f"Saved data for input: {input_data} to cache")

    async def _get_host(self, ip, at_time=None):
        if ip in self.seen_hosts:
            return None

        cache = self._load_from_cache(ip, at_time=at_time)

        if cache:
            self.seen_hosts.add(ip)
            return cache

        try:
            data = await asyncio.to_thread(self.client.view, ip, at_time=at_time)

            if data:
                self.seen_hosts.add(ip)
                self.num_queries += 1
                self._save_to_cache(ip, data, at_time=at_time)
                return data
        except Exception as e:
            logging.error(f"Error fetching host data for {ip}: {e}")

        return None

    async def _search(self, qstr):
        """Use Censys API to search for hosts based on the query and cache the results."""
        qstr = (  # Exclude unwanted host types
            f"({qstr}) and not labels={{tarpit, truncated}}"
        )
        if self.query_prefix:
            qstr = f"({self.query_prefix}) and ({qstr})"

        logging.debug(f"Searching for: {qstr}")

        # Check if the search query is cached
        # we set other here because we want our cache to be unique to the number of results we want.
        cached_results = self._load_from_cache(qstr, other=self.config.max_search_res)
        if cached_results:
            logging.info(f"Cache hit for query: {qstr}")
            for host in cached_results:
                yield host["ip"]
            return
        else:
            logging.info(f"Cache miss for query: {qstr}")

        try:
            pages = max(1, self.config.max_search_res // 100)
            per_page = min(100, self.config.max_search_res)
            logging.info(f"Searching for: {qstr}, pages: {pages}, per_page={per_page}")

            self.num_queries += 1
            res = await asyncio.to_thread(
                self.client.search,
                qstr,
                per_page=per_page,
                pages=pages,
            )

            all_hosts = []
            for page in res:
                for host in page:
                    if len(host["services"]) <= self.config.max_serv_count:
                        all_hosts.append(host)
                        yield host["ip"]

            self._save_to_cache(qstr, all_hosts, other=self.config.max_search_res)

        except Exception as e:
            logging.error(f"Error during search with query '{qstr}': {e}")

    async def _process_ip(
        self, ip, depth, parent, results, searches, queue, query, at_time=None
    ):
        if depth not in self.search_buckets:
            self.search_buckets[depth] = set()

        id = f"{ip}@{at_time}"

        async with self.lock:
            if id in self.in_transit:
                return
            self.in_transit.add(id)

        logging.info(f"processing {ip} (triggered by: {parent}, depth: {depth})")

        data = await self._get_host(ip, at_time=at_time)

        for gadget in self.gadgets:
            if not isinstance(gadget, HostLabelerGadget):
                continue

            logging.info(f"Running labeler gadget {gadget}")

            try:
                if data:
                    gadget.run(data)
            except Exception as e:
                logging.error(f"Gadget {gadget} failed: {e}")

        async with self.lock:
            self.in_transit.remove(id)

        if not data:
            return

        report = await self.find.get_report(data)
        result = {
            "ip": ip,
            "labels": data.get("labels", []),
            "report": report,
            "parent_ip": parent,
            "found_via": query,
            "depth": depth,
            "at_time": at_time,
        }

        for r in report:
            # for each result in the report, if it matches our min/max hostcount, then queue
            # it up for grabbing host _SEARCH_ results.
            if "historical_observations" in r:
                for hip, at_time in r["historical_observations"].items():
                    logging.debug(
                        f"Found historical observation for {hip} at {at_time}"
                    )
                    await queue.put(
                        (
                            self.QUEUE_TYPE_HOST,
                            (hip, at_time, r["query"]),
                            depth + 1,
                            ip,
                        )
                    )

            # need this to grab the weight assigned to this field.
            field = self.config[r["key"]]
            weight = field.weight if field else 0.0

            if self.config.min_host_count <= r["hosts"] <= self.config.max_host_count:
                new_query = r["query"]

                searches.add(new_query)

                # only add if this query hasn't been seen at this depth or any previous depth
                if not any(
                    new_query in self.search_buckets.get(d, set())
                    for d in range(depth + 1)
                ):
                    if depth + 1 > self.depth:
                        logging.debug(
                            f"max depth reached for query: {new_query}, not going any"
                            " further."
                        )
                    else:
                        if weight >= self.config.min_pivot_weight:
                            logging.info(
                                f"Pivoting into:'{new_query}' via: (ip={ip},"
                                f" parent={parent}, host_count={r['hosts']})"
                            )

                            self.search_buckets.setdefault(depth, set()).add(new_query)

                            await queue.put(
                                (self.QUEUE_TYPE_SEARCH, new_query, depth + 1, ip)
                            )

        results.append(result)

    async def _worker(self, queue, results, searches_set):
        while True:
            try:
                q_type, query, depth, parent_ip = await queue.get()

                logging.debug(f"got job: {q_type}, {query}, {depth}, {parent_ip}")

                if depth > self.depth:
                    logging.debug(
                        f"max depth reached for query: {query}, not going any further."
                    )
                    queue.task_done()
                    continue

                if q_type == self.QUEUE_TYPE_SEARCH:
                    async for found_ip in self._search(query):
                        if found_ip not in self.find.seen_hosts:
                            await self._process_ip(
                                found_ip,
                                depth,
                                parent_ip,
                                results,
                                searches_set,
                                queue,
                                query,
                            )
                elif q_type == self.QUEUE_TYPE_HOST:
                    # we store extra information in the query element of this job, so
                    # extract it and process.
                    (ip, at_time, parent_query) = query

                    if query not in self.find.seen_hosts:
                        await self._process_ip(
                            ip,
                            depth,
                            parent_ip,
                            results,
                            searches_set,
                            queue,
                            parent_query,
                            at_time=at_time,
                        )

                queue.task_done()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logging.error(f"worker error: {e}")
                queue.task_done()

    async def run(self, ip):
        searches = set()
        queue = asyncio.Queue()
        results = []

        workers = [
            asyncio.create_task(self._worker(queue, results, searches))
            for _ in range(self.config.workers)
        ]

        await self._process_ip(
            ip, 0, None, results, searches, queue, "", at_time=self.at_time
        )
        await queue.join()

        for w in workers:
            w.cancel()

        await asyncio.gather(*workers, return_exceptions=True)

        return results, searches

    def get_num_queries(self):
        return self.num_queries + self.find.num_queries
