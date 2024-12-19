import asyncio
import hashlib
import logging
import os
import pickle
import urllib.parse
from typing import Any, Optional

from censys.search import SearchClient

from .config import Config
from .const import USER_AGENT
from .gadget import GADGET_NAMESPACE, Gadget, QueryGeneratorGadget


class Aggregator:
    MAX_VALUE_LENGTH = 255  # we don't search for kv pairs longer than this value.

    def __init__(
        self,
        cache_dir=None,
        query_prefix=None,
        duo_reporting=False,
        config: Optional[Config] = None,
        armed_gadgets: Optional[set[Gadget]] = None,
    ):
        self.client = SearchClient(user_agent=USER_AGENT)
        self.seen_hosts: set[str] = set()
        self.seen_queries: set[tuple[str, Any]] = set()
        self.cache_dir = cache_dir
        self.num_queries = 0
        self.query_prefix = query_prefix
        self.duo_reporting = duo_reporting
        if config is None:
            config = Config()
        self.config = config
        self.workers = config.workers
        if armed_gadgets is None:
            armed_gadgets = set()
        self.gadgets = armed_gadgets

        if self.cache_dir:
            os.makedirs(self.cache_dir, exist_ok=True)

    def _is_kv_filtered(self, k, v, parent=None):
        import json

        logging.debug(f"Checking if {json.dumps(k)}={v} is filtered")
        if len(str(v)) > self.MAX_VALUE_LENGTH:
            return True

        if parent and self.config[parent]:
            field = self.config[parent]
            if not field:
                return False

            for ent in field.ignore:
                if k in ent and (v in ent[k] or "*" in ent[k]):
                    return True

        elif k in self.config:
            field = self.config[k]
            if not field:
                return False
            return v in field.ignore

        return False

    def _generate_header_queries(self, headers, parent_key):
        """
        converts censys header fields to censys-like queries
        """
        results = []

        if not isinstance(headers, dict):
            return results

        for k, v in headers.items():
            if k == "_encoding":
                # internal censys thing, just discard
                continue

            # if v is not a list, discard
            if not isinstance(v, list):
                continue

            # censys stores headers with dashes converted to underscores
            header_key = k.replace("_", "-")
            for val in v:
                if "<REDACTED>" in v:
                    # discard redacted values
                    continue

                if header_key == "Location":
                    # censys stores locations as full URLs, we need to wildcard it minus
                    # the host for any further searching
                    if not self._is_kv_filtered(header_key, val, parent_key):
                        results.append(
                            (
                                parent_key,
                                f"(key: '{header_key}' and value.headers: '{val}')",
                            )
                        )

                    u = urllib.parse.urlparse(val)
                    val = f"*{u.path}"

                if self._is_kv_filtered(header_key, val, parent_key):
                    dstr = val[:50] + "..." if len(val) > 50 else val
                    logging.debug(
                        f"Excluding {header_key}={dstr}, it's not in our allowed header"
                        " k/v's"
                    )
                    continue

                val = val.replace("'", "\\'")

                # generate a censys-like header query
                results.append(
                    (parent_key, f"(key: '{header_key}' and value.headers: '{val}')")
                )

        return results

    def _generate_queries(self, data, parent_key=""):
        """
        converts censys field data to censys-like queries
        """
        results = []

        if isinstance(data, dict):
            for k, v in data.items():
                if k.startswith("_"):
                    # internal censys thing, discard
                    continue

                key = f"{parent_key}.{k}" if parent_key else k

                if k == "headers":
                    # special case for headers
                    results.extend(self._generate_header_queries(v, key))
                else:
                    results.extend(self._generate_queries(v, key))

        elif isinstance(data, list):
            for _, v in enumerate(data):
                key = f"{parent_key}"
                results.extend(self._generate_queries(v, key))
        else:
            if self._is_kv_filtered(parent_key, data):
                # make a shorter copy of data
                dstr = data[:50] + "..." if len(data) > 50 else data
                logging.debug(
                    f"Excluding {parent_key}={dstr}, it's not in our allowed k/v's"
                )
                return []

            if len(str(data)) > self.MAX_VALUE_LENGTH:
                logging.debug(f"Excluding {parent_key}, it's too long")
                return []

            kvpair = f"{parent_key}={data}"
            # have we seen this already? Then don't dup.
            if kvpair not in self.seen_queries:
                results.append((parent_key, data))

        return results

    def _cache_file(self, q):
        m = hashlib.md5(q.encode()).hexdigest()
        return os.path.join(self.cache_dir, f"{m}.pkl") if self.cache_dir else None

    def _load_from_cache(self, q):
        cache_file = self._cache_file(q)

        if cache_file and os.path.exists(cache_file):
            with open(cache_file, "rb") as f:
                return pickle.load(f)

        return None

    def _save_to_cache(self, q, res):
        cache_file = self._cache_file(q)
        logging.debug(f"Saving cache for query: {q} {cache_file}")

        if cache_file:
            with open(cache_file, "wb") as f:
                pickle.dump(res, f)

    def _get_certificate_observations(self, fingerprint):
        cached_res = self._load_from_cache(fingerprint)
        if cached_res:
            logging.debug(
                f"Found cached certificate observations for {fingerprint}: {cached_res}"
            )
            return cached_res

        try:
            obs = self.client.v2.certs.get_observations(fingerprint)
            self.num_queries += 1

            ret = dict()

            for ent in obs.get("observations", []):
                if "ip" not in ent:
                    continue
                if "last_observed_at" not in ent:
                    continue

                ret[ent["ip"]] = ent["last_observed_at"]

            logging.debug(
                f"Found {len(ret)} observations for certificate {fingerprint}"
            )
            self._save_to_cache(fingerprint, ret)
            return ret
        except Exception:
            logging.warning(
                f"Failed to fetch certificate observations for {fingerprint}"
            )
            return {}

    async def _get_aggregate_report(self, key, value):
        """
        fetches aggregate report on a query from censys, the value of which is the number of hosts
        """
        if self._is_kv_filtered(key, value):
            logging.debug(f"Excluding {key}={value}, it's not in our allowed k/v's")
            return None

        if isinstance(value, (int, float)):
            value = str(value)

        if "headers" not in key:
            value = (
                value.replace("\\", "\\\\")
                .replace('"', '\\"')
                .replace("\n", "\\n")
                .replace("\r", "\\r")
            )

        query = f'{key}="{value}"'

        if key.startswith("~"):
            if value.startswith("*"):
                logging.debug(f"Excluding query: {value}, it's a wildcard match")
                return None
            query = f'"{value}"'
        elif "headers" in key:
            query = f"{key}:{value}"
        elif key.endswith(f".{GADGET_NAMESPACE}"):
            # this query was generated by a gadget, so we expect the value to be the query we want to run.
            query = value

        if query == '""':
            return None

        if key.startswith("~"):
            # yes we do this again because we want to check for empty query beforehand
            # instead of just doing a raw string query, let's remove the original results from our report
            query = f'(not {key[1:]}:"{value}") and {query}'

        async def _aggregate_report(q):
            cached_result = self._load_from_cache(q)

            if cached_result:
                logging.debug(f"Found cached result for query: {q}")
                return cached_result

            logging.info(f"fetching aggregate report for query: {q}")

            try:
                report = await asyncio.to_thread(
                    self.client.v2.hosts.aggregate, q, "ip", num_buckets=1
                )
                self.num_queries += 1

                host_count = report["total"]
                ret = {"key": key, "val": value, "query": q, "hosts": host_count}
                self._save_to_cache(q, ret)
                return ret
            except Exception as e:
                logging.error(
                    f"Failed to fetch aggregate report for query: {q}, error: {e}"
                )
                return {"key": key, "val": value, "query": q, "hosts": 0}

        query_base = query

        if self.query_prefix:
            query = f"({self.query_prefix}) and ({query})"

        ret = dict()

        if query != query_base and self.duo_reporting:
            # We want to actually make two queries here, one with the query_prefix, and one without. The idea is that
            # we can create a report that shows "number_of_hosts_matching_query_prefix / total_number_of_hosts_matching_query"
            total_report = await _aggregate_report(query_base)  # without query_prefix
            match_report = await _aggregate_report(query)  # with query_prefix
            ret = match_report
            ret["noprefix_hosts"] = total_report["hosts"]
        else:
            ret = await _aggregate_report(query)

        # Special case for services.certificate values of '1' or even '0' (which can happen with --query-prefix)
        # we take that certificate fingerprint, and look for any historical observations.
        if key == "services.certificate" and ret["hosts"] <= 1:
            try:
                obs = self._get_certificate_observations(value)
                # if we only get one returned observation, it means it only matched the host we are running against.
                if obs and len(obs) > 1:
                    ret["historical_observations"] = obs
            except Exception as e:
                logging.error(
                    "Failed to fetch historical observations for certificate"
                    f" {value}: {e}"
                )

        logging.debug(f"aggregate report for query: {query}, hosts: {ret['hosts']}")
        return ret

    def get_queries(self, host_data):
        """
        generates censys-like queries from censys data
        """
        ret = []
        queries = self._generate_queries(host_data)

        # run our query generator gadgets.
        for gadget in self.gadgets:
            if not isinstance(gadget, QueryGeneratorGadget):
                continue
            try:
                pqueries = gadget.run(host_data)
                if pqueries:
                    queries.extend(pqueries)

            except Exception as e:
                logging.error(f"Gadget {gadget} failed: {e}")

        for k, v in queries:
            # check if there is a value-only variant.
            tkey = "~" + k
            if tkey in self.config:
                # this means we should also query just the value in a wildcard search
                # note that we also do the normal key=val statement too
                ret.append((tkey, v))

            if k in self.config:
                ret.append((k, v))

        return ret

    async def get_report(self, host_data):
        report = []
        queries = self.get_queries(host_data)
        sem = asyncio.Semaphore(self.workers)

        logging.info(
            f"{host_data['ip']} gave us {len(queries)} _potential_ pivots to try."
        )

        async def run_worker(k, v):
            async with sem:
                logging.debug(f"running report for '{k}={v}'")
                return await self._get_aggregate_report(k, v)

        tasks = [run_worker(k, v) for k, v in queries]

        logging.info(f"Enqueuing {host_data['ip']} for {len(queries)} reports")

        results = await asyncio.gather(*tasks)

        for result in results:
            if result:
                report.append(result)

        return report
