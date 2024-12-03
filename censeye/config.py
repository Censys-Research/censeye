from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Union

import yaml

IgnoreType = Optional[Union[List[str], List[Dict[str, List[str]]]]]


@dataclass
class Field:
    name: str
    weight: float = 0.0
    ignore: IgnoreType = field(default_factory=list)

    def __eq__(self, other: Any) -> bool:
        if isinstance(other, Field):
            return self.name == other.name
        if isinstance(other, str):
            return self.name == other
        return False

    def __hash__(self) -> int:
        return hash(self.name)


@dataclass
class Config:
    def __init__(self, config_file=None) -> None:
        self._load_defauts()

        if config_file:
            self._load_config(config_file)

    def _load_defauts(self):
        self.workers = 2
        self.max_serv_count = 20
        self.max_search_res = 45
        self.min_host_count = 2
        self.max_host_count = 120
        self.min_pivot_weight = 0.0

        self.fields = [
            Field(name="services.banner_hex", weight=1.0, ignore=[]),
            Field(name="services.ssh.endpoint_id.raw", weight=0.9, ignore=[]),
            Field(
                name="services.ssh.server_host_key.fingerprint_sha256",
                weight=1.0,
                ignore=[],
            ),
            Field(
                name="services.http.response.body_hash",
                weight=1.0,
                ignore=[
                    "sha1:4dcf84abb6c414259c1d5aec9a5598eebfcea842",
                    "sha256:55c801a02ad9a08dfdcf159ba0c8354b37189519ce9a95129941ec6daeca5648",
                    "sha1:11e71530661013137721d635f95630722eaa6afd",
                    "sha256:036bacf3bd34365006eac2a78e4520a953a6250e9550dcf9c9d4b0678c225b4c",
                ],
            ),
            Field(name="services.jarm.fingerprint", weight=1.0, ignore=[]),
            Field(
                name="services.tls.certificates.leaf_data.subject_dn",
                weight=1.0,
                ignore=[],
            ),
            Field(
                name="services.tls.certificates.leaf_data.issuer_dn",
                weight=1.0,
                ignore=[
                    "C=US, O=DigiCert Inc, CN=DigiCert Global G2 TLS RSA SHA256 2020 CA1"
                ],
            ),
            Field(
                name="~services.tls.certificates.leaf_data.issuer.common_name",
                weight=0.5,
                ignore=["127.0.0.1"],
            ),
            Field(
                name="services.tls.certificates.leaf_data.issuer.common_name",
                weight=1.0,
                ignore=["DigiCert Global G2 TLS RSA SHA256 2020 CA1"],
            ),
            Field(
                name="~services.tls.certificates.leaf_data.subject.organization",
                weight=0.5,
                ignore=["Cloudflare, Inc."],
            ),
            Field(
                name="services.tls.certificates.leaf_data.subject.organization",
                weight=1.0,
                ignore=[],
            ),
            Field(name="services.certificate", weight=1.0, ignore=[]),
            Field(
                name="services.http.response.html_tags",
                weight=0.9,
                ignore=[
                    "<title>301 Moved Permanently</title>",
                    "<title>403 Forbidden</title>",
                    "<title> 403 Forbidden </title>",
                    "<title>404 Not Found</title>",
                    "<title></title>",
                    "<title>401 - Unauthorized</title>",
                    "<TITLE>Not Found</TITLE>",
                    '<meta charset="UTF-8">',
                    '<meta charset="utf-8">',
                    "<title>400 The plain HTTP request was sent to HTTPS port</title>",
                    '<meta charset="UTF-8" />',
                    '<meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />',
                    '<META HTTP-EQUIV="Content-Type" CONTENT="text/html; charset=iso-8859-1">',
                    '<meta http-equiv="Content-Type" content="text/html; charset=utf-8">',
                    "<TITLE>ERROR: The request could not be satisfied</TITLE>",
                    "<title>400 The plain HTTP request was sent to HTTPS port</title>",
                ],
            ),
            Field(
                name="services.http.response.favicons.md5_hash", weight=0.9, ignore=[]
            ),
            Field(
                name="services.parsed.opc_ua.endpoints.endpoint_url",
                weight=0.5,
                ignore=[],
            ),
            Field(
                name="services.parsed.opc_ua.endpoints.server.product_uri",
                weight=0.5,
                ignore=[],
            ),
            Field(
                name="services.parsed.opc_ua.endpoints.server.application_name.text",
                weight=0.5,
                ignore=[],
            ),
            Field(
                name="~services.parsed.winrm.ntlm_info.dns_server_name",
                weight=0.1,
                ignore=[],
            ),
            Field(
                name="services.parsed.winrm.ntlm_info.dns_server_name",
                weight=0.4,
                ignore=[],
            ),
            Field(
                name="~services.parsed.winrm.ntlm_info.netbios_computer_name",
                weight=0.5,
                ignore=[],
            ),
            Field(
                name="services.parsed.winrm.ntlm_info.netbios_computer_name",
                weight=0.8,
                ignore=[],
            ),
            Field(name="services.snmp.oid_system.desc", weight=0.5, ignore=[]),
            Field(name="services.snmp.oid_system.contact", weight=0.5, ignore=[]),
            Field(name="services.snmp.oid_system.name", weight=0.3, ignore=[]),
            Field(name="services.snmp.oid_system.location", weight=0.2, ignore=[]),
            Field(name="services.snmp.engine.organization", weight=0.1, ignore=[]),
            Field(
                name="services.parsed.eip.identity.product_name", weight=0.4, ignore=[]
            ),
            Field(
                name="services.parsed.eip.identity.vendor_name", weight=0.3, ignore=[]
            ),
            Field(
                name="services.tls.certificates.leaf_data.subject.organizational_unit",
                weight=1.0,
                ignore=[],
            ),
            Field(
                name="~services.tls.certificates.leaf_data.subject.email_address",
                weight=0.2,
                ignore=[],
            ),
            Field(
                name="services.tls.certificates.leaf_data.subject.email_address",
                weight=0.5,
                ignore=[],
            ),
            Field(name="services.telnet.banner", weight=1.0, ignore=[]),
            Field(
                name="services.http.response.headers",
                weight=0.8,
                ignore=[
                    {"Location": ["*/"]},
                    {"Vary": ["Accept-Encoding"]},
                    {
                        "Content-Type": [
                            "text/html",
                            "text/html; charset=UTF-8",
                            "text/html;charset=UTF-8",
                            "text/html; charset=utf-8",
                        ]
                    },
                    {
                        "Content-type": [
                            "text/html",
                            "text/html; charset=UTF-8",
                            "text/html;charset=UTF-8",
                            "text/html; charset=utf-8",
                        ]
                    },
                    {"Connection": ["close", "keep-alive", "Keep-Alive"]},
                    {"Transfer-Encoding": ["chunked"]},
                    {"Pragma": ["no-cache"]},
                    {"Cache-Control": ["no-cache"]},
                    {"Content-Encoding": ["gzip"]},
                    {"Date": ["<REDACTED>"]},
                    {"X-Frame-Options": ["SAMEORIGIN", "DENY"]},
                    {"Server": ["nginx", "Microsoft-HTTPAPI/2.0", "cloudflare"]},
                    {"Content-Length": ["*"]},
                    {"Last-Modified": ["*"]},
                    {"Accept-Ranges": ["bytes"]},
                ],
            ),
            Field(
                name="~services.parsed.l2tp.sccrp.attribute_values.hostname",
                weight=0.2,
                ignore=[],
            ),
            Field(
                name="services.parsed.l2tp.sccrp.attribute_values.hostname",
                weight=0.5,
                ignore=[],
            ),
            Field(
                name="services.parsed.l2tp.sccrp.attribute_values.vendor_name",
                weight=0.5,
                ignore=[],
            ),
            Field(name="~services.vnc.desktop_name", weight=0.2, ignore=[]),
            Field(name="services.vnc.desktop_name", weight=0.5, ignore=[]),
            Field(name="services.bacnet.vendor_name", weight=0.4, ignore=[]),
            Field(
                name="services.bacnet.application_software_revision",
                weight=0.2,
                ignore=[],
            ),
            Field(name="services.bacnet.object_name", weight=0.2, ignore=[]),
            Field(name="services.bacnet.model_name", weight=0.2, ignore=[]),
            Field(name="~services.bacnet.description", weight=0.1, ignore=[]),
            Field(name="services.bacnet.description", weight=0.2, ignore=[]),
            Field(
                name="~services.parsed.chromecast.applications.display_name",
                weight=0.0,
                ignore=[],
            ),
            Field(
                name="services.parsed.chromecast.applications.display_name",
                weight=0.1,
                ignore=[],
            ),
            Field(name="services.cobalt_strike.x86.post_ex.x86", weight=0.1, ignore=[]),
            Field(name="services.cobalt_strike.x86.post_ex.x64", weight=0.1, ignore=[]),
            Field(
                name="services.cobalt_strike.x86.http_post.uri", weight=1.0, ignore=[]
            ),
            Field(name="services.cobalt_strike.x86.user_agent", weight=1.0, ignore=[]),
            Field(
                name="services.cwmp.http_info.favicons.md5_hash", weight=0.5, ignore=[]
            ),
            Field(name="services.cwmp.http_info.headers", weight=0.5, ignore=[]),
            Field(name="services.cwmp.http_info.html_tags", weight=0.5, ignore=[]),
            Field(name="services.parsed.cwmp.server", weight=1.0, ignore=[]),
            Field(
                name="~services.parsed.dhcpdiscover.params.device_info.machine_name",
                weight=0.2,
                ignore=[],
            ),
            Field(
                name="services.parsed.dhcpdiscover.params.device_info.machine_name",
                weight=0.5,
                ignore=[],
            ),
            Field(
                name="services.parsed.dhcpdiscover.params.device_info.device_type",
                weight=0.1,
                ignore=[],
            ),
            Field(
                name="services.parsed.dhcpdiscover.params.device_info.vendor",
                weight=0.1,
                ignore=[],
            ),
            Field(
                name="services.parsed.dhcpdiscover.params.device_info.version",
                weight=0.1,
                ignore=[],
            ),
            Field(
                name="services.elasticsearch.system_info.version.number",
                weight=0.1,
                ignore=[],
            ),
            Field(
                name="services.elasticsearch.system_info.version.lucene_version",
                weight=0.1,
                ignore=[],
            ),
            Field(
                name="services.elasticsearch.node_info.cluster_combined_info.name",
                weight=0.1,
                ignore=[],
            ),
            Field(
                name="services.elasticsearch.node_info.cluster_combined_info.indices.docs.count",
                weight=0.1,
                ignore=[],
            ),
            Field(
                name="services.elasticsearch.node_info.nodes.node_data.host",
                weight=0.3,
                ignore=[],
            ),
            Field(
                name="services.elasticsearch.node_info.nodes.node_data.name",
                weight=0.1,
                ignore=[],
            ),
            Field(name="services.parsed.etcd.v2.members.id", weight=0.1, ignore=[]),
            Field(
                name="services.parsed.etcd.v3.members.peer_urls", weight=0.1, ignore=[]
            ),
            Field(
                name="services.parsed.etcd.v3.members.client_urls",
                weight=0.2,
                ignore=[],
            ),
            Field(name="~services.fox.hostname", weight=0.2, ignore=[]),
            Field(name="services.fox.hostname", weight=0.5, ignore=[]),
            Field(name="~services.fox.station_name", weight=0.1, ignore=[]),
            Field(name="services.fox.station_name", weight=0.3, ignore=[]),
            Field(name="services.fox.sys_info", weight=0.1, ignore=[]),
            Field(name="services.fox.vm_version", weight=0.1, ignore=[]),
            Field(name="services.fox.os_version", weight=0.1, ignore=[]),
            Field(name="services.fox.hostId", weight=0.1, ignore=[]),
            Field(name="services.mms.model", weight=0.1, ignore=[]),
            Field(name="services.mms.vendor", weight=0.1, ignore=[]),
            Field(
                name="services.mongodb.build_info.git_version", weight=0.1, ignore=[]
            ),
            Field(name="services.mysql.server_version", weight=0.1, ignore=[]),
            Field(name="services.parsed.nbd.exports.name", weight=0.1, ignore=[]),
            Field(
                name="services.parsed.onvif.services.namespace", weight=0.1, ignore=[]
            ),
            Field(name="services.parsed.onvif.services.xaddr", weight=0.1, ignore=[]),
            Field(name="services.parsed.onvif.hostname.name", weight=0.1, ignore=[]),
            Field(name="services.parsed.pcom.model", weight=0.3, ignore=[]),
            Field(name="services.parsed.pcom.os_build", weight=0.1, ignore=[]),
            Field(name="services.parsed.pcom.os_version", weight=0.1, ignore=[]),
            Field(name="~services.pc_anywhere.name", weight=0.5, ignore=[]),
            Field(name="services.pc_anywhere.name", weight=1.0, ignore=[]),
            Field(name="~services.pptp.hostname", weight=0.5, ignore=[]),
            Field(name="services.pptp.hostname", weight=1.0, ignore=[]),
            Field(name="services.parsed.redlion_crimson.model", weight=0.1, ignore=[]),
            Field(
                name="services.parsed.rocketmq.topics.topic_list", weight=0.5, ignore=[]
            ),
            Field(name="services.parsed.rocketmq.version", weight=0.1, ignore=[]),
            Field(name="services.s7.plant_id", weight=0.2, ignore=[]),
            Field(name="services.s7.memory_serial_number", weight=0.3, ignore=[]),
            Field(name="~services.parsed.scpi.manufacturer", weight=0.0, ignore=[]),
            Field(name="services.parsed.scpi.manufacturer", weight=0.1, ignore=[]),
            Field(name="services.parsed.scpi.model", weight=0.1, ignore=[]),
            Field(name="services.parsed.scpi.firmware", weight=0.1, ignore=[]),
            Field(name="services.smb.group_name", weight=1.0, ignore=[]),
            Field(name="services.smb.ntlm", weight=0.1, ignore=[]),
            Field(name="services.upnp.devices.manufacturer", weight=0.1, ignore=[]),
            Field(name="~services.upnp.devices.model_name", weight=0.0, ignore=[]),
            Field(name="services.upnp.devices.model_name", weight=0.1, ignore=[]),
            Field(name="services.upnp.devices.serial_number", weight=0.1, ignore=[]),
            Field(
                name="services.parsed.zeromq.handshake.socket_type",
                weight=0.0,
                ignore=[],
            ),
            Field(
                name="services.tls.certificate.parsed.issuer.locality",
                weight=1.0,
                ignore=[],
            ),
        ]

    def _load_config(self, config_file):
        with open(config_file, "r") as file:
            cfg = yaml.safe_load(file)

        self.workers = cfg.get("workers", self.workers)
        self.max_serv_count = cfg.get("max_serv_count", self.max_serv_count)
        self.max_search_res = cfg.get("max_search_results", self.max_search_res)
        self.min_host_count = cfg.get("rarity", {}).get("min", self.min_host_count)
        self.max_host_count = cfg.get("rarity", {}).get("max", self.max_host_count)
        self.min_pivot_weight = cfg.get("min_pivot_weight", self.min_pivot_weight)

        if "fields" in cfg:
            for item in cfg["fields"]:
                self.fields.append(
                    Field(
                        name=item["field"],
                        weight=item.get("weight", 0.0),
                        ignore=item.get("ignore", []),
                    )
                )

    def __iter__(self):
        return iter(self.fields)

    def __getitem__(self, key):
        for field in self.fields:
            if field == key:
                return field
        return None


if __name__ == "__main__":
    cfg = Config("config.yaml")
    for field in cfg:
        print(field)