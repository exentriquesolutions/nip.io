#!/usr/bin/env python3
# Copyright 2022 Exentrique Solutions Ltd
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""A custom PipeBackend for PowerDNS that does wildcard DNS for any IP address."""

import configparser
import os
import re
import sys
from ipaddress import AddressValueError, IPv4Address, IPv4Network
from typing import Dict, Iterable, List, Optional, Tuple


def _is_debug() -> bool:
    return False


def _resolve_configuration(
    environment_key: str,
    config: configparser.ConfigParser,
    config_section: str,
    config_key: str,
) -> str:
    environment_value = os.getenv(environment_key)
    if environment_value:
        return environment_value
    config_value = config.get(config_section, config_key)
    if config_value:
        return config_value
    raise RuntimeError(
        f"Failed to resolve config for environment_key={environment_key} "
        f"config section={config_section} key=${config_key}"
    )


def _get_env_splitted(
    key: str,
    default: Optional[List[Tuple[str, str]]] = None,
    linesep: str = " ",
    pairsep: str = "=",
) -> Iterable[Tuple[str, str]]:
    environment_value = os.getenv(key)
    if environment_value:
        values = environment_value.split(linesep)
        result: List[Tuple[str, str]] = []
        for value in values:
            parts = value.split(pairsep, 1)
            result.append((parts[0], parts[1]))
        return result
    else:
        if not default:
            default = []
        return default


def _log(msg: str) -> None:
    sys.stderr.write("backend (%s): %s\n" % (os.getpid(), msg))


def _write(*args: str) -> None:
    args_len = len(args)
    c = 0
    for arg in args:
        c += 1
        if _is_debug():
            _log(f"writing: {arg}")
        sys.stdout.write(arg)
        if c < args_len:
            if _is_debug():
                _log("writetab")
            sys.stdout.write("\t")
    if _is_debug():
        _log("writenewline")
    sys.stdout.write("\n")
    sys.stdout.flush()


def _get_next() -> List[str]:
    if _is_debug():
        _log("reading now")
    line = sys.stdin.readline()
    if _is_debug():
        _log(f"read line: {line}")
    return line.strip().split("\t")


def _get_default_config_file() -> str:
    return os.path.join(os.path.dirname(os.path.realpath(__file__)), "backend.conf")


class DynamicBackend:
    """PowerDNS dynamic pipe backend.

    Attributes:
        id
        soa
        domain
        ip_address
        ttl
        name_servers
        whitelisted_ranges
        blacklisted_ips
        caa
        bits
        auth

    Environment variables:
    NIPIO_DOMAIN -- NIP.IO main domain.
    NIPIO_TTL -- Default TTL for NIP.IO backend.
    NIPIO_NONWILD_DEFAULT_IP -- Default IP address for non-wildcard entries.
    NIPIO_SOA_ID -- SOA serial number.
    NIPIO_SOA_HOSTMASTER -- SOA hostmaster email address.
    NIPIO_SOA_NS -- SOA name server.
    NIPIO_SOA_REFRESH -- SOA refresh.
    NIPIO_SOA_RETRY -- SOA retry.
    NIPIO_SOA_EXPIRY -- SOA expiry.
    NIPIO_SOA_MINIMUM_TTL -- SOA minimum time-to-live (TTL).
    NIPIO_NAMESERVERS -- A space-separated list of domain=ip nameserver pairs.
    NIPIO_WHITELIST -- A space-separated list of description=range pairs to whitelist.
                       The range should be in CIDR format.
    NIPIO_BLACKLIST -- A space-separated list of description=ip blacklisted pairs.
    NIPIO_CAA -- A space-separated list of description=value pairs for CAA `issue`
                 records returned for whitelisted IPs
    NIPIO_AUTH -- Indicates whether this response is authoritative, this is for DNSSEC.
    NIPIO_BITS -- Scopebits indicates how many bits from the subnet provided in
                  the question.

    Example:
        backend = DynamicBackend()
        backend.configure()
        backend.run()

    https://doc.powerdns.com/authoritative/backends/pipe.html
    """

    def __init__(self) -> None:
        self.id = ""
        self.soa = ""
        self.domain = ""
        self.ip_address = ""
        self.ttl = ""
        self.name_servers: Dict[str, str] = {}
        self.whitelisted_ranges: List[IPv4Network] = []
        self.blacklisted_ips: List[str] = []
        self.caa: List[str] = []
        self.bits = "0"
        self.auth = "1"

    def configure(self, config_filename: str = _get_default_config_file()) -> None:
        """Configure the pipe backend using the backend.conf file.

        Also reads configuration values from environment variables.
        """
        if not os.path.exists(config_filename):
            _log(f"file {config_filename} does not exist")
            sys.exit(1)

        with open(config_filename) as fp:
            config = configparser.ConfigParser()
            config.read_file(fp)

        self.id = os.getenv("NIPIO_SOA_ID", config.get("soa", "id"))
        self.soa = "%s %s %s %s %s %s %s" % (
            _resolve_configuration("NIPIO_SOA_NS", config, "soa", "ns"),
            _resolve_configuration("NIPIO_SOA_HOSTMASTER", config, "soa", "hostmaster"),
            self.id,
            _resolve_configuration("NIPIO_SOA_REFRESH", config, "soa", "refresh"),
            _resolve_configuration("NIPIO_SOA_RETRY", config, "soa", "retry"),
            _resolve_configuration("NIPIO_SOA_EXPIRY", config, "soa", "expiry"),
            _resolve_configuration("NIPIO_SOA_MINIMUM_TTL", config, "soa", "minimum"),
        )
        self.domain = os.getenv("NIPIO_DOMAIN", config.get("main", "domain"))
        self.ip_address = os.getenv(
            "NIPIO_NONWILD_DEFAULT_IP", config.get("main", "ipaddress")
        )
        self.ttl = os.getenv("NIPIO_TTL", config.get("main", "ttl"))
        self.name_servers = dict(
            _get_env_splitted("NIPIO_NAMESERVERS", config.items("nameservers"))
        )
        self.bits = os.getenv("NIPIO_BITS", config.get("main", "bits"))
        self.auth = os.getenv("NIPIO_AUTH", config.get("main", "auth"))

        if "NIPIO_WHITELIST" in os.environ or config.has_section("whitelist"):
            for entry in _get_env_splitted(
                "NIPIO_WHITELIST",
                config.items("whitelist") if config.has_section("whitelist") else [],
            ):
                # Convert the given range to an IPv4Network
                self.whitelisted_ranges.append(IPv4Network(entry[1]))

        if "NIPIO_BLACKLIST" in os.environ or config.has_section("blacklist"):
            for entry in _get_env_splitted(
                "NIPIO_BLACKLIST",
                config.items("blacklist") if config.has_section("blacklist") else [],
            ):
                self.blacklisted_ips.append(entry[1])

        if "NIPIO_CAA" in os.environ or config.has_section("caa"):
            for entry in _get_env_splitted(
                "NIPIO_CAA",
                config.items("caa") if config.has_section("caa") else [],
            ):
                self.caa.append(entry[1])

        _log(f"Name servers: {self.name_servers}")
        _log(f"ID: {self.id}")
        _log(f"TTL: {self.ttl}")
        _log(f"SOA: {self.soa}")
        _log(f"IP address: {self.ip_address}")
        _log(f"Domain: {self.domain}")
        _log(f"Whitelisted IP ranges: {[str(r) for r in self.whitelisted_ranges]}")
        _log(f"Blacklisted IPs: {self.blacklisted_ips}")
        _log(f"CAA: {self.caa}")

    def run(self) -> None:
        """Run the pipe backend.

        This is a loop that runs forever.
        """
        _log("starting up")
        handshake = _get_next()
        if handshake[1] != "5":
            _log(f"Not version 5: {handshake}")
            sys.exit(1)
        _write("OK", "nip.io backend - We are good")
        _log("Done handshake")

        while True:
            cmd = _get_next()
            if _is_debug():
                _log(f"cmd: {cmd}")

            if cmd[0] == "CMD":
                _log(f"received command: {cmd}")
                self.write_end()
                continue

            if cmd[0] == "END":
                _log("completing")
                break

            if len(cmd) < 6:
                _log(f"did not understand: {cmd}")
                _write("FAIL")
                continue

            qname = cmd[1].lower()
            qtype = cmd[3]

            if qtype in ("ANY", "A", "CAA") and qname.endswith(self.domain):
                if qname == self.domain:
                    self.handle_self(qtype, self.domain)
                elif qname in self.name_servers:
                    self.handle_nameservers(qtype, qname)
                else:
                    self.handle_subdomains(qtype, qname)
            elif qtype == "SOA" and qname.endswith(self.domain):
                self.handle_soa(qname)
            else:
                self.handle_unknown(qtype, qname)

            self.write_end()

    def write_end(self) -> None:
        _write("END")

    def handle_self(self, qtype: str, name: str) -> None:
        if qtype not in ("ANY", "A"):
            return

        _write(
            "DATA",
            self.bits,
            self.auth,
            name,
            "IN",
            "A",
            self.ttl,
            self.id,
            self.ip_address,
        )
        self.write_name_servers(name)

    def handle_subdomains(self, qtype: str, qname: str) -> None:
        subdomain = qname[0 : qname.find(self.domain) - 1]

        subparts = self._split_subdomain(subdomain)
        if len(subparts) < 4:
            if _is_debug():
                _log("subparts less than 4")
            self.handle_invalid_ip(qname)
            return

        # Calculate the IP address string from the extracts parts
        try:
            ip_address = IPv4Address(".".join(subparts[-4:]))
        except AddressValueError:
            self.handle_invalid_ip(qname)
            return
        if _is_debug():
            _log(f"extracted ip: {ip_address}")

        if self.whitelisted_ranges and not any(
            ip_address in ip_range for ip_range in self.whitelisted_ranges
        ):
            self.handle_not_whitelisted(ip_address)
            return

        if str(ip_address) in self.blacklisted_ips:
            self.handle_blacklisted(ip_address)
            return

        if qtype in ("ANY", "A"):
            self.handle_resolved(ip_address, qname)
        if qtype in ("ANY", "CAA"):
            self.handle_caa(qname)

    def handle_resolved(self, address: IPv4Address, qname: str) -> None:
        _write(
            "DATA",
            self.bits,
            self.auth,
            qname,
            "IN",
            "A",
            self.ttl,
            self.id,
            str(address),
        )
        self.write_name_servers(qname)

    def handle_caa(self, qname: str) -> None:
        for value in self.caa:
            _write(
                "DATA",
                self.bits,
                self.auth,
                qname,
                "IN",
                "CAA",
                self.ttl,
                self.id,
                "0",
                "issue",
                '"%s"' % value,
            )

    def handle_nameservers(self, qtype: str, qname: str) -> None:
        if qtype not in ("ANY", "A"):
            return

        ip = self.name_servers[qname]
        _write("DATA", self.bits, self.auth, qname, "IN", "A", self.ttl, self.id, ip)

    def write_name_servers(self, qname: str) -> None:
        for name_server in self.name_servers:
            _write(
                "DATA",
                self.bits,
                self.auth,
                qname,
                "IN",
                "NS",
                self.ttl,
                self.id,
                name_server,
            )

    def handle_soa(self, qname: str) -> None:
        _write(
            "DATA",
            self.bits,
            self.auth,
            qname,
            "IN",
            "SOA",
            self.ttl,
            self.id,
            self.soa,
        )

    def handle_unknown(self, qtype: str, qname: str) -> None:
        _write("LOG", f"Unknown type: {qtype}, domain: {qname}")

    def handle_not_whitelisted(self, ip_address: IPv4Address) -> None:
        _write("LOG", f"Not Whitelisted: {ip_address}")

    def handle_blacklisted(self, ip_address: IPv4Address) -> None:
        _write("LOG", f"Blacklisted: {ip_address}")

    def handle_invalid_ip(self, ip_address: str) -> None:
        _write("LOG", f"Invalid IP address: {ip_address}")

    def _split_subdomain(self, subdomain: str) -> List[str]:
        match = re.search("(?:^|.*[.-])([0-9A-Fa-f]{8})$", subdomain)
        if match:
            s: str = match.group(1)
            return [str(int(i, 16)) for i in [s[j : j + 2] for j in (0, 2, 4, 6)]]
        sub_parts: List[str] = re.split("[.-]", subdomain)
        return sub_parts


if __name__ == "__main__":
    backend = DynamicBackend()
    backend.configure()
    backend.run()
