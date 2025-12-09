#!/usr/bin/python3
"""
Copyright (c) 2025 Penterep Security s.r.o.

ptopenvas - Penterep OpenVAS/GVM Automation Tool

ptopenvas is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

ptopenvas is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with ptopenvas.  If not, see <https://www.gnu.org/licenses/>.
"""

from gvm.connections import UnixSocketConnection
from gvm.protocols.gmp import Gmp
from gvm.transforms import EtreeCheckCommandTransform
from gvm.errors import GvmResponseError, GvmError

import time
import json
import uuid
import subprocess
import shutil

import argparse
import re
import sys; sys.path.append(__file__.rsplit("/", 1)[0])
import socket
import ipaddress

from tqdm import tqdm
from lxml import etree
from _version import __version__
from ptlibs import ptmisclib, ptjsonlib, ptprinthelper, ptnethelper, tldparser
from ptlibs.ptprinthelper import ptprint
from ptlibs.threads import ptthreads, printlock

from modules import helpers
from modules.gvm_setup import GVMSetup

class PtOpenVas:
    SOCK = "/run/gvmd/gvmd.sock"
    USER = "penterep"
    PASS = GVMSetup().get_password()

    def __init__(self, args):
        self.ptjsonlib  = ptjsonlib.PtJsonLib()
        self.args       = args

    def run(self) -> None:
        conn = UnixSocketConnection(path=self.SOCK)
        try:
            with Gmp(conn, transform=EtreeCheckCommandTransform()) as gmp:
                gmp.authenticate(self.USER, self.PASS)
                
                """
                # Print GVM version
                for sub in gmp.get_version().iter():
                    if sub.tag == "version":
                        print("GVMD version:", sub.text)
                """

                tasks = gmp.get_tasks()
                self.run_scan(gmp=gmp, target=self.args.target, ports_or_proto=self.args.ports, scan_type=self.args.scan_config)

        except GvmError as e:
            self.ptjsonlib.end_error(f"{e}", self.args.json)

        self.ptjsonlib.set_status("finished")
        ptmisclib.ptprint(self.ptjsonlib.get_result_json(), "", self.args.json)

    
    def run_scan(self, gmp, target: str, ports_or_proto: str = "tcp", scan_type: str = "Base"):
        """
        Run a scan on the target using the specified scan_type configuration.

        Args:
            gmp: Authenticated GMP connection object
            target: Target IP or hostname
            ports_or_proto: "tcp", "udp", or custom string like "22,80,443"
            scan_type: Name of the scan configuration to use

        Returns:
            report_xml: XML report returned by GVM
        """
        try:
            # resolve/validate target (returns IPv4 string or original hostname)
            host_param = self.resolve_or_validate_target(target)

            # 1) Find scan config id
            config_id = self._get_scan_config_id(gmp, scan_type)

            # 2) Get or create port list
            port_list_id = self._get_port_list_id(gmp, ports_or_proto)

            # 3) Create or find target
            target_id = self._create_or_get_target(gmp, host_param, port_list_id)

            # 4) Create or get task
            scanner_id = helpers.get_default_scanner_id(gmp)
            task_name = f"pt-{scan_type}-{host_param}-{time.strftime('%H:%M:%S')}"
            task_id = self._create_or_get_task(gmp, task_name, config_id, target_id, scanner_id)

            # 5) Start and wait
            gmp.start_task(task_id)
            self._wait_for_task_completion(gmp, task_id)

            # 6) Fetch and process report
            report_xml = self._fetch_report(gmp, task_id)
            self._process_report(report_xml)
            xml_str = etree.tostring(report_xml, pretty_print=True).decode()
        except:
            raise

    def resolve_or_validate_target(self, target: str) -> str:
        """If `target` is a valid IPv4 address return it, otherwise resolve
        DNS (A records) and return the first IPv4 address. Raises ValueError on failure.
        """
        t = target.strip()

        if "://" in t:
            t = t.split("://", 1)[1].split("/", 1)[0]

        if not t:
            raise ValueError("empty target")

        # fast IPv4 validation
        try:
            ip = ipaddress.ip_address(t)
            if ip.version == 4:
                return str(ip)
        except Exception:
            pass

        # Not an IP — try to resolve to IPv4 via DNS
        try:
            infos = socket.getaddrinfo(t, None, family=socket.AF_INET)
            if not infos:
                raise ValueError(f"could not resolve target '{t}' to IPv4")
            # pick first IPv4 address
            addr = infos[0][4][0]
            return addr
        except socket.gaierror as e:
            raise ValueError(f"DNS lookup failed for '{t}': {e}")

    def _get_scan_config_id(self, gmp, scan_type: str) -> str:
        root = gmp.get_scan_configs()
        cfg_node = root.xpath(f"//config[name='{scan_type}']")
        if not cfg_node:
            raise RuntimeError(f"Scan config '{scan_type}' not found")
        return cfg_node[0].get("id")

    def _get_port_list_id(self, gmp, ports_or_proto: str) -> str:
        # For now use helpers to create a temporary port list (keeps behaviour)
        port_list_id, _ = helpers._create_temp_portlist(gmp, ports_or_proto)
        return port_list_id

    def _create_or_get_target(self, gmp, host_param: str, port_list_id: str) -> str:
        try:
            target_xml = gmp.create_target(
                name=f"{host_param}-{time.strftime('%H:%M:%S')}",
                hosts=[host_param],
                port_list_id=port_list_id,
            )
            return target_xml.get("id")
        except GvmResponseError as e:
            if "Target exists already" in str(e):
                existing = gmp.get_targets()
                for t in existing.xpath("//target"):
                    # collect host texts
                    hosts_node = t.find("hosts")
                    if hosts_node is not None and hosts_node.text and host_param in hosts_node.text:
                        return t.get("id")
                    if t.findtext("name") and host_param in t.findtext("name"):
                        return t.get("id")
                    for sub in t.xpath('.//host'):
                        if sub.text and host_param == sub.text.strip():
                            return t.get("id")
                raise RuntimeError("Target exists but could not find its ID")
            raise

    def _create_or_get_task(self, gmp, task_name: str, config_id: str, target_id: str, scanner_id: str) -> str:
        try:
            task_xml = gmp.create_task(
                name=task_name,
                config_id=config_id,
                target_id=target_id,
                scanner_id=scanner_id,
            )
            return task_xml.get("id")
        except GvmResponseError as e:
            if "Task exists already" in str(e):
                existing = gmp.get_tasks()
                node = existing.xpath(f"//task[name='{task_name}']")
                if node:
                    return node[0].get("id")
                raise RuntimeError("Task exists but could not find its ID")
            raise

    def _wait_for_task_completion(self, gmp, task_id: str) -> None:
        progress_bar = tqdm(total=100, desc="Scan Progress", bar_format="{l_bar}{bar}| [{elapsed}]", leave=False)
        try:
            while True:
                status_xml = gmp.get_task(task_id)
                status = status_xml.findtext(".//status")
                progress_text = status_xml.findtext(".//progress")

                if progress_text is None:
                    progress = 0
                elif progress_text == "-1":
                    progress = 100
                else:
                    try:
                        progress = int(progress_text)
                    except Exception:
                        progress = 0

                progress_bar.n = progress
                progress_bar.refresh()

                if status in ("Done", "Stopped"):
                    break
                time.sleep(1)
        finally:
            progress_bar.close()

    def _fetch_report(self, gmp, task_id: str):
        report_id = helpers.wait_for_report(gmp, task_id)
        report_xml = gmp.get_report(
            report_id,
            report_format_id="a994b278-1f62-11e1-96ac-406186ea4fc5",
        )
        return report_xml

    def _process_report(self, report_xml):

        for result in report_xml.xpath(".//result"):
            host = result.findtext("host") or "Unknown host"
            port = result.findtext("port") or "Unknown port"
            name = result.findtext("name") or "Unnamed check"
            severity = result.findtext("severity") or "0.0"
            qod = result.findtext("qod/value") or "0"
            description = result.findtext("description") or ""

            nvt_elem = result.find("nvt")
            if nvt_elem is not None:
                nvt_name = nvt_elem.findtext("name") or "Unnamed NVT"
                nvt_oid = nvt_elem.findtext("oid") or "Unknown OID"
                nvt_family = nvt_elem.findtext("family") or "Unknown family"
            else:
                nvt_name = "Unknown NVT"
                nvt_oid = "Unknown OID"
                nvt_family = "Unknown family"

            print(f"Host: {host}")
            print(f"Port: {port}")
            print(f"Check: {name}")
            print(f"Severity: {severity}, QoD: {qod}")
            print(f"Description: {description.strip()}")
            print("-" * 60)

    def get_scan_configs(self, gmp):
        """returns available tests from configs xml"""
        configs = gmp.get_scan_configs()
        self.print_scan_configs(configs)
        return configs

    def print_scan_configs(self, configs_xml: str):
        """
        Parse GVM get_scan_configs() XML and print key info in CLI tree format.
        """
        configs = configs_xml.xpath("//config")

        for cfg in configs:
            cfg_id = cfg.get("id")
            name = cfg.findtext("name", default="N/A")
            comment = cfg.findtext("comment", default="No description")
            nvt_count = cfg.findtext("nvt_count", default="0")
            family_count = cfg.findtext("family_count", default="0")

            print(f"Config: {name} ({cfg_id})")
            print(f"  Description : {comment}")
            print(f"  NVTs        : {nvt_count}")
            print(f"  Families    : {family_count}")
            print("-" * 50)

def get_help():
    return [
        {"description": ["Penterep OpenVAS/GVM Automation Tool"]},
        {"usage": ["ptopenvas <options>"]},
        {"usage_example": [
            "ptopenvas -T www.example.com -P 80,443",
            "ptopenvas -T 23.192.228.84 -P 80,443 -sc 'Base'",
        ]},
        {"options": [
            ["-T",  "--target",                 "<target>",         "Set Target"],
            ["-P",  "--port",                   "<port>",           "Set Port(s)"],
            ["-sc",  "--scan-config",           "",                 "Select scan config type (default Full and fast): "],
            ["",  "",                           " Full and fast",       " Most NVT's; optimized by using previously collected information"],
            ["",  "",                           " Base",                " Basic config with a minimum set of NVTs"],
            ["",  "",                           " Discovery",           " Network Discovery"],
            ["",  "",                           " System Discovery",    " Network System Discovery"],
            ["",  "",                           " Host Discovery",      " Network Host Discovery"],
            ["",  "",                           " Log4Shell",           " Checks for Log4j and CVE-2021-44228"],
            ["",  "",                           "",           ""],
            ["-v",  "--version",                "",                 "Show script version and exit"],
            ["-h",  "--help",                   "",                 "Show this help message and exit"],
            ["-j",  "--json",                   "",                 "Output in JSON format"],
        ]
        }]


def parse_ports(value: str) -> str:
    """
    Parse a user-supplied ports string and return a canonical comma-separated string.

    Accepts commas, spaces, or semicolons as separators.
    Preserves order but removes duplicates.
    Validates each port is between 1 and 65535.
    """
    MIN_PORT = 1
    MAX_PORT = 65535

    if not isinstance(value, str) or not value.strip():
        raise argparse.ArgumentTypeError("ports must be a non-empty string, e.g. '44,23,23,23'")

    # split on commas, semicolons, or whitespace
    tokens = re.split(r'[,\s;]+', value.strip())
    tokens = [t for t in tokens if t]
    if not tokens:
        raise argparse.ArgumentTypeError("no ports found in input")

    normalized = []
    seen = set()
    for t in tokens:
        if not t.isdigit():
            raise argparse.ArgumentTypeError(f"invalid port '{t}': must be a positive integer")
        n = int(t)
        if n < MIN_PORT or n > MAX_PORT:
            raise argparse.ArgumentTypeError(f"invalid port '{t}': must be between {MIN_PORT} and {MAX_PORT}")
        if n not in seen:
            normalized.append(str(n))
            seen.add(n)
    return ",".join(normalized)

def lowercase_choice(value):
    # map lowercase → original name
    allowed_map = {
        "full and fast": "Full and fast",
        "base": "Base",
        "discovery": "Discovery",
        "system discovery": "System Discovery",
        "host discovery": "Host Discovery",
        "log4shell": "Log4Shell",
    }

    key = value.lower()
    if key not in allowed_map:
        raise argparse.ArgumentTypeError(
            f"Invalid scan config '{value}'. "
            f"Allowed values are: {', '.join(allowed_map.values())}"
        )
    return allowed_map[key]

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(add_help=False, usage="ptopenvas <options>")
    parser.add_argument( "-T",  "--target",          type=str, required=True)
    parser.add_argument( "-P",  "--ports",           type=parse_ports, required=True)
    parser.add_argument( "-sc",  "--scan-config",    type=lowercase_choice, default="full and fast")
    parser.add_argument("-t",  "--threads",          type=int, default=10)
    parser.add_argument("-j",  "--json",             action="store_true")
    #parser.add_argument("-rp", "--reset-password",   action="store_true")
    parser.add_argument("-v",  "--version",          action="version", version=f"{SCRIPTNAME} {__version__}")
    parser.add_argument("--socket-address",          type=str, default=None)
    parser.add_argument("--socket-port",             type=str, default=None)
    parser.add_argument("--process-ident",           type=str, default=None)

    if len(sys.argv) == 1 or "-h" in sys.argv or "--help" in sys.argv:
        ptprinthelper.help_print(get_help(), SCRIPTNAME, __version__)
        sys.exit(0)
    args = parser.parse_args()
    ptprinthelper.print_banner(SCRIPTNAME, __version__, args.json, space=0)
    return args


def main():
    global SCRIPTNAME
    SCRIPTNAME = "ptopenvas"
    args = parse_args()
    GVMSetup(args).run() # Ensure GVM is installed and set up and running
    PtOpenVas(args).run() # Run the main script logic

if __name__ == "__main__":
    main()
