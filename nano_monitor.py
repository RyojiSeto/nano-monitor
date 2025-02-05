#!/usr/bin/env python3

"""
Nano Monitor: Network Monitoring Tool

- Cross-platform compatibility: Windows & Linux
- Recommended Python version: 3.7 or later
- No external libraries required (except for scikit-learn)
- All docstrings, comments, and messages are written in English
- AI tools **must** follow the rules and guidelines outlined above

Repository: https://github.com/RyojiSeto/nano-monitor
"""

import argparse
import concurrent.futures
import csv
import json
import logging
import os
import platform
import queue
import re
import shlex
import shutil
import subprocess
import sys
import threading
import time
import urllib.request
from datetime import datetime
from logging.handlers import RotatingFileHandler
from typing import Any, Dict, List, Optional, Tuple, Union, TextIO, cast

if platform.system().lower() == "windows":
    import msvcrt
else:
    import select
    import tty
    import termios


class ColorManager:

    def __init__(self, enable_color: bool = True) -> None:
        self.enable_color = enable_color
        self.colors = {
            "red": "\033[91m",
            "green": "\033[92m",
            "yellow": "\033[93m",
            "blue": "\033[94m",
            "reset": "\033[0m",
        }

    def colorize(self, text: str, color_name: str) -> str:
        if not self.enable_color or color_name not in self.colors:
            return text
        return f"{self.colors[color_name]}{text}{self.colors['reset']}"


class SIPrefixer:

    def apply(self, raw_value: float) -> Tuple[float, str, float]:
        if raw_value >= 1000000000000:
            return (raw_value / 1000000000000, "T", 1000000000000)
        elif raw_value >= 1000000000:
            return (raw_value / 1000000000, "G", 1000000000)
        elif raw_value >= 1000000:
            return (raw_value / 1000000, "M", 1000000)
        elif raw_value >= 1000:
            return (raw_value / 1000, "k", 1000)
        else:
            return (raw_value, " ", 1.0)

    def format_value(self, value: Optional[float]) -> str:
        if value is None:
            return "N/A"
        scaled, unit, _ = self.apply(value)
        return f"{scaled:.2f} {unit}" if unit else f"{scaled:.2f}"


class ConfigManager:

    def __init__(self) -> None:
        self.args = self.parse_arguments()
        self.validate_args()
        self.check_required_commands()

    def parse_arguments(self) -> argparse.Namespace:
        parser = argparse.ArgumentParser(
            description=(
                "Nano Monitor: Network monitoring tool"
            )
        )
        group = parser.add_mutually_exclusive_group(required=True)
        group.add_argument(
            "--ping",
            nargs="+",
            metavar="TARGET",
            help=(
                "Activate Ping monitoring. Specify one or two target hosts or IP addresses to monitor. "
                "Example: --ping host1.example.com 192.168.1.1"
            ),
        )
        parser.add_argument(
            "--packet-size",
            nargs="+",
            type=str,
            metavar="SIZE",
            help=(
                "Set the packet size for each Ping target. Provide exactly one or two values corresponding to the number of Ping targets. "
                "Use \"default\" to apply the default packet size. "
                "Example: --packet-size 64 128"
            ),
        )
        parser.add_argument(
            "--source",
            nargs="+",
            type=str,
            metavar="ADDRESS",
            help=(
                "Set the source IP address for each Ping target. Provide exactly one or two addresses corresponding to the number of Ping targets. "
                "Use \"default\" to let the system choose the source address. "
                "Example: --source 192.168.1.10 192.168.1.11"
            ),
        )
        parser.add_argument(
            "--ipv",
            nargs="+",
            type=str,
            metavar="VERSION",
            help=(
                "Set the IP version for each Ping target. Provide exactly one or two values (e.g., \"4\" or \"6\") corresponding to the number of Ping targets. "
                "Use \"default\" to use the system's default IP version. "
                "Example: --ipv 4 6"
            ),
        )
        group.add_argument(
            "--http",
            nargs="+",
            metavar="URL",
            help=(
                "Activate HTTP monitoring. Specify one or two URLs to monitor for response times. "
                "Example: --http http://example.com https://anotherdomain.com"
            ),
        )
        group.add_argument(
            "--dns",
            nargs="+",
            metavar="DOMAIN",
            help=(
                "Activate DNS monitoring. Specify one or two domain names to monitor DNS resolution times. "
                "Example: --dns example.com anotherdomain.com"
            ),
        )
        parser.add_argument(
            "--dns-server",
            nargs="+",
            type=str,
            metavar="SERVER",
            help=(
                "Set the DNS server for each DNS target. Provide exactly one or two DNS server addresses corresponding to the number of DNS targets. "
                "Use \"default\" to use the system's default DNS server. "
                "Example: --dns-server 192.168.1.100 192.168.1.101"
            ),
        )
        group.add_argument(
            "--snmp",
            nargs="+",
            metavar="TARGET",
            help=(
                "Activate SNMP monitoring. Specify one or two target devices for SNMP polling. "
                "Requires --community and --oid arguments. "
                "Example: --snmp 192.168.1.100 192.168.1.101"
            ),
        )
        parser.add_argument(
            "--community",
            nargs="+",
            type=str,
            metavar="COMMUNITY",
            help=(
                "Set the SNMP community string for each SNMP target. Specify exactly one or two community strings corresponding to the number of SNMP targets. "
                "Example: --community public private"
            ),
        )
        parser.add_argument(
            "--oid",
            nargs="+",
            type=str,
            metavar="OID",
            help=(
                "Set the Object Identifier (OID) for each SNMP target. Provide exactly one or two OIDs corresponding to the number of SNMP targets. "
                "Example: --oid .1.3.6.1.2.1.2.2.1.14.1 .1.3.6.1.2.1.2.2.1.20.1"
            ),
        )
        group.add_argument(
            "--traffic",
            nargs=1,
            metavar="TARGET",
            help=(
                "Activate Traffic monitoring. Specify a single target device to monitor network traffic. "
                "Requires --community and --interface arguments. "
                "Example: --traffic 192.168.1.100"
            ),
        )
        parser.add_argument(
            "--interface",
            nargs=1,
            type=str,
            metavar="INTERFACE",
            help=(
                "Set the network interface for Traffic monitoring. Provide exactly one ifIndex or ifName. "
                "Example: --interface eth0"
            ),
        )
        csv_group = parser.add_mutually_exclusive_group()
        csv_group.add_argument(
            "--csv",
            action="store_true",
            help=(
                "Activate CSV export to save monitoring results. Results will be stored in daily CSV files named with the current date and monitoring type."
            ),
        )
        csv_group.add_argument(
            "--csv-ms",
            action="store_true",
            help=(
                "Activate CSV export with millisecond precision in the DateTime field. Useful for high-resolution logging."
            ),
        )
        parser.add_argument(
            "--interval",
            type=float,
            default=1.0,
            metavar="SECONDS",
            help=(
                "Set the monitoring interval in seconds. Determines how frequently metrics are collected. "
                "The default interval is 1.0 seconds. "
                "Example: --interval 0.5"
            ),
        )
        parser.add_argument(
            "--exec-timeout",
            type=float,
            default=10.0,
            metavar="SECONDS",
            help=(
                "Set the timeout duration for command executions in seconds. If a command does not complete within this time, it will be terminated. "
                "The default timeout is 10.0 seconds. "
                "Example: --exec-timeout 5"
            ),
        )
        parser.add_argument(
            "--timeout",
            nargs="+",
            type=str,
            metavar="SECONDS",
            help=(
                "Set the timeout in seconds for each target. Provide exactly one or two timeout values corresponding to the number of targets. "
                "Use \"default\" to apply the default timeout. "
                "Example: --timeout 5 10"
            ),
        )
        parser.add_argument(
            "--threshold",
            nargs="+",
            type=str,
            metavar="THRESHOLD",
            help=(
                "Set threshold values for each target to trigger alerts. Provide one or two threshold values corresponding to the number of targets. "
                "Use \"default\" to apply no threshold. "
                "Thresholds can be absolute values or conditional (e.g., \">100\", \"<50\"). "
                "If only a number is specified (e.g., 100), it is interpreted as \">100\". "
                "Example: --threshold 100 default"
            ),
        )
        parser.add_argument(
            "--anomaly",
            action="store_true",
            help=(
                "Enable anomaly detection using the IsolationForest algorithm. This feature requires the scikit-learn library to be installed."
            ),
        )
        parser.add_argument(
            "--samples",
            type=int,
            default=256,
            metavar="SAMPLES",
            help=(
                "Set the number of samples to use for the IsolationForest anomaly detection model. "
                "The default is 256 samples. "
                "Example: --samples 512"
            ),
        )
        parser.add_argument(
            "--contamination",
            type=float,
            default=0.01,
            metavar="CONTAMINATION",
            help=(
                "Set the contamination level for the IsolationForest anomaly detection model, representing the proportion of outliers in the data. "
                "The default contamination is 0.01 (1%%). "
                "Example: --contamination 0.05"
            ),
        )
        parser.add_argument(
            "--webhook",
            type=str,
            metavar="URL",
            help=(
                "Set a Webhook URL to send notifications for alerts and anomalies. "
                "Example: --webhook https://hooks.example.com/XXX"
            ),
        )
        parser.add_argument(
            "--graph-width",
            type=int,
            default=50,
            metavar="WIDTH",
            help=(
                "Set the width of the graph in characters. The default value is 50 characters. "
                "Example: --graph-width 100"
            ),
        )
        parser.add_argument(
            "--graph-height",
            type=int,
            default=10,
            metavar="HEIGHT",
            help=(
                "Set the height of the graph in lines. The default value is 10 lines. "
                "Example: --graph-height 20"
            ),
        )
        parser.add_argument(
            "--graph-symbol",
            nargs="+",
            type=str,
            metavar="SYMBOL",
            help=(
                "Set symbols to each graph target for visual representation. Provide up to two symbols corresponding to the number of targets. "
                "If not specified, default symbols will be used. "
                "Example: --graph-symbol \"@\" \"+\""
            ),
        )
        parser.add_argument(
            "--y-scale",
            type=str,
            default="auto",
            metavar="SCALE",
            help=(
                "Set the Y-axis scaling for the graph. Options are \"auto\" for automatic scaling based on data or a fixed maximum value. "
                "Example: --y-scale 200"
            ),
        )
        parser.add_argument(
            "--keep-data",
            type=int,
            default=2678400,
            metavar="ITERATIONS",
            help=(
                "Set the duration (in iterations) for which monitoring data is retained. The default is 2,678,400 iterations. "
                "Example: --keep-data 10000"
            ),
        )
        parser.add_argument(
            "--debug",
            action="store_true",
            help=(
                "Enable debug logging. When set, the application will output detailed logs useful for troubleshooting."
            ),
        )
        args = parser.parse_args()
        return args

    def validate_args(self) -> None:
        if self.args.graph_symbol:
            max_symbols = 2
            if len(self.args.graph_symbol) > max_symbols:
                print(f"Error: --graph-symbol supports up to {max_symbols} symbols.")
                sys.exit(1)
        if self.args.snmp:
            if not self.args.community or not self.args.oid:
                print("Error: --community and --oid are required when using --snmp.")
                sys.exit(1)
            num_targets = len(self.args.snmp)
            if len(self.args.community) != num_targets:
                print(
                    f"Error: --community expects exactly {num_targets} value(s) for {num_targets} target(s)."
                )
                sys.exit(1)
            if len(self.args.oid) != num_targets:
                print(
                    f"Error: --oid expects exactly {num_targets} value(s) for {num_targets} target(s)."
                )
                sys.exit(1)
        if self.args.traffic:
            if not self.args.community or not self.args.interface:
                print(
                    "Error: --community and --interface are required when using --traffic."
                )
                sys.exit(1)
            if len(self.args.community) != 1:
                print(
                    "Error: --community expects exactly 1 value for traffic monitoring."
                )
                sys.exit(1)
            if len(self.args.interface) != 1:
                print(
                    "Error: --interface expects exactly 1 value for traffic monitoring."
                )
                sys.exit(1)
        if self.args.ping:
            num_targets = len(self.args.ping)
            if self.args.packet_size and len(self.args.packet_size) != num_targets:
                print(
                    f"Error: --packet-size expects exactly {num_targets} value(s) for {num_targets} target(s)."
                )
                sys.exit(1)
            if self.args.source and len(self.args.source) != num_targets:
                print(
                    f"Error: --source expects exactly {num_targets} value(s) for {num_targets} target(s)."
                )
                sys.exit(1)
            if self.args.ipv and len(self.args.ipv) != num_targets:
                print(
                    f"Error: --ipv expects exactly {num_targets} value(s) for {num_targets} target(s)."
                )
                sys.exit(1)
        if self.args.dns:
            num_targets = len(self.args.dns)
            if self.args.dns_server and len(self.args.dns_server) != num_targets:
                print(
                    f"Error: --dns-server expects exactly {num_targets} value(s) for {num_targets} target(s)."
                )
                sys.exit(1)
        if self.args.threshold:
            if self.args.traffic:
                expected = 2
            else:
                num_targets = (
                    len(self.args.ping)
                    if self.args.ping
                    else (
                        len(self.args.http)
                        if self.args.http
                        else (
                            len(self.args.dns)
                            if self.args.dns
                            else len(self.args.snmp) if self.args.snmp else 0
                        )
                    )
                )
                expected = num_targets
            if len(self.args.threshold) != expected:
                print(f"Error: --threshold expects exactly {expected} value(s).")
                sys.exit(1)
        if self.args.timeout:
            if self.args.traffic:
                expected = 1
            else:
                num_targets = (
                    len(self.args.ping)
                    if self.args.ping
                    else (
                        len(self.args.http)
                        if self.args.http
                        else (
                            len(self.args.dns)
                            if self.args.dns
                            else len(self.args.snmp) if self.args.snmp else 0
                        )
                    )
                )
                expected = num_targets
            if len(self.args.timeout) != expected:
                print(f"Error: --timeout expects exactly {expected} value(s).")
                sys.exit(1)

    def check_required_commands(self) -> None:
        monitor_commands = {
            "ping": ["ping"],
            "http": ["curl"],
            "dns": ["dig"],
            "snmp": ["snmpget"],
            "traffic": ["snmpget", "snmpwalk"],
        }
        monitor_type, _ = self.get_monitor_type_and_targets()
        monitor_type_lower = monitor_type.lower()
        missing_cmds = [
            cmd
            for cmd in monitor_commands.get(monitor_type_lower, [])
            if shutil.which(cmd) is None
        ]
        if missing_cmds:
            print(
                f"Error: The following required commands for {monitor_type} monitoring are missing: {', '.join(missing_cmds)}."
            )
            sys.exit(1)

    def get_monitor_type_and_targets(self) -> Tuple[str, List[str]]:
        if self.args.ping:
            return ("Ping", self.args.ping)
        elif self.args.http:
            return ("HTTP", self.args.http)
        elif self.args.dns:
            return ("DNS", self.args.dns)
        elif self.args.snmp:
            return ("SNMP", self.args.snmp)
        elif self.args.traffic:
            return ("Traffic", self.args.traffic)
        else:
            print("Error: No monitoring type specified.")
            sys.exit(1)

    def get_graph_dimensions(self) -> Tuple[int, int]:
        return (self.args.graph_width, self.args.graph_height)

    def get_graph_symbols(self, num_targets: int) -> List[str]:
        if self.args.graph_symbol:
            if len(self.args.graph_symbol) != num_targets:
                print(
                    f"Error: --graph-symbol expects exactly {num_targets} symbol(s) for {num_targets} target(s)."
                )
                sys.exit(1)
            return self.args.graph_symbol
        else:
            default_symbols = ["*", "#", "@", "%", "o", "+", "x", "s"]
            return default_symbols[:num_targets]

    def get_monitor_specific_options(
        self, monitor_type: str, num_targets: int
    ) -> Dict[str, Any]:
        options: Dict[str, Any] = {}
        if monitor_type.lower() == "ping":
            options = {
                "packet_size": self._assign_option(
                    self.args.packet_size, num_targets, default="default"
                ),
                "source": self._assign_option(
                    self.args.source, num_targets, default="default"
                ),
                "ipv": self._assign_option(
                    self.args.ipv, num_targets, default="default"
                ),
                "timeout": self._assign_option(
                    self.args.timeout, num_targets, default="default"
                ),
            }
        elif monitor_type.lower() == "http":
            options = {
                "timeout": self._assign_option(
                    self.args.timeout, num_targets, default="default"
                )
            }
        elif monitor_type.lower() == "dns":
            dns_servers = self._assign_option(
                self.args.dns_server, num_targets, default="default"
            )
            options = {
                "dns_server": dns_servers,
                "timeout": self._assign_option(
                    self.args.timeout, num_targets, default="default"
                ),
            }
        elif monitor_type.lower() == "snmp":
            communities = self.args.community
            oids = self.args.oid
            options = {
                "community": communities,
                "oid": oids,
                "timeout": self._assign_option(
                    self.args.timeout, num_targets, default="default"
                ),
            }
        elif monitor_type.lower() == "traffic":
            communities = self.args.community
            interfaces = self.args.interface
            options = {
                "community": communities,
                "interface": interfaces,
                "timeout": self._assign_option(
                    self.args.timeout, num_targets, default="default"
                ),
            }
        return options

    def _assign_option(
        self, option_values: Optional[List[Any]], num_targets: int, default: Any = None
    ) -> List[Any]:
        if option_values:
            if len(option_values) != num_targets:
                print(
                    f"Error: Option expects exactly {num_targets} value(s) for {num_targets} target(s)."
                )
                sys.exit(1)
            return option_values
        else:
            return [default] * num_targets

    def validate_and_assign_options(
        self, monitors: List["BaseMonitor"], monitor_type: str
    ) -> List[str]:
        num_targets = len(monitors)
        graph_symbols: List[str] = []
        monitor_options = self.get_monitor_specific_options(monitor_type, num_targets)
        if monitor_type.lower() == "ping":
            for monitor, pkt, src, ip, timeout in zip(
                monitors,
                monitor_options["packet_size"],
                monitor_options["source"],
                monitor_options["ipv"],
                monitor_options["timeout"],
            ):
                monitor.set_options(
                    packet_size=pkt, source=src, ipv=ip, timeout=timeout
                )
        elif monitor_type.lower() == "http":
            for monitor, timeout in zip(monitors, monitor_options["timeout"]):
                monitor.set_options(timeout=timeout)
        elif monitor_type.lower() == "dns":
            for monitor, dns_srv, timeout in zip(
                monitors, monitor_options["dns_server"], monitor_options["timeout"]
            ):
                monitor.set_options(dns_server=dns_srv, timeout=timeout)
        elif monitor_type.lower() == "snmp":
            for monitor, community, oid, timeout in zip(
                monitors,
                monitor_options["community"],
                monitor_options["oid"],
                monitor_options["timeout"],
            ):
                monitor.set_options(community=community, oid=oid, timeout=timeout)
        elif monitor_type.lower() == "traffic":
            for monitor, community, interface, timeout in zip(
                monitors,
                monitor_options["community"],
                monitor_options["interface"],
                monitor_options["timeout"],
            ):
                monitor.set_options(
                    community=community, interface=interface, timeout=timeout
                )
        graph_symbols = self.get_graph_symbols(num_targets)
        if monitor_type.lower() == "traffic":
            if len(graph_symbols) < 2:
                default_symbols = ["*", "#"]
                graph_symbols = default_symbols[:2]
            elif len(graph_symbols) > 2:
                graph_symbols = graph_symbols[:2]
        return graph_symbols

    def get_global_options(self) -> Dict[str, Any]:
        return {
            "graph_width": self.args.graph_width,
            "graph_height": self.args.graph_height,
            "y_scale": self.args.y_scale,
            "keep_data": self.args.keep_data,
            "interval": self.args.interval,
            "exec_timeout": self.args.exec_timeout,
            "debug": self.args.debug,
            "csv_enabled": self.args.csv,
            "csv_ms_enabled": self.args.csv_ms,
            "timeout": self.args.timeout,
            "threshold": self.args.threshold,
            "webhook": self.args.webhook,
            "anomaly": self.args.anomaly,
            "samples": self.args.samples,
            "contamination": self.args.contamination,
        }


class CommandExecutor:
    logger: logging.Logger
    default_timeout: float

    def __init__(self, default_timeout: float = 10.0) -> None:
        self.logger = logging.getLogger(self.__class__.__name__)
        self.default_timeout = default_timeout

    def execute(self, cmd: List[str], timeout: Optional[float] = None) -> Optional[str]:
        cmd_str = " ".join((shlex.quote(arg) for arg in cmd))
        effective_timeout = timeout if timeout is not None else self.default_timeout
        try:
            result: subprocess.CompletedProcess[str] = subprocess.run(
                cmd, capture_output=True, text=True, timeout=effective_timeout
            )
            stdout_log = (
                f"\n\n---\n{result.stdout.strip()}\n---\n"
                if result.stdout
                else "(No Output)"
            )
            stderr_log = (
                f"\n\n---\n{result.stderr.strip()}\n---\n"
                if result.stderr
                else "(No Error Output)"
            )
            if result.returncode != 0:
                self.logger.info(
                    f"Command [{cmd_str}] failed with return code {result.returncode}.\nStandard Output: {stdout_log}\nStandard Error: {stderr_log}"
                )
                return None
            if result.stderr:
                self.logger.info(
                    f"Command [{cmd_str}] executed successfully with warnings.\nStandard Output: {stdout_log}\nStandard Error: {stderr_log}"
                )
            else:
                self.logger.debug(
                    f"Command [{cmd_str}] executed successfully.\nStandard Output: {stdout_log}"
                )
            return result.stdout
        except subprocess.TimeoutExpired:
            self.logger.info(
                f"Execution of command [{cmd_str}] timed out after {effective_timeout} seconds (tool-enforced timeout)."
            )
            return None
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Command [{cmd_str}] failed with exception: {e}")
            return None
        except Exception as e:
            self.logger.error(
                f"Command [{cmd_str}] failed with unexpected exception: {e}"
            )
            return None


class BaseMonitor:

    def __init__(self, target: str, executor: CommandExecutor, index: int) -> None:
        self.target = target
        self.executor = executor
        self.index = index
        self.logger = logging.getLogger(self.__class__.__name__)
        self.sysname: Optional[str] = None

    def fetch_and_process_metric(
        self,
    ) -> Optional[Union[float, Dict[str, Optional[float]]]]:
        raise NotImplementedError(
            "fetch_and_process_metric must be implemented in subclasses"
        )

    def set_options(self, **kwargs: Any) -> None:
        pass

    def get_unique_key(self) -> str:
        return f"{self.__class__.__name__}_{self.index}"


class PingMonitor(BaseMonitor):

    def __init__(self, target: str, executor: CommandExecutor, index: int) -> None:
        super().__init__(target, executor, index)
        self.is_windows: bool = platform.system().lower() == "windows"
        self.packet_size: Optional[str] = None
        self.source: Optional[str] = None
        self.ipv: Optional[str] = None
        self.timeout: Optional[str] = None

    def set_options(self, **kwargs: Any) -> None:
        self.packet_size = kwargs.get("packet_size", "default")
        self.source = kwargs.get("source", "default")
        self.ipv = kwargs.get("ipv", "default")
        self.timeout = kwargs.get("timeout", "default")

    def get_unique_key(self) -> str:
        return f"ping_{self.index}"

    def fetch_and_process_metric(self) -> Optional[float]:
        options = self.build_ping_options()
        output = self.execute_ping_command(options)
        if output is None:
            return None
        return self.parse_ping_output(output)

    def build_ping_options(self) -> List[str]:
        options = []
        count_option = "-n" if self.is_windows else "-c"
        options.extend([count_option, "1"])
        if self.packet_size and self.packet_size != "default":
            if self.is_windows:
                options.extend(["-l", self.packet_size])
            else:
                options.extend(["-s", self.packet_size])
        if self.source and self.source != "default":
            if self.is_windows:
                options.extend(["-S", self.source])
            else:
                options.extend(["-I", self.source])
        if self.ipv and self.ipv != "default":
            if self.ipv == "4":
                options.append("-4")
            elif self.ipv == "6":
                options.append("-6")
            else:
                self.logger.error(f"Invalid IPv option: {self.ipv}. Using default.")
        if self.timeout and self.timeout != "default":
            if self.is_windows:
                timeout_ms = int(self.timeout) * 1000
                options.extend(["-w", str(timeout_ms)])
            else:
                timeout_sec = int(self.timeout)
                options.extend(["-W", str(timeout_sec)])
        return options

    def execute_ping_command(self, options: List[str]) -> Optional[str]:
        command = ["ping"] + options + [self.target]
        try:
            return self.executor.execute(command)
        except Exception as e:
            self.logger.error(f"Error executing ping command: {e}")
            return None

    def parse_ping_output(self, output: str) -> Optional[float]:
        try:
            if not self.is_windows:
                match = re.search("(\\d+(?:\\.\\d+)?) ms", output)
            else:
                match = re.search("(\\d+)ms", output)
            return float(match.group(1)) if match else None
        except Exception as e:
            self.logger.error(f"Error parsing ping output: {e}")
            return None


class HttpMonitor(BaseMonitor):

    def __init__(self, target: str, executor: CommandExecutor, index: int) -> None:
        super().__init__(target, executor, index)
        self.timeout: Optional[str] = None

    def set_options(self, **kwargs: Any) -> None:
        self.timeout = kwargs.get("timeout", "default")

    def get_unique_key(self) -> str:
        return f"http_{self.index}"

    def fetch_and_process_metric(self) -> Optional[float]:
        output = self.execute_http_command()
        if output is None:
            return None
        return self.parse_http_output(output)

    def execute_http_command(self) -> Optional[str]:
        command = ["curl", "-s", "-o", os.devnull, "-w", "%{time_total}", self.target]
        if self.timeout and self.timeout != "default":
            command.extend(["--max-time", str(self.timeout)])
        try:
            return self.executor.execute(command)
        except Exception as e:
            self.logger.error(f"Error executing HTTP command: {e}")
            return None

    def parse_http_output(self, output: str) -> Optional[float]:
        try:
            return round(float(output.strip()) * 1000, 3)
        except ValueError:
            self.logger.error(f"Error parsing HTTP response time: {output}")
            return None


class DnsMonitor(BaseMonitor):

    def __init__(self, target: str, executor: CommandExecutor, index: int) -> None:
        super().__init__(target, executor, index)
        self.dns_server: Optional[str] = None
        self.timeout: Optional[str] = None
        self.server_info: Optional[str] = None

    def set_options(self, **kwargs: Any) -> None:
        self.dns_server = kwargs.get("dns_server", "default")
        self.timeout = kwargs.get("timeout", "default")

    def get_unique_key(self) -> str:
        return f"dns_{self.index}"

    def fetch_and_process_metric(self) -> Optional[float]:
        output = self.execute_dns_command()
        if output is None:
            return None
        return self.parse_dns_output(output)

    def execute_dns_command(self) -> Optional[str]:
        command = ["dig", "+noall", "+stats", self.target]
        if self.dns_server and self.dns_server != "default":
            command.append(f"@{self.dns_server}")
        if self.timeout and self.timeout != "default":
            command.append(f"+time={self.timeout}")
        try:
            return self.executor.execute(command)
        except Exception as e:
            self.logger.error(f"Error executing DNS command: {e}")
            return None

    def parse_dns_output(self, output: str) -> Optional[float]:
        try:
            query_time_match = re.search("Query time: (\\d+) msec", output)
            server_info_match = re.search("SERVER: ([\\d\\.]+)", output)
            self.server_info = (
                server_info_match.group(1) if server_info_match else "Unknown"
            )
            if query_time_match:
                return float(query_time_match.group(1))
            else:
                self.logger.error(
                    f"Could not parse DNS query time from output: {output}"
                )
                return None
        except Exception as e:
            self.logger.error(f"Error parsing DNS output: {e}")
            return None


class SnmpMonitor(BaseMonitor):

    def __init__(self, target: str, executor: CommandExecutor, index: int) -> None:
        super().__init__(target, executor, index)
        self.community: Optional[str] = None
        self.oid: Optional[str] = None
        self.timeout: Optional[str] = None
        self.sysname: Optional[str] = None
        self.previous_oid_value: Optional[float] = None
        self.previous_sysuptime: Optional[float] = None
        self.is_counter: bool = False
        self.initial_fetch: bool = True

    def set_options(self, **kwargs: Any) -> None:
        self.community = kwargs.get("community")
        self.oid = kwargs.get("oid")
        self.timeout = kwargs.get("timeout", "default")

    def get_unique_key(self) -> str:
        return f"snmp_{self.index}"

    def fetch_and_process_metric(
        self,
    ) -> Optional[Union[float, Dict[str, Optional[float]]]]:
        output = self.execute_snmpget()
        if not output:
            return None
        snmp_data = self.parse_snmp_output(output)
        if not snmp_data:
            return None
        sysuptime = snmp_data.get("sysUpTime")
        if sysuptime is None:
            self.logger.error(
                f"sysUpTime not found in SNMP response from {self.target}."
            )
            return None
        self.sysname = snmp_data.get("sysName", self.target)
        oid_value, snmp_type = snmp_data.get("oid_value", (None, None))
        if oid_value is None:
            return None
        if not self.is_counter and snmp_type in {"Counter32", "Counter64"}:
            self.is_counter = True
        if self.is_counter:
            return self.process_counter(oid_value, sysuptime)
        else:
            return oid_value

    def process_counter(
        self, oid_value: float, sysuptime: float
    ) -> Optional[Union[float, Dict[str, Optional[float]]]]:
        if self.initial_fetch:
            self.previous_oid_value = oid_value
            self.previous_sysuptime = sysuptime
            self.initial_fetch = False
            return {}
        if self.previous_oid_value is None or self.previous_sysuptime is None:
            return None
        delta_counter = oid_value - self.previous_oid_value
        delta_sysuptime = sysuptime - self.previous_sysuptime
        if delta_counter < 0 or delta_sysuptime <= 0:
            self.logger.warning(
                f"Rollover detected for {self.target}, OID: {self.oid}. Skipping calculation."
            )
            self.previous_oid_value = oid_value
            self.previous_sysuptime = sysuptime
            return None
        rate = delta_counter / delta_sysuptime
        self.previous_oid_value = oid_value
        self.previous_sysuptime = sysuptime
        return rate

    def execute_snmpget(self) -> Optional[str]:
        command = [
            "snmpget",
            "-On",
            "-v",
            "2c",
            "-c",
            self.community,
            self.target,
            self.oid,
            ".1.3.6.1.2.1.1.3.0",
            ".1.3.6.1.2.1.1.5.0",
        ]
        if self.timeout and self.timeout != "default":
            command += ["-t", self.timeout]
        command = [arg if arg is not None else "" for arg in command]
        command_str_list = cast(List[str], command)
        return self.executor.execute(command_str_list)

    def parse_snmp_output(self, output: str) -> Dict[str, Any]:
        snmp_results: Dict[str, Union[str, float, Any]] = {}
        for line in output.strip().splitlines():
            match = re.match("(\\S+) = (\\S+):\\s*(.+)", line)
            if match:
                oid, snmp_type, value = match.groups()
                if oid == ".1.3.6.1.2.1.1.3.0":
                    ticks_match = re.search("\\((\\d+)\\)", value)
                    if ticks_match:
                        snmp_results["sysUpTime"] = int(ticks_match.group(1)) * 0.01
                elif oid == ".1.3.6.1.2.1.1.5.0":
                    cleaned_value = value.strip('"')
                    snmp_results["sysName"] = str(cleaned_value)
                else:
                    try:
                        snmp_results["oid_value"] = (float(value), str(snmp_type))
                    except ValueError:
                        self.logger.error(f"Invalid OID value: {value}")
        return snmp_results


class SnmpTrafficMonitor(BaseMonitor):

    def __init__(self, target: str, executor: CommandExecutor, index: int) -> None:
        super().__init__(target, executor, index)
        self.community: Optional[str] = None
        self.ifindex: Optional[int] = None
        self.ifname: Optional[str] = None
        self.sysname: Optional[str] = None
        self.previous_in_octets: Optional[int] = None
        self.previous_out_octets: Optional[int] = None
        self.previous_sysuptime: Optional[float] = None
        self.use_32bit_counters: Optional[bool] = None
        self.timeout: Optional[str] = None
        self.initial_fetch: bool = True
        self.logger = logging.getLogger(self.__class__.__name__)

    def set_options(self, **kwargs: Any) -> None:
        self.community = kwargs.get("community")
        interface_input = kwargs.get("interface")
        self.timeout = kwargs.get("timeout", "default")
        if interface_input is None:
            self.logger.error("Interface not provided.")
            return
        if interface_input.isdigit():
            self.ifindex = int(interface_input)
            self.ifname = None
            resolved_ifname = self.resolve_ifname(self.ifindex)
            if resolved_ifname is not None:
                self.interface_label = resolved_ifname
            else:
                self.interface_label = f"ifIndex.{self.ifindex}"
        else:
            self.ifname = interface_input
            resolved_ifindex = self.resolve_ifindex(interface_input)
            if resolved_ifindex is not None:
                self.ifindex = resolved_ifindex
                self.interface_label = self.ifname if self.ifname is not None else "Unknown"
            else:
                self.ifindex = None
                self.interface_label = self.ifname if self.ifname is not None else "Unknown"

    def get_unique_key(self) -> str:
        return f"snmp_traffic_{self.index}"

    def fetch_and_process_metric(self) -> Optional[Dict[str, Optional[float]]]:
        if self.initial_fetch:
            self.initial_fetch = False
            self.initialize_counters()
            return {}
        if self.use_32bit_counters is None:
            self.use_32bit_counters = not self.check_64bit_counter_support()
        in_oid, out_oid = self.get_oids()
        output = self.execute_snmpget(in_oid, out_oid)
        if output is None:
            return {"in": None, "out": None}
        snmp_results = self.parse_snmp_output(output)
        if not snmp_results:
            return {"in": None, "out": None}
        sysuptime = self.extract_sysuptime(snmp_results)
        if sysuptime is None:
            return {"in": None, "out": None}
        self.sysname = self.extract_sysname(snmp_results)
        in_octets = self.extract_octet(snmp_results, in_oid, "In")
        out_octets = self.extract_octet(snmp_results, out_oid, "Out")
        rates = self.calculate_rates(in_octets, out_octets, sysuptime)
        return rates

    def initialize_counters(self) -> None:
        if self.use_32bit_counters is None:
            self.use_32bit_counters = not self.check_64bit_counter_support()
        in_oid, out_oid = self.get_oids()
        output = self.execute_snmpget(in_oid, out_oid)
        if output is None:
            return
        snmp_results = self.parse_snmp_output(output)
        if not snmp_results:
            return
        sysuptime = self.extract_sysuptime(snmp_results)
        if sysuptime is None:
            return
        self.sysname = self.extract_sysname(snmp_results)
        in_octets = self.extract_octet(snmp_results, in_oid, "In")
        out_octets = self.extract_octet(snmp_results, out_oid, "Out")
        self.previous_in_octets = in_octets
        self.previous_out_octets = out_octets
        self.previous_sysuptime = sysuptime

    def check_64bit_counter_support(self) -> bool:
        in_oid = f".1.3.6.1.2.1.31.1.1.1.6.{self.ifindex}"
        command: List[str] = [
            "snmpget",
            "-On",
            "-v",
            "2c",
            "-c",
            self.community or "",
            self.target,
            in_oid,
        ]
        output = self.executor.execute(command)
        if output is None:
            self.logger.info(
                "Failed to retrieve any value. Switching to 32-bit counters."
            )
            return False
        if "No Such Object available on this agent at this OID" in output:
            self.logger.info(
                "64bit counters are not supported. Switching to 32-bit counters."
            )
            return False
        snmp_results = self.parse_snmp_output(output)
        if not snmp_results:
            self.logger.info(
                "No valid SNMP output parsed. Switching to 32-bit counters."
            )
            return False
        for _, (_, value) in snmp_results.items():
            if re.match("^\\d+$", value):
                self.logger.debug(
                    "64bit counters are supported. Starting with 64-bit counters."
                )
                return True
        self.logger.info(
            "Unable to determine if 64-bit counters are supported. Switching to 32-bit counters."
        )
        return False

    def get_oids(self) -> Tuple[str, str]:
        if self.use_32bit_counters:
            in_oid = f".1.3.6.1.2.1.2.2.1.10.{self.ifindex}"
            out_oid = f".1.3.6.1.2.1.2.2.1.16.{self.ifindex}"
        else:
            in_oid = f".1.3.6.1.2.1.31.1.1.1.6.{self.ifindex}"
            out_oid = f".1.3.6.1.2.1.31.1.1.1.10.{self.ifindex}"
        return (in_oid, out_oid)

    def execute_snmpget(self, in_oid: str, out_oid: str) -> Optional[str]:
        timeout_option = ""
        if self.timeout and self.timeout != "default":
            timeout_option = f"-t {self.timeout}"
        command: List[str] = [
            "snmpget",
            "-On",
            "-v",
            "2c",
            "-c",
            self.community or "",
            self.target,
            in_oid,
            out_oid,
            ".1.3.6.1.2.1.1.3.0",
            ".1.3.6.1.2.1.1.5.0",
        ]
        if timeout_option:
            command.extend(shlex.split(timeout_option))
        return self.executor.execute(command)

    def parse_snmp_output(self, output: str) -> Dict[str, Tuple[str, str]]:
        try:
            lines = output.strip().splitlines()
            snmp_results: Dict[str, Tuple[str, str]] = {}
            for line in lines:
                match = re.match("(\\S+)\\s*=\\s*(\\S+):\\s*(.+)", line)
                if match:
                    oid = match.group(1)
                    snmp_type = match.group(2)
                    value = match.group(3)
                    snmp_results[oid] = (snmp_type, value)
            return snmp_results
        except Exception as e:
            self.logger.error(f"Error parsing SNMP output: {e}")
            return {}

    def extract_sysuptime(
        self, snmp_results: Dict[str, Tuple[str, str]]
    ) -> Optional[float]:
        sysuptime_oid = ".1.3.6.1.2.1.1.3.0"
        if sysuptime_oid in snmp_results:
            sysuptime_str = snmp_results[sysuptime_oid][1]
            match = re.match("\\((\\d+)\\)\\s+.*", sysuptime_str)
            if match:
                sysuptime_ticks = int(match.group(1))
                sysuptime_seconds = sysuptime_ticks * 0.01
                return sysuptime_seconds
            else:
                self.logger.error(f"Could not parse sysUpTime from: {sysuptime_str}")
        else:
            self.logger.error(
                f"sysUpTime not found in SNMP response from {self.target}."
            )
        return None

    def extract_sysname(
        self, snmp_results: Dict[str, Tuple[str, str]]
    ) -> Optional[str]:
        sysname_oid = ".1.3.6.1.2.1.1.5.0"
        if sysname_oid in snmp_results:
            raw_value = snmp_results[sysname_oid][1]
            return raw_value.strip('"')
        else:
            self.logger.error(f"sysName not found in SNMP response from {self.target}.")
            return self.target

    def extract_octet(
        self, snmp_results: Dict[str, Tuple[str, str]], oid: str, direction: str
    ) -> Optional[int]:
        if oid in snmp_results:
            _, value_str = snmp_results[oid]
            try:
                return int(value_str)
            except ValueError:
                self.logger.error(f"Invalid {direction} Octets value: {value_str}")
        else:
            self.logger.error(
                f"{direction} Octets OID {oid} not found in SNMP response from {self.target}."
            )
        return None

    def calculate_rates(
        self, in_octets: Optional[int], out_octets: Optional[int], sysuptime: float
    ) -> Dict[str, Optional[float]]:
        in_rate: Optional[float] = None
        out_rate: Optional[float] = None
        if self.previous_sysuptime is not None:
            if sysuptime < self.previous_sysuptime:
                self.logger.warning(
                    f"sysUpTime rollover detected for {self.target}. Current sysUpTime: {sysuptime}, Previous sysUpTime: {self.previous_sysuptime}."
                )
                self.previous_sysuptime = sysuptime
                self.previous_in_octets = in_octets
                self.previous_out_octets = out_octets
                return {"in": None, "out": None}
        if (
            in_octets is not None
            and self.previous_in_octets is not None
            and (self.previous_sysuptime is not None)
        ):
            delta_in = in_octets - self.previous_in_octets
            delta_sysuptime = sysuptime - self.previous_sysuptime
            if delta_in < 0:
                self.logger.warning(
                    f"In Octets rollover detected for {self.target}, Interface: {self.ifindex}. Current: {in_octets}, Previous: {self.previous_in_octets}."
                )
            elif delta_sysuptime > 0:
                in_rate = delta_in * 8 / delta_sysuptime
        if (
            out_octets is not None
            and self.previous_out_octets is not None
            and (self.previous_sysuptime is not None)
        ):
            delta_out = out_octets - self.previous_out_octets
            delta_sysuptime = sysuptime - self.previous_sysuptime
            if delta_out < 0:
                self.logger.warning(
                    f"Out Octets rollover detected for {self.target}, Interface: {self.ifindex}. Current: {out_octets}, Previous: {self.previous_out_octets}."
                )
            elif delta_sysuptime > 0:
                out_rate = delta_out * 8 / delta_sysuptime
        self.previous_in_octets = in_octets
        self.previous_out_octets = out_octets
        self.previous_sysuptime = sysuptime
        return {"in": in_rate, "out": out_rate}

    def resolve_ifindex(self, ifname_input: str) -> Optional[int]:
        command: List[str] = [
            "snmpwalk",
            "-On",
            "-v",
            "2c",
            "-c",
            self.community or "",
            self.target,
            ".1.3.6.1.2.1.31.1.1.1.1",
        ]
        output = self.executor.execute(command)
        if output is None:
            self.logger.error("Failed to execute snmpwalk for ifName.")
            return None
        try:
            pattern = re.compile(
                "\\.1\\.3\\.6\\.1\\.2\\.1\\.31\\.1\\.1\\.1\\.1\\.(\\d+) = STRING: (.+)"
            )
            for line in output.strip().splitlines():
                match = pattern.match(line)
                if match:
                    ifindex = int(match.group(1))
                    raw_ifname = match.group(2)
                    ifname = raw_ifname.strip('"')
                    if ifname.lower() == ifname_input.lower():
                        return ifindex
            self.logger.error(f"No interface with name '{ifname_input}' found.")
            return None
        except Exception as e:
            self.logger.error(f"Error parsing snmpwalk output for ifName: {e}")
            return None

    def resolve_ifname(self, ifindex: int) -> Optional[str]:
        oid = f".1.3.6.1.2.1.31.1.1.1.1.{ifindex}"
        command = ["snmpget", "-On", "-v", "2c", "-c", self.community or ""
                   , self.target, oid]
        output = self.executor.execute(command)
        if output is None:
            self.logger.error(
                f"Failed to execute snmpget for ifName with ifIndex {ifindex}."
            )
            return None
        match = re.match(
            f"\\.1\\.3\\.6\\.1\\.2\\.1\\.31\\.1\\.1\\.1\\.1\\.{ifindex} = STRING: (.+)",
            output,
        )
        if match:
            raw_ifname = match.group(1)
            return raw_ifname.strip('"')
        else:
            self.logger.error(f"Could not parse ifName from snmpget output: {output}")
            return None


class BufferedCsvWriterThread(threading.Thread):

    def __init__(
        self,
        monitor_type: str,
        monitors: List["BaseMonitor"],
        targets: List[str],
        stop_event: threading.Event,
        include_ms: bool,
        input_queue: queue.Queue,
    ) -> None:
        super().__init__(daemon=False)
        self.monitor_type = monitor_type.lower()
        self.monitors = monitors
        self.targets = targets
        self.stop_event = stop_event
        self.include_ms = include_ms
        self.data_queue = input_queue
        self.current_date = datetime.now().strftime("%Y%m%d")
        self.file: Optional[TextIO] = None
        self.writer: Optional[Any] = None
        self.header_written = False
        self.lock = threading.Lock()
        self.logger = logging.getLogger(self.__class__.__name__)
        self.monitors_info: Optional[List[dict]] = None

    def run(self) -> None:
        self.logger.info("BufferedCsvWriterThread started.")
        try:
            while not self.stop_event.is_set():
                try:
                    data = self.data_queue.get(timeout=0.5)
                except queue.Empty:
                    time.sleep(0.01)
                    continue
                if (
                    isinstance(data, dict)
                    and "timestamp" in data
                    and ("metrics" in data)
                ):
                    timestamp_str = data["timestamp"]
                    metrics = data["metrics"]
                    if self.monitors_info is None and "monitors_info" in data:
                        self.monitors_info = data["monitors_info"]
                    if not self.header_written:
                        self.write_header()
                        self.header_written = True
                    self.write_data(timestamp_str, metrics)
            if self.file:
                self.logger.info(f"Closing CSV file '{self.file.name}'.")
                self.file.close()
            self.logger.info("BufferedCsvWriterThread stopped.")
        except Exception as e:
            self.logger.error(f"Error in BufferedCsvWriterThread: {e}", exc_info=True)

    def write_header(self) -> None:
        if not self.monitors_info:
            self.logger.error("monitors_info not available for header generation.")
            return
        headers = ["DateTime"]
        if self.monitor_type == "ping":
            for info in self.monitors_info:
                headers.append(f"{info.get('target', 'Unknown')}_Ping_Response_Time_ms")
        elif self.monitor_type == "http":
            for info in self.monitors_info:
                headers.append(f"{info.get('target', 'Unknown')}_HTTP_Response_Time_ms")
        elif self.monitor_type == "dns":
            for info in self.monitors_info:
                server_info = info.get("dns_server", "Unknown")
                headers.append(
                    f"{info.get('target', 'Unknown')}_@{server_info}_DNS_Resolution_Time_ms"
                )
        elif self.monitor_type == "snmp":
            for info in self.monitors_info:
                sysname = info.get("sysName", info.get("target", "Unknown"))
                oid = info.get("oid", "UnknownOID")
                is_counter = info.get("is_counter", False)
                suffix = "_per_sec" if is_counter else ""
                headers.append(f"{sysname}_{oid}{suffix}")
        elif self.monitor_type == "traffic":
            for info in self.monitors_info:
                sysname = info.get("sysName", info.get("target", "Unknown"))
                interface_label = info.get(
                    "ifName", f"ifIndex.{info.get('ifIndex', 'N/A')}"
                )
                direction = info.get("direction", "").lower()
                if direction == "inbound":
                    direction_label = "In_bps"
                elif direction == "outbound":
                    direction_label = "Out_bps"
                else:
                    self.logger.error(
                        "Missing or invalid 'direction' in monitors_info; skipping header entry."
                    )
                    continue
                header = f"{sysname}_{interface_label}_{direction_label}"
                headers.append(header)
        self.open_and_rotate_file()
        if self.writer:
            self.writer.writerow(headers)

    def write_data(self, timestamp: str, metrics: List[Optional[Any]]) -> None:
        cleaned_metrics = []
        for m in metrics:
            if isinstance(m, dict):
                val = m.get("value")
                cleaned_metrics.append(val)
            else:
                cleaned_metrics.append(m)
        if self.monitor_type == "traffic":
            rounded_metrics = [
                str(round(v)) if isinstance(v, (int, float)) else ""
                for v in cleaned_metrics
            ]
        else:
            rounded_metrics = [
                str(round(v, 3)) if isinstance(v, (int, float)) else ""
                for v in cleaned_metrics
            ]
        if not self.include_ms:
            timestamp = timestamp.split(".")[0]
        row = [timestamp] + rounded_metrics
        with self.lock:
            if self.writer and self.file:
                self.writer.writerow(row)
                self.file.flush()

    def open_and_rotate_file(self) -> None:
        new_date = datetime.now().strftime("%Y%m%d")
        if self.file is None or new_date != self.current_date:
            if self.file:
                self.file.close()
                self.logger.info(
                    f"Closing old CSV file for date '{self.current_date}'."
                )
            filename = f"{new_date}_{self.monitor_type.lower()}_monitoring_results.csv"
            self.file = open(filename, "a", newline="")
            self.writer = csv.writer(self.file)
            self.current_date = new_date
            self.header_written = False
            self.logger.info(f"Opening CSV file '{filename}'.")


class WebhookNotifierThread(threading.Thread):

    def __init__(
        self, webhook_url: str, stop_event: threading.Event, input_queue: queue.Queue
    ) -> None:
        super().__init__(daemon=False)
        self.webhook_url = webhook_url
        self.stop_event = stop_event
        self.input_queue = input_queue
        self.logger = logging.getLogger(self.__class__.__name__)

    def run(self) -> None:
        self.logger.info("WebhookNotifierThread started.")
        batch: list[str] = []
        last_sent_time: float = 0.0
        while not self.stop_event.is_set():
            self._collect_notifications(batch)
            current_time = time.time()
            if batch and current_time - last_sent_time >= 1:
                self._send_batch(batch)
                batch = []
                last_sent_time = current_time
            time.sleep(0.05)
        if batch:
            self._send_batch(batch)
        self.logger.info("WebhookNotifierThread stopped.")

    def _collect_notifications(self, batch: list[str]) -> None:
        try:
            notification = self.input_queue.get(timeout=0.5)
            self.logger.debug(
                f"Received notification from webhook queue: {notification}"
            )
            if isinstance(notification, dict) and "message" in notification:
                batch.append(notification["message"])
            else:
                batch.append(str(notification))
        except queue.Empty:
            pass

    def _send_batch(self, batch: list[str]) -> None:
        text_message = "\n".join(batch)
        payload = {"text": text_message}
        self.logger.debug(f"Sending payload:\n{json.dumps(payload, indent=2)}")
        try:
            data = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(
                self.webhook_url,
                data=data,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=5) as response:
                status_code = response.getcode()
                if status_code == 200:
                    self.logger.info(
                        f"Webhook notification sent successfully: {payload}"
                    )
                else:
                    self.logger.error(
                        f"Webhook notification failed: HTTP {status_code}"
                    )
        except Exception as e:
            self.logger.error(f"Error sending webhook notification: {e}")


class NoneStateMonitorThread(threading.Thread):

    def __init__(
        self,
        stop_event: threading.Event,
        input_queue: queue.Queue,
        webhook_queue: queue.Queue,
    ) -> None:
        super().__init__(daemon=False)
        self.logger = logging.getLogger(self.__class__.__name__)
        self.stop_event = stop_event
        self.input_queue = input_queue
        self.webhook_queue = webhook_queue
        self.prev_none_state: Dict[int, bool] = {}

    def run(self) -> None:
        self.logger.info("NoneStateMonitorThread started.")
        try:
            while not self.stop_event.is_set():
                data = self._get_data_from_queue()
                if data is None:
                    continue
                if not (
                    isinstance(data, dict)
                    and "metrics" in data
                    and ("monitors_info" in data)
                ):
                    self.logger.error(
                        "Received invalid data format in NoneStateMonitorThread."
                    )
                    continue
                metrics = data["metrics"]
                monitors_info = data["monitors_info"]
                for idx, metric_data in enumerate(metrics):
                    self._check_none_state(idx, metric_data, monitors_info)
                time.sleep(0.01)
        finally:
            self.logger.info("NoneStateMonitorThread stopped.")

    def _get_data_from_queue(self) -> Optional[dict]:
        try:
            return self.input_queue.get(timeout=0.5)
        except queue.Empty:
            return None

    def _check_none_state(
        self, idx: int, metric_data: dict, monitors_info: List[dict]
    ) -> None:
        value = metric_data.get("value", None)
        if idx not in self.prev_none_state:
            self.prev_none_state[idx] = False
        was_none = self.prev_none_state[idx]
        is_none_now = value is None
        info = monitors_info[idx] if idx < len(monitors_info) else {}
        if is_none_now != was_none:
            self.prev_none_state[idx] = is_none_now
            message = self._format_none_state_message(is_none_now, metric_data, info)
            self.logger.info(message)
            self.webhook_queue.put({"message": message})

    def _format_none_state_message(
        self, is_none: bool, metric_data: dict, info: dict
    ) -> str:
        monitor_type = info.get("monitor_type", "Unknown").lower()
        target = info.get("target", "Unknown")
        timestamp = metric_data.get("timestamp", "")
        current_value = metric_data.get("value")
        prefix = "[Monitoring Failure]" if is_none else "[Monitoring Restored]"
        if monitor_type == "ping":
            if is_none:
                msg = f"{prefix} [Ping] {timestamp} Target: {target}"
            else:
                msg = f"{prefix} [Ping] {timestamp} Target: {target}"
        elif monitor_type == "http":
            if is_none:
                msg = f"{prefix} [HTTP] {timestamp} Target: {target}"
            else:
                msg = f"{prefix} [HTTP] {timestamp} Target: {target}"
        elif monitor_type == "dns":
            dns_server = info.get("dns_server", "default")
            if is_none:
                msg = f"{prefix} [DNS] {timestamp} Query: {target}, DNS Server: {dns_server}"
            else:
                msg = f"{prefix} [DNS] {timestamp} Query: {target}, DNS Server: {dns_server}"
        elif monitor_type == "snmp":
            sysname = info.get("sysName", target)
            oid = info.get("oid", "UnknownOID")
            if is_none:
                msg = f"{prefix} [SNMP] {timestamp} Target: {sysname}, OID: {oid}"
            else:
                msg = f"{prefix} [SNMP] {timestamp} Target: {sysname}, OID: {oid}"
        elif monitor_type == "traffic":
            sysname = info.get("sysName", target)
            interface_label = info.get("ifName", "Unknown Interface")
            direction = info.get("direction", "Unknown")
            if is_none:
                msg = f"{prefix} [Traffic] {timestamp} Target: {sysname}, Interface: {interface_label}, Direction: {direction}"
            else:
                msg = f"{prefix} [Traffic] {timestamp} Target: {sysname}, Interface: {interface_label}, Direction: {direction}"
        elif is_none:
            msg = f"{prefix} [{monitor_type.upper()}] {timestamp} Target: {target}"
        else:
            msg = f"{prefix} [{monitor_type.upper()}] {timestamp} Target: {target}"
        return msg


class AnomalyDetectorThread(threading.Thread):

    def __init__(
        self,
        stop_event: threading.Event,
        input_queue: queue.Queue,
        webhook_queue: Optional[queue.Queue],
        monitor_type: str,
        samples: int = 256,
        contamination: float = 0.01,
        retrain_interval: int = 1,
        shared_data: Optional[Dict[str, List[Dict[str, Any]]]] = None,
        data_lock: Optional[threading.Lock] = None,
        refresh_event: Optional[threading.Event] = None,
    ) -> None:
        super().__init__(daemon=False)
        self.logger = logging.getLogger(self.__class__.__name__)
        self.si_formatter = SIPrefixer()
        self.stop_event = stop_event
        self.input_queue = input_queue
        self.webhook_queue = webhook_queue
        self.monitor_type = monitor_type.lower()
        self.samples = samples
        self.contamination = contamination
        self.retrain_interval = retrain_interval
        self.shared_data = shared_data if shared_data is not None else {}
        self.data_lock = data_lock
        self.refresh_event = (
            refresh_event if refresh_event is not None else threading.Event()
        )
        from sklearn.ensemble import IsolationForest  # type: ignore[import-untyped]

        self.IsolationForest = IsolationForest
        self.models: Dict[str, Any] = {}
        self.model_fitted: Dict[str, bool] = {}
        self.data_buffers: Dict[str, List[float]] = {}
        self.current_batch_counts: Dict[str, int] = {}

    def run(self) -> None:
        self.logger.info("AnomalyDetectorThread started (per-target mode).")
        try:
            while not self.stop_event.is_set():
                data = self._get_data_from_queue()
                if data is None:
                    continue
                if not (
                    isinstance(data, dict)
                    and "metrics" in data
                    and ("monitors_info" in data)
                ):
                    self.logger.debug("Invalid data format in AnomalyDetectorThread.")
                    continue
                metrics = data["metrics"]
                monitors_info = data["monitors_info"]
                for m_data, info in zip(metrics, monitors_info):
                    self._process_metric(m_data, info)
                time.sleep(0.01)
        finally:
            self.logger.info("AnomalyDetectorThread stopped.")

    def _get_data_from_queue(self) -> Optional[dict]:
        try:
            return self.input_queue.get(timeout=0.01)
        except queue.Empty:
            return None

    def _process_metric(self, metric_data: dict, info: dict) -> None:
        base_unique_key = info.get("unique_key")
        if not base_unique_key:
            return
        direction = info.get("direction")
        if direction:
            unique_key = f"{base_unique_key}_{('in' if 'inbound' in direction.lower() else 'out')}"
        else:
            unique_key = base_unique_key
        val = metric_data.get("value")
        if val is None:
            return
        try:
            float_val = float(val)
        except (ValueError, TypeError):
            return
        if unique_key not in self.data_buffers:
            self.data_buffers[unique_key] = []
            self.models[unique_key] = self.IsolationForest(
                n_estimators=100,
                max_samples=self.samples,
                contamination=self.contamination,
                random_state=None,
            )
            self.model_fitted[unique_key] = False
            self.current_batch_counts[unique_key] = 0
        self.data_buffers[unique_key].append(float_val)
        if len(self.data_buffers[unique_key]) > self.samples:
            self.data_buffers[unique_key] = self.data_buffers[unique_key][
                -self.samples :
            ]
        self.current_batch_counts[unique_key] += 1
        if len(self.data_buffers[unique_key]) >= self.samples:
            if self.current_batch_counts[unique_key] >= self.retrain_interval:
                self._retrain_model(unique_key)
                self.current_batch_counts[unique_key] = 0
        if self.model_fitted[unique_key]:
            self._detect_anomaly(unique_key, float_val, metric_data, info)

    def _retrain_model(self, unique_key: str) -> None:
        data_list = self.data_buffers[unique_key]
        if not data_list:
            return
        try:
            train_data = [[x] for x in data_list]
            self.models[unique_key].fit(train_data)
            self.model_fitted[unique_key] = True
            self.logger.debug(
                f"IsolationForest re-trained for {unique_key} on {len(data_list)} samples."
            )
        except Exception as e:
            self.model_fitted[unique_key] = False
            self.logger.error(
                f"Error during IsolationForest training ({unique_key}): {e}"
            )

    def _detect_anomaly(
        self, unique_key: str, latest_val: float, metric_data: dict, info: dict
    ) -> None:
        try:
            prediction = self.models[unique_key].predict([[latest_val]])
            if prediction[0] == -1:
                self._mark_anomaly_in_shared_data(metric_data, unique_key)
                msg = self._format_anomaly_message(
                    info, latest_val, metric_data.get("timestamp", "")
                )
                self.logger.info(msg)
                if self.webhook_queue:
                    self.webhook_queue.put({"message": msg})
                self._update_refresh_event()
        except Exception as e:
            self.logger.error(f"Error during anomaly detection ({unique_key}): {e}")

    def _format_anomaly_message(self, info: dict, value: float, timestamp: str) -> str:
        monitor_type = info.get("monitor_type", "").lower()
        if monitor_type == "ping":
            return f"[Anomaly Detected] [Ping] {timestamp} Target: {info.get('target')}, Response Time: {value} ms"
        elif monitor_type == "http":
            return f"[Anomaly Detected] [HTTP] {timestamp} Target: {info.get('target')}, Response Time: {value} ms"
        elif monitor_type == "dns":
            return f"[Anomaly Detected] [DNS] {timestamp} Query: {info.get('target')}, DNS Server: {info.get('dns_server')}, Resolution Time: {value} ms"
        elif monitor_type == "snmp":
            sysname = info.get("sysName", info.get("target"))
            scaled_val = self.si_formatter.format_value(value)
            return f"[Anomaly Detected] [SNMP] {timestamp} Target: {sysname}, OID: {info.get('oid')}, Value: {scaled_val}"
        elif monitor_type == "traffic":
            sysname = info.get("sysName", info.get("target"))
            interface_label = info.get("ifName", info.get("interface_label"))
            scaled_val = self.si_formatter.format_value(value)
            direction = info.get("direction", "Unknown")
            return f"[Anomaly Detected] [Traffic] {timestamp} Target: {sysname}, Interface: {interface_label}, Direction: {direction}, Traffic: {scaled_val}bps"
        return f"[Anomaly Detected] {timestamp} Target: {info.get('target')}, Value: {value}"

    def _mark_anomaly_in_shared_data(self, metric_data: dict, unique_key: str) -> None:
        idx = metric_data.get("index")
        if idx is None or not self.data_lock:
            return
        with self.data_lock:
            data_list = self.shared_data.get(unique_key, [])
            entry = next((x for x in data_list if x["index"] == idx), None)
            if entry:
                entry["anomaly_detected"] = True

    def _update_refresh_event(self) -> None:
        self.logger.debug("Setting refresh_event due to anomaly detection update.")
        self.refresh_event.set()


class ThresholdMonitorThread(threading.Thread):

    def __init__(
        self,
        thresholds: List[str],
        stop_event: threading.Event,
        input_queue: queue.Queue,
        webhook_queue: queue.Queue,
        shared_data: Dict[str, List[Dict[str, Any]]],
        data_lock: threading.Lock,
        refresh_event: threading.Event,
    ):
        super().__init__(daemon=False)
        self.logger = logging.getLogger(self.__class__.__name__)
        self.si_formatter = SIPrefixer()
        self.thresholds = [th.strip() for th in thresholds]
        self.stop_event = stop_event
        self.input_queue = input_queue
        self.webhook_queue = webhook_queue
        self.shared_data = shared_data
        self.data_lock = data_lock
        self.prev_threshold_state: Dict[int, bool] = {}
        self.refresh_event = refresh_event

    def run(self) -> None:
        self.logger.info("ThresholdMonitorThread started.")
        try:
            while not self.stop_event.is_set():
                data = self._get_data_from_queue()
                if data is None:
                    continue
                if not (
                    isinstance(data, dict)
                    and "metrics" in data
                    and ("monitors_info" in data)
                ):
                    self.logger.error(
                        "Unexpected data format in ThresholdMonitorThread."
                    )
                    continue
                metrics = data["metrics"]
                monitors_info = data["monitors_info"]
                for i, metric_data in enumerate(metrics):
                    th_str = (
                        self.thresholds[i] if i < len(self.thresholds) else "default"
                    )
                    info = monitors_info[i] if i < len(monitors_info) else {}
                    self._check_threshold(metric_data, th_str, info, index=i)
                threading.Event().wait(0.01)
        finally:
            self.logger.info("ThresholdMonitorThread stopped.")

    def _get_data_from_queue(self) -> Optional[dict]:
        try:
            return self.input_queue.get(timeout=0.01)
        except queue.Empty:
            return None

    def _check_threshold(
        self, metric_data: dict, th_str: str, info: dict, index: int
    ) -> None:
        value = metric_data.get("value")
        if not info or "unique_key" not in info:
            return
        base_unique_key = info["unique_key"]
        if info.get("monitor_type", "").lower() == "traffic" and "direction" in info:
            direction = info["direction"].lower()
            unique_key = (
                f"{base_unique_key}_{('in' if 'inbound' in direction else 'out')}"
            )
        else:
            unique_key = base_unique_key
        if th_str.lower() == "default" or value is None:
            return
        is_exceeded = False
        try:
            if th_str.startswith(">"):
                threshold_val = float(th_str[1:])
                if value > threshold_val:
                    is_exceeded = True
            elif th_str.startswith("<"):
                threshold_val = float(th_str[1:])
                if value < threshold_val:
                    is_exceeded = True
            else:
                threshold_val = float(th_str)
                if value > threshold_val:
                    is_exceeded = True
        except ValueError:
            self.logger.error(f"Invalid threshold value: {th_str}")
            return
        was_exceeded = self.prev_threshold_state.get(index, False)
        if is_exceeded != was_exceeded:
            msg = self._format_threshold_message(
                info, value, th_str, is_exceeded, metric_data.get("timestamp", "")
            )
            self.logger.info(msg)
            self.webhook_queue.put({"message": msg})
            self._update_refresh_event()
        if is_exceeded:
            self._update_refresh_event()
        self.prev_threshold_state[index] = is_exceeded
        with self.data_lock:
            data_list = self.shared_data.get(unique_key, [])
            entry = next(
                (x for x in data_list if x["index"] == metric_data.get("index")), None
            )
            if entry:
                entry["threshold_exceeded"] = is_exceeded

    def _format_threshold_message(
        self,
        info: dict,
        value: float,
        threshold: str,
        is_exceeded: bool,
        timestamp: str,
    ) -> str:
        monitor_type = info.get("monitor_type", "").lower()
        state_str = "Threshold Exceeded" if is_exceeded else "Threshold Recovery"
        if monitor_type == "ping":
            msg = f"[{state_str}] [Ping] {timestamp} Target: {info.get('target')}, Response Time: {value} ms, Threshold: {threshold} ms"
        elif monitor_type == "http":
            msg = f"[{state_str}] [HTTP] {timestamp} Target: {info.get('target')}, Response Time: {value} ms, Threshold: {threshold} ms"
        elif monitor_type == "dns":
            msg = f"[{state_str}] [DNS] {timestamp} Query: {info.get('target')}, DNS Server: {info.get('dns_server')}, Resolution Time: {value} ms, Threshold: {threshold} ms"
        elif monitor_type == "snmp":
            sysname = info.get("sysName", info.get("target"))
            scaled_value = self.si_formatter.format_value(value)
            try:
                th_val = float(threshold.lstrip("><"))
                scaled_threshold = self.si_formatter.format_value(th_val)
            except ValueError:
                scaled_threshold = threshold
            msg = f"[{state_str}] [SNMP] {timestamp} Target: {sysname}, OID: {info.get('oid')}, Value: {scaled_value}, Threshold: {scaled_threshold}"
        elif monitor_type == "traffic":
            sysname = info.get("sysName", info.get("target"))
            interface_label = info.get("ifName", info.get("interface_label"))
            scaled_value = self.si_formatter.format_value(value)
            try:
                th_val = float(threshold.lstrip("><"))
                scaled_threshold = self.si_formatter.format_value(th_val)
            except ValueError:
                scaled_threshold = threshold
            direction = info.get("direction", "Unknown")
            msg = f"[{state_str}] [Traffic] {timestamp} Target: {sysname}, Interface: {interface_label}, Direction: {direction}, Traffic: {scaled_value}bps, Threshold: {scaled_threshold}bps"
        else:
            msg = f"[{state_str}] {timestamp} Target: {info.get('target')}, Value: {value}, Threshold: {threshold}"
        return msg

    def _update_refresh_event(self) -> None:
        self.logger.debug("Setting refresh_event due to threshold update.")
        self.refresh_event.set()


class InputHandler:

    def __init__(self) -> None:
        self.logger = logging.getLogger(self.__class__.__name__)
        self.zoom_level: int = 0
        self.height_mode: str = "max"
        self.fd: Optional[int] = None
        self.original_settings = None
        if platform.system().lower() != "windows":
            self.fd = sys.stdin.fileno()
            self.configure_terminal()

    def configure_terminal(self) -> None:
        if self.fd is not None:
            self.original_settings = termios.tcgetattr(self.fd)  # type: ignore[attr-defined]
            tty.setcbreak(self.fd)  # type: ignore[attr-defined]

    def restore_terminal(self) -> None:
        if self.fd is not None and self.original_settings:
            termios.tcsetattr(self.fd, termios.TCSADRAIN, self.original_settings)

    def get_key_press(self) -> Optional[str]:
        if platform.system().lower() == "windows":
            if msvcrt.kbhit():
                return msvcrt.getwch()
            return None
        else:
            dr, _, _ = select.select([sys.stdin], [], [], 0)
            if dr:
                return sys.stdin.read(1)
            return None

    def process_input(self) -> bool:
        key_pressed = self.get_key_press()
        if not key_pressed:
            return False
        redraw = False
        if key_pressed in ["i", "o"]:
            self.adjust_zoom(key_pressed)
            redraw = True
        elif key_pressed in ["g", "n", "x"]:
            self.adjust_height_mode(key_pressed)
            redraw = True
        return redraw

    def adjust_zoom(self, key: str) -> None:
        old_zoom_level = self.zoom_level
        if key == "i":
            if self.zoom_level > 0:
                self.zoom_level -= 1
        elif key == "o":
            self.zoom_level += 1
        self.logger.debug(
            f"Zoom level changed from {old_zoom_level} to {self.zoom_level}."
        )

    def adjust_height_mode(self, key: str) -> None:
        old_mode = self.height_mode
        if key == "g":
            self.height_mode = "avg"
        elif key == "n":
            self.height_mode = "min"
        elif key == "x":
            self.height_mode = "max"
        self.logger.debug(f"Height mode changed from {old_mode} to {self.height_mode}.")


class GraphDrawer:

    def __init__(
        self,
        width: int = 50,
        height: int = 10,
        y_scale: str = "auto",
        scale_y: bool = False,
        color_manager: Optional["ColorManager"] = None,
    ) -> None:
        self.width = width
        self.height = height
        self.y_scale = y_scale
        self.scale_y = scale_y
        self.logger = logging.getLogger(self.__class__.__name__)
        self.unit: str = ""
        self.color_manager = color_manager
        self.si_formatter = SIPrefixer()
        self.factor: float = 1.0

    def draw_graph(
        self,
        datasets: List[List[Dict[str, Any]]],
        symbols: List[str],
        zoom_level: int = 0,
    ) -> str:
        if not self._validate_datasets(datasets):
            return "No data to display."
        group_size = 2**zoom_level
        max_value = self._determine_max_value(datasets)
        step = self._calculate_step(max_value)
        padded_datasets = self._pad_datasets(datasets)
        left_margin = len(self._build_left_label(self.height * step))
        graph_lines = self._draw_graph_body(padded_datasets, symbols, step, left_margin)
        x_axis_line = self._draw_x_axis(left_margin)
        label_line = self._draw_iteration_labels(left_margin, group_size)
        graph_lines.append(x_axis_line)
        graph_lines.append(label_line)
        return "\n".join(graph_lines)

    def _validate_datasets(self, datasets: List[List[Dict[str, Any]]]) -> bool:
        if not datasets or not all(datasets):
            self.logger.debug("Datasets are empty or contain empty lists.")
            return False
        return True

    def _determine_max_value(self, datasets: List[List[Dict[str, Any]]]) -> float:
        raw_max_candidates = []
        for series in datasets:
            for entry in series:
                val = entry["value"]
                if val is not None:
                    raw_max_candidates.append(val)
        if not raw_max_candidates:
            return 1.0
        raw_max = max(raw_max_candidates)
        if raw_max <= 0:
            raw_max = 1.0
        if self.scale_y:
            scaled_max, unit, factor = self.si_formatter.apply(raw_max)
            self.unit = unit
            self.factor = factor
            return scaled_max
        else:
            self.unit = ""
            self.factor = 1.0
            if self.y_scale == "auto":
                return raw_max
            else:
                try:
                    fixed_scale = float(self.y_scale)
                    if fixed_scale <= 0:
                        raise ValueError
                    return fixed_scale
                except ValueError:
                    self.logger.error(
                        f"Invalid y_scale value: {self.y_scale}. Using auto scaling."
                    )
                    return raw_max

    def _calculate_step(self, max_value: float) -> float:
        return max_value / self.height if self.height > 0 else 1.0

    def _pad_datasets(
        self, datasets: List[List[Dict[str, Any]]]
    ) -> List[List[Dict[str, Any]]]:
        padded = []
        for series in datasets:
            if len(series) < self.width:
                pad_length = self.width - len(series)
                pad_entries = [
                    {
                        "value": None,
                        "threshold_exceeded": False,
                        "anomaly_detected": False,
                    }
                ] * pad_length
                padded_data = pad_entries + series
            else:
                padded_data = series[-self.width :]
            if self.scale_y and self.factor != 1.0:
                new_series = []
                for entry in padded_data:
                    val = entry["value"]
                    scaled_val = val / self.factor if val is not None else None
                    new_series.append(
                        {
                            "value": scaled_val,
                            "threshold_exceeded": entry["threshold_exceeded"],
                            "anomaly_detected": entry["anomaly_detected"],
                        }
                    )
                padded.append(new_series)
            else:
                padded.append(padded_data)
        return padded

    def _draw_graph_body(
        self,
        padded_datasets: List[List[Dict[str, Any]]],
        symbols: List[str],
        step: float,
        left_margin: int,
    ) -> List[str]:
        graph_lines = []
        for row in range(self.height, 0, -1):
            current_level = row * step
            label = self._build_left_label(current_level)
            line = f"{label} | "
            for col in range(self.width):
                drawn_symbol = self._determine_symbol(
                    padded_datasets, symbols, col, current_level, row
                )
                line += drawn_symbol
            graph_lines.append(line)
        return graph_lines

    def _build_left_label(self, current_level: float) -> str:
        if self.scale_y:
            return f"{current_level:.2f} {self.unit}".rjust(8)
        else:
            return f"{current_level:4.0f}".rjust(4)

    def _determine_symbol(
        self,
        padded_datasets: List[List[Dict[str, Any]]],
        symbols: List[str],
        col: int,
        current_level: float,
        row: int,
    ) -> str:
        col_values = []
        for dataset_idx, series in enumerate(padded_datasets):
            entry = series[col]
            val = entry["value"]
            thr_ex = entry["threshold_exceeded"]
            ano_dt = entry["anomaly_detected"]
            col_values.append((val, dataset_idx, thr_ex, ano_dt))

        def none_to_neginf(v: Optional[float]) -> float:
            return float("-inf") if v is None else float(v)

        col_values.sort(key=lambda x: none_to_neginf(x[0]))
        for val, ds_idx, thr_ex, ano_dt in col_values:
            if val is not None and (val >= current_level or (val > 0 and row == 1)):
                symbol = symbols[ds_idx] if ds_idx < len(symbols) else "*"
                if ano_dt and self.color_manager:
                    symbol = self.color_manager.colorize(symbol, "red")
                elif thr_ex and self.color_manager:
                    symbol = self.color_manager.colorize(symbol, "red")
                return symbol
        return " "

    def _draw_x_axis(self, left_margin: int) -> str:
        left_margin += 2
        axis_len = self.width + 2
        first_chunk_length = self.width % 10 + 1
        first_chunk = "-" * first_chunk_length + "|"
        repeated_chunk = "---------" + "|"
        axis_str = first_chunk
        while len(axis_str) < axis_len:
            axis_str += repeated_chunk
        axis_str = axis_str[:axis_len]
        return " " * left_margin + axis_str

    def _draw_iteration_labels(self, left_margin: int, group_size: int) -> str:
        left_margin += 3
        axis_len = self.width + 2
        label_array = [" "] * (axis_len + left_margin)
        total_range = self.width * group_size
        bar_positions = [col for col in range(0, self.width + 1, 10)]
        for col in bar_positions:
            label_val = round((self.width - col) / self.width * total_range)
            label_str = str(label_val)
            pos = left_margin + col
            if pos < 0:
                pos = 0
            for i, ch in enumerate(label_str):
                if pos + i < len(label_array):
                    label_array[pos + i] = ch
        return "".join(label_array)

    def scale_value(self, raw_value: Optional[float]) -> str:
        if raw_value is None:
            return "N/A"
        scaled_val = raw_value / self.factor
        if self.factor != 1.0:
            return f"{scaled_val:.2f} {self.unit}"
        else:
            return f"{raw_value:.2f}"


class DataAggregator:

    def __init__(
        self,
        monitors: List["BaseMonitor"],
        shared_data: Dict[str, List[Dict[str, Any]]],
        data_lock: threading.Lock,
        graph_width: int,
    ) -> None:
        self.logger = logging.getLogger(self.__class__.__name__)
        self.monitors = monitors
        self.shared_data = shared_data
        self.data_lock = data_lock
        self.graph_width = graph_width

    def aggregate_data_for_display(
        self, zoom_level: int, height_mode: str, monitor_type: str
    ) -> List[List[Dict[str, Any]]]:
        with self.data_lock:
            aggregated_datasets: List[List[Dict[str, Any]]] = []
            for monitor in self.monitors:
                if monitor_type.lower() == "traffic":
                    unique_key = monitor.get_unique_key()
                    in_key = f"{unique_key}_in"
                    out_key = f"{unique_key}_out"
                    data_in = self.shared_data.get(in_key, [])
                    data_out = self.shared_data.get(out_key, [])
                    aggregated_in = self._aggregate_data(
                        data_in, zoom_level, height_mode, self.graph_width
                    )
                    aggregated_out = self._aggregate_data(
                        data_out, zoom_level, height_mode, self.graph_width
                    )
                    aggregated_datasets.append(aggregated_in)
                    aggregated_datasets.append(aggregated_out)
                else:
                    unique_key = monitor.get_unique_key()
                    data_list = self.shared_data.get(unique_key, [])
                    aggregated = self._aggregate_data(
                        data_list, zoom_level, height_mode, self.graph_width
                    )
                    aggregated_datasets.append(aggregated)
        return aggregated_datasets

    def _aggregate_data(
        self, data: List[Dict[str, Any]], zoom_level: int, height_mode: str, width: int
    ) -> List[Dict[str, Any]]:
        group_size = 2**zoom_level if zoom_level > 0 else 1
        relevant_data = data[-(width * group_size) :]
        pad_size = width * group_size - len(relevant_data)
        pad_entry = {
            "index": -1,
            "timestamp": "",
            "value": None,
            "threshold_exceeded": False,
            "anomaly_detected": False,
        }
        relevant_data = [pad_entry.copy() for _ in range(pad_size)] + relevant_data
        aggregated: List[Dict[str, Any]] = []
        for i in range(0, len(relevant_data), group_size):
            group = relevant_data[i : i + group_size]
            valid_values = [x["value"] for x in group if x["value"] is not None]
            threshold_ex = any((x["threshold_exceeded"] for x in group))
            anomaly_det = any((x["anomaly_detected"] for x in group))
            if height_mode == "min":
                agg_value = min(valid_values) if valid_values else None
            elif height_mode == "avg":
                agg_value = (
                    sum(valid_values) / len(valid_values) if valid_values else None
                )
            else:
                agg_value = max(valid_values) if valid_values else None
            aggregated.append(
                {
                    "value": agg_value,
                    "threshold_exceeded": threshold_ex,
                    "anomaly_detected": anomaly_det,
                }
            )
        if len(aggregated) > width:
            aggregated = aggregated[-width:]
        elif len(aggregated) < width:
            short_pad = width - len(aggregated)
            aggregated = [
                {"value": None, "threshold_exceeded": False, "anomaly_detected": False}
            ] * short_pad + aggregated
        return aggregated


class DisplayStatisticsHelper:

    def __init__(
        self, monitor_type: str, monitors: List["BaseMonitor"], graph_symbols: List[str]
    ):
        self.monitor_type = monitor_type.lower()
        self.monitors = monitors
        self.graph_symbols = graph_symbols
        self.si_formatter = SIPrefixer()

    def append_statistics(
        self, output_buffer: List[str], stats_dict: Dict[str, "StatisticsManager"]
    ) -> None:
        if self.monitor_type == "traffic":
            self.append_traffic_statistics(output_buffer, stats_dict)
        elif self.monitor_type == "snmp":
            self.append_snmp_statistics(output_buffer, stats_dict)
        else:
            self.append_general_statistics(output_buffer, stats_dict)

    def append_traffic_statistics(
        self, output_buffer: List[str], stats_dict: Dict[str, "StatisticsManager"]
    ) -> None:
        for monitor in self.monitors:
            traffic_monitor = cast(SnmpTrafficMonitor, monitor)
            unique_key_in = f"{traffic_monitor.get_unique_key()}_in"
            unique_key_out = f"{traffic_monitor.get_unique_key()}_out"
            symbol_in = self.graph_symbols[0] if len(self.graph_symbols) > 0 else "*"
            symbol_out = self.graph_symbols[1] if len(self.graph_symbols) > 1 else "#"
            interface_label = getattr(
                traffic_monitor, "interface_label", f"ifIndex.{traffic_monitor.ifindex}"
            )
            output_buffer.append(
                f"{traffic_monitor.sysname} {interface_label} In [{symbol_in}], Out [{symbol_out}]:"
            )
            stats_data_in = stats_dict[unique_key_in].get_statistics()
            min_value_in = self.si_formatter.format_value(stats_data_in["min_value"])
            avg_value_in = self.si_formatter.format_value(stats_data_in["avg_value"])
            max_value_in = self.si_formatter.format_value(stats_data_in["max_value"])
            current_value_in = self.si_formatter.format_value(
                stats_data_in["current_value"]
            )
            stats_data_out = stats_dict[unique_key_out].get_statistics()
            min_value_out = self.si_formatter.format_value(stats_data_out["min_value"])
            avg_value_out = self.si_formatter.format_value(stats_data_out["avg_value"])
            max_value_out = self.si_formatter.format_value(stats_data_out["max_value"])
            current_value_out = self.si_formatter.format_value(
                stats_data_out["current_value"]
            )
            field_width = 8
            output_buffer.append(
                f"[{symbol_in}] Min: {min_value_in:>{field_width}}, Avg: {avg_value_in:>{field_width}}, Max: {max_value_in:>{field_width}}, Cur: {current_value_in:>{field_width}}"
            )
            output_buffer.append(
                f"[{symbol_out}] Min: {min_value_out:>{field_width}}, Avg: {avg_value_out:>{field_width}}, Max: {max_value_out:>{field_width}}, Cur: {current_value_out:>{field_width}}"
            )
            output_buffer.append("-" * 62)

    def append_snmp_statistics(
        self, output_buffer: List[str], stats_dict: Dict[str, "StatisticsManager"]
    ) -> None:
        for idx, monitor in enumerate(self.monitors):
            snmp_monitor = cast(SnmpMonitor, monitor)
            unique_key = snmp_monitor.get_unique_key()
            symbol = self.graph_symbols[idx] if idx < len(self.graph_symbols) else "*"
            stats_label = f"{snmp_monitor.sysname} {snmp_monitor.oid} [{symbol}]:"
            stats_data = stats_dict[unique_key].get_statistics()
            min_value = self.si_formatter.format_value(stats_data["min_value"])
            avg_value = self.si_formatter.format_value(stats_data["avg_value"])
            max_value = self.si_formatter.format_value(stats_data["max_value"])
            current_value = self.si_formatter.format_value(stats_data["current_value"])
            output_buffer.append(stats_label)
            field_width = 8
            output_buffer.append(
                f"Min: {min_value:>{field_width}}, Avg: {avg_value:>{field_width}}, Max: {max_value:>{field_width}}, Cur: {current_value:>{field_width}}"
            )
            output_buffer.append("-" * 62)

    def append_general_statistics(
        self, output_buffer: List[str], stats_dict: Dict[str, "StatisticsManager"]
    ) -> None:
        for idx, monitor in enumerate(self.monitors):
            unique_key = monitor.get_unique_key()
            symbol = self.graph_symbols[idx] if idx < len(self.graph_symbols) else "*"
            server_info = ""
            if isinstance(monitor, DnsMonitor) and hasattr(monitor, "server_info"):
                dns_monitor = cast(DnsMonitor, monitor)
                if dns_monitor.server_info:
                    server_info = f" @{dns_monitor.server_info}"
            target_label = f"{monitor.target}{server_info} [{symbol}]:"
            stats_data = stats_dict[unique_key].get_statistics()
            min_value = (
                f"{stats_data['min_value']:.0f}"
                if stats_data["min_value"] is not None
                else "N/A"
            )
            avg_value = (
                f"{stats_data['avg_value']:.0f}"
                if stats_data["avg_value"] is not None
                else "N/A"
            )
            max_value = (
                f"{stats_data['max_value']:.0f}"
                if stats_data["max_value"] is not None
                else "N/A"
            )
            current_value = (
                f"{stats_data['current_value']:.0f}"
                if stats_data["current_value"] is not None
                else "N/A"
            )
            output_buffer.append(target_label)
            output_buffer.append(
                f"Total: {stats_data['total']}, Fail: {stats_data['failures']}, Min: {min_value}, Avg: {avg_value}, Max: {max_value}, Cur: {current_value}"
            )
            output_buffer.append("-" * 57)


class DisplayThread(threading.Thread):

    def __init__(
        self,
        monitor_type: str,
        monitors: List["BaseMonitor"],
        stats_dict: Dict[str, "StatisticsManager"],
        graphdrawer: "GraphDrawer",
        interval: float,
        keep_data: int,
        graph_symbols: List[str],
        shared_data: Dict[str, List[Dict[str, Any]]],
        data_lock: threading.Lock,
        stop_event: threading.Event,
        input_queue: queue.Queue,
        color_manager: Optional["ColorManager"] = None,
        refresh_event: Optional[threading.Event] = None,
    ) -> None:
        super().__init__(daemon=False)
        self.logger = logging.getLogger(self.__class__.__name__)
        self.monitor_type = monitor_type
        self.monitors = monitors
        self.stats_dict = stats_dict
        self.graphdrawer = graphdrawer
        self.interval = interval
        self.keep_data = keep_data
        self.graph_symbols = graph_symbols
        self.shared_data = shared_data
        self.data_lock = data_lock
        self.stop_event = stop_event
        self.color_manager = color_manager
        self.input_queue = input_queue
        self.refresh_event = (
            refresh_event if refresh_event is not None else threading.Event()
        )
        self.input_handler = InputHandler()
        self.data_processor = DataAggregator(
            monitors=self.monitors,
            shared_data=self.shared_data,
            data_lock=self.data_lock,
            graph_width=self.graphdrawer.width,
        )
        self.output_buffer: List[str] = []
        self.initial_clear: bool = True
        self.stats_helper = DisplayStatisticsHelper(
            monitor_type=self.monitor_type,
            monitors=self.monitors,
            graph_symbols=self.graph_symbols,
        )

    def run(self) -> None:
        self.logger.info("DisplayThread started.")
        try:
            while not self.stop_event.is_set():
                redraw_due_to_input = self.input_handler.process_input()
                data_received = False
                new_metrics: Optional[dict] = None
                try:
                    new_metrics = self.input_queue.get(timeout=0.05)
                    data_received = True
                except queue.Empty:
                    pass
                if redraw_due_to_input or data_received or self.refresh_event.is_set():
                    if self.refresh_event.is_set():
                        self.logger.debug(
                            "Refresh event detected. Forcing immediate redraw."
                        )
                        self.refresh_event.clear()
                    self.flicker_free_clear_screen()
                    aggregated_datasets = (
                        self.data_processor.aggregate_data_for_display(
                            zoom_level=self.input_handler.zoom_level,
                            height_mode=self.input_handler.height_mode,
                            monitor_type=self.monitor_type,
                        )
                    )
                    self.prepare_and_display_output(aggregated_datasets)
                time.sleep(0.01)
        finally:
            self.logger.info("DisplayThread stopped.")
            self.input_handler.restore_terminal()

    def flicker_free_clear_screen(self) -> None:
        if self.initial_clear:
            if platform.system().lower() == "windows":
                subprocess.run("cls", shell=True)
            else:
                subprocess.run("clear", shell=True)
            self.initial_clear = False
        else:
            print("\033[H\033[J", end="")

    def prepare_and_display_output(
        self, aggregated_datasets: List[List[Dict[str, Any]]]
    ) -> None:
        self.output_buffer.clear()
        zoom_info = f"(Zoom Level: 1/{2 ** self.input_handler.zoom_level} using {self.input_handler.height_mode.capitalize()})"
        graph_title = self.get_graph_title()
        self.output_buffer.append(f"{graph_title} {zoom_info}:")
        graph_str = self.graphdrawer.draw_graph(
            aggregated_datasets,
            self.graph_symbols,
            zoom_level=self.input_handler.zoom_level,
        )
        self.output_buffer.append(graph_str)
        self.stats_helper.append_statistics(self.output_buffer, self.stats_dict)
        self.output_buffer.append("i:Zoom In, o:Zoom Out, n:Min, g:Avg, x:Max")
        print("\n".join(self.output_buffer))

    def get_graph_title(self) -> str:
        titles = {
            "ping": "Ping Response Time Graph (ms)",
            "http": "HTTP Response Time Graph (ms)",
            "dns": "DNS Resolution Time Graph (ms)",
            "snmp": "SNMP Value Graph",
            "traffic": "SNMP Traffic Graph (bits/sec)",
        }
        return titles.get(self.monitor_type.lower(), "Unknown Monitoring Type Graph")


class StatisticsManager:

    def __init__(self) -> None:
        self.reset_statistics()

    def reset_statistics(self) -> None:
        self.total: int = 0
        self.success: int = 0
        self.failures: int = 0
        self.min_value: Optional[float] = None
        self.max_value: Optional[float] = None
        self.sum_value: float = 0.0
        self.current_value: Optional[float] = None

    def update_statistics(self, metric_value: Optional[float]) -> None:
        self.total += 1
        if metric_value is not None:
            self.success += 1
            self.current_value = metric_value
            self.sum_value += metric_value
            self.min_value = (
                metric_value
                if self.min_value is None
                else min(self.min_value, metric_value)
            )
            self.max_value = (
                metric_value
                if self.max_value is None
                else max(self.max_value, metric_value)
            )
        else:
            self.failures += 1
            self.current_value = None

    def get_statistics(self) -> Dict[str, Any]:
        avg_value = self.sum_value / self.success if self.success > 0 else None
        failure_rate = self.failures / self.total * 100 if self.total > 0 else 0
        return {
            "total": self.total,
            "success": self.success,
            "failures": self.failures,
            "failure_rate": failure_rate,
            "min_value": self.min_value,
            "avg_value": avg_value,
            "max_value": self.max_value,
            "current_value": self.current_value,
        }


class CollectorThread(threading.Thread):

    def __init__(
        self,
        monitor_type: str,
        monitors: List["BaseMonitor"],
        stats_dict: Dict[str, "StatisticsManager"],
        shared_data: Dict[str, List[Dict[str, Any]]],
        executor_pool: concurrent.futures.ThreadPoolExecutor,
        keep_data: int,
        data_lock: threading.Lock,
        stop_event: threading.Event,
        interval: float,
        display_queue: queue.Queue,
        csv_queue: queue.Queue,
        threshold_queue: queue.Queue,
        anomaly_queue: Optional[queue.Queue] = None,
        none_state_queue: Optional[queue.Queue] = None,
    ) -> None:
        super().__init__(daemon=False)
        self.logger = logging.getLogger(self.__class__.__name__)
        self.monitor_type = monitor_type.lower()
        self.monitors = monitors
        self.stats_dict = stats_dict
        self.shared_data = shared_data
        self.executor_pool = executor_pool
        self.keep_data = keep_data
        self.data_lock = data_lock
        self.stop_event = stop_event
        self.interval = interval
        self.display_queue = display_queue
        self.csv_queue = csv_queue
        self.threshold_queue = threshold_queue
        self.anomaly_queue = anomaly_queue
        self.none_state_queue = none_state_queue
        self.futures: Dict[concurrent.futures.Future, "BaseMonitor"] = {}
        self.current_index: Dict[str, int] = {
            m.get_unique_key(): 0 for m in self.monitors
        }

    def run(self) -> None:
        self.logger.info(f"CollectorThread started for {self.monitor_type}.")
        while not self.stop_event.is_set():
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
            self.submit_fetch_tasks()
            results = self.process_completed_futures()
            monitors_info = self.collect_monitors_info()
            indexed_metrics = self._build_indexed_metrics(
                timestamp, results, monitors_info
            )
            if not indexed_metrics:
                self.logger.debug(
                    "No valid metrics generated in this cycle. Skipping queue send."
                )
            else:
                data_for_queues = {
                    "timestamp": timestamp,
                    "metrics": indexed_metrics,
                    "monitors_info": monitors_info,
                }
                self.logger.debug(f"data_for_queues: {data_for_queues}")
                self.send_to_queues(data_for_queues)
            if self.stop_event.wait(timeout=self.interval):
                break
        self.logger.info("CollectorThread stopped.")

    def _build_indexed_metrics(
        self, timestamp: str, results: List[Optional[Any]], monitors_info: List[dict]
    ) -> List[Dict[str, Any]]:
        indexed_metrics: List[Dict[str, Any]] = []
        for monitor, raw_result in zip(self.monitors, results):
            if isinstance(raw_result, dict) and (not raw_result):
                self.logger.debug(
                    f"Skipping monitor {monitor.get_unique_key()} due to empty result."
                )
                continue
            unique_key = monitor.get_unique_key()
            self.current_index[unique_key] += 1
            idx = self.current_index[unique_key]
            if self.monitor_type == "traffic" and isinstance(raw_result, dict):
                items = self._process_traffic_data(
                    unique_key, timestamp, idx, raw_result
                )
                indexed_metrics.extend(items)
            else:
                item = self._process_general_data(
                    unique_key, timestamp, idx, raw_result
                )
                indexed_metrics.append(item)
        self.logger.debug(f"_build_indexed_metrics: {indexed_metrics}")
        return indexed_metrics

    def _process_traffic_data(
        self, unique_key: str, timestamp: str, idx: int, result_value: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        val_in = result_value.get("in")
        val_out = result_value.get("out")
        for suffix, v in [("in", val_in), ("out", val_out)]:
            sub_key = f"{unique_key}_{suffix}"
            if sub_key in self.stats_dict:
                self.stats_dict[sub_key].update_statistics(v)
        data_item_in = {
            "index": idx,
            "timestamp": timestamp,
            "value": val_in,
            "threshold_exceeded": False,
            "anomaly_detected": False,
        }
        data_item_out = {
            "index": idx,
            "timestamp": timestamp,
            "value": val_out,
            "threshold_exceeded": False,
            "anomaly_detected": False,
        }
        with self.data_lock:
            self._append_to_shared_data(f"{unique_key}_in", data_item_in)
            self._append_to_shared_data(f"{unique_key}_out", data_item_out)
        return [data_item_in, data_item_out]

    def _process_general_data(
        self, unique_key: str, timestamp: str, idx: int, result_value: Any
    ) -> Dict[str, Any]:
        if unique_key in self.stats_dict:
            self.stats_dict[unique_key].update_statistics(result_value)
        data_item = {
            "index": idx,
            "timestamp": timestamp,
            "value": result_value,
            "threshold_exceeded": False,
            "anomaly_detected": False,
        }
        with self.data_lock:
            if unique_key not in self.shared_data:
                self.shared_data[unique_key] = []
            self.shared_data[unique_key].append(data_item)
            if len(self.shared_data[unique_key]) > self.keep_data:
                self.shared_data[unique_key] = self.shared_data[unique_key][
                    -self.keep_data :
                ]
        return data_item

    def submit_fetch_tasks(self) -> None:
        self.futures = {
            self.executor_pool.submit(m.fetch_and_process_metric): m
            for m in self.monitors
        }

    def process_completed_futures(self) -> List[Optional[Any]]:
        result_map: Dict[str, Optional[Any]] = {}
        for future, monitor in self.futures.items():
            unique_key = monitor.get_unique_key()
            try:
                val = future.result()
            except Exception as e:
                self.logger.error(f"Error fetching metric for {monitor.target}: {e}")
                val = None
            result_map[unique_key] = val
        results: List[Optional[Any]] = []
        for m in self.monitors:
            results.append(result_map.get(m.get_unique_key()))
        self.logger.debug(f"process_completed_futures -> results={results}")
        return results

    def collect_monitors_info(self) -> List[dict]:
        monitors_info = []
        if self.monitor_type == "traffic":
            for m in self.monitors:
                base = {
                    "monitor_type": self.monitor_type,
                    "target": m.target,
                    "unique_key": m.get_unique_key(),
                    "sysName": getattr(m, "sysname", m.target),
                    "ifName": getattr(
                        m, "interface_label", f"ifIndex.{getattr(m, 'ifindex', 'N/A')}"
                    ),
                    "ifIndex": getattr(m, "ifindex", "N/A"),
                    "use_32bit": getattr(m, "use_32bit_counters", True),
                }
                in_info = dict(base)
                in_info["direction"] = "Inbound"
                out_info = dict(base)
                out_info["direction"] = "Outbound"
                monitors_info.append(in_info)
                monitors_info.append(out_info)
        else:
            for m in self.monitors:
                info: dict[str, Any] = {
                    "monitor_type": self.monitor_type,
                    "target": m.target,
                    "unique_key": m.get_unique_key(),
                }
                if self.monitor_type == "dns":
                    info["dns_server"] = getattr(m, "dns_server", "default")
                elif self.monitor_type == "snmp":
                    info["sysName"] = getattr(m, "sysname", m.target)
                    info["oid"] = getattr(m, "oid", "UnknownOID")
                    info["is_counter"] = str(getattr(m, "is_counter", False))
                monitors_info.append(info)
        return monitors_info

    def _append_to_shared_data(self, key: str, item: Dict[str, Any]) -> None:
        if key not in self.shared_data:
            self.shared_data[key] = []
        self.shared_data[key].append(item)
        if len(self.shared_data[key]) > self.keep_data:
            self.shared_data[key] = self.shared_data[key][-self.keep_data :]

    def send_to_queues(self, data: dict) -> None:
        self.display_queue.put(data)
        if self.csv_queue:
            self.csv_queue.put(data)
        if self.threshold_queue:
            self.threshold_queue.put(data)
        if self.anomaly_queue:
            self.anomaly_queue.put(data)
        if self.none_state_queue:
            self.none_state_queue.put(data)


class QueueLoggingHandlerThread(logging.Handler):

    def __init__(self, webhook_queue: queue.Queue, level=logging.WARNING) -> None:
        super().__init__(level=level)
        self.webhook_queue = webhook_queue
        self.formatter = logging.Formatter(
            '{"time": "%(asctime)s", "level": "%(levelname)s", "logger": "%(name)s", "function": "%(funcName)s", "line": %(lineno)d, "message": "%(message)s"}'
        )

    def emit(self, record: logging.LogRecord) -> None:
        try:
            log_message = self.format(record)
            self.webhook_queue.put({"message": log_message})
        except Exception:
            self.handleError(record)


class AppManager:

    def __init__(self) -> None:
        self.webhook_queue: queue.Queue[Any] = queue.Queue(maxsize=4096)
        self.config = ConfigManager()
        self.configure_logging()
        self.color_manager = ColorManager(enable_color=True)
        global_options = self.config.get_global_options()
        self.graph_width, self.graph_height = self.config.get_graph_dimensions()
        self.monitor_type, self.targets = self.config.get_monitor_type_and_targets()
        self.executor = CommandExecutor(default_timeout=global_options["exec_timeout"])
        try:
            self.monitors = self.initialize_monitors(
                self.monitor_type, self.targets, self.executor
            )
        except ValueError as e:
            print(f"Error: {e}")
            sys.exit(1)
        self.graph_symbols = self.config.validate_and_assign_options(
            self.monitors, self.monitor_type
        )
        self.graphdrawer = GraphDrawer(
            width=self.graph_width,
            height=self.graph_height,
            y_scale=global_options["y_scale"],
            scale_y=self.monitor_type.lower() in ["snmp", "traffic"],
            color_manager=self.color_manager,
        )
        self.stats_dict: Dict[str, StatisticsManager] = {}
        self.shared_data: Dict[str, List[Dict[str, Any]]] = {}
        self.data_lock = threading.Lock()
        self.stop_event = threading.Event()
        csv_enabled = global_options["csv_enabled"]
        csv_ms_enabled = global_options["csv_ms_enabled"]
        if self.monitor_type.lower() == "traffic":
            for monitor in self.monitors:
                unique_key = monitor.get_unique_key()
                in_key = f"{unique_key}_in"
                out_key = f"{unique_key}_out"
                self.stats_dict[in_key] = StatisticsManager()
                self.stats_dict[out_key] = StatisticsManager()
                self.shared_data[in_key] = []
                self.shared_data[out_key] = []
        else:
            for monitor in self.monitors:
                unique_key = monitor.get_unique_key()
                self.stats_dict[unique_key] = StatisticsManager()
                self.shared_data[unique_key] = []
        self.anomaly_enabled = global_options.get("anomaly", False)
        if self.anomaly_enabled:
            print("Loading scikit-learn... Please wait...")
            try:
                import sklearn  # type: ignore[import-untyped]
            except ImportError:
                print(
                    "Error: scikit-learn is not installed. Please install it to use anomaly detection."
                )
                sys.exit(1)
        self.display_queue: queue.Queue[Any] = queue.Queue(maxsize=4096)
        self.csv_queue: Optional[queue.Queue[Any]] = (
            queue.Queue(maxsize=4096) if csv_enabled or csv_ms_enabled else None
        )
        self.threshold_queue: Optional[queue.Queue[Any]] = (
            queue.Queue(maxsize=4096)
            if global_options.get("threshold") is not None
            else None
        )
        self.anomaly_queue: Optional[queue.Queue[Any]] = queue.Queue(maxsize=4096) if self.anomaly_enabled else None
        self.none_state_queue: queue.Queue[Any] = queue.Queue(maxsize=4096)
        logging.getLogger("AppManager").info("AppManager initialized.")

    def run(self) -> None:
        global_options = self.config.get_global_options()
        csv_enabled = global_options.get("csv_enabled", False)
        csv_ms_enabled = global_options.get("csv_ms_enabled", False)
        interval = global_options["interval"]
        keep_data = global_options["keep_data"]
        webhook_url = global_options.get("webhook")
        refresh_event = threading.Event()
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=len(self.monitors)
        ) as executor_pool:
            collector = CollectorThread(
                monitor_type=self.monitor_type,
                monitors=self.monitors,
                stats_dict=self.stats_dict,
                shared_data=self.shared_data,
                executor_pool=executor_pool,
                keep_data=keep_data,
                data_lock=self.data_lock,
                stop_event=self.stop_event,
                interval=interval,
                display_queue=self.display_queue,
                csv_queue=self.csv_queue if self.csv_queue is not None else queue.Queue(),
                threshold_queue=self.threshold_queue if self.threshold_queue is not None else queue.Queue(),
                anomaly_queue=self.anomaly_queue,
                none_state_queue=self.none_state_queue,
            )
            display = DisplayThread(
                monitor_type=self.monitor_type,
                monitors=self.monitors,
                stats_dict=self.stats_dict,
                graphdrawer=self.graphdrawer,
                interval=interval,
                keep_data=keep_data,
                graph_symbols=self.graph_symbols,
                shared_data=self.shared_data,
                data_lock=self.data_lock,
                stop_event=self.stop_event,
                input_queue=self.display_queue,
                color_manager=self.color_manager,
                refresh_event=refresh_event,
            )
            csv_writer_thread: Optional[BufferedCsvWriterThread] = None
            if csv_enabled or csv_ms_enabled:
                csv_writer_thread = BufferedCsvWriterThread(
                    monitor_type=self.monitor_type,
                    monitors=self.monitors,
                    targets=self.targets,
                    stop_event=self.stop_event,
                    include_ms=csv_ms_enabled,
                    input_queue=self.csv_queue if self.csv_queue is not None else queue.Queue(),
                )
            threshold_monitor: Optional[ThresholdMonitorThread] = None
            if global_options.get("threshold") is not None:
                threshold_monitor = ThresholdMonitorThread(
                    thresholds=global_options.get("threshold")
                    or ["default"] * len(self.targets),
                    stop_event=self.stop_event,
                    input_queue=self.threshold_queue if self.threshold_queue is not None else queue.Queue(),
                    webhook_queue=self.webhook_queue,
                    shared_data=self.shared_data,
                    data_lock=self.data_lock,
                    refresh_event=refresh_event,
                )
            webhook_notifier: Optional[WebhookNotifierThread] = None
            if webhook_url:
                webhook_notifier = WebhookNotifierThread(
                    webhook_url=webhook_url,
                    stop_event=self.stop_event,
                    input_queue=self.webhook_queue,
                )
            anomaly_detector_thread = None
            if self.anomaly_enabled:
                anomaly_detector_thread = AnomalyDetectorThread(
                    stop_event=self.stop_event,
                    input_queue=self.anomaly_queue if self.anomaly_queue is not None else queue.Queue(),
                    webhook_queue=self.webhook_queue,
                    monitor_type=self.monitor_type,
                    samples=global_options["samples"],
                    contamination=global_options["contamination"],
                    shared_data=self.shared_data,
                    data_lock=self.data_lock,
                    refresh_event=refresh_event,
                )
            none_state_monitor = NoneStateMonitorThread(
                stop_event=self.stop_event,
                input_queue=self.none_state_queue,
                webhook_queue=self.webhook_queue,
            )
            collector.start()
            display.start()
            if threshold_monitor:
                threshold_monitor.start()
            if webhook_notifier:
                webhook_notifier.start()
            if csv_writer_thread:
                csv_writer_thread.start()
            if anomaly_detector_thread:
                anomaly_detector_thread.start()
            none_state_monitor.start()
            try:
                while collector.is_alive() and display.is_alive():
                    time.sleep(0.1)
                    if csv_writer_thread and (not csv_writer_thread.is_alive()):
                        logging.getLogger("AppManager").warning(
                            "CSV Writer Thread ended unexpectedly."
                        )
            except KeyboardInterrupt:
                logging.getLogger("AppManager").info(
                    "KeyboardInterrupt received. Stopping monitoring."
                )
                print("\nExiting.")
                self.stop_event.set()
            finally:
                self.stop_event.set()
                collector.join()
                display.join()
                if threshold_monitor:
                    threshold_monitor.join()
                if webhook_notifier:
                    webhook_notifier.join()
                if csv_writer_thread:
                    csv_writer_thread.join()
                if anomaly_detector_thread:
                    anomaly_detector_thread.join()
                none_state_monitor.join()
                logging.getLogger("AppManager").info(
                    "All threads stopped. Application exiting."
                )

    def register_monitors(self) -> Dict[str, type]:
        return {
            "ping": PingMonitor,
            "http": HttpMonitor,
            "dns": DnsMonitor,
            "snmp": SnmpMonitor,
            "traffic": SnmpTrafficMonitor,
        }

    def initialize_monitors(
        self, monitor_type: str, targets: List[str], executor: "CommandExecutor"
    ) -> List["BaseMonitor"]:
        monitor_classes = self.register_monitors()
        if monitor_type.lower() not in monitor_classes:
            raise ValueError(f"Unsupported monitor type: {monitor_type}")
        max_allowed = 1 if monitor_type.lower() == "traffic" else 2
        if len(targets) > max_allowed:
            print(
                f"Error: {monitor_type} monitoring supports up to {max_allowed} target(s)."
            )
            sys.exit(1)
        MonitorClass = monitor_classes[monitor_type.lower()]
        monitors = [
            MonitorClass(target, executor, i + 1) for i, target in enumerate(targets)
        ]
        return monitors

    def configure_logging(self) -> None:
        debug = self.config.get_global_options()["debug"]
        logger = logging.getLogger()
        logger.setLevel(logging.DEBUG if debug else logging.INFO)
        formatter = logging.Formatter(
            '{"time": "%(asctime)s", "level": "%(levelname)s", "logger": "%(name)s", "function": "%(funcName)s", "line": %(lineno)d, "message": "%(message)s"}'
        )
        file_handler = RotatingFileHandler(
            "nano_monitor.log",
            maxBytes=32 * 1024 * 1024,
            backupCount=8,
            encoding="utf-8",
        )
        file_handler.setLevel(logging.DEBUG if debug else logging.INFO)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
        queue_logging_handler = QueueLoggingHandlerThread(
            self.webhook_queue, level=logging.WARNING
        )
        queue_logging_handler.setFormatter(formatter)
        logger.addHandler(queue_logging_handler)


def main() -> None:
    app_manager = AppManager()
    app_manager.run()


if __name__ == "__main__":
    main()
