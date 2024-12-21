import csv
import inspect
import json
import os
import platform
import re
import shlex
import subprocess
import time
import urllib.request
from dataclasses import dataclass
from datetime import datetime
from typing import Optional, Tuple, List, Dict
from urllib.parse import urlparse

# Flag to indicate the availability of scikit-learn
SKLEARN_AVAILABLE = False

# Determine if the operating system is Windows
IS_WINDOWS = platform.system() == "Windows"

# Default log filenames
DEFAULT_PING_LOG = "ping_monitor_log.csv"
DEFAULT_HTTP_LOG = "http_monitor_log.csv"
DEFAULT_SNMP_LOG = "snmp_monitor_log.csv"
DEFAULT_TRAFFIC_LOG = "traffic_monitor_log.csv"

# Console color settings
COLOR_GRAY = "\033[90m"
COLOR_RED = "\033[91m"
COLOR_RESET = "\033[0m"

# SNMP OID bases
OID_IFHC_IN_OCTETS = "1.3.6.1.2.1.31.1.1.1.6."
OID_IFHC_OUT_OCTETS = "1.3.6.1.2.1.31.1.1.1.10."
OID_IF_IN_OCTETS = "1.3.6.1.2.1.2.2.1.10."
OID_IF_OUT_OCTETS = "1.3.6.1.2.1.2.2.1.16."

# Graph drawing constants
MAX_GRAPH_LENGTH = 50
GRAPH_HEIGHT = 10

@dataclass
class ThresholdCondition:
    """
    Represents a single threshold condition.
    """
    operator: str
    value: float

@dataclass
class TrafficThresholdCondition:
    """
    Represents threshold conditions for traffic monitoring, separated by direction.
    """
    in_condition: Optional[ThresholdCondition] = None
    out_condition: Optional[ThresholdCondition] = None

@dataclass
class MonitorConfig:
    """
    Configuration settings for network monitoring.
    """
    target: str
    snmp: Optional[Dict[str, str]] = None
    interval: float = 1.0
    timeout: Optional[float] = None
    stop_after: Optional[int] = None
    should_log: bool = False
    log_filename: Optional[str] = None
    debug_mode: bool = False
    anomaly_mode: bool = False
    min_data_count: int = 256
    contamination: float = 0.01
    webhook_url: Optional[str] = None
    notification_interval: Optional[int] = None
    threshold: Optional[ThresholdCondition] = None
    traffic_threshold: Optional[TrafficThresholdCondition] = None
    fail_notify: bool = False

class Logger:
    """
    Logger class for handling error and debug logs.
    """

    @staticmethod
    def get_class_name() -> str:
        """
        Retrieve the name of the calling class, if any.
        """
        frame = inspect.currentframe().f_back
        class_name = None
        while frame:
            if 'self' in frame.f_locals:
                class_name = frame.f_locals['self'].__class__.__name__
                break
            frame = frame.f_back
        return class_name if class_name else "No Class"

    @staticmethod
    def write_log(filename: str, data: str):
        """
        Write data to a specified log file.
        """
        with open(filename, "a") as file:
            file.write(data)

    @staticmethod
    def log_error(message: str):
        """
        Log error messages with timestamp and caller information.
        """
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        caller_name = inspect.currentframe().f_back.f_code.co_name
        class_name = Logger.get_class_name()
        error_message = (
            f"----- Error Info ({timestamp}) -----\n"
            f"Class: {class_name}\n"
            f"Function: {caller_name}\n"
            f"Error: {message}\n"
            "--------------------------------------------\n"
        )
        Logger.write_log("error.log", error_message)

    @staticmethod
    def log_debug_info(debug_mode: bool = False, **kwargs):
        """
        Log debug information if debug mode is enabled.
        """
        if not debug_mode:
            return
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        caller_name = inspect.currentframe().f_back.f_code.co_name
        class_name = Logger.get_class_name()
        log_data = [f"\n----- Debug Info ({timestamp}) -----\n"]
        log_data.append(f"Class: {class_name}\n")
        log_data.append(f"Function: {caller_name}\n")
        for key, value in kwargs.items():
            log_data.append(f"{key}: {value}\n")
        log_data.append("--------------------------------------------\n")
        Logger.write_log("debug_info.log", "".join(log_data))


def import_isolation_forest() -> bool:
    """
    Lazy import of IsolationForest from scikit-learn.
    Returns True if available, False otherwise.
    """
    global SKLEARN_AVAILABLE
    if 'IsolationForest' not in globals():
        print("\nPlease wait...")
        try:
            from sklearn.ensemble import IsolationForest
            SKLEARN_AVAILABLE = True
        except ImportError:
            SKLEARN_AVAILABLE = False
    return SKLEARN_AVAILABLE


def is_valid_url(url: str) -> bool:
    """
    Validate if the given string is a well-formed HTTP or HTTPS URL.
    """
    try:
        result = urlparse(url)
        return result.scheme in ["http", "https"] and bool(result.netloc)
    except ValueError:
        return False


def evaluate_threshold(value: float, operator: str, threshold: float) -> bool:
    """
    Evaluate the threshold condition.
    """
    if operator == ">=":
        return value >= threshold
    elif operator == "<=":
        return value <= threshold
    elif operator == ">":
        return value > threshold
    elif operator == "<":
        return value < threshold
    elif operator == "==":
        return value == threshold
    else:
        Logger.log_error(f"Unsupported threshold operator: {operator}")
        return False


def send_webhook_notification(webhook_url: str, message: str, notification_type: str, config: MonitorConfig, last_notification_times: Dict[str, float]):
    """
    Send a JSON payload with the specified message to the given webhook URL.
    Handles suppression based on notification type and suppression interval.
    """
    current_time = time.time()
    last_time = last_notification_times.get(notification_type, 0)
    interval = config.notification_interval * 60 if config.notification_interval else 0

    if current_time - last_time < interval:
        return

    try:
        data = json.dumps({"text": message}).encode('utf-8')
        req = urllib.request.Request(webhook_url, data=data, headers={'Content-Type': 'application/json'})
        with urllib.request.urlopen(req) as response:
            response.read().decode('utf-8')
        last_notification_times[notification_type] = current_time
    except Exception as e:
        Logger.log_error(f"Failed to send webhook notification: {e}")


def check_curl_command() -> bool:
    """
    Verify if the 'curl' command is available in the system.
    """
    try:
        command = ["where", "curl"] if IS_WINDOWS else ["which", "curl"]
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if result.returncode != 0:
            raise FileNotFoundError
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False
    return True

def check_snmp_command() -> bool:
    """
    Verify if the 'snmpget' command is available in the system.
    """
    try:
        command = ["where", "snmpget"] if IS_WINDOWS else ["which", "snmpget"]
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if result.returncode != 0:
            raise FileNotFoundError
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False
    return True

def get_snmp_value(target: str, community: str, oid: str, timeout: Optional[float] = None, debug_mode: bool = False) -> Optional[str]:
    """
    Execute the SNMPGET command and parse the returned string value.
    """
    try:
        timeout_option = ["-t", str(timeout)] if timeout else []
        command = ["snmpget", "-On", "-v", "2c", "-c", community] + timeout_option + [target, oid]
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        Logger.log_debug_info(
            debug_mode=debug_mode,
            Command=' '.join(command),
            Return_Code=result.returncode,
            STDOUT=result.stdout.strip(),
            STDERR=result.stderr.strip()
        )

        if "Timeout: No Response" in result.stderr:
            return None

        if result.returncode != 0:
            Logger.log_error(f"Failed to execute snmpget for OID {oid}. Please check SNMP settings for {target}.")
            return None

        parts = result.stdout.strip().split(' = ', 1)
        if len(parts) != 2:
            Logger.log_error(f"Unexpected SNMP output format: {result.stdout.strip()}")
            return None

        oid_received = parts[0].strip()
        value_str = parts[1].strip()

        match = re.match(r'^\w+:\s+"?(.*?)"?$', value_str)
        if match:
            return match.group(1).strip()
    except Exception as e:
        Logger.log_error(f"Unexpected error during snmpget for OID {oid}: {e}")
    return None

def get_ifindex_from_ifname(target: str, community: str, ifname: str) -> Optional[str]:
    """
    Retrieve the ifIndex corresponding to a given interface name using SNMP.
    """
    command = ["snmpwalk", "-On", "-v", "2c", "-c", community, target, "1.3.6.1.2.1.31.1.1.1.1"]
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    if result.returncode != 0:
        print(f"Failed to execute snmpwalk. Please check SNMP settings for {target}.")
        return None

    ifname_lower = ifname.lower()
    for line in result.stdout.splitlines():
        match = re.match(r"^\.?1\.3\.6\.1\.2\.1\.31\.1\.1\.1\.1\.(\d+)\s*=\s*STRING:\s*(.+)", line)
        if match:
            index = match.group(1)
            name = match.group(2).strip().lower()
            if name == ifname_lower:
                return index

    return None


def human_readable_size(value: int) -> Tuple[float, str, int]:
    """
    Convert a numerical value into a human-readable format with appropriate units.
    Returns a tuple of (scaled_value: float, unit: str, scale: int).
    """
    units = ['', 'K', 'M', 'G', 'T', 'P', 'E']
    scale = 0
    abs_value = abs(value)

    if abs_value < 1000:
        return float(value), '', scale

    while abs_value >= 1000 and scale < len(units) - 1:
        abs_value /= 1000
        scale += 1

    return abs_value, units[scale], scale


def convert_traffic_unit(value_mbps: Optional[float]) -> Tuple[str, str]:
    """
    Convert traffic value from Mbps to a more readable unit (Kbps, Mbps, Gbps).
    """
    if value_mbps is None:
        return "N/A", "Mbps"

    value_kbps = value_mbps * 1000
    value_gbps = value_mbps / 1000

    if value_mbps < 1:
        return f"{value_kbps:.2f}", "Kbps"
    elif value_mbps >= 1000:
        return f"{value_gbps:.2f}", "Gbps"
    else:
        return f"{value_mbps:.2f}", "Mbps"


class NetworkMonitor:
    """
    Base class for all network monitoring types.
    """

    def __init__(self, config: MonitorConfig):
        self.config = config
        self.last_notification_time = 0
        self.response_values: List[Dict] = []
        self.anomaly_model = None
        self.last_notification_times: Dict[str, float] = {}

    def monitor(self):
        """
        Start the monitoring process.
        """
        count = 0
        while True:
            self.perform_check()
            self.update_display()
            time.sleep(self.config.interval)
            count += 1
            if self.config.stop_after and count >= self.config.stop_after:
                print(f"\nCompleted {self.config.stop_after} checks.\n")
                break

    def perform_check(self):
        """
        Execute the specific monitoring check.
        Must be implemented by subclasses.
        """
        raise NotImplementedError

    def update_display(self):
        """
        Update the console display with the latest monitoring data.
        Must be implemented by subclasses.
        """
        raise NotImplementedError

    def log_response(self, data_list: List):
        """
        Log the monitoring response to a CSV file.
        """
        if self.config.should_log and self.config.log_filename:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            with open(self.config.log_filename, mode="a", newline="") as file:
                writer = csv.writer(file)
                if isinstance(self, TrafficMonitor):
                    if self.config.anomaly_mode:
                        in_anomaly = "" if self.anomaly_model_in is None else str(self.response_values[-1]["is_anomaly"][0]).upper()
                        out_anomaly = "" if self.anomaly_model_out is None else str(self.response_values[-1]["is_anomaly"][1]).upper()
                        writer.writerow([timestamp] + data_list[:4] + [in_anomaly, out_anomaly])
                    else:
                        writer.writerow([timestamp] + data_list[:4])
                else:
                    if self.config.anomaly_mode:
                        anomaly_value = self.response_values[-1].get("is_anomaly")
                        if anomaly_value is None:
                            writer.writerow([timestamp] + data_list + [""])
                        else:
                            writer.writerow([timestamp] + data_list + [str(anomaly_value).upper()])
                    else:
                        writer.writerow([timestamp] + data_list)

    def detect_anomalies(self):
        """
        Initialize and train the anomaly detection model using IsolationForest.
        """
        if self.anomaly_model is not None:
            Logger.log_debug_info(
                debug_mode=self.config.debug_mode,
                Message="Anomaly model already exists, skipping re-training."
            )
            return

        values = [
            v["anomaly_value"] for v in self.response_values
            if "anomaly_value" in v and v["anomaly_value"] is not None
        ]

        if isinstance(values[0], tuple):
            X = [list(v) for v in values if None not in v]
        else:
            X = [[v] for v in values if v is not None]

        if len(X) < self.config.min_data_count:
            Logger.log_debug_info(
                debug_mode=self.config.debug_mode,
                Message="Not enough data for anomaly detection.",
                Min_Data_Count=self.config.min_data_count,
                Current_Data_Count=len(X)
            )
            return

        if not X:
            Logger.log_debug_info(
                debug_mode=self.config.debug_mode,
                Message="No valid data for anomaly detection."
            )
            return

        from sklearn.ensemble import IsolationForest

        model = IsolationForest(contamination=self.config.contamination)
        model.fit(X)
        self.anomaly_model = model

        Logger.log_debug_info(
            debug_mode=self.config.debug_mode,
            Message="Anomaly model training completed.",
            Training_Data_Size=len(X),
            Contamination=self.config.contamination
        )

    def check_anomaly(self, value, notification_type: str):
        """
        Check if the latest value is an anomaly and send a webhook notification if necessary.
        """
        if self.anomaly_model is None:
            return False

        input_value = [list(value)] if isinstance(value, tuple) else [[value]]
        anomaly_score = self.anomaly_model.decision_function(input_value)
        prediction = self.anomaly_model.predict(input_value)

        Logger.log_debug_info(
            debug_mode=self.config.debug_mode,
            Message="Anomaly score calculated.",
            Input_Value=input_value,
            Anomaly_Score=anomaly_score[0],
            Prediction=prediction[0]
        )

        if prediction[0] == -1:
            if self.config.webhook_url:
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                message = self.generate_anomaly_message(timestamp, value)
                send_webhook_notification(
                    self.config.webhook_url,
                    message,
                    notification_type,
                    self.config,
                    self.last_notification_times
                )
            return True

        return False

    def generate_anomaly_message(self, timestamp: str, value):
        """
        Generate a webhook message based on the type of monitor.
        """
        if isinstance(self, PingMonitor):
            return f"{timestamp}\nAnomaly detected on Ping monitoring of {self.config.target}\nResponse time: {value} ms"
        elif isinstance(self, HttpMonitor):
            return f"{timestamp}\nAnomaly detected on HTTP monitoring of {self.config.target}\nResponse time: {value} ms"
        elif isinstance(self, SnmpMonitor):
            if self.is_counter and isinstance(value, (float, int)):
                value_formatted = f"{value:.2f}"
                oid_display = f"{self.oid} / sec"
            else:
                value_formatted = value
                oid_display = self.oid
            return f"{timestamp}\nAnomaly detected on SNMP monitoring of {self.config.target} ({self.sysname})\nOID: {oid_display}\nValue: {value_formatted}"
        elif isinstance(self, TrafficMonitor):
            direction = "In" if value[0] else "Out"
            return f"{timestamp}\nAnomaly detected on {direction} traffic monitoring of {self.config.target} ({self.sysname})\nOID: {self.oid}\nValue: {value}"
        else:
            return f"{timestamp}\nAnomaly detected on monitoring of {self.config.target}\nValue: {value}"

    def clear_screen(self):
        """
        Clear the console screen.
        """
        os.system("cls" if IS_WINDOWS else "clear")


class PingMonitor(NetworkMonitor):
    """
    Monitor class for ping response times.
    """

    def __init__(self, config: MonitorConfig):
        super().__init__(config)
        self.first_draw = True
        self.initialize_csv()

    def initialize_csv(self):
        """
        Initialize the CSV log file with appropriate headers.
        """
        if self.config.should_log and self.config.log_filename and not os.path.exists(self.config.log_filename):
            with open(self.config.log_filename, mode="w", newline="") as file:
                writer = csv.writer(file)
                if self.config.anomaly_mode:
                    writer.writerow(["", self.config.target, self.config.target])
                    writer.writerow(["Time", "Ping Response Time (ms)", "Anomaly Detected"])
                else:
                    writer.writerow(["", self.config.target])
                    writer.writerow(["Time", "Ping Response Time (ms)"])

    def perform_check(self):
        """
        Execute a ping check and handle anomaly and threshold detection if enabled.
        """
        response_time = self.get_ping_response()
        anomaly_value = response_time if response_time is not None else None
        threshold_breached = False

        if self.config.threshold and response_time is not None:
            operator = self.config.threshold.operator
            threshold = self.config.threshold.value
            threshold_breached = evaluate_threshold(response_time, operator, threshold)

            if threshold_breached and self.config.webhook_url:
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                message = f"{timestamp}\nThreshold breached on Ping monitoring of {self.config.target}\nResponse time: {response_time} ms (Condition: {operator}{threshold})"
                send_webhook_notification(
                    self.config.webhook_url,
                    message,
                    "threshold_ping",
                    self.config,
                    self.last_notification_times
                )

        is_anomaly = False
        if self.config.anomaly_mode and response_time is not None:
            valid_data = [v for v in self.response_values if v["anomaly_value"] is not None]
            if len(valid_data) >= self.config.min_data_count and self.anomaly_model is None:
                self.detect_anomalies()
            if self.anomaly_model is not None:
                is_anomaly = self.check_anomaly(anomaly_value, "anomaly_ping")

        if response_time is None:

            if self.config.fail_notify and self.config.webhook_url:
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                message = (
                    f"{timestamp}\n"
                    f"Ping failed for {self.config.target}.\n"
                    f"Failed to retrieve response time."
                )
                send_webhook_notification(
                    self.config.webhook_url,
                    message,
                    "fail_ping",
                    self.config,
                    self.last_notification_times
                )

        self.response_values.append({
            "response_time": response_time,
            "anomaly_value": anomaly_value,
            "is_anomaly": is_anomaly if self.anomaly_model is not None else None,
            "threshold_breached": threshold_breached
        })
        self.log_response([response_time if response_time is not None else ''])

    def get_ping_response(self) -> Optional[int]:
        """
        Execute the ping command and parse the response time.
        """
        count_option = "-n" if IS_WINDOWS else "-c"
        timeout_option = "-w" if IS_WINDOWS else "-W"
        command = ["ping", count_option, "1", self.config.target]
        if self.config.timeout:
            if IS_WINDOWS:
                timeout = str(int(self.config.timeout * 1000))
                command += [timeout_option, timeout]
            else:
                timeout = str(int(self.config.timeout))
                command += [timeout_option, timeout]

        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        Logger.log_debug_info(
            debug_mode=self.config.debug_mode,
            Command=' '.join(command),
            Return_Code=result.returncode,
            STDOUT=result.stdout.strip(),
            STDERR=result.stderr.strip()
        )

        match = re.search(r"(\d+)\s*ms", result.stdout)
        if match:
            try:
                return int(match.group(1))
            except ValueError:
                return None
        return None

    def update_display(self):
        """
        Update the console display with the latest ping response time graph and statistics.
        """
        if self.first_draw:
            self.clear_screen()
            self.first_draw = False
        else:
            print("\033[H\033[J", end="")

        output = []
        output.append(f"\n{COLOR_GRAY}Monitoring:{COLOR_RESET} {self.config.target}")
        output.append(f"{COLOR_GRAY}Ping Response Time Graph (ms):{COLOR_RESET}")
        output.append(self.build_graph())
        output.append(self.build_statistics())

        if self.config.anomaly_mode:
            valid_data_count = len([v for v in self.response_values if v["anomaly_value"] is not None])
            if self.anomaly_model is None and valid_data_count < self.config.min_data_count:
                remaining = self.config.min_data_count - valid_data_count
                output.append(f"{COLOR_GRAY}Currently Training... Remaining data points needed:{COLOR_RESET} {remaining}{COLOR_GRAY}.{COLOR_RESET}\n")
            elif self.anomaly_model is not None:
                output.append(f"{COLOR_GRAY}Training completed. Anomaly detection is active.{COLOR_RESET}\n")

        print("\n".join(output))

    def build_graph(self):
        """
        Build a text-based graph of the ping response times.
        """
        values = [v["response_time"] for v in self.response_values[-MAX_GRAPH_LENGTH:]]
        anomalies = [v.get("is_anomaly", False) for v in self.response_values[-MAX_GRAPH_LENGTH:]]
        thresholds = [v.get("threshold_breached", False) for v in self.response_values[-MAX_GRAPH_LENGTH:]]

        if len(values) < MAX_GRAPH_LENGTH:
            padding = MAX_GRAPH_LENGTH - len(values)
            values = [None] * padding + values
            anomalies = [False] * padding + anomalies
            thresholds = [False] * padding + thresholds

        max_value = max(filter(None, values), default=1)
        step = max_value / GRAPH_HEIGHT if max_value else 1
        graph = []

        for i in range(GRAPH_HEIGHT, -1, -1):
            y_value = i * step
            line = f"{int(y_value):4d} | "
            for value, is_anomaly, threshold_breached in zip(values, anomalies, thresholds):
                if value is not None and value >= y_value:
                    if is_anomaly or threshold_breached:
                        line += f"{COLOR_RED}*{COLOR_RESET}"
                    else:
                        line += "*"
                else:
                    line += " "
            graph.append(line)

        x_axis_line = "      " + "-" * (MAX_GRAPH_LENGTH + 1)
        x_axis_labels = "       " + "".join("|" if (i + 1) % 10 == 0 else " " for i in range(MAX_GRAPH_LENGTH))
        graph.append(x_axis_line)
        graph.append(x_axis_labels)

        return "\n".join(graph)

    def build_statistics(self):
        """
        Build statistics related to ping responses.
        """
        total = len(self.response_values)
        success = sum(1 for v in self.response_values if v["response_time"] is not None)
        failure = total - success
        fail_rate = (failure / total) * 100 if total > 0 else 0
        valid_values = [v["response_time"] for v in self.response_values if v["response_time"] is not None]
        min_time = min(valid_values, default=0)
        max_time = max(valid_values, default=0)
        cur_time = valid_values[-1] if valid_values else 0

        if self.response_values and self.response_values[-1]["response_time"] is None:
            failure_color = COLOR_RED
            fail_rate_color = COLOR_RED
        else:
            failure_color = ""
            fail_rate_color = ""

        stats = [
            f"{COLOR_GRAY}Statistics:{COLOR_RESET}",
            f"{COLOR_GRAY}Total:{COLOR_RESET} {total}, "
            f"{COLOR_GRAY}Success:{COLOR_RESET} {success}, "
            f"{COLOR_GRAY}Failure:{COLOR_RESET} {failure_color}{failure}{COLOR_RESET}, "
            f"{COLOR_GRAY}Failure Rate:{COLOR_RESET} {fail_rate_color}{fail_rate:.2f}%{COLOR_RESET}",
            f"{COLOR_GRAY}Min Time:{COLOR_RESET} {min_time} ms, "
            f"{COLOR_GRAY}Max Time:{COLOR_RESET} {max_time} ms, "
            f"{COLOR_GRAY}Cur Time:{COLOR_RESET} {cur_time} ms\n"
        ]

        return "\n".join(stats)

class HttpMonitor(NetworkMonitor):
    """
    Monitor class for HTTP response times.
    """

    def __init__(self, config: MonitorConfig):
        super().__init__(config)
        self.first_draw = True
        self.initialize_csv()

    def initialize_csv(self):
        """
        Initialize the CSV log file with appropriate headers.
        """
        if self.config.should_log and self.config.log_filename and not os.path.exists(self.config.log_filename):
            with open(self.config.log_filename, mode="w", newline="") as file:
                writer = csv.writer(file)
                if self.config.anomaly_mode:
                    writer.writerow(["", self.config.target, self.config.target])
                    writer.writerow(["Time", "HTTP Response Time (ms)", "Anomaly Detected"])
                else:
                    writer.writerow(["", self.config.target])
                    writer.writerow(["Time", "HTTP Response Time (ms)"])

    def perform_check(self):
        """
        Execute an HTTP check and handle anomaly and threshold detection if enabled.
        """
        response_time = self.get_http_response()
        anomaly_value = response_time if response_time is not None else None
        threshold_breached = False

        if self.config.threshold and response_time is not None:
            operator = self.config.threshold.operator
            threshold = self.config.threshold.value
            threshold_breached = evaluate_threshold(response_time, operator, threshold)

            if threshold_breached and self.config.webhook_url:
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                message = f"{timestamp}\nThreshold breached on HTTP monitoring of {self.config.target}\nResponse time: {response_time} ms (Condition: {operator}{threshold})"
                send_webhook_notification(
                    self.config.webhook_url,
                    message,
                    "threshold_http",
                    self.config,
                    self.last_notification_times
                )

        is_anomaly = False
        if self.config.anomaly_mode and response_time is not None:
            valid_data = [v for v in self.response_values if v["anomaly_value"] is not None]
            if len(valid_data) >= self.config.min_data_count and self.anomaly_model is None:
                self.detect_anomalies()
            if self.anomaly_model is not None:
                is_anomaly = self.check_anomaly(anomaly_value, "anomaly_http")

        if response_time is None:

            if self.config.fail_notify and self.config.webhook_url:
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                message = (
                    f"{timestamp}\n"
                    f"HTTP check failed for {self.config.target}.\n"
                    f"Failed to retrieve response time."
                )
                send_webhook_notification(
                    self.config.webhook_url,
                    message,
                    "fail_http",
                    self.config,
                    self.last_notification_times
                )

        self.response_values.append({
            "response_time": response_time,
            "anomaly_value": anomaly_value,
            "is_anomaly": is_anomaly if self.anomaly_model is not None else None,
            "threshold_breached": threshold_breached
        })
        self.log_response([response_time if response_time is not None else ''])

    def get_http_response(self) -> Optional[int]:
        """
        Execute the HTTP request and parse the response time.
        """
        output_option = "NUL" if IS_WINDOWS else "/dev/null"
        command = ["curl", "-o", output_option, "-s", "-w", "%{http_code} %{time_total}"]
        if self.config.timeout is not None:
            command.extend(["--max-time", f"{self.config.timeout:.1f}"])
        command.append(self.config.target)

        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        Logger.log_debug_info(
            debug_mode=self.config.debug_mode,
            Command=' '.join(command),
            Return_Code=result.returncode,
            STDOUT=result.stdout.strip(),
            STDERR=result.stderr.strip()
        )

        if result.returncode == 0:
            try:
                http_code, time_total = result.stdout.strip().split()
                if http_code == "200":
                    return int(float(time_total) * 1000)
            except ValueError:
                return None
        return None

    def update_display(self):
        """
        Update the console display with the latest HTTP response time graph and statistics.
        """
        if self.first_draw:
            self.clear_screen()
            self.first_draw = False
        else:
            print("\033[H\033[J", end="")

        output = []
        output.append(f"\n{COLOR_GRAY}Monitoring:{COLOR_RESET} {self.config.target}")
        output.append(f"{COLOR_GRAY}HTTP Response Time Graph (ms):{COLOR_RESET}")
        output.append(self.build_graph())
        output.append(self.build_statistics())

        if self.config.anomaly_mode:
            valid_data_count = len([v for v in self.response_values if v["anomaly_value"] is not None])
            if self.anomaly_model is None and valid_data_count < self.config.min_data_count:
                remaining = self.config.min_data_count - valid_data_count
                output.append(f"{COLOR_GRAY}Currently Training... Remaining data points needed:{COLOR_RESET} {remaining}{COLOR_GRAY}.{COLOR_RESET}\n")
            elif self.anomaly_model is not None:
                output.append(f"{COLOR_GRAY}Training completed. Anomaly detection is active.{COLOR_RESET}\n")

        print("\n".join(output))

    def build_graph(self):
        """
        Build a text-based graph of the HTTP response times.
        """
        values = [v["response_time"] for v in self.response_values[-MAX_GRAPH_LENGTH:]]
        anomalies = [v.get("is_anomaly", False) for v in self.response_values[-MAX_GRAPH_LENGTH:]]
        thresholds = [v.get("threshold_breached", False) for v in self.response_values[-MAX_GRAPH_LENGTH:]]

        if len(values) < MAX_GRAPH_LENGTH:
            padding = MAX_GRAPH_LENGTH - len(values)
            values = [None] * padding + values
            anomalies = [False] * padding + anomalies
            thresholds = [False] * padding + thresholds

        max_value = max(filter(None, values), default=1)
        step = max_value / GRAPH_HEIGHT if max_value else 1
        graph = []

        for i in range(GRAPH_HEIGHT, -1, -1):
            y_value = i * step
            line = f"{int(y_value):4d} | "
            for value, is_anomaly, threshold_breached in zip(values, anomalies, thresholds):
                if value is not None and value >= y_value:
                    if is_anomaly or threshold_breached:
                        line += f"{COLOR_RED}*{COLOR_RESET}"
                    else:
                        line += "*"
                else:
                    line += " "
            graph.append(line)

        x_axis_line = "      " + "-" * (MAX_GRAPH_LENGTH + 1)
        x_axis_labels = "       " + "".join("|" if (i + 1) % 10 == 0 else " " for i in range(MAX_GRAPH_LENGTH))
        graph.append(x_axis_line)
        graph.append(x_axis_labels)

        return "\n".join(graph)

    def build_statistics(self):
        """
        Build statistics related to HTTP responses.
        """
        total = len(self.response_values)
        success = sum(1 for v in self.response_values if v["response_time"] is not None)
        failure = total - success
        fail_rate = (failure / total) * 100 if total > 0 else 0
        valid_values = [v["response_time"] for v in self.response_values if v["response_time"] is not None]
        min_time = min(valid_values, default=0)
        max_time = max(valid_values, default=0)
        cur_time = valid_values[-1] if valid_values else 0

        if self.response_values and self.response_values[-1]["response_time"] is None:
            failure_color = COLOR_RED
            fail_rate_color = COLOR_RED
        else:
            failure_color = ""
            fail_rate_color = ""

        stats = [
            f"{COLOR_GRAY}Statistics:{COLOR_RESET}",
            f"{COLOR_GRAY}Total:{COLOR_RESET} {total}, "
            f"{COLOR_GRAY}Success:{COLOR_RESET} {success}, "
            f"{COLOR_GRAY}Failure:{COLOR_RESET} {failure_color}{failure}{COLOR_RESET}, "
            f"{COLOR_GRAY}Failure Rate:{COLOR_RESET} {fail_rate_color}{fail_rate:.2f}%{COLOR_RESET}",
            f"{COLOR_GRAY}Min Time:{COLOR_RESET} {min_time} ms, "
            f"{COLOR_GRAY}Max Time:{COLOR_RESET} {max_time} ms, "
            f"{COLOR_GRAY}Cur Time:{COLOR_RESET} {cur_time} ms\n"
        ]

        return "\n".join(stats)

class SnmpMonitor(NetworkMonitor):
    """
    Monitor class for SNMP OID values.
    """

    def __init__(self, config: MonitorConfig):
        super().__init__(config)
        self.first_draw = True
        self.community = config.snmp.get('community') if config.snmp else ""
        self.oid = config.snmp.get('oid') if config.snmp else ""
        self.sysname = self.get_snmp_value("1.3.6.1.2.1.1.5.0")
        self.is_counter = False
        self.prev_value: Optional[int] = None
        self.prev_sys_uptime: Optional[int] = None
        self.first_check_done = False

    def get_snmp_value(self, oid: str) -> Optional[str]:
        """
        Wrapper around the global get_snmp_value function with class-specific parameters.
        """
        return get_snmp_value(
            target=self.config.target,
            community=self.community,
            oid=oid,
            timeout=self.config.timeout,
            debug_mode=self.config.debug_mode
        )

    def initialize_csv(self, is_counter: bool, anomaly_mode: bool):
        """
        Initialize the CSV log file with appropriate headers based on counter type and anomaly mode.
        
        Args:
            is_counter (bool): Whether the OID is a counter type.
            anomaly_mode (bool): Whether anomaly mode is enabled.
        """
        if not self.config.should_log or not self.config.log_filename or os.path.exists(self.config.log_filename):
            return

        with open(self.config.log_filename, mode="w", newline="") as file:
            writer = csv.writer(file)
            target_info = f"{self.config.target} ({self.sysname})" if self.sysname else self.config.target

            if anomaly_mode:
                if is_counter:
                    writer.writerow(["", target_info, target_info, target_info])
                    writer.writerow(["Time", f"{self.oid} / sec", f"{self.oid}", "Anomaly Detected"])
                else:
                    writer.writerow(["", target_info, target_info])
                    writer.writerow(["Time", f"{self.oid}", "Anomaly Detected"])
            else:
                if is_counter:
                    writer.writerow(["", target_info, target_info])
                    writer.writerow(["Time", f"{self.oid} / sec", f"{self.oid}"])
                else:
                    writer.writerow(["", target_info])
                    writer.writerow(["Time", f"{self.oid}"])

    def perform_check(self):
        """
        Execute an SNMP check and handle anomaly and threshold detection if enabled.
        """
        snmp_values = self.get_snmp_value_with_sysuptime()
        
        if snmp_values is None:
            self.response_values.append({
                "value": None,
                "raw_value": None,
                "anomaly_value": None,
                "is_anomaly": None,
                "threshold_breached": False
            })
            if self.config.fail_notify and self.config.webhook_url:
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                message = (
                    f"{timestamp}\n"
                    f"SNMP check failed for {self.config.target} ({self.sysname}).\n"
                    f"OID: {self.oid}\n"
                    f"Failed to retrieve SNMP value."
                )
                send_webhook_notification(
                    self.config.webhook_url,
                    message,
                    "fail_snmp",
                    self.config,
                    self.last_notification_times
                )
            if self.config.anomaly_mode:
                self.log_response([None, None])
            else:
                self.log_response([None])
            return

        sys_uptime = int(snmp_values['sys_uptime'])

        if not self.is_counter:
            data_type = snmp_values.get('data_type', '')
            if data_type == 'Counter64':
                self.is_counter = True
                self.counter_bits = 64
            elif data_type == 'Counter32':
                self.is_counter = True
                self.counter_bits = 32
            else:
                self.is_counter = False
                self.counter_bits = None

        if self.is_counter:
            try:
                current_value = int(snmp_values['value'])
            except ValueError:
                Logger.log_error(f"Failed to parse counter value for OID {self.oid}.")
                current_value = None

            if current_value is not None:
                calculated_value = self.calculate_value(current_value, sys_uptime)
            else:
                calculated_value = None
        else:
            try:
                current_value = int(snmp_values['value'])
            except ValueError:
                Logger.log_error(f"Failed to parse value for OID {self.oid}.")
                current_value = None
            calculated_value = current_value

        if not self.first_check_done:
            self.prev_value = current_value
            self.prev_sys_uptime = sys_uptime
            self.first_check_done = True

            self.initialize_csv(is_counter=self.is_counter, anomaly_mode=self.config.anomaly_mode)
            return

        threshold_breached = False
        if self.is_counter and calculated_value is not None:
            if self.config.threshold and self.config.threshold.operator and self.config.threshold.value:
                condition = self.config.threshold
                threshold_breached = evaluate_threshold(calculated_value, condition.operator, condition.value)
                if threshold_breached and self.config.webhook_url:
                    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    message = (
                        f"{timestamp}\n"
                        f"Threshold breached on SNMP monitoring of {self.config.target} ({self.sysname})\n"
                        f"OID: {self.oid} / sec\n"
                        f"Value: {calculated_value:.2f} (Condition: {condition.operator}{condition.value})"
                    )
                    send_webhook_notification(
                        self.config.webhook_url,
                        message,
                        "threshold_snmp",
                        self.config,
                        self.last_notification_times
                    )
        elif not self.is_counter and current_value is not None:
            if self.config.threshold and self.config.threshold.operator and self.config.threshold.value:
                condition = self.config.threshold
                threshold_breached = evaluate_threshold(current_value, condition.operator, condition.value)
                if threshold_breached and self.config.webhook_url:
                    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    message = (
                        f"{timestamp}\n"
                        f"Threshold breached on SNMP monitoring of {self.config.target} ({self.sysname})\n"
                        f"OID: {self.oid}\n"
                        f"Value: {current_value} (Condition: {condition.operator}{condition.value})"
                    )
                    send_webhook_notification(
                        self.config.webhook_url,
                        message,
                        "threshold_snmp",
                        self.config,
                        self.last_notification_times
                    )

        is_anomaly = None
        anomaly_value = calculated_value if self.is_counter else current_value
        if self.config.anomaly_mode and anomaly_value is not None:
            valid_data = [v for v in self.response_values if v.get("anomaly_value") is not None]
            if len(valid_data) >= self.config.min_data_count and self.anomaly_model is None:
                self.detect_anomalies()
            if self.anomaly_model is not None:
                is_anomaly = self.check_anomaly(anomaly_value, "anomaly_snmp")

        self.response_values.append({
            "value": calculated_value if self.is_counter else current_value,
            "raw_value": current_value if self.is_counter else None,
            "anomaly_value": anomaly_value,
            "is_anomaly": is_anomaly,
            "threshold_breached": threshold_breached
        })

        if self.is_counter:
            if self.config.anomaly_mode:
                self.log_response([
                    round(calculated_value, 2) if calculated_value is not None else '',
                    current_value if current_value is not None else ''
                ])
            else:
                self.log_response([
                    round(calculated_value, 2) if calculated_value is not None else '',
                    current_value if current_value is not None else ''
                ])
        else:
            if self.config.anomaly_mode:
                self.log_response([
                    current_value if current_value is not None else ''
                ])
            else:
                self.log_response([
                    current_value if current_value is not None else ''
                ])

    def get_snmp_value_with_sysuptime(self) -> Optional[Dict[str, str]]:
        """
        Executes the SNMPGET command to retrieve the target OID value and sysUpTime.
        """
        try:
            oids = [self.oid, "1.3.6.1.2.1.1.3.0"]
            timeout_option = ["-t", str(self.config.timeout)] if self.config.timeout else []
            command = ["snmpget", "-On", "-v", "2c", "-c", self.community] + timeout_option + [self.config.target] + oids
            result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

            Logger.log_debug_info(
                debug_mode=self.config.debug_mode,
                Command=' '.join(command),
                Return_Code=result.returncode,
                STDOUT=result.stdout.strip(),
                STDERR=result.stderr.strip()
            )

            if "Timeout: No Response" in result.stderr:
                return None

            if result.returncode != 0:
                Logger.log_error(f"Failed to execute snmpget for {self.config.target}.")
                return None

            lines = result.stdout.strip().splitlines()
            if len(lines) < 2:
                Logger.log_error(f"Unexpected SNMP output format for {self.config.target}.")
                return None

            value_line = lines[0]
            uptime_line = lines[1]

            snmp_values = {}

            value_parts = value_line.split("=", 1)
            if len(value_parts) != 2:
                Logger.log_error(f"Failed to parse SNMP value line: {value_line}")
                return None
            snmp_values['value_raw'] = value_parts[1].strip()

            match = re.match(r'\s*(\w+):\s*(.+)', snmp_values['value_raw'])
            if match:
                data_type = match.group(1)
                value_str = match.group(2)
                snmp_values['data_type'] = data_type
                snmp_values['value'] = value_str.strip()
            else:
                Logger.log_error(f"Failed to parse SNMP data type and value from line: {value_line}")
                return None

            match = re.search(r"Timeticks: \((\d+)\)", uptime_line)
            if match:
                snmp_values['sys_uptime'] = match.group(1)
            else:
                Logger.log_error(f"Failed to parse sysUpTime from line: {uptime_line}")
                return None

            return snmp_values
        except Exception as e:
            Logger.log_error(f"Unexpected error during snmpget: {e}")
            return None

    def calculate_value(self, current_value: int, current_sys_uptime: int) -> Optional[float]:
        """
        Calculates the rate per second based on the current OID value and sysUpTime.
        """
        if self.prev_value is None or self.prev_sys_uptime is None:
            self.prev_value = current_value
            self.prev_sys_uptime = current_sys_uptime
            return None

        try:
            current_uptime_seconds = current_sys_uptime / 100.0
            prev_uptime_seconds = self.prev_sys_uptime / 100.0
            uptime_diff = current_uptime_seconds - prev_uptime_seconds

            if uptime_diff <= 0:
                Logger.log_error("Invalid sysUpTime difference detected. Device may have restarted.")
                self.prev_value = current_value
                self.prev_sys_uptime = current_sys_uptime
                return None

            if self.counter_bits == 64:
                max_counter = 2**64
            elif self.counter_bits == 32:
                max_counter = 2**32
            else:
                Logger.log_error("Counter bits not set correctly.")
                return None

            if current_value < self.prev_value:
                count_diff = (current_value + max_counter) - self.prev_value
            else:
                count_diff = current_value - self.prev_value

            rate_diff = count_diff / uptime_diff

            self.prev_value = current_value
            self.prev_sys_uptime = current_sys_uptime

            return rate_diff

        except Exception as e:
            Logger.log_error(f"Error during value calculation: {e}")
            return None

    def update_display(self):
        """
        Update the console display with the latest SNMP OID value graph and statistics.
        """
        if self.first_draw:
            self.clear_screen()
            self.first_draw = False
        else:
            print("\033[H\033[J", end="")

        display_target = f"{self.config.target} ({self.sysname})" if self.sysname else self.config.target
        output = []
        output.append(f"\n{COLOR_GRAY}Monitoring:{COLOR_RESET} {display_target}")
        
        if self.is_counter:
            graph_title = f"{COLOR_GRAY}OID:{COLOR_RESET} {self.oid} {COLOR_GRAY}/ sec Graph:{COLOR_RESET}"
        else:
            graph_title = f"{COLOR_GRAY}OID:{COLOR_RESET} {self.oid} {COLOR_GRAY}Graph:{COLOR_RESET}"
        
        output.append(graph_title)
        output.append(self.build_graph())
        output.append(self.build_statistics())

        if self.config.anomaly_mode:
            valid_data_count = len([v for v in self.response_values if v["value"] is not None])
            if self.anomaly_model is None and valid_data_count < self.config.min_data_count:
                remaining = self.config.min_data_count - valid_data_count
                output.append(f"{COLOR_GRAY}Currently Training... Remaining data points needed:{COLOR_RESET} {remaining}{COLOR_GRAY}.{COLOR_RESET}\n")
            elif self.anomaly_model is not None:
                output.append(f"{COLOR_GRAY}Training completed. Anomaly detection is active.{COLOR_RESET}\n")

        print("\n".join(output))

    def build_graph(self):
        """
        Build a text-based graph of the SNMP OID values with properly scaled Y-axis labels.
        """
        values = [v["value"] for v in self.response_values[-MAX_GRAPH_LENGTH:]]
        anomalies = [v.get("is_anomaly", False) for v in self.response_values[-MAX_GRAPH_LENGTH:]]
        thresholds = [v.get("threshold_breached", False) for v in self.response_values[-MAX_GRAPH_LENGTH:]]

        if len(values) < MAX_GRAPH_LENGTH:
            padding = MAX_GRAPH_LENGTH - len(values)
            values = [None] * padding + values
            anomalies = [False] * padding + anomalies
            thresholds = [False] * padding + thresholds

        valid_values = [v for v in values if v is not None]
        max_value = max(valid_values, default=0)
        scaled_max, unit, unit_scale = human_readable_size(max_value)

        if scaled_max == 0.0:
            scaled_max = 1.0

        step = scaled_max / GRAPH_HEIGHT if scaled_max else 1.0
        max_label_length = len(f"{scaled_max:.2f} {unit}")
        graph = []

        for i in range(GRAPH_HEIGHT, -1, -1):
            y_value = i * step
            y_label = f"{y_value:.2f} {unit}"
            line = f"{y_label:>{max_label_length}} | "

            for value, is_anomaly, threshold_breached in zip(values, anomalies, thresholds):
                if value is not None:
                    scaled_value = value / (1000 ** unit_scale)

                    if scaled_value == 0.0:
                        line += " "
                    elif scaled_value >= y_value:
                        if is_anomaly or threshold_breached:
                            line += f"{COLOR_RED}*{COLOR_RESET}"
                        else:
                            line += "*"
                    else:
                        line += " "
                else:
                    line += " "
            graph.append(line)

        x_axis_line = " " * (max_label_length + 2) + "-" * (MAX_GRAPH_LENGTH + 1)
        x_axis_labels = " " * (max_label_length + 3) + "".join(
            "|" if (i + 1) % 10 == 0 else " " for i in range(MAX_GRAPH_LENGTH)
        )
        graph.append(x_axis_line)
        graph.append(x_axis_labels)

        return "\n".join(graph)

    def build_statistics(self):
        """
        Build statistics related to SNMP OID values.
        """
        values = [v["value"] for v in self.response_values if v["value"] is not None]
        total = len(self.response_values)
        success = len(values)
        failure = total - success
        fail_rate = (failure / total) * 100 if total > 0 else 0
        min_value = min(values, default=0)
        max_value = max(values, default=0)
        cur_value = values[-1] if values else 0

        min_str, min_unit, _ = human_readable_size(min_value)
        max_str, max_unit, _ = human_readable_size(max_value)
        cur_str, cur_unit, _ = human_readable_size(cur_value)

        if self.response_values and self.response_values[-1]["value"] is None:
            failure_color = COLOR_RED
            fail_rate_color = COLOR_RED
        else:
            failure_color = ""
            fail_rate_color = ""

        stats = [
            f"{COLOR_GRAY}Statistics:{COLOR_RESET}",
            f"{COLOR_GRAY}Total:{COLOR_RESET} {total}, "
            f"{COLOR_GRAY}Success:{COLOR_RESET} {success}, "
            f"{COLOR_GRAY}Failure:{COLOR_RESET} {failure_color}{failure}{COLOR_RESET}, "
            f"{COLOR_GRAY}Failure Rate:{COLOR_RESET} {fail_rate_color}{fail_rate:.2f}%{COLOR_RESET}",
            f"{COLOR_GRAY}Min Value:{COLOR_RESET} {min_str:.2f} {min_unit}, "
            f"{COLOR_GRAY}Max Value:{COLOR_RESET} {max_str:.2f} {max_unit}, "
            f"{COLOR_GRAY}Cur Value:{COLOR_RESET} {cur_str:.2f} {cur_unit}\n"
        ]

        return "\n".join(stats)

class TrafficMonitor(NetworkMonitor):
    """
    Monitor class for network traffic using SNMP counters.
    """

    def __init__(self, config: MonitorConfig):
        super().__init__(config)
        self.community = config.snmp.get('community') if config.snmp else ""
        self.oid = config.snmp.get('oid') if config.snmp else ""
        self.index = self.extract_ifindex()
        self.ifname = self.get_snmp_value(f"1.3.6.1.2.1.31.1.1.1.1.{self.index}") if self.index else None
        self.sysname = self.get_snmp_value("1.3.6.1.2.1.1.5.0") if not hasattr(self, 'sysname') else self.sysname
        self.counter_bits = self.determine_counter_bits()
        self.anomaly_model_in = None
        self.anomaly_model_out = None
        self.initialize_csv()
        self.skip_initial_draw = True
        self.first_draw = True

    def determine_counter_bits(self) -> int:
        """
        Determine whether 64-bit counters are available by attempting to retrieve ifHCInOctets.
        """
        if not self.index:
            Logger.log_error("ifIndex is not determined.")
            return 32

        hc_in_oid = OID_IFHC_IN_OCTETS + self.index
        value = get_snmp_value(
            target=self.config.target,
            community=self.community,
            oid=hc_in_oid,
            timeout=self.config.timeout,
            debug_mode=self.config.debug_mode
        )

        if value is not None:
            Logger.log_debug_info(
                debug_mode=self.config.debug_mode,
                Message=f"64-bit counters are available for ifIndex {self.index}."
            )
            return 64
        else:
            Logger.log_debug_info(
                debug_mode=self.config.debug_mode,
                Message=f"64-bit counters are not available for ifIndex {self.index}. Using 32-bit counters."
            )
            return 32

    def get_snmp_value(self, oid: str) -> Optional[str]:
        """
        Wrapper around the global get_snmp_value function with class-specific parameters.
        """
        return get_snmp_value(
            target=self.config.target,
            community=self.community,
            oid=oid,
            timeout=self.config.timeout,
            debug_mode=self.config.debug_mode
        )
    
    def extract_ifindex(self) -> Optional[str]:
        """
        Extract the ifIndex from the OID specified in the format 'traffic.X'.
        """
        try:
            parts = self.oid.split(".")
            if len(parts) != 2 or parts[0].lower() != "traffic":
                Logger.log_error(f"Invalid traffic OID format: {self.oid}. Expected format 'traffic.X'.")
                return None
            identifier = parts[1]
            if identifier.isdigit():
                return identifier
            else:
                ifindex = get_ifindex_from_ifname(self.config.target, self.community, identifier)
                if ifindex is None:
                    Logger.log_error(f"ifName '{identifier}' not found for target {self.config.target}.")
                return ifindex
        except IndexError:
            Logger.log_error(f"Failed to extract ifIndex from OID: {self.oid}.")
            return None

    def initialize_csv(self):
        """
        Initialize the CSV log file with appropriate headers.
        """
        if self.config.should_log and self.config.log_filename and not os.path.exists(self.config.log_filename):
            with open(self.config.log_filename, mode="w", newline="") as file:
                writer = csv.writer(file)
                index = self.index

                target_info = f"{self.config.target} ({self.sysname})"

                if self.config.anomaly_mode:
                    num_columns = 7
                else:
                    num_columns = 5

                first_row = [""] + [target_info] * (num_columns - 1)
                writer.writerow(first_row)

                headers = ["Time"]
                headers += [
                    f"{self.ifname} - In Mbps" if self.ifname else f"ifIndex.{index} - In Mbps",
                    f"{self.ifname} - Out Mbps" if self.ifname else f"ifIndex.{index} - Out Mbps",
                    f"ifHCInOctets.{index}" if self.counter_bits == 64 else f"ifInOctets.{index}",
                    f"ifHCOutOctets.{index}" if self.counter_bits == 64 else f"ifOutOctets.{index}"
                ]

                if self.config.anomaly_mode:
                    headers += [
                        f"{self.ifname} - In - Anomaly Detected" if self.ifname else f"ifIndex.{index} - In - Anomaly Detected",
                        f"{self.ifname} - Out - Anomaly Detected" if self.ifname else f"ifIndex.{index} - Out - Anomaly Detected"
                    ]

                writer.writerow(headers)

    def perform_check(self):
        """
        Execute traffic monitoring by retrieving SNMP counters and calculating Mbps.
        """
        _, in_oid, out_oid = self.get_traffic_oids()
        oids = [in_oid, out_oid, "1.3.6.1.2.1.1.3.0"]
        snmp_values = self.get_snmp_traffic_values_with_sysuptime(oids)

        if snmp_values is None:

            self.response_values.append({
                "octets": (None, None),
                "mbps": (None, None),
                "anomaly_value": (None, None),
                "is_anomaly": (False, False),
                "threshold_breached": (False, False),
                "sys_uptime": None
            })

            if self.config.fail_notify and self.config.webhook_url:
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                message = f"{timestamp}\nFailed to retrieve SNMP traffic data from {self.config.target}\nOID: {in_oid}, {out_oid}"
                send_webhook_notification(
                    self.config.webhook_url,
                    message,
                    "fail_traffic",
                    self.config,
                    self.last_notification_times
                )

            if self.config.anomaly_mode:
                self.log_response(['', '', '', '', '', ''])
            else:
                self.log_response(['', '', '', '', ''])
            return

        in_value = snmp_values['in_octets']
        out_value = snmp_values['out_octets']
        sys_uptime = snmp_values['sys_uptime']

        if not self.response_values or self.response_values[-1]["octets"] == (None, None):
            self.response_values.append({
                "octets": (in_value, out_value),
                "mbps": (None, None),
                "anomaly_value": (None, None),
                "is_anomaly": (False, False),
                "threshold_breached": (False, False),
                "sys_uptime": sys_uptime
            })
            return

        prev_data = self.response_values[-1]
        in_mbps = self.calculate_traffic(in_value, prev_data["octets"][0], sys_uptime, prev_data["sys_uptime"])
        out_mbps = self.calculate_traffic(out_value, prev_data["octets"][1], sys_uptime, prev_data["sys_uptime"])

        is_threshold_breached_in, is_threshold_breached_out = self.handle_threshold_detection(in_mbps, out_mbps)

        is_anomaly_in, is_anomaly_out = self.handle_anomaly_detection(in_mbps, out_mbps)

        self.response_values.append({
            "octets": (in_value, out_value),
            "mbps": (in_mbps, out_mbps),
            "anomaly_value": (in_mbps, out_mbps),
            "is_anomaly": (is_anomaly_in, is_anomaly_out),
            "threshold_breached": (is_threshold_breached_in, is_threshold_breached_out),
            "sys_uptime": sys_uptime
        })

        if self.config.anomaly_mode:
            in_anomaly = "" if self.anomaly_model_in is None else str(is_anomaly_in).upper()
            out_anomaly = "" if self.anomaly_model_out is None else str(is_anomaly_out).upper()
            self.log_response([
                round(in_mbps, 2) if in_mbps is not None else '',
                round(out_mbps, 2) if out_mbps is not None else '',
                in_value, out_value,
                in_anomaly, out_anomaly
            ])
        else:
            self.log_response([
                round(in_mbps, 2) if in_mbps is not None else '',
                round(out_mbps, 2) if out_mbps is not None else '',
                in_value, out_value
            ])

    def handle_threshold_detection(self, in_mbps: Optional[float], out_mbps: Optional[float]) -> Tuple[bool, bool]:
        """
        Handle threshold detection for inbound and outbound traffic.
        """
        is_threshold_breached_in = is_threshold_breached_out = False

        if self.config.traffic_threshold:
            if self.config.traffic_threshold.in_condition and in_mbps is not None:
                condition = self.config.traffic_threshold.in_condition
                is_threshold_breached_in = evaluate_threshold(in_mbps, condition.operator, condition.value)
                if is_threshold_breached_in and self.config.webhook_url:
                    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    if self.ifname:
                        interface_info = self.ifname
                    else:
                        interface_info = f"ifIndex.{self.index}"
                    message = (
                        f"{timestamp}\n"
                        f"Threshold breached on In traffic monitoring of {self.config.target} ({self.sysname}) - {interface_info}\n"
                        f"In Traffic: {in_mbps:.2f} Mbps (Condition: {condition.operator}{condition.value} Mbps)"
                    )
                    send_webhook_notification(
                        self.config.webhook_url,
                        message,
                        "threshold_traffic_in",
                        self.config,
                        self.last_notification_times
                    )

            if self.config.traffic_threshold.out_condition and out_mbps is not None:
                condition = self.config.traffic_threshold.out_condition
                is_threshold_breached_out = evaluate_threshold(out_mbps, condition.operator, condition.value)
                if is_threshold_breached_out and self.config.webhook_url:
                    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    if self.ifname:
                        interface_info = self.ifname
                    else:
                        interface_info = f"ifIndex.{self.index}"
                    message = (
                        f"{timestamp}\n"
                        f"Threshold breached on Out traffic monitoring of {self.config.target} ({self.sysname}) - {interface_info}\n"
                        f"Out Traffic: {out_mbps:.2f} Mbps (Condition: {condition.operator}{condition.value} Mbps)"
                    )
                    send_webhook_notification(
                        self.config.webhook_url,
                        message,
                        "threshold_traffic_out",
                        self.config,
                        self.last_notification_times
                    )

        return is_threshold_breached_in, is_threshold_breached_out

    def handle_anomaly_detection(self, in_mbps: Optional[float], out_mbps: Optional[float]) -> Tuple[bool, bool]:
        """
        Handle anomaly detection for both inbound and outbound traffic.
        """
        is_anomaly_in = is_anomaly_out = False

        if self.config.anomaly_mode:
            valid_in_data = len([v for v in self.response_values if v["anomaly_value"][0] is not None])
            valid_out_data = len([v for v in self.response_values if v["anomaly_value"][1] is not None])

            if (self.anomaly_model_in is None or self.anomaly_model_out is None) and \
               min(valid_in_data, valid_out_data) >= self.config.min_data_count:
                self.detect_anomalies()

            if self.anomaly_model_in is not None and in_mbps is not None:
                is_anomaly_in = self.check_anomaly(in_mbps, "anomaly_traffic_in")

            if self.anomaly_model_out is not None and out_mbps is not None:
                is_anomaly_out = self.check_anomaly(out_mbps, "anomaly_traffic_out")

        return is_anomaly_in, is_anomaly_out

    def get_snmp_traffic_values_with_sysuptime(self, oids: List[str]) -> Optional[Dict[str, int]]:
        """
        Executes the SNMPGET command to retrieve traffic values and sysUpTime.
        """
        try:
            timeout_option = ["-t", str(self.config.timeout)] if self.config.timeout else []
            command = ["snmpget", "-On", "-v", "2c", "-c", self.community] + timeout_option + [self.config.target] + oids
            result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

            Logger.log_debug_info(
                debug_mode=self.config.debug_mode,
                Command=' '.join(command),
                Return_Code=result.returncode,
                STDOUT=result.stdout.strip(),
                STDERR=result.stderr.strip()
            )

            if "Timeout: No Response" in result.stderr:
                return None

            if result.returncode != 0:
                Logger.log_error(f"Failed to execute snmpget for {self.config.target}.")
                return None

            values = {}
            for line in result.stdout.splitlines():
                parts = line.split(' = ', 1)
                if len(parts) != 2:
                    continue

                oid = parts[0].strip()
                value_str = parts[1].strip()

                if re.match(r"^\.?1\.3\.6\.1\.2\.1\.31\.1\.1\.1\.6\.\d+$", oid) or re.match(r"^\.?1\.3\.6\.1\.2\.1\.2\.2\.1\.10\.\d+$", oid):
                    match = re.search(r"Counter\d+: (\d+)", value_str)
                    if match:
                        values['in_octets'] = int(match.group(1))
                elif re.match(r"^\.?1\.3\.6\.1\.2\.1\.31\.1\.1\.1\.10\.\d+$", oid) or re.match(r"^\.?1\.3\.6\.1\.2\.1\.2\.2\.1\.16\.\d+$", oid):
                    match = re.search(r"Counter\d+: (\d+)", value_str)
                    if match:
                        values['out_octets'] = int(match.group(1))
                elif re.match(r"^\.?1\.3\.6\.1\.2\.1\.1\.3\.0$", oid):
                    match = re.search(r"Timeticks: \((\d+)\)", value_str)
                    if match:
                        values['sys_uptime'] = int(match.group(1))

            if 'in_octets' not in values or 'out_octets' not in values or 'sys_uptime' not in values:
                Logger.log_error(f"Missing one or more SNMP values for {self.config.target}.")
                return None

            return values
        except Exception as e:
            Logger.log_error(f"Unexpected error during snmpget: {e}")
            return None

    def get_traffic_oids(self) -> Tuple[str, str, str]:
        """
        Determine the appropriate OIDs for traffic monitoring based on counter bits.
        """
        index = self.index
        if self.counter_bits == 64:
            in_oid = OID_IFHC_IN_OCTETS + index
            out_oid = OID_IFHC_OUT_OCTETS + index
        else:
            in_oid = OID_IF_IN_OCTETS + index
            out_oid = OID_IF_OUT_OCTETS + index
        return index, in_oid, out_oid

    def calculate_traffic(self, current_value: Optional[int], previous_value: Optional[int],
                          current_uptime: Optional[int], previous_uptime: Optional[int]) -> Optional[float]:
        """
        Calculate the traffic in Mbps based on SNMP counter differences and uptime.
        """
        if current_value is None or previous_value is None or current_uptime is None or previous_uptime is None:
            return None

        if current_uptime < previous_uptime:
            uptime_diff = (current_uptime + (2**32 - previous_uptime)) / 100
        else:
            uptime_diff = (current_uptime - previous_uptime) / 100

        if uptime_diff <= 0:
            return None

        max_counter = 2 ** self.counter_bits
        byte_diff = current_value - previous_value
        if byte_diff < 0:
            byte_diff += max_counter

        bits = byte_diff * 8
        return (bits / uptime_diff) / 1000 / 1000

    def detect_anomalies(self):
        """
        Initialize and train the anomaly detection models for In and Out traffic using IsolationForest.
        """
        if self.anomaly_model_in is not None and self.anomaly_model_out is not None:
            Logger.log_debug_info(
                debug_mode=self.config.debug_mode,
                Message="Anomaly models already exist, skipping re-training."
            )
            return

        in_values = [
            v["anomaly_value"][0] for v in self.response_values
            if v["anomaly_value"][0] is not None
        ]
        out_values = [
            v["anomaly_value"][1] for v in self.response_values
            if v["anomaly_value"][1] is not None
        ]

        if len(in_values) >= self.config.min_data_count:
            from sklearn.ensemble import IsolationForest
            model_in = IsolationForest(contamination=self.config.contamination)
            model_in.fit([[v] for v in in_values])
            self.anomaly_model_in = model_in
            Logger.log_debug_info(
                debug_mode=self.config.debug_mode,
                Message="Anomaly model training completed for In traffic.",
                Training_Data_Size=len(in_values),
                Contamination=self.config.contamination
            )

        if len(out_values) >= self.config.min_data_count:
            from sklearn.ensemble import IsolationForest
            model_out = IsolationForest(contamination=self.config.contamination)
            model_out.fit([[v] for v in out_values])
            self.anomaly_model_out = model_out
            Logger.log_debug_info(
                debug_mode=self.config.debug_mode,
                Message="Anomaly model training completed for Out traffic.",
                Training_Data_Size=len(out_values),
                Contamination=self.config.contamination
            )

    def check_anomaly(self, value: float, notification_type: str) -> bool:
        """
        Check if the latest value is an anomaly and send a webhook notification if necessary.
        """
        if notification_type == "anomaly_traffic_in" and self.anomaly_model_in is not None:
            prediction = self.anomaly_model_in.predict([[value]])
            if prediction[0] == -1:
                if self.config.webhook_url:
                    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    message = self.generate_anomaly_message(timestamp, value, direction="In")
                    send_webhook_notification(
                        self.config.webhook_url,
                        message,
                        notification_type,
                        self.config,
                        self.last_notification_times
                    )
                return True
        elif notification_type == "anomaly_traffic_out" and self.anomaly_model_out is not None:
            prediction = self.anomaly_model_out.predict([[value]])
            if prediction[0] == -1:
                if self.config.webhook_url:
                    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    message = self.generate_anomaly_message(timestamp, value, direction="Out")
                    send_webhook_notification(
                        self.config.webhook_url,
                        message,
                        notification_type,
                        self.config,
                        self.last_notification_times
                    )
                return True
        return False

    def generate_anomaly_message(self, timestamp: str, value: float, direction: str) -> str:
        """
        Generate a webhook message based on the type of monitor and direction.
        """
        if self.ifname:
            target_info = f"{self.config.target} ({self.sysname}) - {self.ifname}"
        else:
            target_info = f"{self.config.target} ({self.sysname}) - ifIndex.{self.index}"

        return (
            f"{timestamp}\n"
            f"Anomaly detected on {direction} traffic monitoring of {target_info}\n"
            f"Traffic: {value:.2f} Mbps"
        )

    def update_display(self):
        """
        Update the console display with the latest traffic graph and statistics.
        """
        if self.skip_initial_draw:
            self.skip_initial_draw = False
            return

        if self.first_draw:
            self.clear_screen()
            self.first_draw = False
        else:
            print("\033[H\033[J", end="")

        output = []
        if self.sysname:
            display_target = f"{self.config.target} ({self.sysname})"
        else:
            display_target = self.config.target
        output.append(f"\n{COLOR_GRAY}Monitoring:{COLOR_RESET} {display_target}")
        index = self.index
        max_in_value_mbps = max([v["mbps"][0] for v in self.response_values[-MAX_GRAPH_LENGTH:] if v["mbps"][0] is not None], default=0)
        max_out_value_mbps = max([v["mbps"][1] for v in self.response_values[-MAX_GRAPH_LENGTH:] if v["mbps"][1] is not None], default=0)
        max_value_mbps = max(max_in_value_mbps, max_out_value_mbps)
        value_converted, unit = convert_traffic_unit(max_value_mbps)
        if self.ifname and isinstance(self.ifname, str):
            output.append(f"{self.ifname} {COLOR_GRAY}Traffic Graph ({COLOR_RESET}{unit}{COLOR_GRAY}, * = In, # = Out):{COLOR_RESET}")
        else:
            output.append(f"{COLOR_GRAY}ifIndex.{COLOR_RESET}{index} {COLOR_GRAY}Traffic Graph ({COLOR_RESET}{unit}{COLOR_GRAY}, * = In, # = Out):{COLOR_RESET}")
        output.append(self.build_traffic_graph(unit))
        output.append(self.build_traffic_statistics())
        if self.config.anomaly_mode:
            valid_in_data = len([v for v in self.response_values if v["anomaly_value"][0] is not None])
            valid_out_data = len([v for v in self.response_values if v["anomaly_value"][1] is not None])
            if self.anomaly_model_in is None or self.anomaly_model_out is None:
                remaining_data_points = max(0, self.config.min_data_count - min(valid_in_data, valid_out_data))
                if remaining_data_points > 0:
                    output.append(f"{COLOR_GRAY}Currently Training... Remaining data points needed:{COLOR_RESET} {remaining_data_points}{COLOR_GRAY}.{COLOR_RESET}\n")
            else:
                output.append(f"{COLOR_GRAY}Training completed. Anomaly detection is active.{COLOR_RESET}\n")
        print("\n".join(output))

    def build_traffic_graph(self, unit):
        """
        Build a text-based graph of the traffic in and out, highlighting anomalies and threshold breaches.
        """
        latest_values = self.response_values[-MAX_GRAPH_LENGTH:]
        if len(latest_values) < MAX_GRAPH_LENGTH:
            latest_values = [None] * (MAX_GRAPH_LENGTH - len(latest_values)) + latest_values

        in_values = [v["mbps"][0] if v else None for v in latest_values]
        out_values = [v["mbps"][1] if v else None for v in latest_values]
        anomalies_in = [v.get("is_anomaly", (False, False))[0] if v else False for v in latest_values]
        anomalies_out = [v.get("is_anomaly", (False, False))[1] if v else False for v in latest_values]
        thresholds_in = [v.get("threshold_breached", (False, False))[0] if v else False for v in latest_values]
        thresholds_out = [v.get("threshold_breached", (False, False))[1] if v else False for v in latest_values]

        max_in_value_mbps = max([v for v in in_values if v is not None], default=0)
        max_out_value_mbps = max([v for v in out_values if v is not None], default=0)
        max_value_mbps = max(max_in_value_mbps, max_out_value_mbps)

        step_value = max_value_mbps / GRAPH_HEIGHT if max_value_mbps else 1
        graph_lines = []
        for i in range(GRAPH_HEIGHT, -1, -1):
            y_value = i * step_value

            if unit == "Kbps":
                y_value_converted = y_value * 1000
            elif unit == "Gbps":
                y_value_converted = y_value / 1000
            else:
                y_value_converted = y_value

            line = f"{y_value_converted:>6.2f} | "

            for idx in range(len(in_values)):
                in_mbps = in_values[idx]
                out_mbps = out_values[idx]
                is_anomaly_in = anomalies_in[idx]
                is_anomaly_out = anomalies_out[idx]
                is_threshold_in = thresholds_in[idx]
                is_threshold_out = thresholds_out[idx]

                char = " "

                if in_mbps is not None and in_mbps >= y_value and in_mbps > 0:
                    if out_mbps is not None and out_mbps >= y_value and out_mbps > 0:
                        if in_mbps <= out_mbps:
                            if is_anomaly_in or is_threshold_in:
                                char = f"{COLOR_RED}*{COLOR_RESET}"
                            else:
                                char = "*"
                        else:
                            if is_anomaly_out or is_threshold_out:
                                char = f"{COLOR_RED}#{COLOR_RESET}"
                            else:
                                char = "#"
                    else:
                        if is_anomaly_in or is_threshold_in:
                            char = f"{COLOR_RED}*{COLOR_RESET}"
                        else:
                            char = "*"
                elif out_mbps is not None and out_mbps >= y_value and out_mbps > 0:
                    if is_anomaly_out or is_threshold_out:
                        char = f"{COLOR_RED}#{COLOR_RESET}"
                    else:
                        char = "#"
                else:
                    char = " "

                line += char
            graph_lines.append(line)

        x_axis_line = "        " + "-" * (MAX_GRAPH_LENGTH + 1)
        x_axis_labels = "         " + "".join(
            "|" if (i + 1) % 10 == 0 else " " for i in range(MAX_GRAPH_LENGTH)
        )
        graph_lines.append(x_axis_line)
        graph_lines.append(x_axis_labels)

        return "\n".join(graph_lines)

    def build_traffic_statistics(self):
        """
        Build and return traffic statistics with dynamic units, ensuring zero values are displayed correctly.
        """
        in_values = [v["mbps"][0] for v in self.response_values if v["mbps"][0] is not None]
        out_values = [v["mbps"][1] for v in self.response_values if v["mbps"][1] is not None]

        in_min, in_min_unit = convert_traffic_unit(min(in_values) if in_values else 0.0)
        in_max, in_max_unit = convert_traffic_unit(max(in_values) if in_values else 0.0)
        in_cur = in_values[-1] if in_values else 0.0
        in_cur_str, in_cur_unit = convert_traffic_unit(in_cur)

        out_min, out_min_unit = convert_traffic_unit(min(out_values) if out_values else 0.0)
        out_max, out_max_unit = convert_traffic_unit(max(out_values) if out_values else 0.0)
        out_cur = out_values[-1] if out_values else 0.0
        out_cur_str, out_cur_unit = convert_traffic_unit(out_cur)

        stats_lines = []
        stats_lines.append(f"{COLOR_GRAY}Statistics:{COLOR_RESET}")
        stats_lines.append(f"{COLOR_GRAY}In  Min:{COLOR_RESET}{in_min:>6} {in_min_unit}, "
                           f"{COLOR_GRAY}In  Max:{COLOR_RESET}{in_max:>6} {in_max_unit}, "
                           f"{COLOR_GRAY}In  Cur:{COLOR_RESET}{in_cur_str:>6} {in_cur_unit}")
        stats_lines.append(f"{COLOR_GRAY}Out Min:{COLOR_RESET}{out_min:>6} {out_min_unit}, "
                           f"{COLOR_GRAY}Out Max:{COLOR_RESET}{out_max:>6} {out_max_unit}, "
                           f"{COLOR_GRAY}Out Cur:{COLOR_RESET}{out_cur_str:>6} {out_cur_unit}\n")
        return "\n".join(stats_lines)

def display_help():
    """
    Display the help message with available options and usage examples.
    """
    help_message = """
Options:
  -i <interval> (default: 1)
      Set the check interval in seconds.

  -W <timeout> (default: system-dependent)
      Set the timeout value in seconds for each check.

  --stop-after <n> (default: unlimited)
      Stop monitoring after <n> checks.

  --log <file> (default: see below)
      Log responses to the specified CSV file.
      Default filenames:
        - ping_monitor_log.csv (Ping monitoring)
        - http_monitor_log.csv (HTTP monitoring)
        - snmp_monitor_log.csv (SNMP monitoring)
        - traffic_monitor_log.csv (Traffic monitoring)

  --snmp <community> <oid>
      Use SNMP for monitoring. Requires Net-SNMP.
      For traffic monitoring, you can also specify 'traffic.X'
      instead of the OID (where X is ifIndex or ifName).
      Example formats:
          - traffic.1 (using ifIndex)
          - traffic.Gi0/1 (using ifName)
      Note:
          - ifName matching is case-insensitive
            and must match exactly.
          - The script automatically determines
            whether to use 32-bit or 64-bit counters.
          - Traffic calculations are based on 1000, not 1024.
            This means 1 Mbps = 1000^2 bits.
          - If the OID value is of counter type,
            it is automatically calculated as per second.
          - SNMP version is fixed at 2c.

  --thresh <condition> [<condition> ...]
      Set threshold conditions for monitoring.
      Applicable to Ping, HTTP, SNMP, and Traffic monitors.
      When a threshold breach occurs:
          - The graph will highlight the breach in red.
          - A webhook notification will be sent
            if the --webhook option is enabled.
      For non-traffic monitors:
          Example: --thresh >=300
      For traffic monitors:
          Example: --thresh in>=1gbps out>=500mbps
          You can specify one or both directions (in/out).
          Units supported: bps, kbps, mbps, gbps (case-insensitive)
      Note:
          - For traffic monitors, direction and unit are required.
          - If the OID value is a counter type,
            the specified threshold values must be per second.

  --anomaly <count> <contamination> (default: 256, 0.01)
      Enable anomaly detection using machine learning
      to automatically identify unusual data points.
      Requires scikit-learn.
      When an anomaly is detected:
          - The graph will highlight the anomaly in red.
          - A webhook notification will be sent
            if the --webhook option is enabled.

      <count> specifies the minimum number of data points
      needed for anomaly detection (default is 256).
      In general, the more data you have,
      the more accurate the detection will be.

      <contamination> defines the expected percentage of anomalies
      in the dataset (default is 0.01, meaning 1%). 
      A higher value increases the sensitivity to anomalies,
      but may also lead to more false positives.

      The anomaly detection is performed using a machine learning algorithm
      called IsolationForest, which automatically identifies patterns
      that deviate from the norm in large datasets.
      It is recommended to use at least 256 data points for reliable detection.

  --fail
      Enable failure notifications.
      When a monitoring check fails to retrieve a value,
      a webhook notification will be sent if --webhook is enabled.

  --webhook <url> <interval> (default: no webhook, no suppression interval)
      Specify a webhook URL to send notifications
      when an anomaly, threshold breach, or failure is detected.
      <interval> is optional and specifies the minimum time (in minutes)
      between successive notifications of the same type.
      If not provided, notifications are sent immediately after each event.

  --debug (default: off)
      Enable debug mode for detailed logs.

  -h, --help, ?
      Display this help message and exit.

Examples:
  # Simple Ping monitoring
  192.168.1.1

  # Simple HTTP monitoring (GET request)
  https://example.com

  # SNMP monitoring of a specific OID
  192.168.1.1 --snmp public 1.3.6.1.4.1.2021.11.11.0

  # Traffic monitoring on ifIndex.1
  192.168.1.1 --snmp public traffic.1

  # Traffic monitoring using ifName (e.g., Gi0/1)
  192.168.1.1 --snmp public traffic.Gi0/1

  # Ping monitoring with anomaly detection (256 data points, 0.01 contamination)
  192.168.1.1 --anomaly

  # Ping monitoring with threshold detection
  192.168.1.1 --thresh >=300

  # Traffic monitoring with threshold detection
  192.168.1.1 --snmp public traffic.Gi0/1 --thresh in>=1gbps out>=500mbps

  # Ping monitoring with failure and webhook notifications (15-minute suppression interval)
  192.168.1.1 --fail --webhook https://example.com/webhook 15

  # Ping monitoring with logging (default filename)
  192.168.1.1 --log

  # Ping monitoring with debugging
  192.168.1.1 --debug
    """
    print(help_message)


def parse_user_input(user_input: str) -> Optional[MonitorConfig]:
    """
    Parse the user's input string and return a MonitorConfig object.
    Returns None if parsing fails.
    """
    try:
        tokens = shlex.split(user_input)
    except ValueError as e:
        print(f"\nError parsing input: {e}")
        return None

    if not tokens:
        print("\nError: No target specified.")
        return None

    target = tokens[0]
    options = tokens[1:]

    if is_valid_url(target) and "--snmp" in options:
        print("\nError: Cannot use URL target with SNMP option.")
        return None

    config = MonitorConfig(target=target)

    i = 0
    while i < len(options):
        option = options[i]
        if option == "--snmp":
            if i + 2 >= len(options):
                print("\nError: Missing values for --snmp option.")
                return None
            community = options[i + 1]
            oid = options[i + 2]
            if oid.lower().startswith("traffic."):
                identifier = oid.split(".")[1]
                if not identifier.isdigit():
                    ifindex = get_ifindex_from_ifname(target, community, identifier)
                    if ifindex is None:
                        print(f"\nError: ifName '{identifier}' not found for {target}.")
                        return None
                    oid = f"traffic.{ifindex}"
            config.snmp = {'community': community, 'oid': oid}
            i += 3
        elif option == "--thresh":
            if i + 1 >= len(options):
                print("\nError: Missing value for --thresh option.")
                return None
            thresh_args = []
            j = i + 1
            while j < len(options) and not options[j].startswith("-"):
                thresh_args.append(options[j])
                j += 1
            if not thresh_args:
                print("\nError: No conditions specified for --thresh option.")
                return None
            if config.snmp and config.snmp['oid'].lower().startswith("traffic."):
                traffic_threshold = TrafficThresholdCondition()
                for condition in thresh_args:
                    match = re.match(r'(?i)(in|out)(>=|<=|>|<|==)(\d+)(bps|kbps|mbps|gbps)', condition)
                    if not match:
                        print(f"\nError: Invalid traffic threshold condition: {condition}")
                        return None
                    direction, operator, value, unit = match.groups()
                    value = float(value)
                    unit = unit.lower()
                    if unit == 'bps':
                        value_mbps = value / 1_000_000
                    elif unit == 'kbps':
                        value_mbps = value / 1_000
                    elif unit == 'mbps':
                        value_mbps = value
                    elif unit == 'gbps':
                        value_mbps = value * 1_000
                    else:
                        print(f"\nError: Unsupported unit in threshold condition: {unit}")
                        return None
                    thresh_condition = ThresholdCondition(operator=operator, value=value_mbps)
                    if direction.lower() == 'in':
                        traffic_threshold.in_condition = thresh_condition
                    elif direction.lower() == 'out':
                        traffic_threshold.out_condition = thresh_condition
                config.traffic_threshold = traffic_threshold
            else:
                condition = thresh_args[0]
                match = re.match(r'(>=|<=|>|<|==)(\d+)', condition)
                if not match:
                    print(f"\nError: Invalid threshold condition: {condition}")
                    return None
                operator, value = match.groups()
                value = float(value)
                config.threshold = ThresholdCondition(operator=operator, value=value)
                if len(thresh_args) > 1:
                    print("\nError: Multiple threshold conditions are not supported yet.")
                    return None
            i = j
        elif option == "-i":
            if i + 1 >= len(options):
                print("\nError: Missing value for -i option.")
                return None
            try:
                config.interval = float(options[i + 1])
                if config.interval <= 0:
                    print("\nError: Interval must be a positive number.")
                    return None
            except ValueError:
                print("\nError: Invalid value for -i option.")
                return None
            i += 2
        elif option == "-W":
            if i + 1 >= len(options):
                print("\nError: Missing value for -W option.")
                return None
            try:
                config.timeout = float(options[i + 1])
                if config.timeout <= 0:
                    print("\nError: Timeout must be a positive number.")
                    return None
            except ValueError:
                print("\nError: Invalid value for -W option.")
                return None
            i += 2
        elif option == "--stop-after":
            if i + 1 >= len(options):
                print("\nError: Missing value for --stop-after option.")
                return None
            try:
                config.stop_after = int(options[i + 1])
                if config.stop_after <= 0:
                    print("\nError: --stop-after value must be a positive integer.")
                    return None
            except ValueError:
                print("\nError: Invalid value for --stop-after option.")
                return None
            i += 2
        elif option == "--log":
            config.should_log = True
            if i + 1 < len(options) and not options[i + 1].startswith("-"):
                config.log_filename = options[i + 1]
                i += 2
            else:
                if config.snmp and config.snmp['oid'].lower().startswith("traffic."):
                    config.log_filename = DEFAULT_TRAFFIC_LOG
                elif config.snmp:
                    config.log_filename = DEFAULT_SNMP_LOG
                elif is_valid_url(target):
                    config.log_filename = DEFAULT_HTTP_LOG
                else:
                    config.log_filename = DEFAULT_PING_LOG
                i += 1
        elif option == "--debug":
            config.debug_mode = True
            i += 1
        elif option == "--anomaly":
            config.anomaly_mode = True
            if i + 1 < len(options) and not options[i + 1].startswith("-"):
                try:
                    config.min_data_count = int(options[i + 1])
                    i += 1
                except ValueError:
                    print("\nError: Invalid value for --anomaly option.")
                    return None
            if i + 1 < len(options) and not options[i + 1].startswith("-"):
                try:
                    config.contamination = float(options[i + 1])
                    if not (0 < config.contamination < 1):
                        print(f"\nError: Contamination value {config.contamination} is out of range (0 < contamination < 1).")
                        return None
                    i += 1
                except ValueError:
                    print("\nError: Invalid value for --anomaly option.")
                    return None
            if not import_isolation_forest():
                print("\nError: scikit-learn is required for the --anomaly option.")
                return None
            i += 1
        elif option == "--webhook":
            if i + 1 >= len(options):
                print("\nError: Missing webhook URL for --webhook option.")
                return None
            webhook_url = options[i + 1]
            if not is_valid_url(webhook_url):
                print(f"\nError: Invalid webhook URL: {webhook_url}")
                return None
            config.webhook_url = webhook_url
            if i + 2 < len(options) and options[i + 2].isdigit():
                config.notification_interval = int(options[i + 2])
                if config.notification_interval <= 0:
                    print("\nError: Notification interval must be a positive integer.")
                    return None
                i += 3
            else:
                config.notification_interval = 0
                i += 2
        elif option in ["-h", "--help", "?"]:
            display_help()
            return None
        elif option == "--fail":
            config.fail_notify = True
            i += 1
        elif option.lower().startswith("traffic."):
            if config.snmp and config.snmp['oid'].lower().startswith("traffic."):
                i += 1
            else:
                print("\nError: 'traffic.X' should be used with --snmp option.")
                return None
        else:
            print(f"\nError: Invalid option found: {option}")
            return None

    return config


def create_monitor(config: MonitorConfig) -> Optional[NetworkMonitor]:
    """
    Instantiate the appropriate monitor class based on the configuration.
    Returns the monitor instance or None if instantiation fails.
    """
    if is_valid_url(config.target):
        return HttpMonitor(config)
    elif config.snmp:
        if config.snmp['oid'].lower().startswith("traffic."):
            return TrafficMonitor(config)
        else:
            return SnmpMonitor(config)
    else:
        return PingMonitor(config)


def main():
    """
    Main function to run the network monitoring tool.
    """
    try:
        while True:
            user_input = input("\nEnter the host or URL to monitor: ").strip()
            if not user_input or user_input in ["--help", "-h", "?"]:
                display_help()
                continue
            config = parse_user_input(user_input)
            if config is None:
                continue

            monitor = create_monitor(config)
            if monitor is None:
                continue

            if isinstance(monitor, HttpMonitor):
                if not check_curl_command():
                    print("\nError: 'curl' command is not available. Please install cURL.")
                    continue

            if config.snmp:
                if not check_snmp_command():
                    print("\nError: 'snmpget' command is not available. Please install Net-SNMP.")
                    continue

            monitor.monitor()
            break
    except KeyboardInterrupt:
        print("\nExiting.\n")


if __name__ == "__main__":
    main()
