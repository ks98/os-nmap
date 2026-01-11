#!/usr/local/bin/python3


import argparse
import base64
import datetime
import ipaddress
import json
import os
import shlex
import signal
import subprocess
import sys
import threading
import xml.etree.ElementTree as ET

PROFILE_OPTIONS = {
    "ping": ["-sn"],
    "fast": ["-F", "-sS"],
    "regular": ["-sS"],
    "service": ["-sS", "-sV"],
    "full": ["-sS", "-p", "1-65535"],
    "aggressive": ["-A"],
}

MAX_HOSTS = 1024
SCAN_TIMEOUT = 36000
RESULTS_PATH = "/var/db/nmap/scan_results.json"
STATUS_PATH = "/var/db/nmap/scan_status.json"
MAX_STATUS_OUTPUT = 200000
STATUS_LOCK = threading.Lock()
LOOPBACK_HOSTNAMES = {
    "localhost",
    "localhost.localdomain",
    "ip6-localhost",
    "ip6-loopback",
}


def is_valid_hostname(name):
    if not name or len(name) > 253:
        return False
    if name.endswith("."):
        name = name[:-1]
    labels = name.split(".")
    for label in labels:
        if not label or len(label) > 63:
            return False
        if label[0] == "-" or label[-1] == "-":
            return False
        for ch in label:
            if not (ch.isalnum() or ch == "-"):
                return False
    return True


def is_loopback_target(target):
    normalized = target.lower().strip()
    if normalized.endswith("."):
        normalized = normalized[:-1]
    if normalized in LOOPBACK_HOSTNAMES:
        return True
    if "/" in target:
        addr = target.split("/", 1)[0]
        try:
            ip = ipaddress.ip_address(addr)
        except ValueError:
            return False
        return ip.is_loopback
    try:
        ip = ipaddress.ip_address(target)
    except ValueError:
        return False
    return ip.is_loopback


def validate_target(target):
    if not target:
        return None, "Target is required.", None
    if target.startswith("-"):
        return None, "Invalid target value.", None
    if any(ch.isspace() for ch in target):
        return None, "Target must not contain spaces.", None
    if is_loopback_target(target):
        return None, "Loopback targets are not allowed.", None
    if "/" in target:
        addr, prefix = target.split("/", 1)
        if not prefix.isdigit():
            return None, "Invalid CIDR prefix.", None
        try:
            ip = ipaddress.ip_address(addr)
        except ValueError:
            return None, "Invalid IP address.", None
        prefix_len = int(prefix)
        max_prefix = 32 if ip.version == 4 else 128
        if prefix_len < 0 or prefix_len > max_prefix:
            return None, "Invalid CIDR prefix length.", None
        network = ipaddress.ip_network(target, strict=False)
        warning = None
        if network.num_addresses > MAX_HOSTS:
            warning = (
                "Warning: target {target} expands to {network} "
                "({hosts} hosts), recommended max is {limit}."
            ).format(
                target=target,
                network=network.with_prefixlen,
                hosts=network.num_addresses,
                limit=MAX_HOSTS,
            )
        return ip.version, None, warning
    try:
        ip = ipaddress.ip_address(target)
        return ip.version, None, None
    except ValueError:
        if is_valid_hostname(target):
            return 0, None, None
    return None, "Invalid target value.", None


def validate_targets_list(targets_value):
    targets = [t for t in targets_value.split(",") if t]
    if not targets:
        return None, None, "No targets supplied."
    versions = set()
    warnings = []
    for target in targets:
        version, error, warning = validate_target(target)
        if error is not None:
            return None, None, error
        versions.add(version)
        if warning:
            warnings.append(warning)
    return targets, warnings, None


def decode_custom_args(payload):
    if not payload:
        return [], None
    try:
        raw = base64.b64decode(payload.encode("ascii"), validate=True)
    except (ValueError, UnicodeError):
        return None, "Invalid custom arguments encoding."
    if len(raw) > 4096:
        return None, "Custom arguments too long."
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None, "Custom arguments must be UTF-8."
    if not text.strip():
        return [], None
    try:
        return shlex.split(text), None
    except ValueError:
        return None, "Unable to parse custom arguments."


def run_command(cmd):
    try:
        return subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=SCAN_TIMEOUT,
        )
    except subprocess.TimeoutExpired:
        return None


def collect_output(result):
    if result is None:
        return f"Scan timed out after {SCAN_TIMEOUT} seconds."
    output = ""
    if result.stdout:
        output += result.stdout
    if result.stderr:
        if output:
            output += "\n"
        output += result.stderr
    output = output.strip()
    if not output:
        output = "No output returned."
    return output


def truncate_output(text, limit=MAX_STATUS_OUTPUT):
    text = text or ""
    if len(text) <= limit:
        return text, False
    truncated = text[:limit]
    suffix = "\n[output truncated]"
    if len(truncated) + len(suffix) <= limit:
        truncated += suffix
    return truncated, True


def parse_nmap_xml(xml_text):
    root = ET.fromstring(xml_text)
    hosts = []
    for host in root.findall("host"):
        status_el = host.find("status")
        status = status_el.get("state", "") if status_el is not None else ""
        address = ""
        mac = ""
        vendor = ""
        for addr_el in host.findall("address"):
            addr_type = addr_el.get("addrtype", "")
            if addr_type in ("ipv4", "ipv6") and not address:
                address = addr_el.get("addr", "")
            elif addr_type == "mac":
                mac = addr_el.get("addr", "")
                vendor = addr_el.get("vendor", "")
        if not address:
            continue
        hostname = ""
        hostnames_el = host.find("hostnames")
        if hostnames_el is not None:
            hostname_el = hostnames_el.find("hostname")
            if hostname_el is not None:
                hostname = hostname_el.get("name", "") or ""
        ports = []
        ports_el = host.find("ports")
        if ports_el is not None:
            for port_el in ports_el.findall("port"):
                state_el = port_el.find("state")
                state = state_el.get("state", "") if state_el is not None else ""
                if not state.startswith("open"):
                    continue
                service_el = port_el.find("service")
                service_name = service_el.get("name", "") if service_el is not None else ""
                ports.append({
                    "port": int(port_el.get("portid", "0") or 0),
                    "proto": port_el.get("protocol", ""),
                    "state": state,
                    "service": service_name,
                    "product": service_el.get("product", "") if service_el is not None else "",
                    "version": service_el.get("version", "") if service_el is not None else "",
                    "extra": service_el.get("extrainfo", "") if service_el is not None else "",
                    "tunnel": service_el.get("tunnel", "") if service_el is not None else "",
                })
        hosts.append({
            "address": address,
            "hostname": hostname,
            "status": status,
            "mac": mac,
            "vendor": vendor,
            "ports": ports,
        })
    return root, hosts


def write_results(data):
    directory = os.path.dirname(RESULTS_PATH)
    os.makedirs(directory, exist_ok=True)
    tmp_path = RESULTS_PATH + ".tmp"
    with open(tmp_path, "w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2, sort_keys=True)
    os.replace(tmp_path, RESULTS_PATH)


def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def read_status_unlocked():
    if not os.path.isfile(STATUS_PATH):
        return None
    try:
        with open(STATUS_PATH, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) else None


def write_status_unlocked(data):
    directory = os.path.dirname(STATUS_PATH)
    os.makedirs(directory, exist_ok=True)
    tmp_path = STATUS_PATH + ".tmp"
    with open(tmp_path, "w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2, sort_keys=True)
    os.replace(tmp_path, STATUS_PATH)


def read_status():
    with STATUS_LOCK:
        return read_status_unlocked()


def write_status(data):
    with STATUS_LOCK:
        write_status_unlocked(data)


def pid_is_running(pid):
    try:
        pid = int(pid)
    except (TypeError, ValueError):
        return False
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True


def write_running_status(pid, args, targets, warnings):
    if not isinstance(targets, list):
        targets = [targets]
    status = {
        "running": True,
        "pid": pid,
        "started_at": now_iso(),
        "completed_at": None,
        "mode": args.mode,
        "profile": args.profile,
        "targets": targets,
        "warnings": warnings or [],
        "exit_code": None,
        "message": "",
        "output": "",
        "output_truncated": False,
        "stale": False,
    }
    write_status(status)


def write_finished_status(exit_code, message=None, output=None, output_truncated=False):
    with STATUS_LOCK:
        status = read_status_unlocked() or {}
        status["running"] = False
        status["completed_at"] = now_iso()
        status["exit_code"] = exit_code
        if message is not None:
            status["message"] = message
        if output is not None:
            status["output"] = output
            status["output_truncated"] = bool(output_truncated)
        write_status_unlocked(status)


def start_background_scan(args, targets, warnings):
    existing = read_status()
    if existing and existing.get("running") and pid_is_running(existing.get("pid")):
        print("Scan already running.")
        return 1
    if existing and existing.get("running") and not pid_is_running(existing.get("pid")):
        existing["running"] = False
        existing["stale"] = True
        existing["completed_at"] = now_iso()
        write_status(existing)

    cmd = [
        sys.executable,
        os.path.abspath(__file__),
        "--worker",
        args.mode,
        args.targets,
        args.profile,
        args.open_only,
        args.no_dns,
        args.skip_discovery,
        args.ipv6,
        args.custom_b64,
    ]
    try:
        with open(os.devnull, "w", encoding="utf-8") as devnull:
            proc = subprocess.Popen(
                cmd,
                stdout=devnull,
                stderr=devnull,
                close_fds=True,
                start_new_session=True,
            )
    except OSError:
        print("Unable to start background scan.")
        return 1

    write_running_status(proc.pid, args, targets, warnings)
    print("Scan started.")
    return 0


def run_text_scan(cmd, args, targets, warnings, update_status=False):
    if update_status:
        write_running_status(os.getpid(), args, targets, warnings)

    result = run_command(cmd)
    output = collect_output(result)
    exit_code = 1 if result is None else result.returncode

    if update_status:
        truncated_output, was_truncated = truncate_output(output)
        message = None
        if exit_code != 0:
            message = output if output.startswith("Scan timed out") else "Scan finished with errors."
        write_finished_status(exit_code, message, output=truncated_output, output_truncated=was_truncated)
    print(output)
    return 0 if exit_code == 0 else 1


def cancel_scan(pid):
    status = read_status()
    if not status or not status.get("running"):
        print("No running scan.")
        return 1
    try:
        pid = int(pid)
    except (TypeError, ValueError):
        print("Invalid PID.")
        return 1
    if pid <= 0:
        print("Invalid PID.")
        return 1
    if status.get("pid") and int(status.get("pid")) != pid:
        print("Scan PID mismatch.")
        return 1
    try:
        os.killpg(pid, signal.SIGTERM)
    except ProcessLookupError:
        status["running"] = False
        status["stale"] = True
        status["completed_at"] = now_iso()
        status["exit_code"] = 1
        status["message"] = "Scan already stopped."
        status["output"] = ""
        status["output_truncated"] = False
        write_status(status)
        print("Scan already stopped.")
        return 1
    except PermissionError:
        print("Unable to stop scan.")
        return 1
    status["running"] = False
    status["completed_at"] = now_iso()
    status["exit_code"] = 130
    status["message"] = "Scan canceled."
    status["output"] = ""
    status["output_truncated"] = False
    write_status(status)
    print("Scan canceled.")
    return 0


def run_hosts_scan(cmd, args, targets, warnings, update_status=False):
    if update_status:
        write_running_status(os.getpid(), args, targets, warnings)

    if update_status:
        xml_path = os.path.join(os.path.dirname(RESULTS_PATH), f"scan_output_{os.getpid()}.xml")
        os.makedirs(os.path.dirname(xml_path), exist_ok=True)
        cmd_to_run = list(cmd)
        try:
            idx = cmd_to_run.index("-oX")
        except ValueError:
            idx = -1
        if idx != -1 and idx + 1 < len(cmd_to_run):
            cmd_to_run[idx + 1] = xml_path
        else:
            cmd_to_run.extend(["-oX", xml_path])
        result = run_command(cmd_to_run)
        if result is None:
            message = f"Scan timed out after {SCAN_TIMEOUT} seconds."
            write_finished_status(1, message)
            print(message)
            return 1
        stdout_payload = ""
        if os.path.isfile(xml_path):
            try:
                with open(xml_path, "r", encoding="utf-8", errors="replace") as handle:
                    stdout_payload = handle.read()
            finally:
                try:
                    os.remove(xml_path)
                except OSError:
                    pass
        if not stdout_payload:
            stdout_payload = result.stdout or ""
        stderr_payload = result.stderr or ""
        if result.stdout and stdout_payload != result.stdout:
            stderr_payload = (stderr_payload + ("\n" if stderr_payload else "") + result.stdout)
        stderr_payload = stderr_payload.strip()
        returncode = result.returncode
    else:
        result = run_command(cmd)
        if result is None:
            message = f"Scan timed out after {SCAN_TIMEOUT} seconds."
            if update_status:
                write_finished_status(1, message)
            print(message)
            return 1
        stdout_payload = result.stdout or ""
        stderr_payload = result.stderr or ""
        returncode = result.returncode

    try:
        root, hosts = parse_nmap_xml(stdout_payload)
    except ET.ParseError:
        message = "Unable to parse scan results."
        if update_status:
            write_finished_status(1, message)
        print(message)
        return 1

    data = {
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "command": root.get("args", ""),
        "profile": args.profile,
        "targets": targets,
        "hosts": hosts,
        "stderr": stderr_payload.strip(),
        "warnings": warnings or [],
    }

    write_results(data)

    message = f"Scan completed: {len(hosts)} hosts"
    exit_code = returncode
    if update_status:
        status_message = message if exit_code == 0 else "Scan finished with errors."
        write_finished_status(exit_code, status_message)
    print(message)
    return 0 if exit_code == 0 else 1


def main():
    parser = argparse.ArgumentParser(description="Run an Nmap scan")
    parser.add_argument("--background", action="store_true", help="Run scans in background")
    parser.add_argument("--cancel", type=int, help="Cancel scan by PID")
    parser.add_argument("--worker", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("mode", nargs="?", choices=["simple", "hosts", "custom"])
    parser.add_argument("targets", nargs="?")
    parser.add_argument("profile", nargs="?")
    parser.add_argument("open_only", nargs="?", choices=["0", "1"])
    parser.add_argument("no_dns", nargs="?", choices=["0", "1"])
    parser.add_argument("skip_discovery", nargs="?", choices=["0", "1"])
    parser.add_argument("ipv6", nargs="?", choices=["0", "1"])
    parser.add_argument("custom_b64", nargs="?")

    args = parser.parse_args()

    if args.cancel is not None:
        return cancel_scan(args.cancel)

    if not args.mode or not args.targets or not args.profile:
        print("Missing scan parameters.")
        return 1
    if args.open_only is None or args.no_dns is None or args.skip_discovery is None or args.ipv6 is None:
        print("Missing scan parameters.")
        return 1
    if args.custom_b64 is None:
        print("Missing scan parameters.")
        return 1

    custom_args, error = decode_custom_args(args.custom_b64)
    if error is not None:
        print(error)
        return 1

    if args.mode == "custom":
        if not args.targets:
            print("Target is required.")
            return 1
        targets = [args.targets]
        warnings = []
        if args.background and not args.worker:
            return start_background_scan(args, targets, warnings)
        cmd = ["/usr/local/bin/nmap"]
        cmd.extend(custom_args)
        cmd.append(args.targets)
        return run_text_scan(cmd, args, targets, warnings, update_status=args.worker)

    targets, warnings, error = validate_targets_list(args.targets)
    if error is not None:
        print(error)
        return 1
    if warnings:
        for warning in warnings:
            print(warning)

    cmd = ["/usr/local/bin/nmap"]
    if custom_args:
        cmd.extend(custom_args)
    elif args.profile in PROFILE_OPTIONS:
        cmd.extend(PROFILE_OPTIONS[args.profile])
    elif not args.profile:
        print("Invalid scan profile.")
        return 1

    if args.skip_discovery == "1" and "-Pn" not in cmd and "-sn" not in cmd:
        cmd.append("-Pn")
    if args.open_only == "1" and "--open" not in cmd:
        cmd.append("--open")
    if args.no_dns == "1" and "-n" not in cmd:
        cmd.append("-n")
    if args.ipv6 == "1" and "-6" not in cmd:
        cmd.append("-6")

    if args.mode == "simple":
        cmd.extend(targets)
        if args.background and not args.worker:
            return start_background_scan(args, targets, warnings)
        return run_text_scan(cmd, args, targets, warnings, update_status=args.worker)

    if args.background and not args.worker:
        return start_background_scan(args, targets, warnings)

    cmd.extend(["-oX", "-"])
    cmd.extend(targets)
    return run_hosts_scan(cmd, args, targets, warnings, update_status=args.worker)


if __name__ == "__main__":
    sys.exit(main())
