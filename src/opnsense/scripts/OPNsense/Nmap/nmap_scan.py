#!/usr/local/bin/python3


import argparse
import base64
import datetime
import ipaddress
import json
import os
import shlex
import subprocess
import sys
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
SCAN_TIMEOUT = 3600
RESULTS_PATH = "/var/db/nmap/scan_results.json"
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


def main():
    parser = argparse.ArgumentParser(description="Run an Nmap scan")
    parser.add_argument("mode", choices=["simple", "hosts", "custom"])
    parser.add_argument("targets")
    parser.add_argument("profile")
    parser.add_argument("open_only", choices=["0", "1"])
    parser.add_argument("no_dns", choices=["0", "1"])
    parser.add_argument("skip_discovery", choices=["0", "1"])
    parser.add_argument("ipv6", choices=["0", "1"])
    parser.add_argument("custom_b64")

    args = parser.parse_args()

    custom_args, error = decode_custom_args(args.custom_b64)
    if error is not None:
        print(error)
        return 1

    if args.mode == "custom":
        if not args.targets:
            print("Target is required.")
            return 1
        cmd = ["/usr/local/bin/nmap"]
        cmd.extend(custom_args)
        cmd.append(args.targets)
        result = run_command(cmd)
        print(collect_output(result))
        return 0 if result is not None and result.returncode == 0 else 1

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
        result = run_command(cmd)
        print(collect_output(result))
        return 0 if result is not None and result.returncode == 0 else 1

    cmd.extend(["-oX", "-"])
    cmd.extend(targets)
    result = run_command(cmd)
    if result is None:
        print(f"Scan timed out after {SCAN_TIMEOUT} seconds.")
        return 1

    try:
        root, hosts = parse_nmap_xml(result.stdout or "")
    except ET.ParseError:
        print("Unable to parse scan results.")
        return 1

    data = {
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "command": root.get("args", ""),
        "profile": args.profile,
        "targets": targets,
        "hosts": hosts,
        "stderr": result.stderr.strip() if result.stderr else "",
        "warnings": warnings or [],
    }

    write_results(data)

    print(f"Scan completed: {len(hosts)} hosts")
    return 0 if result.returncode == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
