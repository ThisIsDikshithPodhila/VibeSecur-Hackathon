#!/usr/bin/env python3
"""Provision the exact internal bridge required by OpenShell Docker compute.

Run on the trusted host before starting the gateway. A conflicting or changed
network fails closed. This script never attaches a worker or payment container.
"""

from __future__ import annotations

import ipaddress
import json
import re
import subprocess
import sys

from deploy.repair.route_proof import route_proof


NAME = "vibesecur-worker-internal"
SUBNET = "172.30.0.0/24"
GATEWAY = "172.30.0.1"
SUPERVISOR_SUBNET = "10.200.0.0/24"
SUPERVISOR_GATEWAY = "10.200.0.1"


def _docker(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["docker", *args], capture_output=True, text=True,
                          timeout=20, check=False)


def validate(network: dict) -> None:
    ipam = network.get("IPAM", {}).get("Config") or []
    if (network.get("Name") != NAME or network.get("Driver") != "bridge"
            or network.get("Internal") is not True
            or network.get("Attachable") is not True
            or network.get("EnableIPv6") is not False
            or len(ipam) != 1
            or ipam[0].get("Subnet") != SUBNET
            or ipam[0].get("Gateway") != GATEWAY
            or not isinstance(network.get("Id"), str)
            or not re.fullmatch(r"[0-9a-f]{64}", network["Id"])):
        raise ValueError("OpenShell worker network identity mismatch")


def validate_attachment(container: dict, network_id: str) -> None:
    """Pin a sandbox's actual Docker endpoint to the gated bridge instance."""
    networks = container.get("NetworkSettings", {}).get("Networks") or {}
    endpoint = networks.get(NAME) or {}
    if (container.get("HostConfig", {}).get("NetworkMode") != NAME
            or set(networks) != {NAME}
            or endpoint.get("NetworkID") != network_id):
        raise ValueError("OpenShell sandbox attached to a different network")


def nested_route_proof(ipv4_text: str, ipv6_text: str) -> dict:
    """Attest the pinned OpenShell proxy veth, without claiming no default.

    The nested default reaches only the supervisor. The host Docker bridge
    rule and direct owned-endpoint probe establish outer forwarding denial.
    """
    route = route_proof(ipv4_text, ipv6_text, SUPERVISOR_SUBNET)
    rows = route.get("ipv4Routes") or []
    defaults = [row for row in rows if row.get("destination") == "0.0.0.0/0"]
    connected = [row for row in rows if row.get("destination") == SUPERVISOR_SUBNET]
    interface = defaults[0].get("interface") if len(defaults) == 1 else None
    nested = ("parseError" not in route and len(rows) == 2
              and len(defaults) == len(connected) == 1
              and isinstance(interface, str) and interface.startswith("veth-s-")
              and connected[0].get("interface") == interface
              and defaults[0].get("gateway") == SUPERVISOR_GATEWAY
              and connected[0].get("gateway") == "0.0.0.0"
              and all((row.get("disposition") == "reject" or
                       (row.get("gateway") == "::" and
                        (ipaddress.IPv6Network(row["destination"]).subnet_of(
                            ipaddress.IPv6Network("fe80::/10")) or
                         ipaddress.IPv6Network(row["destination"]).subnet_of(
                            ipaddress.IPv6Network("ff00::/8")) or
                         row.get("destination") == "::1/128")))
                      for row in route.get("ipv6Routes", [])))
    route["nestedDefaultViaSupervisor"] = nested
    route["supervisorInterface"] = interface
    route["providerRouteDenied"] = None
    return route


def effective_forwarding_denial(chains: dict[str, str], bridge: str) -> bool:
    """Require Docker's actual rule order to drop worker bridge egress.

    The only earlier FORWARD jump may be Docker's conntrack chain, whose
    established-return rules must match output to a bridge, never input from
    this worker bridge. DOCKER-USER must be empty.
    """
    if not re.fullmatch(r"br-[0-9a-f]{12}", bridge):
        return False
    required = {"FORWARD", "DOCKER-USER", "DOCKER-FORWARD", "DOCKER-CT", "DOCKER-INTERNAL"}
    if set(chains) != required:
        return False
    lines = {name: [line.strip() for line in chains[name].splitlines() if line.strip()]
             for name in required}
    if ("-P FORWARD DROP" not in lines["FORWARD"]
            or [line for line in lines["FORWARD"] if line.startswith("-A ")][:2] !=
            ["-A FORWARD -j DOCKER-USER", "-A FORWARD -j DOCKER-FORWARD"]
            or any(line.startswith("-A ") for line in lines["DOCKER-USER"])):
        return False
    forward = [line for line in lines["DOCKER-FORWARD"] if line.startswith("-A ")]
    if forward[:2] != ["-A DOCKER-FORWARD -j DOCKER-CT",
                       "-A DOCKER-FORWARD -j DOCKER-INTERNAL"]:
        return False
    ct = [line for line in lines["DOCKER-CT"] if line.startswith("-A ")]
    if any((" -j ACCEPT" not in line or "--ctstate RELATED,ESTABLISHED" not in line
            or " -i " in line or " -o " not in line) for line in ct):
        return False
    internal = [line for line in lines["DOCKER-INTERNAL"] if line.startswith("-A ")]
    outbound = ("-A DOCKER-INTERNAL ! -d " + SUBNET + " -i " + bridge + " -j DROP")
    if outbound not in internal:
        return False
    before = internal[:internal.index(outbound)]
    if any(not line.endswith(" -j DROP") for line in before):
        return False
    return True


def main() -> int:
    listed = _docker("network", "ls", "-q", "--filter", f"name=^{NAME}$")
    if listed.returncode:
        raise RuntimeError("Docker worker network lookup failed")
    if not listed.stdout.strip():
        all_networks = _docker("network", "ls", "-q")
        if all_networks.returncode:
            raise RuntimeError("Docker network inventory unavailable")
        names = all_networks.stdout.split()
        if names:
            inspected = _docker("network", "inspect", *names)
            if inspected.returncode:
                raise RuntimeError("Docker network inventory inspect failed")
            target = ipaddress.ip_network(SUBNET)
            for network in json.loads(inspected.stdout):
                for config in network.get("IPAM", {}).get("Config") or []:
                    subnet = config.get("Subnet")
                    if subnet and target.overlaps(ipaddress.ip_network(subnet)):
                        raise ValueError("Proposed worker subnet overlaps existing Docker network")
        created = _docker("network", "create", "--driver", "bridge", "--internal",
                          "--attachable", "--subnet", SUBNET, "--gateway", GATEWAY,
                          "--label", "vibesecur.role=worker-boundary", NAME)
        if created.returncode:
            raise RuntimeError("Internal worker network creation failed")
    existing = _docker("network", "inspect", NAME)
    if existing.returncode:
        raise RuntimeError("Internal worker network inspection failed")
    network = json.loads(existing.stdout)[0]
    validate(network)
    print(json.dumps({"network": NAME, "networkId": network["Id"],
                      "internal": True, "subnet": SUBNET, "gateway": GATEWAY}))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as exc:
        print(f"blocked: {type(exc).__name__}: {exc}", file=sys.stderr)
        raise SystemExit(2) from None
