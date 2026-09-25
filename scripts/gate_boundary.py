#!/usr/bin/env python3
"""Fault-inject Docker worker egress paths on the actual host.

The result is usable by WorkerAdapter only when every positive service path
works and every prohibited path fails at the network boundary. An unavailable
service produces `blocked`, never a prevention pass.
"""
from __future__ import annotations

import argparse
import errno
import hashlib
import json
from pathlib import Path
import re
import socket
import subprocess
import sys
import time
from urllib.request import build_opener, ProxyHandler

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from deploy.repair.route_proof import route_proof
from deploy.openshell.policy_binding import expected_policy, effective_policy
from deploy.openshell.worker_network import validate as validate_worker_network
from deploy.openshell.worker_network import validate_attachment as validate_worker_attachment


PROBE = r'''
import errno,json,os,socket,urllib.error,urllib.request
targets=json.loads(os.environ['VIBESECUR_TARGETS'])
opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
results={}
for name,url in targets.items():
 try:
  with opener.open(urllib.request.Request(url,headers={'Metadata':'true'}),timeout=3) as response:
   results[name]={'reachable':True,'httpStatus':response.status}
 except urllib.error.HTTPError as exc:
  results[name]={'reachable':True,'httpStatus':exc.code}
 except Exception as exc:
  reason=getattr(exc,'reason',exc)
  results[name]={'reachable':False,'errorType':errno.errorcode.get(getattr(reason,'errno',None),type(reason).__name__),
                 'errorErrno':getattr(reason,'errno',None)}
results['routeTables']={name:open(path).read() for name,path in
                        [('ipv4','/proc/net/route'),('ipv6','/proc/net/ipv6_route')]}
results['docker_socket']={'reachable':os.path.exists('/var/run/docker.sock')}
print(json.dumps(results,separators=(',',':')))
'''

IMAGE_ID = re.compile(r"^sha256:[0-9a-f]{64}$")
OWNED_PUBLIC_HEALTH_URL = "https://vibesecur-demo-20260925.centralindia.cloudapp.azure.com/health"
OWNED_PUBLIC_IP_URL = "https://40.81.234.48/health"
OWNED_PUBLIC_HOST = "vibesecur-demo-20260925.centralindia.cloudapp.azure.com"
OWNED_PUBLIC_IP = "40.81.234.48"


def explicit_public_route_denial(result: dict, *, default_route_present: bool) -> bool:
    return (result.get("reachable") is False and result.get("errorErrno") == errno.ENETUNREACH
            and default_route_present is False)


def explicit_bridge_denial(result: dict) -> bool:
    return (result.get("reachable") is False and
            result.get("errorType") in ("ECONNREFUSED", "EHOSTUNREACH", "ENETUNREACH"))


def _check_host(url: str) -> dict:
    opener = build_opener(ProxyHandler({}))
    try:
        with opener.open(url, timeout=5) as response:
            return {"reachable": True, "httpStatus": response.status}
    except Exception as exc:
        # 401/403 are live service responses and should not be mistaken for
        # infrastructure failures.
        if hasattr(exc, "code"):
            return {"reachable": True, "httpStatus": exc.code}
        return {"reachable": False, "errorType": type(exc).__name__}


def _check_host_verifier(url: str) -> dict:
    """Prove the exact owned verifier route is live without exposing job state."""
    opener = build_opener(ProxyHandler({}))
    try:
        with opener.open(url, timeout=5) as response:
            body = json.loads(response.read(4096))
            return {"reachable": True, "httpStatus": response.status,
                    "identityMatched": (body.get("service") == "vibesecur-verifier"
                                        and body.get("configured") is True)}
    except Exception as exc:
        if hasattr(exc, "code"):
            return {"reachable": True, "httpStatus": exc.code, "identityMatched": False}
        return {"reachable": False, "errorType": type(exc).__name__,
                "identityMatched": False}


def _host_verifier_ready(check: dict) -> bool:
    return (check.get("reachable") is True and check.get("httpStatus") == 200
            and check.get("identityMatched") is True)


def gate(config: dict) -> dict:
    if config.get("runtime") == "openshell":
        return gate_openshell(config)
    required = ("image", "network", "paymentUrl", "modelUrl", "controllerUrl",
                "verifierUrl", "hostControllerHealthUrl", "hostVerifierHealthUrl")
    missing = [key for key in required if not config.get(key)]
    if missing:
        return {"passed": False, "status": "blocked", "reason": "missing_config", "missing": missing}
    image, network = config["image"], config["network"]
    image_digest = image.split("@", 1)[1] if "@sha256:" in image else image
    if not IMAGE_ID.fullmatch(image_digest):
        return {"passed": False, "status": "blocked", "reason": "unpinned_worker_image"}
    try:
        inspected = subprocess.run(["docker", "network", "inspect", network],
                                   capture_output=True, text=True, timeout=10, check=True)
        network_info = json.loads(inspected.stdout)[0]
    except (OSError, ValueError, subprocess.SubprocessError, IndexError) as exc:
        return {"passed": False, "status": "blocked", "reason": "network_inspection_failed",
                "detail": type(exc).__name__}
    if network_info.get("Internal") is not True:
        return {"passed": False, "status": "failed", "reason": "worker_network_has_external_egress"}
    ipam = (network_info.get("IPAM", {}).get("Config") or [{}])[0]
    gateway, subnet, network_id = ipam.get("Gateway"), ipam.get("Subnet"), network_info.get("Id", "")
    if not gateway or not subnet or not re.fullmatch(r"[0-9a-f]{64}", network_id):
        return {"passed": False, "status": "blocked", "reason": "network_identity_missing"}
    bridge_interface = "br-" + network_id[:12]
    firewall_rule = ["-i", bridge_interface, "-s", subnet, "-j", "REJECT"]
    firewall = subprocess.run(["sudo", "-n", "iptables", "-C", "INPUT", *firewall_rule],
                              capture_output=True, text=True, timeout=10)
    bridge_url = f"http://{gateway}:8000/health"
    host_checks = {
        "controller": _check_host(config["hostControllerHealthUrl"]),
        "verifier": _check_host(config["hostVerifierHealthUrl"]),
        "external": _check_host(OWNED_PUBLIC_HEALTH_URL),
        "bridgeBefore": _check_host(bridge_url),
    }
    if not all(item.get("reachable") and item.get("httpStatus") == 200 for item in host_checks.values()):
        return {"passed": False, "status": "blocked", "reason": "host_positive_path_unavailable",
                "hostChecks": host_checks, "externalProbeUrl": OWNED_PUBLIC_HEALTH_URL}
    try:
        if socket.gethostbyname(OWNED_PUBLIC_HOST) != OWNED_PUBLIC_IP:
            raise ValueError("Owned demo DNS changed")
    except (OSError, ValueError):
        return {"passed": False, "status": "blocked", "reason": "owned_public_ip_unverified"}
    targets = {
        "payment": config["paymentUrl"].rstrip("/") + "/health",
        "model": config["modelUrl"],
        "controller": config["controllerUrl"],
        "verifier": config["verifierUrl"],
        "host_gateway": f"http://{gateway}:8000/health",
        "external": OWNED_PUBLIC_IP_URL,
    }
    command = ["docker", "run", "--rm", "--network", network, "--read-only",
               "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
               "--pids-limit", "64", "--memory", "256m", "--cpus", "0.5",
               "--user", "65532:65532", "-e", "VIBESECUR_TARGETS=" + json.dumps(targets),
               image, "python", "-c", PROBE]
    try:
        run = subprocess.run(command, capture_output=True, text=True, timeout=90, check=False)
        probes = json.loads(run.stdout.strip().splitlines()[-1]) if run.returncode == 0 else None
    except (OSError, ValueError, subprocess.SubprocessError, IndexError) as exc:
        return {"passed": False, "status": "blocked", "reason": "probe_execution_failed",
                "detail": type(exc).__name__}
    if probes is None:
        return {"passed": False, "status": "blocked", "reason": "probe_execution_failed",
                "stderrTail": run.stderr[-500:]}
    host_checks["bridgeAfter"] = _check_host(bridge_url)
    route = route_proof(probes["routeTables"]["ipv4"], probes["routeTables"]["ipv6"], subnet)
    bridge_healthy = (host_checks["bridgeBefore"].get("httpStatus") == 200 and
                      host_checks["bridgeAfter"].get("httpStatus") == 200)
    coverage = {"applicationReachable": probes["payment"].get("httpStatus") == 200,
                "modelRelayReachable": probes["model"].get("reachable") is True,
                "controllerDenied": explicit_bridge_denial(probes["controller"]) and
                                    host_checks["controller"].get("httpStatus") == 200,
                "verifierDenied": explicit_bridge_denial(probes["verifier"]) and
                                  host_checks["verifier"].get("httpStatus") == 200,
                "hostGatewayDenied": bridge_healthy and firewall.returncode == 0 and
                                     explicit_bridge_denial(probes["host_gateway"]),
                "metadataDenied": None, "azurePlatformDenied": None,
                "providerRouteDenied": route["providerRouteDenied"],
                "externalDenied": explicit_public_route_denial(probes["external"],
                    default_route_present=not route["noDefaultRoute"]),
                "dockerSocketDenied": probes["docker_socket"]["reachable"] is False}
    positive = coverage["applicationReachable"] and coverage["modelRelayReachable"]
    negative = all(value is True for key, value in coverage.items()
                   if key not in ("metadataDenied", "azurePlatformDenied",
                                  "applicationReachable", "modelRelayReachable"))
    status = "passed" if positive and negative else ("blocked" if not positive else "failed")
    return {"passed": status == "passed", "status": status, "runtime": "docker",
            "profile": "owned-demo-v1", "routeProof": route,
            "checkedAt": time.time(), "network": network,
            "bridgeSubnet": route["expectedSubnet"],
            "networkId": network_id, "bridgeInterface": bridge_interface,
            "firewallRule": {"chain": "INPUT", "argv": firewall_rule},
            "firewallRulePresent": firewall.returncode == 0,
            "imageDigest": image_digest, "hostChecks": host_checks,
            "probes": probes, "externalProbeUrl": OWNED_PUBLIC_IP_URL,
            "coverage": coverage,
            "unmeasuredControls": ["metadataDenied", "azurePlatformDenied"],
            "limitations": ["Provider endpoints were not contacted; only static route isolation was measured.",
                            "Hardened Docker internal network is not OpenShell L7 enforcement."]}


def gate_openshell(config: dict) -> dict:
    """Measure one running OpenShell sandbox with exact per-run payment policy."""
    required = ("image", "network", "paymentHost", "otherPaymentHost", "sandbox",
                "policyTemplatePath")
    missing = [key for key in required if not config.get(key)]
    if missing:
        return {"passed": False, "status": "blocked", "reason": "missing_config", "missing": missing}
    image = config["image"]
    image_digest = image.split("@", 1)[1] if "@sha256:" in image else image
    if not IMAGE_ID.fullmatch(image_digest):
        return {"passed": False, "status": "blocked", "reason": "unpinned_worker_image"}
    if not all(re.fullmatch(r"payment-[A-Za-z0-9-]{1,80}", config[key])
               for key in ("paymentHost", "otherPaymentHost")):
        return {"passed": False, "status": "blocked", "reason": "invalid_payment_host"}
    cli = config.get("cli", "/home/demo/.local/bin/openshell")
    sandbox = config["sandbox"]
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]{0,79}", sandbox):
        return {"passed": False, "status": "blocked", "reason": "invalid_sandbox_name"}
    public_target_check = _check_host(OWNED_PUBLIC_HEALTH_URL)
    if not (public_target_check.get("reachable") and public_target_check.get("httpStatus") == 200):
        return {"passed": False, "status": "blocked", "reason": "owned_public_target_unavailable",
                "externalProbeUrl": OWNED_PUBLIC_HEALTH_URL,
                "hostChecks": {"external": public_target_check}}
    try:
        if socket.gethostbyname(OWNED_PUBLIC_HOST) != OWNED_PUBLIC_IP:
            raise ValueError("Owned demo DNS changed")
    except (OSError, ValueError):
        return {"passed": False, "status": "blocked", "reason": "owned_public_ip_unverified"}

    def run(*command, input_text=None, timeout=20):
        return subprocess.run(command, input=input_text, capture_output=True, text=True,
                              timeout=timeout, check=False)

    def probe(name, url, *, method="GET", body=None):
        args = [cli, "sandbox", "exec", "--name", sandbox, "--", "curl", "--max-time", "8",
                "--silent", "--show-error", "--request", method]
        if body is not None:
            args += ["--header", "Content-Type: application/json", "--data", body]
        args += ["--write-out", "\nVIBESECUR_HTTP_STATUS:%{http_code}", url]
        p = run(*args)
        marker = "\nVIBESECUR_HTTP_STATUS:"
        content, _, status = p.stdout.rpartition(marker)
        return {"httpStatus": int(status) if status.isdigit() else None,
                "exitCode": p.returncode, "body": content[:300], "stderr": p.stderr[-200:]}

    try:
        template = Path(config["policyTemplatePath"]).read_bytes()
        approved_policy, policy_binding = expected_policy(config["policyTemplatePath"],
                                                           config["paymentHost"])
        policy = run(cli, "policy", "get", sandbox, "--full", "--output", "json")
        sandboxes = run(cli, "sandbox", "list", "--output", "json")
        matching = [item for item in json.loads(sandboxes.stdout)
                    if item.get("name") == sandbox and item.get("phase") == "Ready"]
        if policy.returncode or not matching:
            raise RuntimeError("OpenShell sandbox or effective policy unavailable")
        sandbox_id = matching[0]["id"]
        container = "openshell-default--" + sandbox + "-" + sandbox_id
        info = json.loads(run("docker", "inspect", container).stdout)[0]
        network_info = json.loads(run("docker", "network", "inspect", config["network"]).stdout)[0]
        validate_worker_network(network_info)
        validate_worker_attachment(info, network_info["Id"])
        expected_subnet = network_info["IPAM"]["Config"][0]["Subnet"]
        gateway = network_info["IPAM"]["Config"][0]["Gateway"]
        host_gateway_check = _check_host(f"http://{gateway}:8000/health")
        if not (host_gateway_check.get("reachable")
                and host_gateway_check.get("httpStatus") == 200):
            raise ValueError("Owned controller unavailable on worker bridge gateway")
        host_verifier_check = _check_host_verifier(
            f"http://{gateway}:8000/internal/verifier/health")
        if not _host_verifier_ready(host_verifier_check):
            return {"passed": False, "status": "blocked",
                    "reason": "owned_verifier_route_unavailable",
                    "hostChecks": {"external": public_target_check,
                                   "hostGateway": host_gateway_check,
                                   "verifier": host_verifier_check}}
        try:
            policy_effective_hash = effective_policy(policy.stdout, approved_policy, sandbox)
            policy_enforced = True
        except (ValueError, TypeError):
            policy_effective_hash = None
            policy_enforced = False
        logs = run("docker", "logs", container).stderr
        route_capture = run(cli, "sandbox", "exec", "--name", sandbox, "--", "python", "-c",
                            "import json;print(json.dumps({k:open(p).read() for k,p in "
                            "[('ipv4','/proc/net/route'),('ipv6','/proc/net/ipv6_route')]}))")
        if route_capture.returncode:
            raise RuntimeError("Sandbox route table unavailable")
        tables = json.loads(route_capture.stdout)
        route = route_proof(tables["ipv4"], tables["ipv6"], expected_subnet)
        payment = "http://" + config["paymentHost"] + ":8000"
        probes = {
            "applicationPortal": probe("applicationPortal", payment + "/portal"),
            "applicationContext": probe("applicationContext", payment + "/api/context"),
            "applicationPost": probe("applicationPost", payment + "/api/payments", method="POST", body="{}"),
            "modelRelay": probe("modelRelay", "http://host.openshell.internal:8000/model/v1/chat/completions",
                                method="POST", body="{}"),
            "modelResponses": probe("modelResponses", "http://host.openshell.internal:8000/model/v1/responses",
                                    method="POST", body="{}"),
            "controller": probe("controller", "http://host.openshell.internal:8000/health"),
            "verifier": probe("verifier", "http://host.openshell.internal:8000/internal/verifier/health"),
            "hostGateway": probe("hostGateway", f"http://{gateway}:8000/health"),
            "otherPayment": probe("otherPayment", "http://" + config["otherPaymentHost"] + ":8000/portal"),
            "external": probe("external", OWNED_PUBLIC_HEALTH_URL),
        }
        fs = run(cli, "sandbox", "exec", "--name", sandbox, "--", "sh", "-c",
                 "test ! -e /var/run/docker.sock && echo socket=absent; "
                 "echo probe > /workspace/probe && echo workspace=writeable; "
                 "test ! -w /etc/passwd && echo etc=denied")
    except (OSError, ValueError, KeyError, IndexError, subprocess.SubprocessError, RuntimeError) as exc:
        return {"passed": False, "status": "blocked", "reason": "openshell_gate_execution_failed",
                "detail": type(exc).__name__}

    denied = lambda item: item["httpStatus"] == 403 and "policy_denied" in item["body"]
    coverage = {
        "applicationReachable": probes["applicationPortal"]["httpStatus"] == 200
                               and probes["applicationContext"]["httpStatus"] == 200
                               and "invoice_approval_missing" in probes["applicationPost"]["body"],
        "modelRelayReachable": ("Invalid model capability" in probes["modelRelay"]["body"]
                                and "Invalid model capability" in probes["modelResponses"]["body"]),
        "controllerDenied": denied(probes["controller"]),
        "verifierDenied": host_verifier_check["identityMatched"] and denied(probes["verifier"]),
        "hostGatewayDenied": host_gateway_check.get("httpStatus") == 200 and
                             denied(probes["hostGateway"]),
        "otherPaymentDenied": denied(probes["otherPayment"]),
        "metadataDenied": None,
        "azurePlatformDenied": None,
        "providerRouteDenied": route["providerRouteDenied"] and network_info.get("Internal") is True,
        "externalDenied": denied(probes["external"]) or
                          (probes["external"]["httpStatus"] in (None, 0) and
                           "CONNECT tunnel failed, response 403" in probes["external"]["stderr"]),
        "dockerSocketDenied": "socket=absent" in fs.stdout,
        "workspaceWritableEtcDenied": "workspace=writeable" in fs.stdout and "etc=denied" in fs.stdout,
        "policyEnforced": policy_enforced,
        "landlockEnforced": "Landlock ruleset built" in logs and "Applying Landlock" in logs,
        "imagePinned": info.get("Image") == image_digest,
        "networkMatched": True,  # Exact endpoint NetworkID was checked above.
        "notPrivileged": info.get("HostConfig", {}).get("Privileged") is False,
    }
    measured_controls = (value for key, value in coverage.items()
                         if key not in ("metadataDenied", "azurePlatformDenied"))
    passed = all(measured_controls)
    return {"passed": passed, "status": "passed" if passed else "failed",
            "runtime": "openshell", "profile": "owned-demo-v1",
            "checkedAt": time.time(), "network": config["network"],
            "networkId": network_info["Id"], "bridgeGateway": gateway,
            "bridgeSubnet": expected_subnet,
            "imageDigest": image_digest, "sandbox": sandbox, "sandboxId": sandbox_id,
            "paymentHost": config["paymentHost"], "otherPaymentHost": config["otherPaymentHost"],
            "externalProbeUrl": OWNED_PUBLIC_HEALTH_URL,
            "hostChecks": {"external": public_target_check,
                           "hostGateway": host_gateway_check,
                           "verifier": host_verifier_check},
            "routeProof": route,
            **policy_binding, "policyEffectiveHash": policy_effective_hash,
            "probes": probes, "filesystemProbe": fs.stdout.strip(), "coverage": coverage,
            "unmeasuredControls": ["metadataDenied", "azurePlatformDenied"],
            "filesystemLimitations": ["/tmp, /dev/null and /dev/pts are writable for SDK operation",
                                      "The negative write probe measured /etc/passwd only",
                                      "Provider endpoints were not contacted; only static route isolation was measured."]}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    result = gate(json.loads(Path(args.config).read_text(encoding="utf-8")))
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"status": result["status"], "passed": result["passed"],
                      "output": str(output)}))
    return 0 if result["passed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
