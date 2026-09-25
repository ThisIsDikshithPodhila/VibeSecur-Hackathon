#!/bin/sh
set -eu

ensure_network() {
    name="$1"
    expected_id="$2"
    expected_subnet="$3"
    expected_gateway="$4"
    network_id="$(docker network inspect "$name" --format '{{.Id}}')"
    internal="$(docker network inspect "$name" --format '{{.Internal}}')"
    subnet="$(docker network inspect "$name" --format '{{range .IPAM.Config}}{{.Subnet}}{{end}}')"
    gateway="$(docker network inspect "$name" --format '{{range .IPAM.Config}}{{.Gateway}}{{end}}')"

    test "$network_id" = "$expected_id"
    test "$internal" = 'true'
    test "$subnet" = "$expected_subnet"
    test "$gateway" = "$expected_gateway"

    interface="br-$(printf '%s' "$network_id" | cut -c1-12)"
    if ! /usr/sbin/iptables -C INPUT -i "$interface" -s "$subnet" -j REJECT; then
        /usr/sbin/iptables -I INPUT 1 -i "$interface" -s "$subnet" -j REJECT
    fi
}

ensure_network vs-repair-internal \
    f92eadd8c46febaeff9b939bdb98c695c749a0bf05035f5dd0e3466587fa10bf \
    172.28.0.0/24 172.28.0.1
ensure_network vs-verify-internal \
    0d88e0a4cda48d25135dc67f0bdfe9e992f6d91e3168f517efdd5e27555e8e3d \
    172.29.0.0/24 172.29.0.1
