"""Parse sandbox kernel route tables without contacting provider endpoints."""
from __future__ import annotations

import ipaddress


def route_proof(ipv4_text: str, ipv6_text: str, expected_subnet: str) -> dict:
    result = {'method': 'proc_net_route', 'expectedSubnet': expected_subnet,
              'ipv4Routes': [], 'ipv6Routes': [], 'noDefaultRoute': False,
              'onlyExpectedInternalRoutes': False, 'providerRouteDenied': False}
    try:
        expected = ipaddress.IPv4Network(expected_subnet, strict=True)
        ipv4_networks = []
        for line in ipv4_text.splitlines()[1:]:
            fields = line.split()
            if not fields:
                continue
            if len(fields) < 8:
                raise ValueError('Incomplete IPv4 route')
            address = ipaddress.IPv4Address(int.from_bytes(bytes.fromhex(fields[1]), 'little'))
            gateway = ipaddress.IPv4Address(int.from_bytes(bytes.fromhex(fields[2]), 'little'))
            mask = ipaddress.IPv4Address(int.from_bytes(bytes.fromhex(fields[7]), 'little'))
            network = ipaddress.IPv4Network(f'{address}/{mask}', strict=False)
            result['ipv4Routes'].append({'destination': str(network),
                                         'gateway': str(gateway), 'interface': fields[0]})
            ipv4_networks.append((network, gateway))
        ipv6_networks = []
        for line in ipv6_text.splitlines():
            fields = line.split()
            if not fields:
                continue
            if len(fields) < 10:
                raise ValueError('Incomplete IPv6 route')
            address = ipaddress.IPv6Address(int(fields[0], 16))
            prefix = int(fields[1], 16)
            source_address = ipaddress.IPv6Address(int(fields[2], 16))
            source_prefix = int(fields[3], 16)
            if not 0 <= source_prefix <= 128:
                raise ValueError('Invalid IPv6 source prefix')
            gateway = ipaddress.IPv6Address(int(fields[4], 16))
            metric = int(fields[5], 16)
            flags = int(fields[8], 16)
            interface = fields[-1]
            network = ipaddress.IPv6Network((address, prefix), strict=False)
            # Linux records its IPv6 null route as ::/0 on lo. Its exact
            # REJECT|NONEXTHOP flags and maximum metric make it a denial,
            # not a forwarding default. Keep any other ::/0 fail closed.
            rejected_default = (network.prefixlen == 0 and
                                address == ipaddress.IPv6Address('::') and
                                source_address == ipaddress.IPv6Address('::') and
                                source_prefix == 0 and interface == 'lo' and
                                gateway == ipaddress.IPv6Address('::') and
                                metric == 0xffffffff and flags == 0x00200200)
            result['ipv6Routes'].append({'destination': str(network),
                                         'gateway': str(gateway), 'interface': interface,
                                         'flags': f'0x{flags:08x}', 'metric': metric,
                                         'disposition': ('reject' if rejected_default else
                                                         'local' if network.prefixlen else
                                                         'forwarding_default')})
            ipv6_networks.append((network, gateway, rejected_default))
        # noDefaultRoute means no forwarding default. Rejected ::/0 rows stay
        # visible in ipv6Routes with their exact flags and disposition.
        no_default = (all(network.prefixlen != 0 for network, _ in ipv4_networks) and
                      all(network.prefixlen != 0 or rejected
                          for network, _, rejected in ipv6_networks))
        local_ipv4 = ipaddress.IPv4Network('127.0.0.0/8')
        local_ipv6 = (ipaddress.IPv6Network('::1/128'), ipaddress.IPv6Network('fe80::/10'))
        only_internal = (any(network == expected and gateway == ipaddress.IPv4Address('0.0.0.0')
                             for network, gateway in ipv4_networks) and
                         all((network.subnet_of(expected) or network.subnet_of(local_ipv4)) and
                             gateway == ipaddress.IPv4Address('0.0.0.0')
                             for network, gateway in ipv4_networks) and
                         all(rejected or
                             (any(network.subnet_of(allowed) for allowed in local_ipv6) and
                              gateway == ipaddress.IPv6Address('::'))
                             for network, gateway, rejected in ipv6_networks))
        # Static route inspection only: these addresses are never requested.
        provider_addresses = (ipaddress.IPv4Address('169.254.169.254'),
                              ipaddress.IPv4Address('168.63.129.16'))
        provider_route = any(address in network for network, _ in ipv4_networks
                             for address in provider_addresses)
        result.update(noDefaultRoute=no_default,
                      onlyExpectedInternalRoutes=only_internal,
                      providerRouteDenied=no_default and only_internal and not provider_route)
    except (ValueError, IndexError, ipaddress.AddressValueError, ipaddress.NetmaskValueError):
        result['parseError'] = 'invalid_route_table'
    return result
