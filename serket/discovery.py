"""Active Directory service discovery helpers."""

from __future__ import annotations

import socket

import dns.exception
import dns.resolver


class DomainControllerDiscoveryError(RuntimeError):
    """Raised when DNS cannot locate a controller for an AD domain."""


def _target_name(record) -> str:
    return str(record.target).rstrip(".")


def discover_domain_controller(domain: str, resolver=None) -> str:
    """Return a DC hostname discovered through the domain's LDAP SRV records."""
    domain = domain.strip().strip(".")
    if not domain:
        raise DomainControllerDiscoveryError("The AD domain cannot be empty.")

    resolver = resolver or dns.resolver.Resolver()
    queries = (
        f"_ldap._tcp.dc._msdcs.{domain}",
        f"_ldap._tcp.{domain}",
    )

    for query in queries:
        try:
            records = list(resolver.resolve(query, "SRV", lifetime=5.0))
        except (dns.exception.DNSException, OSError):
            continue

        if records:
            selected = min(
                records,
                key=lambda record: (
                    int(record.priority),
                    -int(record.weight),
                    _target_name(record).lower(),
                ),
            )
            return _target_name(selected)

    # AD DNS commonly maps the domain apex to one or more controllers. This is
    # a useful fallback for environments that omit or filter SRV responses.
    try:
        socket.getaddrinfo(domain, None, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise DomainControllerDiscoveryError(
            f"No domain controller was found for {domain}. "
            "Check AD DNS or provide one explicitly with -dc HOST."
        ) from exc

    return domain
