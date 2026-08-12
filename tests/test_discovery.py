import socket
import unittest
from unittest.mock import patch

import dns.resolver

from serket.discovery import (
    DomainControllerDiscoveryError,
    discover_domain_controller,
)


class FakeSrvRecord:
    def __init__(self, target, priority=0, weight=0):
        self.target = target
        self.priority = priority
        self.weight = weight


class FakeResolver:
    def __init__(self, answers):
        self.answers = list(answers)
        self.queries = []

    def resolve(self, query, record_type, lifetime):
        self.queries.append((query, record_type, lifetime))
        answer = self.answers.pop(0)
        if isinstance(answer, Exception):
            raise answer
        return answer


class DiscoveryTests(unittest.TestCase):
    def test_discovers_dc_from_ad_srv_record(self):
        resolver = FakeResolver(
            [[
                FakeSrvRecord("dc02.corp.local.", priority=10, weight=100),
                FakeSrvRecord("dc01.corp.local.", priority=0, weight=50),
            ]]
        )

        dc = discover_domain_controller("corp.local", resolver=resolver)

        self.assertEqual(dc, "dc01.corp.local")
        self.assertEqual(
            resolver.queries[0][0],
            "_ldap._tcp.dc._msdcs.corp.local",
        )

    @patch("serket.discovery.socket.getaddrinfo", return_value=[object()])
    def test_falls_back_to_domain_address(self, getaddrinfo):
        resolver = FakeResolver([dns.resolver.NXDOMAIN(), dns.resolver.NoAnswer()])

        dc = discover_domain_controller("corp.local.", resolver=resolver)

        self.assertEqual(dc, "corp.local")
        getaddrinfo.assert_called_once_with(
            "corp.local",
            None,
            type=socket.SOCK_STREAM,
        )

    @patch("serket.discovery.socket.getaddrinfo", side_effect=socket.gaierror())
    def test_reports_actionable_error_when_discovery_fails(self, _getaddrinfo):
        resolver = FakeResolver([dns.resolver.NXDOMAIN(), dns.resolver.NoAnswer()])

        with self.assertRaisesRegex(DomainControllerDiscoveryError, "-dc HOST"):
            discover_domain_controller("corp.local", resolver=resolver)


if __name__ == "__main__":
    unittest.main()
