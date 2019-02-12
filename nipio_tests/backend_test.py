# Copyright 2019 Exentrique Solutions Ltd
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import collections
import os
import sys
import unittest

from assertpy import assert_that
from mock.mock import patch, call

from nipio.backend import DynamicBackend


class DynamicBackendTest(unittest.TestCase):
    def setUp(self):
        self.mock_sys_patcher = patch("nipio.backend.sys")
        self.mock_sys = self.mock_sys_patcher.start()

        self.mock_sys.stderr.write = sys.stderr.write

        import nipio
        nipio.backend._is_debug = lambda: True

    def tearDown(self):
        sys.stderr.flush()

        self.mock_sys_patcher.stop()

    def test_backend_ends_response_to_ANY_request_if_ip_is_blacklisted(self):
        self._send_commands(["Q", "subdomain.127.0.0.2.lcl.io", "IN", "ANY", "1", "127.0.0.1"])

        self._run_backend()

        self._assert_expected_responses(["LOG", "Blacklisted: 127.0.0.2"])

    def test_backend_ends_response_to_A_request_if_ip_is_blacklisted(self):
        self._send_commands(["Q", "subdomain.127.0.0.2.lcl.io", "IN", "A", "1", "127.0.0.1"])

        self._run_backend()

        self._assert_expected_responses(
            ["LOG", "Blacklisted: 127.0.0.2"]
        )

    def test_backend_responds_to_ANY_request_with_valid_ip(self):
        self._send_commands(["Q", "subdomain.127.0.0.1.lcl.io", "IN", "ANY", "1", "127.0.0.1"])

        self._run_backend()

        self._assert_expected_responses(
            ["DATA", "subdomain.127.0.0.1.lcl.io", "IN", "A", "200", "22", "127.0.0.1"],
            ["DATA", "subdomain.127.0.0.1.lcl.io", "IN", "NS", "200", "22", "ns1.lcl.io"],
            ["DATA", "subdomain.127.0.0.1.lcl.io", "IN", "NS", "200", "22", "ns2.lcl.io"],
        )

    def test_backend_responds_to_A_request_with_valid_ip(self):
        self._send_commands(["Q", "subdomain.127.0.0.1.lcl.io", "IN", "A", "1", "127.0.0.1"])

        self._run_backend()

        self._assert_expected_responses(
            ["DATA", "subdomain.127.0.0.1.lcl.io", "IN", "A", "200", "22", "127.0.0.1"],
            ["DATA", "subdomain.127.0.0.1.lcl.io", "IN", "NS", "200", "22", "ns1.lcl.io"],
            ["DATA", "subdomain.127.0.0.1.lcl.io", "IN", "NS", "200", "22", "ns2.lcl.io"],
        )

    def test_backend_responds_to_ANY_request_with_valid_ip_separated_by_dashes(self):
        self._send_commands(["Q", "subdomain-127-0-0-1.lcl.io", "IN", "ANY", "1", "127.0.0.1"])

        self._run_backend()

        self._assert_expected_responses(
            ["DATA", "subdomain-127-0-0-1.lcl.io", "IN", "A", "200", "22", "127.0.0.1"],
            ["DATA", "subdomain-127-0-0-1.lcl.io", "IN", "NS", "200", "22", "ns1.lcl.io"],
            ["DATA", "subdomain-127-0-0-1.lcl.io", "IN", "NS", "200", "22", "ns2.lcl.io"],
        )

    def test_backend_responds_to_A_request_with_valid_ip_separated_by_dashes(self):
        self._send_commands(["Q", "subdomain-127-0-0-1.lcl.io", "IN", "A", "1", "127.0.0.1"])

        self._run_backend()

        self._assert_expected_responses(
            ["DATA", "subdomain-127-0-0-1.lcl.io", "IN", "A", "200", "22", "127.0.0.1"],
            ["DATA", "subdomain-127-0-0-1.lcl.io", "IN", "NS", "200", "22", "ns1.lcl.io"],
            ["DATA", "subdomain-127-0-0-1.lcl.io", "IN", "NS", "200", "22", "ns2.lcl.io"],
        )

    def test_backend_responds_to_invalid_ip_in_ANY_request_with_self_ip(self):
        self._send_commands(["Q", "subdomain.127.0.1.lcl.io", "IN", "ANY", "1", "127.0.0.1"])

        self._run_backend()

        self._assert_expected_responses(
            ["DATA", "subdomain.127.0.1.lcl.io", "IN", "A", "200", "22", "127.0.0.33"],
            ["DATA", "subdomain.127.0.1.lcl.io", "IN", "NS", "200", "22", "ns1.lcl.io"],
            ["DATA", "subdomain.127.0.1.lcl.io", "IN", "NS", "200", "22", "ns2.lcl.io"],
        )

    def test_backend_responds_to_invalid_ip_in_A_request_with_self(self):
        self._send_commands(["Q", "subdomain.127.0.1.lcl.io", "IN", "A", "1", "127.0.0.1"])

        self._run_backend()

        self._assert_expected_responses(
            ["DATA", "subdomain.127.0.1.lcl.io", "IN", "A", "200", "22", "127.0.0.33"],
            ["DATA", "subdomain.127.0.1.lcl.io", "IN", "NS", "200", "22", "ns1.lcl.io"],
            ["DATA", "subdomain.127.0.1.lcl.io", "IN", "NS", "200", "22", "ns2.lcl.io"],
        )

    def test_backend_responds_to_short_ip_in_ANY_request_with_self_ip(self):
        self._send_commands(["Q", "127.0.1.lcl.io", "IN", "ANY", "1", "127.0.0.1"])

        self._run_backend()

        self._assert_expected_responses(
            ["DATA", "127.0.1.lcl.io", "IN", "A", "200", "22", "127.0.0.33"],
            ["DATA", "127.0.1.lcl.io", "IN", "NS", "200", "22", "ns1.lcl.io"],
            ["DATA", "127.0.1.lcl.io", "IN", "NS", "200", "22", "ns2.lcl.io"],
        )

    def test_backend_responds_to_short_ip_in_A_request_with_self(self):
        self._send_commands(["Q", "127.0.1.lcl.io", "IN", "A", "1", "127.0.0.1"])

        self._run_backend()

        self._assert_expected_responses(
            ["DATA", "127.0.1.lcl.io", "IN", "A", "200", "22", "127.0.0.33"],
            ["DATA", "127.0.1.lcl.io", "IN", "NS", "200", "22", "ns1.lcl.io"],
            ["DATA", "127.0.1.lcl.io", "IN", "NS", "200", "22", "ns2.lcl.io"],
        )

    def test_backend_responds_to_large_ip_in_ANY_request_with_self(self):
        self._send_commands(["Q", "subdomain.127.0.300.1.lcl.io", "IN", "ANY", "1", "127.0.0.1"])

        self._run_backend()

        self._assert_expected_responses(
            ["DATA", "subdomain.127.0.300.1.lcl.io", "IN", "A", "200", "22", "127.0.0.33"],
            ["DATA", "subdomain.127.0.300.1.lcl.io", "IN", "NS", "200", "22", "ns1.lcl.io"],
            ["DATA", "subdomain.127.0.300.1.lcl.io", "IN", "NS", "200", "22", "ns2.lcl.io"],
        )

    def test_backend_responds_to_large_ip_in_A_request_with_self(self):
        self._send_commands(["Q", "subdomain.127.0.300.1.lcl.io", "IN", "A", "1", "127.0.0.1"])

        self._run_backend()

        self._assert_expected_responses(
            ["DATA", "subdomain.127.0.300.1.lcl.io", "IN", "A", "200", "22", "127.0.0.33"],
            ["DATA", "subdomain.127.0.300.1.lcl.io", "IN", "NS", "200", "22", "ns1.lcl.io"],
            ["DATA", "subdomain.127.0.300.1.lcl.io", "IN", "NS", "200", "22", "ns2.lcl.io"],
        )

    def test_backend_responds_to_string_in_ip_in_ANY_request_with_self(self):
        self._send_commands(["Q", "subdomain.127.0.STRING.1.lcl.io", "IN", "ANY", "1", "127.0.0.1"])

        self._run_backend()

        self._assert_expected_responses(
            ["DATA", "subdomain.127.0.string.1.lcl.io", "IN", "A", "200", "22", "127.0.0.33"],
            ["DATA", "subdomain.127.0.string.1.lcl.io", "IN", "NS", "200", "22", "ns1.lcl.io"],
            ["DATA", "subdomain.127.0.string.1.lcl.io", "IN", "NS", "200", "22", "ns2.lcl.io"],
        )

    def test_backend_responds_to_string_in_ip_in_A_request_with_self(self):
        self._send_commands(["Q", "subdomain.127.0.STRING.1.lcl.io", "IN", "A", "1", "127.0.0.1"])

        self._run_backend()

        self._assert_expected_responses(
            ["DATA", "subdomain.127.0.string.1.lcl.io", "IN", "A", "200", "22", "127.0.0.33"],
            ["DATA", "subdomain.127.0.string.1.lcl.io", "IN", "NS", "200", "22", "ns1.lcl.io"],
            ["DATA", "subdomain.127.0.string.1.lcl.io", "IN", "NS", "200", "22", "ns2.lcl.io"],
        )

    def test_backend_responds_to_no_ip_in_ANY_request_with_self(self):
        self._send_commands(["Q", "subdomain.127.0.1.lcl.io", "IN", "ANY", "1", "127.0.0.1"])

        self._run_backend()

        self._assert_expected_responses(
            ["DATA", "subdomain.127.0.1.lcl.io", "IN", "A", "200", "22", "127.0.0.33"],
            ["DATA", "subdomain.127.0.1.lcl.io", "IN", "NS", "200", "22", "ns1.lcl.io"],
            ["DATA", "subdomain.127.0.1.lcl.io", "IN", "NS", "200", "22", "ns2.lcl.io"],
        )

    def test_backend_responds_to_no_ip_in_A_request_with_self(self):
        self._send_commands(["Q", "subdomain.127.0.1.lcl.io", "IN", "A", "1", "127.0.0.1"])

        self._run_backend()

        self._assert_expected_responses(
            ["DATA", "subdomain.127.0.1.lcl.io", "IN", "A", "200", "22", "127.0.0.33"],
            ["DATA", "subdomain.127.0.1.lcl.io", "IN", "NS", "200", "22", "ns1.lcl.io"],
            ["DATA", "subdomain.127.0.1.lcl.io", "IN", "NS", "200", "22", "ns2.lcl.io"],
        )

    def test_backend_responds_to_self_domain_to_A_request(self):
        self._send_commands(["Q", "lcl.io", "IN", "A", "1", "127.0.0.1"])

        self._run_backend()

        self._assert_expected_responses(
            ["DATA", "lcl.io", "IN", "A", "200", "22", "127.0.0.33"],
            ["DATA", "lcl.io", "IN", "NS", "200", "22", "ns1.lcl.io"],
            ["DATA", "lcl.io", "IN", "NS", "200", "22", "ns2.lcl.io"],
        )

    def test_backend_responds_to_self_domain_to_ANY_request(self):
        self._send_commands(["Q", "lcl.io", "IN", "ANY", "1", "127.0.0.1"])

        self._run_backend()

        self._assert_expected_responses(
            ["DATA", "lcl.io", "IN", "A", "200", "22", "127.0.0.33"],
            ["DATA", "lcl.io", "IN", "NS", "200", "22", "ns1.lcl.io"],
            ["DATA", "lcl.io", "IN", "NS", "200", "22", "ns2.lcl.io"],
        )

    def test_backend_responds_to_name_servers_A_request_with_valid_ip(self):
        self._send_commands(["Q", "ns1.lcl.io", "IN", "A", "1", "127.0.0.1"])

        self._run_backend()

        self._assert_expected_responses(
            ["DATA", "ns1.lcl.io", "IN", "A", "200", "22", "127.0.0.34"],
        )

    def test_backend_responds_to_name_servers_ANY_request_with_valid_ip(self):
        self._send_commands(["Q", "ns2.lcl.io", "IN", "ANY", "1", "127.0.0.1"])

        self._run_backend()

        self._assert_expected_responses(
            ["DATA", "ns2.lcl.io", "IN", "A", "200", "22", "127.0.0.35"],
        )

    def test_backend_responds_to_SOA_request_for_self(self):
        self._send_commands(["Q", "lcl.io", "IN", "SOA", "1", "127.0.0.1"])

        self._run_backend()

        self._assert_expected_responses(
            ["DATA", "lcl.io", "IN", "SOA", "200", "22", "MY_SOA"]
        )

    def test_backend_responds_to_SOA_request_for_valid_ip(self):
        self._send_commands(["Q", "subdomain.127.0.0.1.lcl.io", "IN", "SOA", "1", "127.0.0.1"])

        self._run_backend()

        self._assert_expected_responses(
            ["DATA", "subdomain.127.0.0.1.lcl.io", "IN", "SOA", "200", "22", "MY_SOA"]
        )

    def test_backend_responds_to_SOA_request_for_invalid_ip(self):
        self._send_commands(["Q", "subdomain.127.0.1.lcl.io", "IN", "SOA", "1", "127.0.0.1"])

        self._run_backend()

        self._assert_expected_responses(
            ["DATA", "subdomain.127.0.1.lcl.io", "IN", "SOA", "200", "22", "MY_SOA"]
        )

    def test_backend_responds_to_SOA_request_for_no_ip(self):
        self._send_commands(["Q", "subdomain.lcl.io", "IN", "SOA", "1", "127.0.0.1"])

        self._run_backend()

        self._assert_expected_responses(
            ["DATA", "subdomain.lcl.io", "IN", "SOA", "200", "22", "MY_SOA"]
        )

    def test_backend_responds_to_SOA_request_for_nameserver(self):
        self._send_commands(["Q", "ns1.lcl.io", "IN", "SOA", "1", "127.0.0.1"])

        self._run_backend()

        self._assert_expected_responses(
            ["DATA", "ns1.lcl.io", "IN", "SOA", "200", "22", "MY_SOA"]
        )

    def test_backend_responds_to_A_request_for_unknown_domain_with_invalid_response(self):
        self._send_commands(["Q", "unknown.domain", "IN", "A", "1", "127.0.0.1"])

        self._run_backend()

        self._assert_expected_responses(
            ["LOG", "Unknown type: A, domain: unknown.domain"]
        )

    def test_backend_responds_to_invalid_request_with_invalid_response(self):
        self._send_commands(["Q", "lcl.io", "IN", "INVALID", "1", "127.0.0.1"])

        self._run_backend()

        self._assert_expected_responses(
            ["LOG", "Unknown type: INVALID, domain: lcl.io"]
        )

    def test_backend_responds_to_invalid_command_with_fail(self):
        self._send_commands(["INVALID", "COMMAND"])

        self._run_backend()

        calls = [
            call("OK"),
            call("\t"),
            call("We are good"),
            call("\n"),

            call("FAIL"),
            call("\n"),
        ]

        self.mock_sys.stdout.write.assert_has_calls(calls)
        assert_that(self.mock_sys.stdout.write.call_count).is_equal_to(len(calls))

        assert_that(self.mock_sys.stdout.flush.call_count).is_equal_to(2)

    def test_configure_with_full_config(self):
        backend = self._configure_backend()

        assert_that(backend.id).is_equal_to("55")
        assert_that(backend.ip_address).is_equal_to("127.0.0.40")
        assert_that(backend.domain).is_equal_to("lcl.io")
        assert_that(backend.ttl).is_equal_to("1000")
        assert_that(backend.name_servers).is_equal_to({"ns1.lcl.io": "127.0.0.41", "ns2.lcl.io" : "127.0.0.42"})
        assert_that(backend.blacklisted_ips).is_equal_to(["10.0.0.100"])
        assert_that(backend.soa).is_equal_to("ns1.lcl.io emailaddress@lcl.io 55")

    def test_configure_with_config_missing_blacklists(self):
        backend = self._configure_backend(filename="backend_test_no_blacklist.conf")

        assert_that(backend.blacklisted_ips).is_empty()

    def _run_backend(self):
        backend = self._create_backend()
        backend.run()

    def _send_commands(self, *commands):
        commands_to_send = ["HELO\t1\n"]

        for command in commands:
            commands_to_send.append("\t".join(command) + "\n")

        commands_to_send.append("END\n")

        self.mock_sys.stdin.readline.side_effect = commands_to_send

    def _assert_expected_responses(self, *responses):
        calls = [
            call("OK"),
            call("\t"),
            call("We are good"),
            call("\n"),
        ]

        for response in responses:
            tab_separated = ["\t"] * (len(response) * 2 - 1)
            tab_separated[0::2] = response
            tab_separated.append("\n")

            calls.extend([call(response_item) for response_item in tab_separated])

        calls.extend([
            call("END"),
            call("\n"),
        ])

        self.mock_sys.stdout.write.assert_has_calls(calls)
        assert_that(self.mock_sys.stdout.write.call_count).is_equal_to(len(calls))

        assert_that(self.mock_sys.stdout.flush.call_count).is_equal_to(len(responses) + 2)

    @staticmethod
    def _create_backend():
        backend = DynamicBackend()
        backend.id = "22"
        backend.soa = "MY_SOA"
        backend.ip_address = "127.0.0.33"
        backend.ttl = "200"
        backend.name_servers = collections.OrderedDict([
            ("ns1.lcl.io", "127.0.0.34"),
            ("ns2.lcl.io", "127.0.0.35"),
        ])
        backend.domain = "lcl.io"
        backend.blacklisted_ips = ["127.0.0.2"]
        return backend

    def _configure_backend(self, filename="backend_test.conf"):
        backend = DynamicBackend()
        backend._get_config_filename = lambda: self._get_test_config_filename(filename)
        backend.configure()
        return backend

    def _get_test_config_filename(self, filename):
        return os.path.join(os.path.dirname(os.path.realpath(__file__)), filename)

