import unittest
import ssl
from dataclasses import replace
from unittest.mock import patch

from armour import (
    ActionProposal,
    ArmourGate,
    BindingConsumed,
    BindingError,
    BindingExpired,
    BindingMismatch,
    DependencyPolicy,
    Effect,
    GuardedExecutor,
    NetworkBinder,
    Policy,
    Risk,
    prepare_execution_binding,
)
from armour.verifiers import NetworkVerifier


class FakeClock:
    def __init__(self) -> None:
        self.now_ns = 1_000_000_000

    def __call__(self) -> int:
        return self.now_ns

    def advance_ms(self, milliseconds: float) -> None:
        self.now_ns += int(milliseconds * 1_000_000)


class FakeResponse:
    status = 200
    reason = "OK"

    def __init__(self, body: bytes = b"safe") -> None:
        self.body = body

    def read(self, amount: int) -> bytes:
        return self.body[:amount]

    def getheaders(self):
        return [("Content-Type", "text/plain")]


class FakeConnection:
    def __init__(self, destination_ip: str, body: bytes = b"safe") -> None:
        self.destination_ip = destination_ip
        self.response = FakeResponse(body)
        self.requests = []
        self.closed = False

    def request(self, method: str, target: str) -> None:
        self.requests.append((method, target))

    def getresponse(self) -> FakeResponse:
        return self.response

    def close(self) -> None:
        self.closed = True


class NetworkBindingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.clock = FakeClock()
        self.addresses = ["93.184.216.34"]
        self.resolution_calls = []

        def resolver(host: str):
            self.resolution_calls.append(host)
            return tuple(self.addresses)

        self.resolver = resolver
        self.policy = Policy(
            allowed_actions=frozenset({"fetch_url"}),
            action_effects={"fetch_url": Effect.READ_ONLY},
            action_dependencies={
                "fetch_url": {
                    "network": DependencyPolicy(kind="network", max_age_ms=25)
                }
            },
            policy_id="network-binding-tests",
        )
        self.proposal = ActionProposal(
            "fetch_url",
            Effect.READ_ONLY,
            Risk.LOW,
            resource="https://example.com/data?item=1",
            method="GET",
        )
        self.connections = []

        def open_connection(**kwargs):
            connection = FakeConnection(kwargs["destination_ip"])
            self.connections.append(connection)
            return connection

        self.open_connection = open_connection

    def prepare(self, proposal=None, policy=None, execution_id="exec-1"):
        binder = NetworkBinder(resolver=self.resolver)
        with patch(
            "armour.network_binding._open_pinned_connection",
            side_effect=self.open_connection,
        ):
            binding = prepare_execution_binding(
                proposal or self.proposal,
                policy or self.policy,
                execution_id=execution_id,
                binders={"network": binder},
                monotonic_ns=self.clock,
            )
        return binding, binder

    def consume(self, binding, proposal=None, policy=None, execution_id="exec-1"):
        return binding.consume(
            proposal=proposal or self.proposal,
            policy_fingerprint=(policy or self.policy).fingerprint(),
            execution_id=execution_id,
        )

    def test_destination_substitution_after_binding_cannot_redirect_handler(self):
        class SwapDNSAtAuditStart:
            def append(inner_self, _proposal, _decision, _outcome=None, *, phase, execution_id):
                if phase == "started":
                    self.addresses[:] = ["203.0.113.10"]

        gate = ArmourGate(
            self.policy, network_verifier=NetworkVerifier(resolver=self.resolver)
        )
        executor = GuardedExecutor(
            gate, SwapDNSAtAuditStart(), monotonic_ns=self.clock
        )
        binder = NetworkBinder(resolver=self.resolver)
        executor.register_bound(
            "fetch_url",
            lambda _proposal, context: context.capability("network").request(),
            {"network": binder},
        )
        with patch(
            "armour.network_binding._open_pinned_connection",
            side_effect=self.open_connection,
        ):
            outcome = executor.execute(self.proposal)

        self.assertTrue(outcome.success)
        self.assertEqual(outcome.output.destination_ip, "93.184.216.34")
        self.assertEqual(self.connections[0].destination_ip, "93.184.216.34")
        self.assertEqual(self.connections[0].requests, [("GET", "/data?item=1")])
        self.assertNotIn("203.0.113.10", [item.destination_ip for item in self.connections])

    def test_private_loopback_link_local_and_reserved_addresses_are_rejected(self):
        unsafe = (
            "10.0.0.4",
            "127.0.0.1",
            "169.254.1.2",
            "192.0.2.10",
            "::1",
            "fe80::1",
        )
        for address in unsafe:
            with self.subTest(address=address):
                self.addresses[:] = [address]
                with self.assertRaisesRegex(BindingError, "non-public"):
                    self.prepare()

    def test_one_unsafe_answer_rejects_mixed_dns_results(self):
        self.addresses[:] = ["93.184.216.34", "127.0.0.1"]
        with self.assertRaisesRegex(BindingError, "non-public"):
            self.prepare()
        self.assertEqual(self.connections, [])

    def test_disallowed_methods_are_rejected(self):
        for method in ("POST", "PUT", "DELETE", "PATCH"):
            with self.subTest(method=method):
                proposal = replace(self.proposal, method=method)
                with self.assertRaisesRegex(BindingError, "method"):
                    self.prepare(proposal=proposal)
        self.assertEqual(self.connections, [])

    def test_insecure_tls_context_is_rejected_at_construction(self):
        context = ssl._create_unverified_context()
        with self.assertRaisesRegex(ValueError, "certificate verification"):
            NetworkBinder(ssl_context=context)

    def test_tls_context_weakened_after_construction_fails_closed(self):
        context = ssl.create_default_context()
        binder = NetworkBinder(resolver=self.resolver, ssl_context=context)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with self.assertRaisesRegex(BindingError, "certificate verification"):
            prepare_execution_binding(
                self.proposal,
                self.policy,
                execution_id="exec-1",
                binders={"network": binder},
                monotonic_ns=self.clock,
            )
        self.assertEqual(self.connections, [])

    def test_invalid_port_and_url_credentials_fail_before_connection(self):
        resources = (
            "https://example.com:0/data",
            "https://example.com:99999/data",
            "https://user:secret@example.com/data",
            "https://example.com/data#fragment",
        )
        for resource in resources:
            with self.subTest(resource=resource):
                with self.assertRaises(BindingError):
                    self.prepare(proposal=replace(self.proposal, resource=resource))
        self.assertEqual(self.connections, [])

    def test_capability_is_single_use(self):
        binding, _binder = self.prepare()
        context = self.consume(binding)
        capability = context.capability("network")
        response = capability.request()
        self.assertEqual(response.body, b"safe")
        with self.assertRaises(BindingConsumed):
            capability.request()
        context.close()

    def test_binding_expiry_fails_closed_before_handler_context(self):
        binding, binder = self.prepare()
        self.clock.advance_ms(25)
        with self.assertRaises(BindingExpired):
            self.consume(binding)
        binding.close()
        self.assertTrue(binder.last_capability.closed)
        self.assertEqual(self.connections[0].requests, [])

    def test_capability_rechecks_expiry_at_actual_request(self):
        binding, _binder = self.prepare()
        context = self.consume(binding)
        capability = context.capability("network")
        self.clock.advance_ms(25)
        with self.assertRaises(BindingExpired):
            capability.request()
        context.close()
        self.assertEqual(self.connections[0].requests, [])

    def test_binding_rejects_proposal_policy_and_execution_mismatch(self):
        cases = (
            {
                "proposal": replace(self.proposal, id="another"),
                "policy_fingerprint": self.policy.fingerprint(),
                "execution_id": "exec-1",
            },
            {
                "proposal": self.proposal,
                "policy_fingerprint": replace(self.policy, revision=2).fingerprint(),
                "execution_id": "exec-1",
            },
            {
                "proposal": self.proposal,
                "policy_fingerprint": self.policy.fingerprint(),
                "execution_id": "exec-2",
            },
        )
        for arguments in cases:
            with self.subTest(arguments=arguments):
                binding, _binder = self.prepare()
                with self.assertRaises(BindingMismatch):
                    binding.consume(**arguments)
                binding.close()

    def test_head_is_supported_and_redirects_are_not_followed(self):
        proposal = replace(self.proposal, method="HEAD")
        binding, _binder = self.prepare(proposal=proposal)
        context = binding.consume(
            proposal=proposal,
            policy_fingerprint=self.policy.fingerprint(),
            execution_id="exec-1",
        )
        context.capability("network").request()
        self.assertEqual(self.connections[0].requests, [("HEAD", "/data?item=1")])
        self.assertEqual(len(self.connections), 1)
        context.close()


if __name__ == "__main__":
    unittest.main()
