# -*- coding: utf-8 -*-
# Copyright: (c) 2020, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import typing

import pytest

import spnego
import spnego._gss
from spnego._context import GSSMech
from spnego._negotiate import NegotiateProxy
from spnego._spnego import NegState, NegTokenInit, NegTokenResp
from spnego.exceptions import BadMechanismError, InvalidTokenError


def test_token_rejected(ntlm_cred):
    c = spnego.client(ntlm_cred[0], ntlm_cred[1], options=spnego.NegotiateOptions.use_negotiate)

    c.step()
    token_resp = NegTokenResp(neg_state=NegState.reject).pack()

    with pytest.raises(InvalidTokenError, match="Received SPNEGO rejection with no token error message"):
        c.step(token_resp)


def test_token_invalid_input(ntlm_cred):
    c = spnego.client(ntlm_cred[0], ntlm_cred[1], options=spnego.NegotiateOptions.use_negotiate)

    c.step()
    with pytest.raises(InvalidTokenError, match="Failed to unpack input token"):
        c.step(b"\x00")


def test_token_no_common_mechs(ntlm_cred):
    c = spnego.client(ntlm_cred[0], ntlm_cred[1], options=spnego.NegotiateOptions.use_negotiate)

    with pytest.raises(BadMechanismError, match="Unable to negotiate common mechanism"):
        c.step(NegTokenInit(mech_types=["1.2.3.4"]).pack())


def test_token_acceptor_first(ntlm_cred):
    c = spnego.client(ntlm_cred[0], ntlm_cred[1], options=spnego.NegotiateOptions.use_negotiate)
    s = spnego.server(options=spnego.NegotiateOptions.use_negotiate)

    assert getattr(c, "_mech_list", None) == []
    assert getattr(s, "_mech_list", None) == []

    token1 = s.step()
    assert isinstance(token1, bytes)
    assert not c.complete
    assert not s.complete
    assert getattr(c, "_mech_list", None) == []
    assert GSSMech.ntlm.value in getattr(s, "_mech_list", [])

    negotiate = c.step(token1)
    assert isinstance(negotiate, bytes)
    assert not c.complete
    assert not s.complete
    assert getattr(c, "_mech_list", None) == [GSSMech.ntlm.value]
    assert GSSMech.ntlm.value in getattr(s, "_mech_list", [])

    challenge = s.step(negotiate)
    assert isinstance(challenge, bytes)
    assert not c.complete
    assert not s.complete

    authenticate = c.step(challenge)
    assert isinstance(authenticate, bytes)
    assert not c.complete
    assert not s.complete

    mech_list_mic = s.step(authenticate)
    assert isinstance(mech_list_mic, bytes)
    assert not c.complete
    assert s.complete

    final_token = c.step(mech_list_mic)
    assert final_token is None
    assert c.complete
    assert s.complete


@pytest.mark.skipif("ntlm" not in spnego._sspi.SSPIProxy.available_protocols(), reason="Requires SSPI library")
def test_iov_available_sspi():
    assert NegotiateProxy.iov_available()


@pytest.mark.skipif(not spnego._gss.HAS_GSSAPI, reason="Requires the gssapi library to be installed for testing")
def test_iov_available_gssapi():
    assert NegotiateProxy.iov_available() == spnego._gss.GSSAPIProxy.iov_available()


class FakeKerberosContext(spnego._context.ContextProxy):
    """A stand in for a Kerberos context that completes in one round trip without needing a KDC."""

    def __init__(self, usage: str = "initiate") -> None:
        super().__init__(
            [spnego.CredentialCache()],
            None,
            None,
            None,
            spnego.ContextReq.default,
            usage,
            "kerberos",
            spnego.NegotiateOptions.none,
        )
        self._complete = False
        self.tokens: typing.List[typing.Optional[bytes]] = []

    @classmethod
    def available_protocols(cls, options=None):
        return ["kerberos"]

    @property
    def client_principal(self):
        return None

    @property
    def complete(self):
        return self._complete

    @property
    def negotiated_protocol(self):
        return "kerberos"

    @property
    def session_key(self):
        return b"\x00" * 16

    def new_context(self):
        return FakeKerberosContext(self.usage)

    def query_message_sizes(self):
        raise NotImplementedError()

    def step(self, in_token=None, *, channel_bindings=None):
        self.tokens.append(in_token)
        if self.usage == "accept":
            self._complete = True
            return b"AP-REP"

        elif in_token:
            self._complete = True
            return None

        else:
            return b"AP-REQ"

    def wrap(self, data, encrypt=True, qop=None):
        raise NotImplementedError()

    def wrap_iov(self, iov, encrypt=True, qop=None):
        raise NotImplementedError()

    def wrap_winrm(self, data):
        raise NotImplementedError()

    def unwrap(self, data):
        raise NotImplementedError()

    def unwrap_iov(self, iov):
        raise NotImplementedError()

    def unwrap_winrm(self, header, data):
        raise NotImplementedError()

    def sign(self, data, qop=None):
        return b"MIC" + data

    def verify(self, data, mic):
        assert mic == b"MIC" + data
        return 0

    @property
    def _context_attr_map(self):
        return []


@pytest.fixture()
def kerberos_preferred(monkeypatch):
    """Make the Negotiate proxy prefer Kerberos regardless of what the host supports."""
    monkeypatch.setattr(
        NegotiateProxy,
        "available_protocols",
        classmethod(lambda cls, options=None: ["kerberos", "ntlm", "negotiate"]),
    )


@pytest.mark.parametrize(
    "mech_types, expected_mech",
    [
        # Windows lists the MS Kerberos OID first and rejects a reply that does not echo it.
        (
            [GSSMech._ms_kerberos.value, GSSMech.kerberos.value, GSSMech.negoex.value, GSSMech.ntlm.value],
            GSSMech._ms_kerberos.value,
        ),
        ([GSSMech.kerberos.value, GSSMech._ms_kerberos.value, GSSMech.ntlm.value], GSSMech.kerberos.value),
        ([GSSMech.kerberos.value, GSSMech.ntlm.value], GSSMech.kerberos.value),
        ([GSSMech._ms_kerberos.value, GSSMech.ntlm.value], GSSMech._ms_kerberos.value),
    ],
)
def test_acceptor_echoes_offered_kerberos_oid(mech_types, expected_mech, kerberos_preferred):
    s = NegotiateProxy(
        usage="accept",
        options=spnego.NegotiateOptions.use_negotiate,
        _negotiate_contexts={GSSMech.kerberos: FakeKerberosContext("accept")},
    )

    init = NegTokenInit(mech_types=mech_types, mech_token=b"AP-REQ").pack()
    out_token = s.step(init)
    assert out_token
    resp = spnego._spnego.unpack_token(out_token)

    assert isinstance(resp, NegTokenResp)
    assert resp.supported_mech == expected_mech
    assert resp.neg_state == NegState.accept_complete
    assert resp.response_token == b"AP-REP"
    assert resp.mech_list_mic is None
    assert s.complete
    assert s.negotiated_protocol == "kerberos"


def test_acceptor_verifies_mic_after_ms_kerberos(kerberos_preferred):
    s = NegotiateProxy(
        usage="accept",
        options=spnego.NegotiateOptions.use_negotiate,
        _negotiate_contexts={GSSMech.kerberos: FakeKerberosContext("accept")},
    )

    mech_types = [GSSMech._ms_kerberos.value, GSSMech.kerberos.value, GSSMech.ntlm.value]
    s.step(NegTokenInit(mech_types=mech_types, mech_token=b"AP-REQ").pack())
    assert s.complete

    # Windows still sends its mechListMIC after accept-completed, it must verify against the list it sent.
    mic = b"MIC" + spnego._spnego.pack_mech_type_list(mech_types)
    assert s.step(NegTokenResp(mech_list_mic=mic).pack()) is None
    assert s.complete


def test_acceptor_creates_mech_contexts_with_credentials(monkeypatch, kerberos_preferred):
    real_server = spnego.server
    calls = []

    def fake_server(**kwargs):
        calls.append(kwargs)
        if kwargs["protocol"] == "kerberos":
            return FakeKerberosContext("accept")

        return real_server(**kwargs)

    monkeypatch.setattr(spnego, "server", fake_server)

    cred = spnego.Password(username="svc-winrm@PSWSMAN.TEST", password="pass")
    s = NegotiateProxy(
        cred,
        hostname="winrm.pswsman.test",
        service="HTTP",
        usage="accept",
        options=spnego.NegotiateOptions.use_negotiate,
    )

    # Only the MS Kerberos OID is offered, the acceptor must still treat that as Kerberos.
    init = NegTokenInit(mech_types=[GSSMech._ms_kerberos.value, GSSMech.ntlm.value], mech_token=b"AP-REQ").pack()
    out_token = s.step(init)
    assert out_token
    resp = spnego._spnego.unpack_token(out_token)
    assert isinstance(resp, NegTokenResp)

    kerberos_calls = [c for c in calls if c["protocol"] == "kerberos"]
    assert len(kerberos_calls) == 1
    assert kerberos_calls[0]["credentials"] == [cred]
    assert kerberos_calls[0]["hostname"] == "winrm.pswsman.test"
    assert kerberos_calls[0]["service"] == "HTTP"

    assert resp.supported_mech == GSSMech._ms_kerberos.value
    assert resp.neg_state == NegState.accept_complete
    assert s.complete


@pytest.mark.parametrize("supported_mech", [GSSMech._ms_kerberos.value, GSSMech._kerberos_draft.value])
def test_initiator_accepts_kerberos_alias_supported_mech(supported_mech):
    c = NegotiateProxy(
        usage="initiate",
        options=spnego.NegotiateOptions.use_negotiate,
        _negotiate_contexts={GSSMech.kerberos: FakeKerberosContext("initiate")},
    )

    out_token = c.step()
    assert out_token
    init = spnego._spnego.unpack_token(out_token)
    assert isinstance(init, NegTokenInit)
    assert init.mech_types == [GSSMech.kerberos.value]
    assert init.mech_token == b"AP-REQ"

    resp = NegTokenResp(
        neg_state=NegState.accept_complete,
        supported_mech=supported_mech,
        response_token=b"AP-REP",
    ).pack()
    assert c.step(resp) is None
    assert c.complete
    assert c.negotiated_protocol == "kerberos"


class _RecordingNTLMContext(spnego._context.ContextProxy):
    """Minimal stand in for an NTLM context that records the tokens it receives."""

    def __init__(self, usage: str = "accept") -> None:
        super().__init__(
            [spnego.Password("user", "pass")],
            None,
            None,
            None,
            spnego.ContextReq.default,
            usage,
            "ntlm",
            spnego.NegotiateOptions.none,
        )
        self._complete = False
        self.received: typing.List[typing.Optional[bytes]] = []
        self._step_count = 0

    @classmethod
    def available_protocols(cls, options=None):
        return ["ntlm"]

    @property
    def client_principal(self):
        return None

    @property
    def complete(self):
        return self._complete

    @property
    def negotiated_protocol(self):
        return "ntlm"

    @property
    def session_key(self):
        return b"\x00" * 16

    def new_context(self):
        return _RecordingNTLMContext(self.usage)

    def query_message_sizes(self):
        raise NotImplementedError()

    def step(self, in_token=None, *, channel_bindings=None):
        self.received.append(in_token)
        self._step_count += 1
        if self.usage == "accept":
            # First call emits the NTLM challenge, second call completes the context.
            if self._step_count == 1:
                return b"NTLMSSP\x00\x02challenge"
            self._complete = True
            return None

        if self._step_count == 1:
            return b"NTLMSSP\x00\x01negotiate"
        self._complete = True
        return b"NTLMSSP\x00\x03authenticate"

    def wrap(self, data, encrypt=True, qop=None):
        raise NotImplementedError()

    def wrap_iov(self, iov, encrypt=True, qop=None):
        raise NotImplementedError()

    def wrap_winrm(self, data):
        raise NotImplementedError()

    def unwrap(self, data):
        raise NotImplementedError()

    def unwrap_iov(self, iov):
        raise NotImplementedError()

    def unwrap_winrm(self, header, data):
        raise NotImplementedError()

    def sign(self, data, qop=None):
        return b"MIC" + data

    def verify(self, data, mic):
        assert mic == b"MIC" + data
        return 0

    @property
    def _context_attr_map(self):
        return []


def _ntlm_only_server() -> NegotiateProxy:
    return NegotiateProxy(
        usage="accept",
        options=spnego.NegotiateOptions.use_negotiate,
        _negotiate_contexts={GSSMech.ntlm: _RecordingNTLMContext("accept")},
    )


def test_acceptor_ignores_optimistic_token_for_non_preferred_mech():
    # The initiator prefers Kerberos and includes an optimistic AP-REQ but the acceptor only supports NTLM. The
    # optimistic token must never reach the NTLM context (which previously raised a raw struct.error/KeyError).
    s = _ntlm_only_server()

    init = NegTokenInit(
        mech_types=[GSSMech.kerberos.value, GSSMech.ntlm.value],
        mech_token=b"optimistic-kerberos-ap-req",
    ).pack()
    out = s.step(init)
    resp = spnego._spnego.unpack_token(out)

    assert isinstance(resp, NegTokenResp)
    assert resp.neg_state == NegState.request_mic
    assert resp.supported_mech == GSSMech.ntlm.value
    assert resp.response_token is None
    assert not s.complete

    ntlm_context = s._context_list[GSSMech.ntlm][0]
    assert isinstance(ntlm_context, _RecordingNTLMContext)
    assert ntlm_context.received == []
    assert ntlm_context.step is not None  # context was never driven with the foreign token


def test_acceptor_optimistic_token_mismatch_allows_ntlm_restart():
    # Full RFC 4178 downgrade: after the request-mic reply the initiator restarts NTLM from scratch and the exchange
    # completes with a mechListMIC.
    s = _ntlm_only_server()
    mech_types = [GSSMech.kerberos.value, GSSMech.ntlm.value]

    first_reply = s.step(NegTokenInit(mech_types=mech_types, mech_token=b"kerb-ap-req").pack())
    first_resp = spnego._spnego.unpack_token(first_reply)
    assert first_resp.neg_state == NegState.request_mic

    c = NegotiateProxy(
        usage="initiate",
        options=spnego.NegotiateOptions.use_negotiate,
        _negotiate_contexts={GSSMech.ntlm: _RecordingNTLMContext("initiate")},
    )
    c.step()
    c._mech_list = mech_types

    negotiate = c.step(first_reply)
    negotiate_resp = spnego._spnego.unpack_token(negotiate)
    assert negotiate_resp.response_token == b"NTLMSSP\x00\x01negotiate"

    challenge = s.step(negotiate)
    authenticate = c.step(challenge)
    authenticate_resp = spnego._spnego.unpack_token(authenticate)
    assert authenticate_resp.mech_list_mic is not None

    mic_reply = s.step(authenticate)
    assert s.complete
    assert c.step(mic_reply) is None
    assert c.complete
    assert c.negotiated_protocol == "ntlm"


def test_acceptor_does_not_trust_peer_accept_complete_without_mic(ntlm_cred):
    # A spoofed final NegTokenResp that strips the mechListMIC but claims accept-complete must not complete the
    # context while the MIC exchange is still outstanding.
    c = spnego.client(ntlm_cred[0], ntlm_cred[1], options=spnego.NegotiateOptions.use_negotiate)
    s = spnego.server(options=spnego.NegotiateOptions.use_negotiate)

    negotiate = c.step()
    challenge = s.step(negotiate)
    authenticate = c.step(challenge)

    tampered_resp = spnego._spnego.unpack_token(authenticate)
    assert isinstance(tampered_resp, NegTokenResp)
    assert tampered_resp.mech_list_mic is not None
    tampered_resp.neg_state = NegState.accept_complete
    tampered_resp.mech_list_mic = None

    out = s.step(tampered_resp.pack())
    assert not s.complete
    # The server keeps the negotiation alive and continues to demand the MIC.
    reply = spnego._spnego.unpack_token(out)
    assert isinstance(reply, NegTokenResp)
    assert reply.mech_list_mic is not None


def _server_challenge(client, server):
    return server.step(client.step())


def test_acceptor_rejects_request_mic_neg_state_from_initiator(ntlm_cred):
    c = spnego.client(ntlm_cred[0], ntlm_cred[1], options=spnego.NegotiateOptions.use_negotiate)
    s = spnego.server(options=spnego.NegotiateOptions.use_negotiate)

    s.step(c.step())

    with pytest.raises(InvalidTokenError, match="only valid in a reply from the target"):
        s.step(NegTokenResp(neg_state=NegState.request_mic).pack())


def test_acceptor_rejects_reject_neg_state_from_initiator(ntlm_cred):
    c = spnego.client(ntlm_cred[0], ntlm_cred[1], options=spnego.NegotiateOptions.use_negotiate)
    s = spnego.server(options=spnego.NegotiateOptions.use_negotiate)

    s.step(c.step())

    with pytest.raises(InvalidTokenError, match="only valid in a reply from the target"):
        s.step(NegTokenResp(neg_state=NegState.reject).pack())


def test_acceptor_rejects_supported_mech_from_initiator(ntlm_cred):
    c = spnego.client(ntlm_cred[0], ntlm_cred[1], options=spnego.NegotiateOptions.use_negotiate)
    s = spnego.server(options=spnego.NegotiateOptions.use_negotiate)

    s.step(c.step())

    with pytest.raises(InvalidTokenError, match="supportedMech can only be sent by the target acceptor"):
        s.step(NegTokenResp(supported_mech=GSSMech.ntlm.value).pack())


def test_neg_token_init_with_empty_mech_types_is_invalid(ntlm_cred):
    s = spnego.server(options=spnego.NegotiateOptions.use_negotiate)

    with pytest.raises(InvalidTokenError, match="did not contain any mechanisms in mechTypes"):
        s.step(NegTokenInit(mech_types=[]).pack())


def test_neg_token_resp_with_unknown_neg_state_is_invalid(ntlm_cred):
    c = spnego.client(ntlm_cred[0], ntlm_cred[1], options=spnego.NegotiateOptions.use_negotiate)
    c.step()

    from spnego._asn1 import TagClass, pack_asn1, pack_asn1_enumerated, pack_asn1_sequence

    bad = pack_asn1(
        TagClass.context_specific,
        True,
        1,
        pack_asn1_sequence([pack_asn1(TagClass.context_specific, True, 0, pack_asn1_enumerated(9))]),
    )

    with pytest.raises(InvalidTokenError, match="Invalid NegTokenResp negState value 9"):
        c.step(bad)


def test_truncated_spnego_token_is_invalid_token(ntlm_cred):
    # A truncated token previously surfaced as a raw IndexError from the ASN.1 parser.
    c = spnego.client(ntlm_cred[0], ntlm_cred[1], options=spnego.NegotiateOptions.use_negotiate)
    c.step()

    with pytest.raises(InvalidTokenError, match="Failed to unpack input token"):
        c.step(b"\xa1\x07\x30\x05\xa0\x03\x0a\x01")


def test_initiator_rejects_unknown_supported_mech(ntlm_cred):
    c = spnego.client(ntlm_cred[0], ntlm_cred[1], options=spnego.NegotiateOptions.use_negotiate)
    c.step()

    bad = NegTokenResp(
        neg_state=NegState.accept_incomplete,
        supported_mech="1.2.3.4.5.6.7.8.9",
        response_token=b"",
    ).pack()

    with pytest.raises(InvalidTokenError, match="not a known mechanism"):
        c.step(bad)


def test_malformed_inner_mechanism_token_raises_invalid_token(ntlm_cred):
    # A responseToken that cannot be parsed by the selected mechanism must surface as InvalidTokenError rather than a
    # raw struct.error/KeyError from the mechanism implementation.
    c = spnego.client(ntlm_cred[0], ntlm_cred[1], options=spnego.NegotiateOptions.use_negotiate)
    c.step()

    bad = NegTokenResp(
        neg_state=NegState.accept_incomplete,
        supported_mech=GSSMech.ntlm.value,
        response_token=b"not-an-ntlm-message",
    ).pack()

    with pytest.raises(InvalidTokenError, match="Failed to process the ntlm mechanism token"):
        c.step(bad)


def test_windows_post_accept_complete_mic_flow_still_works(kerberos_preferred):
    # Regression guard for the Windows interop flow where the mechListMIC arrives after accept-complete.
    s = NegotiateProxy(
        usage="accept",
        options=spnego.NegotiateOptions.use_negotiate,
        _negotiate_contexts={GSSMech.kerberos: FakeKerberosContext("accept")},
    )

    mech_types = [GSSMech._ms_kerberos.value, GSSMech.kerberos.value, GSSMech.ntlm.value]
    s.step(NegTokenInit(mech_types=mech_types, mech_token=b"AP-REQ").pack())
    assert s.complete

    mic = b"MIC" + spnego._spnego.pack_mech_type_list(mech_types)
    assert s.step(NegTokenResp(mech_list_mic=mic).pack()) is None
    assert s.complete
