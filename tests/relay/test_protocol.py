"""The rules for what crosses the relay, as pure functions: headers, addresses, cookies, frames."""

import json

import pytest

from relay import protocol
from relay.config import ConfigError, RelayConfig, check_origin_template, gateway_label
from relay.protocol import CookieJar, ProtocolError

ORIGIN = "https://0123abcd.console.example.net"


def for_gateway(headers, **overrides):
    options = {
        "cookie_header": "",
        "client_ip": "203.0.113.9",
        "origin": ORIGIN,
        "session_id": "sess-1",
        "content_length": None,
    }
    return protocol.request_headers_for_gateway(headers, **{**options, **overrides})


# --- what a gateway is sent -----------------------------------------------------------------------


def test_a_browsers_cookies_and_credentials_never_reach_a_gateway():
    sent = dict(
        for_gateway(
            [
                ("Cookie", "sessionid=the-hubs-session; csrftoken=the-hubs-token; pulsar_console=relay-secret"),
                ("Authorization", "Bearer something-meant-for-the-hub"),
                ("Proxy-Authorization", "Basic abc"),
                ("Accept", "text/html"),
            ]
        )
    )
    assert "cookie" not in sent and "authorization" not in sent and "proxy-authorization" not in sent
    assert sent["accept"] == "text/html"


def test_only_the_sessions_own_jar_becomes_the_cookie_header():
    sent = dict(for_gateway([("Cookie", "sessionid=hub")], cookie_header="sessionid=gateway; csrftoken=t"))
    assert sent["cookie"] == "sessionid=gateway; csrftoken=t"


def test_forwarding_headers_are_written_by_the_relay_and_never_taken_from_the_browser():
    sent = for_gateway(
        [
            ("X-Forwarded-For", "10.0.0.1"),
            ("X-Forwarded-Proto", "http"),
            ("X-Forwarded-Host", "evil.example"),
            ("Forwarded", "for=10.0.0.1"),
            ("X-Real-IP", "10.0.0.1"),
            ("Via", "1.1 evil"),
            ("X-Hub-Console-Session", "someone-elses"),
            ("X-Hub-User", "owner@victim.example"),
            ("X-Pulsar-Mtls-Verified", "1"),
            ("X-Pulsar-Mtls-Fingerprint", "ab" * 32),
            ("Host", "internal-service:8080"),
        ]
    )
    assert sorted(sent) == sorted(
        [
            ["x-forwarded-for", "203.0.113.9"],
            ["x-forwarded-proto", "https"],
            ["x-forwarded-host", "0123abcd.console.example.net"],
            ["x-hub-console-session", "sess-1"],
        ]
    )


def test_hop_by_hop_headers_and_those_named_by_connection_are_dropped():
    sent = dict(
        for_gateway(
            [
                ("Connection", "keep-alive, X-Secret-Hop"),
                ("Keep-Alive", "timeout=5"),
                ("TE", "trailers"),
                ("Transfer-Encoding", "chunked"),
                ("Upgrade", "websocket"),
                ("X-Secret-Hop", "1"),
                ("Expect", "100-continue"),
                ("Content-Length", "999999"),
                ("Content-Type", "text/plain"),
            ],
            content_length=12,
        )
    )
    for gone in ("connection", "keep-alive", "te", "transfer-encoding", "upgrade", "x-secret-hop", "expect"):
        assert gone not in sent
    assert sent["content-length"] == "12" and sent["content-type"] == "text/plain"


def test_a_header_that_could_split_a_request_is_dropped():
    sent = dict(for_gateway([("X-Ok", "fine"), ("X-Bad", "a\r\nHost: evil"), ("Bad Name", "x")]))
    assert sent["x-ok"] == "fine" and "x-bad" not in sent and "bad name" not in sent


# --- what a browser is sent -----------------------------------------------------------------------


def for_browser(headers, shared_origin=False):
    out, cookies = protocol.response_headers_for_browser(headers, shared_origin=shared_origin)
    return {name.lower(): value for name, value in out}, cookies


def test_set_cookie_goes_to_the_jar_and_never_to_the_browser():
    headers, cookies = for_browser([["Set-Cookie", "sessionid=abc; Path=/"], ["Set-Cookie", "csrftoken=t"]])
    assert "set-cookie" not in headers
    assert cookies == ["sessionid=abc; Path=/", "csrftoken=t"]


def test_a_console_cannot_change_how_the_browser_treats_the_origin():
    headers, _ = for_browser(
        [
            ["Strict-Transport-Security", "max-age=1; includeSubDomains; preload"],
            ["Clear-Site-Data", '"cookies"'],
            ["Service-Worker-Allowed", "/"],
            ["Alt-Svc", 'h3="evil.example:443"'],
            ["Public-Key-Pins", "x"],
            ["Connection", "close"],
            ["Transfer-Encoding", "chunked"],
            ["Content-Type", "text/html"],
            ["Referrer-Policy", "unsafe-url"],
            ["Cross-Origin-Resource-Policy", "cross-origin"],
        ]
    )
    for gone in (
        "strict-transport-security",
        "clear-site-data",
        "service-worker-allowed",
        "alt-svc",
        "public-key-pins",
        "connection",
        "transfer-encoding",
    ):
        assert gone not in headers
    assert headers["content-type"] == "text/html"
    assert headers["referrer-policy"] == "same-origin"
    assert headers["cross-origin-resource-policy"] == "same-origin"
    assert headers["x-content-type-options"] == "nosniff"
    assert headers["cross-origin-opener-policy"] == "same-origin"


def test_on_a_shared_origin_nothing_from_a_gateway_may_be_cached():
    headers, _ = for_browser(
        [["Cache-Control", "public, max-age=31536000, immutable"], ["ETag", '"x"'], ["Expires", "never"]],
        shared_origin=True,
    )
    assert headers["cache-control"] == "no-store" and "etag" not in headers and "expires" not in headers
    headers, _ = for_browser([["Cache-Control", "max-age=60"]])
    assert headers["cache-control"] == "max-age=60"
    headers, _ = for_browser([])
    assert headers["cache-control"] == "private, no-cache"


@pytest.mark.parametrize(
    ("sent", "kept"),
    [
        ("/ui/", "/ui/"),
        ("/ui/?saved=1#top", "/ui/?saved=1#top"),
        ("../doors/", "../doors/"),
        ("http://10.0.0.5:8000/ui/?saved=1", "/ui/?saved=1"),
        ("https://gateway.local/ui/", "/ui/"),
        ("https://evil.example/landing?x=1", "/landing?x=1"),
        ("//evil.example/x", "/x"),
        ("/\\evil.example/x", "/x"),
        ("\\\\evil.example\\x", "/x"),
        ("https://evil.example", "/"),
        ("javascript:alert(1)", "/"),
        ("data:text/html,<script>1</script>", "/"),
        ("  /ui/\t", "/ui/"),
        ("/ui/\r\nSet-Cookie: x=1", "/ui/Set-Cookie: x=1"),
        ("", "/"),
    ],
)
def test_an_address_from_a_gateway_stays_on_the_console_origin(sent, kept):
    assert protocol.confine_location(sent) == kept
    confined = protocol.confine_location(sent)
    assert not confined.startswith("//") and "://" not in confined.split("?")[0]


def test_every_header_that_moves_the_browser_is_confined():
    headers, _ = for_browser(
        [
            ["Location", "http://192.168.1.50/ui/done"],
            ["Content-Location", "https://evil.example/a"],
            ["HX-Redirect", "https://evil.example/hx"],
            ["HX-Push-Url", "//evil.example/p"],
            ["HX-Replace-Url", "https://evil.example/r"],
            ["HX-Location", json.dumps({"path": "https://evil.example/l", "target": "#main"})],
            ["Refresh", "0; url=https://evil.example/x"],
        ]
    )
    assert headers["location"] == "/ui/done"
    assert headers["content-location"] == "/a"
    assert headers["hx-redirect"] == "/hx"
    assert headers["hx-push-url"] == "/p"
    assert headers["hx-replace-url"] == "/r"
    assert json.loads(headers["hx-location"]) == {"path": "/l", "target": "#main"}
    assert headers["refresh"] == "0; url=/x"


def test_response_headers_have_a_size_limit():
    with pytest.raises(ProtocolError):
        protocol.response_headers_for_browser([["X-Big", "a" * (protocol.MAX_HEADER_BYTES + 1)]], shared_origin=False)
    with pytest.raises(ProtocolError):
        protocol.response_headers_for_browser(
            [[f"X-{n}", "v"] for n in range(protocol.MAX_HEADER_COUNT + 1)], shared_origin=False
        )
    with pytest.raises(ProtocolError):
        protocol.response_headers_for_browser([["X-Not-Text", 5]], shared_origin=False)


# --- requests that change something must come from the console's own pages ------------------------


@pytest.mark.parametrize(
    ("method", "headers", "allowed"),
    [
        ("GET", [], True),
        ("HEAD", [("Origin", "https://evil.example")], True),
        ("POST", [("Origin", ORIGIN)], True),
        ("POST", [("Origin", ORIGIN.upper())], True),
        ("POST", [("Origin", "https://evil.example")], False),
        ("POST", [("Origin", "null")], False),
        ("POST", [("Origin", "https://hub.example.com")], False),
        ("POST", [("Referer", ORIGIN + "/ui/form")], True),
        ("POST", [("Referer", "https://evil.example/" + ORIGIN)], False),
        ("POST", [], False),
        ("DELETE", [("Origin", "http://0123abcd.console.example.net")], False),
        ("PUT", [("Origin", ORIGIN + ":8443")], False),
    ],
)
def test_same_origin_rule(method, headers, allowed):
    assert protocol.same_origin_request(method, headers, ORIGIN) is allowed


# --- the cookie jar -------------------------------------------------------------------------------


def test_the_jar_gives_back_what_a_console_set_by_path():
    jar = CookieJar()
    jar.store("sessionid=abc; HttpOnly; Path=/; SameSite=Lax", request_path="/accounts/login/")
    jar.store("csrftoken=tok; Path=/; Max-Age=31449600", request_path="/accounts/login/")
    jar.store("wizard=2; Path=/ui/setup", request_path="/ui/setup/step")
    assert jar.header_for("/ui/") == "sessionid=abc; csrftoken=tok"
    assert jar.header_for("/ui/setup/step?x=1") == "wizard=2; sessionid=abc; csrftoken=tok"
    assert jar.header_for("/ui/setupother") == "sessionid=abc; csrftoken=tok"


def test_the_jar_honours_deletion_and_expiry():
    now = [1000.0]
    jar = CookieJar(now=lambda: now[0])
    jar.store("a=1; Max-Age=60", request_path="/")
    jar.store("b=2; Expires=Thu, 01 Jan 1970 00:20:00 GMT", request_path="/")  # 1200 s
    jar.store("c=3", request_path="/")
    assert jar.header_for("/") == "a=1; b=2; c=3"
    now[0] = 1100.0
    assert jar.header_for("/") == "b=2; c=3"
    jar.store("c=; Max-Age=0", request_path="/")
    assert jar.header_for("/") == "b=2"
    jar.store('b=""; expires=Thu, 01 Jan 1970 00:00:00 GMT', request_path="/")
    assert jar.header_for("/") == "" and len(jar) == 0


def test_the_jar_is_bounded_and_refuses_what_it_cannot_send_back_safely():
    jar = CookieJar()
    for n in range(protocol.JAR_MAX_COOKIES + 20):
        jar.store(f"c{n}=v", request_path="/")
    assert len(jar) == protocol.JAR_MAX_COOKIES
    jar = CookieJar()
    jar.store("big=" + "x" * 5000, request_path="/")
    jar.store("split=a; b", request_path="/")  # the value ends at the first ';'
    jar.store("inject=a\r\nX: y", request_path="/")
    jar.store("=novalue", request_path="/")
    jar.store("no-equals-sign", request_path="/")
    assert jar.header_for("/") == "split=a"


def test_a_cookies_domain_attribute_cannot_move_it_anywhere():
    """A jar belongs to one session on one gateway. Whatever Domain a console names, the cookie is
    only ever sent back to that same gateway, and never to a browser at all."""
    jar = CookieJar()
    jar.store("sessionid=planted; Domain=hub.example.com; Path=/", request_path="/")
    assert jar.header_for("/") == "sessionid=planted"


# --- frames ---------------------------------------------------------------------------------------


def test_frames_round_trip_and_reject_what_is_malformed():
    frame = protocol.parse_text_frame(protocol.text_frame("req", s=7, method="GET"))
    assert frame == {"t": "req", "s": 7, "method": "GET"} and protocol.stream_id_of(frame) == 7
    assert protocol.parse_data_frame(protocol.data_frame(7, b"abc")) == (7, b"abc")
    for bad in ("not json", "[]", '{"s": 1}', '{"t": 5}'):
        with pytest.raises(ProtocolError):
            protocol.parse_text_frame(bad)
    with pytest.raises(ProtocolError):
        protocol.parse_text_frame('{"t":"x","pad":"' + "a" * protocol.MAX_TEXT_FRAME + '"}')
    for bad in (b"", b"\x00\x00\x00\x01", b"\x00\x00\x00\x01" + b"a" * (protocol.MAX_DATA + 1)):
        with pytest.raises(ProtocolError):
            protocol.parse_data_frame(bad)
    for bad in ({"t": "res"}, {"t": "res", "s": 0}, {"t": "res", "s": True}, {"t": "res", "s": "1"}, {"s": 2**32}):
        with pytest.raises(ProtocolError):
            protocol.stream_id_of(bad)


def test_the_newest_common_protocol_version_is_chosen():
    assert protocol.choose_subprotocol("pulsar-console.v1") == "pulsar-console.v1"
    assert protocol.choose_subprotocol("pulsar-console.v9, pulsar-console.v1") == "pulsar-console.v1"
    assert protocol.choose_subprotocol("pulsar-console.v0") is None
    assert protocol.choose_subprotocol("") is None


# --- settings -------------------------------------------------------------------------------------


def test_production_needs_an_https_origin_per_gateway():
    check_origin_template("https://{gateway}.console.example.net", allow_plain_http=False)
    for bad in (
        "",
        "http://{gateway}.console.example.net",  # not https
        "https://console.example.net",  # one origin for every gateway
        "https://{host}:8443",  # the hub's own host name
        "https://{gateway}.console.example.net/path",
        "https://console.example.net/{gateway}",  # a path is not an origin
        "https://x{gateway}.console.example.net",
        "https://{gateway}.console.example.net?x=1",
        "https://{other}.console.example.net",
        "ftp://{gateway}.console.example.net",
    ):
        with pytest.raises(ConfigError):
            check_origin_template(bad, allow_plain_http=False)


def test_a_plain_http_lab_may_use_one_shared_origin():
    check_origin_template("http://{host}:8081", allow_plain_http=True)
    check_origin_template("http://192.168.1.143:8081", allow_plain_http=True)
    check_origin_template("https://{gateway}.console.example.net", allow_plain_http=True)
    with pytest.raises(ConfigError):
        check_origin_template("http://{host}:8081/console", allow_plain_http=True)


def test_relay_settings_come_from_the_environment(monkeypatch):
    for name in ("RELAY_INTERNAL_SECRET", "CONSOLE_ORIGIN_TEMPLATE", "HUB_BASE_URL", "RELAY_ALLOW_PLAIN_HTTP"):
        monkeypatch.delenv(name, raising=False)
    assert RelayConfig.from_env() is None  # nothing set: the remote console is off
    monkeypatch.setenv("CONSOLE_ORIGIN_TEMPLATE", "https://{gateway}.console.example.net")
    with pytest.raises(ConfigError):  # no secret
        RelayConfig.from_env()
    monkeypatch.setenv("RELAY_INTERNAL_SECRET", "short")
    with pytest.raises(ConfigError):
        RelayConfig.from_env()
    monkeypatch.setenv("RELAY_INTERNAL_SECRET", "s" * 40)
    monkeypatch.setenv("HUB_BASE_URL", "https://hub.example.com")
    config = RelayConfig.from_env()
    assert config.hub_host == "hub.example.com" and not config.shared_origin and not config.allow_plain_http
    assert config.max_request_body == 16 * 1024 * 1024
    monkeypatch.setenv("CONSOLE_ORIGIN_TEMPLATE", "http://{host}:8081")
    with pytest.raises(ConfigError):  # a shared plain-HTTP origin without the lab flag
        RelayConfig.from_env()
    monkeypatch.setenv("RELAY_ALLOW_PLAIN_HTTP", "True")
    assert RelayConfig.from_env().shared_origin
    monkeypatch.setenv("CONSOLE_MAX_UPLOAD_MB", "500")
    with pytest.raises(ConfigError):
        RelayConfig.from_env()


def test_a_gateways_console_host_name_is_its_id():
    assert gateway_label("0f8fad5b-d9cb-469f-a165-70867728950e") == "0f8fad5bd9cb469fa16570867728950e"
