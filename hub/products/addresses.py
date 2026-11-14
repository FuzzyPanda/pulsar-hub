"""Addresses the hub links to: validating what an Owner or Admin typed, and building the link.

The hub never calls these addresses (rule 3). It only writes them into a page as links, and the
person's own browser goes there. They are still checked strictly, because a link on the hub's
front page is trusted by whoever clicks it: only `http` and `https`, a real host, and nothing that
could hide where the link leads (credentials, a query string or a fragment in the base).

`{host}` may stand in for the host name of a base address. It is replaced, when a page is drawn,
with the host name the browser used to reach the hub. One setting then works whether a bench hub
is opened by its LAN address or by its mesh VPN name.
"""

import re
from urllib.parse import quote, urlsplit

from django.core.exceptions import ValidationError
from django.http.request import split_domain_port

HOST_PLACEHOLDER = "{host}"
ORG_SLUG_PLACEHOLDER = "{org_slug}"
MAX_ADDRESS_LENGTH = 300
# Stands in for `{host}` while the rest of the address is parsed. `.invalid` never resolves.
_STAND_IN = "host-placeholder.invalid"


# A DNS name or an IPv4 address, or (with colons) the inside of a bracketed IPv6 address.
_HOST_NAME = re.compile(r"^[A-Za-z0-9:]([A-Za-z0-9.:-]*[A-Za-z0-9:])?$")


def _has_unsafe_characters(value: str) -> bool:
    """Anything but visible ASCII, and the few ASCII characters that have no place in a link.

    Refusing non-ASCII outright keeps look-alike letters and invisible direction marks out of a
    link people are asked to trust. An internationalised host name can be given in its xn-- form.
    """
    return any(not 0x21 <= ord(ch) <= 0x7E or ch in '\\<>"`' for ch in value)


def clean_base_address(value: str, *, allow_host_placeholder: bool = True, what: str = "The address") -> str:
    """The address as it is stored: checked, and without a trailing slash on a bare host.

    Raises `ValidationError` with a sentence fit to show the person who typed it.
    """
    value = (value or "").strip()
    if not value:
        raise ValidationError(f"{what} is needed.")
    if len(value) > MAX_ADDRESS_LENGTH:
        raise ValidationError(f"{what} is too long.")
    if _has_unsafe_characters(value):
        raise ValidationError(f"{what} must not contain spaces or special characters.")
    placeholders = value.count(HOST_PLACEHOLDER)
    if placeholders and not allow_host_placeholder:
        raise ValidationError(f"{what} cannot use {HOST_PLACEHOLDER} here. Enter the full address.")
    if placeholders > 1:
        raise ValidationError(f"{what} can use {HOST_PLACEHOLDER} only once.")
    probe = value.replace(HOST_PLACEHOLDER, _STAND_IN)
    if "{" in probe or "}" in probe:
        raise ValidationError(f"{what} can contain {HOST_PLACEHOLDER} and no other placeholder.")
    try:
        parts = urlsplit(probe)
        port = parts.port
        host = parts.hostname or ""
    except ValueError as exc:
        raise ValidationError(f"{what} is not a web address.") from exc
    if parts.scheme not in ("http", "https"):
        raise ValidationError(f"{what} must start with http:// or https://.")
    if not host or not _HOST_NAME.match(host):
        raise ValidationError(f"{what} needs a host name, such as https://rostering.example.com.")
    if "@" in parts.netloc or parts.username is not None or parts.password is not None:
        raise ValidationError(f"{what} must not contain a user name or password.")
    if parts.query or "?" in probe:
        raise ValidationError(f"{what} must not contain a question mark or anything after one.")
    if parts.fragment or "#" in probe:
        raise ValidationError(f"{what} must not contain a # or anything after one.")
    if placeholders and host != _STAND_IN:
        # `{host}` is the whole host name, never a part of one or a part of the path.
        raise ValidationError(f"{HOST_PLACEHOLDER} must be the whole host name, as in http://{HOST_PLACEHOLDER}:8080.")
    if port is not None and not 1 <= port <= 65535:
        raise ValidationError(f"{what} has a port that is out of range.")
    if parts.path in ("", "/"):
        return value.rstrip("/")
    return value


def clean_launch_path(value: str) -> str:
    """A path on the product, appended to the base address. Blank means the product's own default."""
    value = (value or "").strip()
    if not value:
        return ""
    if len(value) > MAX_ADDRESS_LENGTH:
        raise ValidationError("The launch path is too long.")
    if _has_unsafe_characters(value):
        raise ValidationError("The launch path must not contain spaces or special characters.")
    if not value.startswith("/") or value.startswith("//"):
        raise ValidationError("The launch path must start with a single /, such as /login.")
    if "#" in value:
        raise ValidationError("The launch path must not contain a #.")
    probe = value.replace(ORG_SLUG_PLACEHOLDER, "")
    if "{" in probe or "}" in probe:
        raise ValidationError(f"The launch path can contain {ORG_SLUG_PLACEHOLDER} and no other placeholder.")
    return value


def browser_host(request) -> str:
    """The host name the browser used to reach the hub, without a port.

    `get_host()` has already been checked against DJANGO_ALLOWED_HOSTS, so this is one of the
    hub's own names and never something a caller made up.
    """
    domain, _port = split_domain_port(request.get_host())
    return domain


def resolve_address(address: str, *, host: str) -> str:
    """`address` as a link: `{host}` filled in. Empty when the address would not be a safe link."""
    if not address:
        return ""
    if HOST_PLACEHOLDER in address:
        if not host:
            return ""
        address = address.replace(HOST_PLACEHOLDER, host)
    try:
        clean_base_address(address, allow_host_placeholder=False)
    except ValidationError:
        return ""
    return address


def launch_url(base_address: str, launch_path: str, *, host: str, org_slug: str) -> str:
    """The "Open" link for a product: the resolved base address and the launch path."""
    base = resolve_address(base_address, host=host)
    if not base:
        return ""
    try:
        path = clean_launch_path(launch_path)
    except ValidationError:
        return ""
    path = path.replace(ORG_SLUG_PLACEHOLDER, quote(org_slug, safe=""))
    return base.rstrip("/") + (path or "/")
