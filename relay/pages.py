"""The few pages the relay itself shows on a console origin. Plain, with no script and no asset."""

from html import escape

from aiohttp import web

_CSP = "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
_STYLE = (
    "body{font:16px/1.5 system-ui,sans-serif;max-width:34rem;margin:15vh auto;padding:0 1rem;color:#1c2430}"
    "h1{font-size:1.4rem}a{color:#1d4ed8}"
)


def page(title: str, body_html: str, *, status: int = 200, head: str = "", headers: dict | None = None) -> web.Response:
    html = (
        '<!doctype html><html lang="en-AU"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        f"{head}<title>{escape(title)}</title><style>{_STYLE}</style></head>"
        f"<body><h1>{escape(title)}</h1>{body_html}</body></html>"
    )
    response = web.Response(text=html, status=status, content_type="text/html", charset="utf-8")
    response.headers.update(
        {
            "Content-Security-Policy": _CSP,
            "Cache-Control": "no-store",
            "Referrer-Policy": "no-referrer",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Cross-Origin-Opener-Policy": "same-origin",
            "Cross-Origin-Resource-Policy": "same-origin",
        }
    )
    if headers:
        response.headers.update(headers)
    return response


def back_link(return_url: str) -> str:
    if not return_url:
        return "<p>Go back to the hub and open the console again from the site's page.</p>"
    return f'<p><a href="{escape(return_url, quote=True)}" rel="noreferrer">Back to the site in the hub</a></p>'


def opening() -> web.Response:
    return page(
        "Opening the remote console",
        '<p>One moment. <a href="/">Continue</a> if nothing happens.</p>',
        head='<meta http-equiv="refresh" content="0;url=/">',
    )


def ended(return_url: str = "", *, status: int = 200, headers: dict | None = None) -> web.Response:
    return page(
        "This remote console session has ended",
        "<p>Remote console sessions are short and end when you sign out of the hub, when someone ends them "
        "there, or when the gateway drops its connection.</p>" + back_link(return_url),
        status=status,
        headers=headers,
    )


def refused(title: str, detail: str, *, status: int, headers: dict | None = None) -> web.Response:
    return page(title, f"<p>{escape(detail)}</p>", status=status, headers=headers)
