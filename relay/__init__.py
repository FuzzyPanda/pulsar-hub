"""The remote-console relay: a small asynchronous service beside the hub's web workers.

It holds each gateway's outbound tunnel (a WebSocket the gateway opened) and carries a signed-in
person's browser requests down it to that gateway's own web console. It holds no business logic
and no database connection: it asks the hub's web service, over the internal Docker network,
whether a credential, a hand-off token or a session is valid, and tells it what happened. The
wire contract is `docs/CONTRACTS.md`, "Remote console"; the hub's side of the decisions is
`hub/console/`.

Nothing here imports Django, and the container that runs it is given no database credentials.
"""
