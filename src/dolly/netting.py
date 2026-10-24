"""Explicit transport budgets for Dolly's public and source connections."""

from keri.app.indirecting import createHttpServer


HTTP_HEADER_LIMIT = 64 * 1024
HTTP_BODY_LIMIT = 8 * 1024 * 1024
HTTP_RX_BUFFER_LIMIT = 9 * 1024 * 1024
HTTP_REQUEST_TIMEOUT = 20.0
CONNECTION_IDLE_TIMEOUT = 30.0
MAX_CONNECTIONS = 128
ACCEPTS_PER_TURN = 16
RX_BYTES_PER_TURN = 64 * 1024
MAX_RESPONSE_BODY = 8 * 1024 * 1024
MAX_SUBMISSIONS = 4096
MAX_OUTBOUND_REQUESTS_PER_TURN = 8
OUTBOUND_RETRY_INITIAL = 5.0
OUTBOUND_RETRY_MAXIMUM = 300.0


def boundedHttpServer(host, port, app, *, keypath=None, certpath=None,
                      cafilepath=None):
    """Create KERIpy's HTTP/TLS server with finite HIO ingress budgets."""
    server = createHttpServer(host=host, port=port, app=app, keypath=keypath,
                              certpath=certpath, cafilepath=cafilepath)
    server.requestHeaderLimit = HTTP_HEADER_LIMIT
    server.requestBodyLimit = HTTP_BODY_LIMIT
    server.requestTimeout = HTTP_REQUEST_TIMEOUT
    server.servant.tymeout = CONNECTION_IDLE_TIMEOUT
    server.servant.maxConnections = MAX_CONNECTIONS
    server.servant.acceptsPerTurn = ACCEPTS_PER_TURN
    server.servant.rxbsLimit = HTTP_RX_BUFFER_LIMIT
    server.servant.rxbsPerTurn = RX_BYTES_PER_TURN
    return server


def clientLimits():
    """Return finite HIO response and unread-buffer limits for HTTP clients."""
    return dict(responseBodyLimit=MAX_RESPONSE_BODY,
                rxbsLimit=HTTP_RX_BUFFER_LIMIT)


def tcpServerLimits():
    """Return finite HIO connection, admission, and receive budgets for raw TCP."""
    return dict(tymeout=CONNECTION_IDLE_TIMEOUT,
                maxConnections=MAX_CONNECTIONS,
                acceptsPerTurn=ACCEPTS_PER_TURN,
                rxbsLimit=HTTP_RX_BUFFER_LIMIT,
                rxbsPerTurn=RX_BYTES_PER_TURN)
