"""Resource-limit wiring at Dolly's service boundary."""

import socket
from types import MethodType, SimpleNamespace

import falcon
from hio.base import tyming
from hio.core import tcp

from dolly import netting
from dolly import serving


def test_http_tcp_and_client_budgets_are_explicit():
    server = netting.boundedHttpServer("127.0.0.1", 0, falcon.App())
    try:
        assert server.requestHeaderLimit == 64 * 1024
        assert server.requestBodyLimit == 8 * 1024 * 1024
        assert server.requestTimeout == 20.0
        assert server.servant.maxConnections == 128
        assert server.servant.acceptsPerTurn == 16
        assert server.servant.rxbsLimit == 9 * 1024 * 1024
        assert server.servant.rxbsPerTurn == 64 * 1024
        assert netting.clientLimits()["responseBodyLimit"] == 8 * 1024 * 1024
        assert netting.tcpServerLimits()["rxbsPerTurn"] == 64 * 1024
        assert netting.MAX_SUBMISSIONS == 4096
        assert netting.MAX_OUTBOUND_REQUESTS_PER_TURN == 8
        assert netting.OUTBOUND_RETRY_MAXIMUM == 300.0
    finally:
        server.close()


def test_tcp_listener_admits_only_one_turn_budget():
    """The deployed Dolly TCP settings cap actual accepts at 16 per service turn."""
    server = tcp.Server(ha=("127.0.0.1", 0), **netting.tcpServerLimits())
    clients = []
    try:
        assert server.reopen()
        address = server.ss.getsockname()
        for _ in range(netting.ACCEPTS_PER_TURN + 1):
            clients.append(socket.create_connection(address))
        server.serviceAccepts()
        assert len(server.axes) == netting.ACCEPTS_PER_TURN
        assert server.connectionCount() == netting.ACCEPTS_PER_TURN
        server.serviceAccepts()
        assert len(server.axes) == netting.ACCEPTS_PER_TURN + 1
    finally:
        while server.axes:
            accepted, _ = server.axes.popleft()
            accepted.close()
        server.close()
        for client in clients:
            client.close()


class Store:
    """Minimal tuple-key store used to drive the real Dolly work generator."""
    def __init__(self, values=()):
        self.values = dict(values)

    def get(self, keys):
        return self.values.get(keys)


def workContext(records):
    """Build a scheduler-only Context over deterministic durable rows."""
    exns = Store(((record.grant,), SimpleNamespace(
        said=record.grant, pvrsn=SimpleNamespace(major=2)))
        for _, record in records)
    context = object.__new__(serving.Context)
    context.db = SimpleNamespace(
        submissions=SimpleNamespace(
            getTopItemIter=lambda: iter(records),
            pin=lambda keys, record: None))
    context.hby = SimpleNamespace(
        db=SimpleNamespace(exns=exns, epse=Store()), kevers={})
    context.hab = object()
    context.acdcV2Ipex = SimpleNamespace(
        _presentationRegistries=lambda serder: [])
    context.fresh = lambda regid: False
    context.observer = "https://observer.invalid"
    context.observerTrust = object()
    context.webhook = "https://webhook.invalid"
    context.process = MethodType(lambda self: None, context)
    context.observe = MethodType(lambda self, regid, response: None, context)
    context._deliveryFailures, context._deliveryRetry = {}, {}
    context._registryCursor = context._deliveryCursor = None
    return context


def test_work_loop_rotates_past_eight_unresponsive_registries(monkeypatch):
    """Failed first-turn pulls cannot starve registry candidates nine onward."""
    records = [((f"grant-{index:02}",), SimpleNamespace(
        grant=f"grant-{index:02}", state="pending", delivered=False))
        for index in range(12)]
    context = workContext(records)
    calls = []

    monkeypatch.setattr(serving.exchanging, "verify", lambda hby, exn: None)
    monkeypatch.setattr(serving.exchanging, "loadParsedNestedSubstreams",
                        lambda hby, said: [SimpleNamespace(
                            serder=SimpleNamespace(regid=said.replace("grant", "registry")),
                            ssts=[])])
    monkeypatch.setattr(serving, "issuerRegistry", lambda serder: serder.regid)
    monkeypatch.setattr(serving, "signedQuery",
                        lambda hab, route, query: query["i"])

    def request(self, url, *, body=None, data=None, trust=None):
        calls.append(body)
        if False:
            yield
        return None

    context.request = MethodType(request, context)
    tymist = tyming.Tymist(tyme=0.0)
    work = context.workDo(tymth=tymist.tymen(), tock=0.0)
    next(work)
    next(work)
    assert calls == [f"registry-{index:02}" for index in range(8)]

    tymist.tick(tock=1.1)
    next(work)
    assert calls[8:12] == [f"registry-{index:02}" for index in range(8, 12)]
    work.close()


def test_webhook_socket_failure_is_contained_and_backed_off(monkeypatch):
    """A webhook OSError retains its durable row and enters bounded retry."""
    record = SimpleNamespace(
        grant="grant-00", state="accepted", delivered=False, payload={"ok": True})
    context = workContext([((record.grant,), record)])
    calls = []

    def request(self, url, *, body=None, data=None, trust=None):
        calls.append(url)
        if False:
            yield
        raise OSError("connection refused")

    context.request = MethodType(request, context)
    tymist = tyming.Tymist(tyme=0.0)
    work = context.workDo(tymth=tymist.tymen(), tock=0.0)
    next(work)
    next(work)
    assert calls == [context.webhook]
    assert not record.delivered
    assert context._deliveryFailures == {record.grant: 1}
    assert context._deliveryRetry == {record.grant: netting.OUTBOUND_RETRY_INITIAL}

    tymist.tick(tock=1.1)
    next(work)
    assert calls == [context.webhook]
    work.close()
