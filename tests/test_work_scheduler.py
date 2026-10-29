"""Dolly's bounded application work and durable delivery retries."""

from types import MethodType, SimpleNamespace

import pytest

from hio.base import doing, tyming
from hio.core import http, tcp

from dolly import serving


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
    context.synchronized = lambda regid: False
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


def test_webhook_request_failure_is_backed_off(monkeypatch):
    """A substituted request-generator OSError retains its row and enters retry."""
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
    assert context._deliveryRetry == {record.grant: serving.OUTBOUND_RETRY_INITIAL}

    tymist.tick(tock=1.1)
    next(work)
    assert calls == [context.webhook]
    work.close()


@pytest.mark.parametrize('scope', ['webhook', 'observer'])
def test_scheduled_client_failure_preserves_next_request_and_cancellation(monkeypatch, scope):
    """Actual child faults fail one request; healthy work and cancellation still run."""
    context = object.__new__(serving.Context)
    context.clients, context.timeout = set(), 0.5
    results, clients, owners, cancelled, closed = [], [], [], [], []
    # Select observer ownership without performing a TLS handshake; real wrong-CA
    # and hostname failures remain covered by test_dolly's socket/TLS workflow.
    trust = SimpleNamespace(cafilepath=None, certedhost=None) if scope == 'observer' else None

    def requester(tymth=None, tock=0.01, **kwa):
        yield tock
        results.append((yield from context.request('http://127.0.0.1:1/',
            data={'failed': True}, trust=trust)))
        results.append((yield from context.request('http://127.0.0.1:1/',
            data={'healthy': True})))
        try:
            yield from context.request('http://127.0.0.1:1/', data={'cancelled': True})
        finally:
            cancelled.append(True)

    doing.DoDoer.__init__(context, doers=[doing.doify(requester)], tock=0.01)

    def service(client):
        if client not in clients:
            clients.append(client)
            owners.append(next(owner for owner in context.doers
                               if getattr(owner, 'client', None) is client))
        index = clients.index(client)
        if index == 0 and scope == 'webhook':
            raise OSError('scheduled socket send failed')
        client.waited = True
        if index == 0:
            client.connector.rxbs.extend(
                b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nnot-hex\r\n')
        elif index == 1:
            client.connector.rxbs.extend(b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}')
        # Feed wire bytes through the actual HIO respondent/chunk parser. The
        # service/socket substitutions avoid external I/O, not the failing parser.
        client.serviceResponse()

    original_close = http.clienting.Client.close

    def close(client):
        if client in clients:
            closed.append(client)
        original_close(client)

    monkeypatch.setattr(http.clienting.Client, 'close', close)
    monkeypatch.setattr(http.clienting.Client, 'reopen', lambda client: True)
    monkeypatch.setattr(http.clienting.Client, 'service', service)
    monkeypatch.setattr(tcp.clienting.Client, 'serviceReceives', lambda client: None)
    doing.Doist(tock=0.01, limit=0.2).do(doers=[context])
    assert results[0] is None and results[1]['status'] == 200
    assert isinstance(owners[0].error, OSError if scope == 'webhook' else ValueError)
    assert owners[0].done is True
    assert cancelled == [True] and len(clients) == 3
    assert not context.clients and not context.deeds
    assert all(client in closed for client in clients)
    assert all(client.connector.cs is None for client in clients)
