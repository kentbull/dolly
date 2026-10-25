"""Dolly's bounded application work and durable delivery retries."""

from types import MethodType, SimpleNamespace

from hio.base import tyming

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
    assert context._deliveryRetry == {record.grant: serving.OUTBOUND_RETRY_INITIAL}

    tymist.tick(tock=1.1)
    next(work)
    assert calls == [context.webhook]
    work.close()
