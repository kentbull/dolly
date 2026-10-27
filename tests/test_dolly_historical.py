"""Dolly historical inspection preserves proof validity and reporting policy.

The bound-graph construction adapts test_bound_state_profile's real anchored
history. Independent verifier/observer stores add application policy, retained
disclosure, actual webhook silence, and reopen without replay.
"""
from copy import deepcopy
from dataclasses import asdict
import json
from pathlib import Path

import falcon
from falcon import testing
from hio.base import doing
from hio.core import http, tcp
import pytest

from keri import Kinds, Vrsn_2_0
from keri.acdc import Regery, Registrar, acdcmap, blindate, grant, sectattr
from keri.acdc.regbasing import RegBaser
from keri.acdc.sectioning import SectionBaser
from dolly.serving import Context as Dolly, DollyBaser
from keri.app.evidencing import EvidenceContext, signedQuery
from keri.app.habbing import Habery, openHby
from keri.app.configing import Configer
from keri.app.keeping import Keeper
from keri.db.basing import Baser
from keri.app.httping import CESR_CONTENT_TYPE
from keri.core import Blinder, Codens, Compactor, Counter, Diger, Noncer, Number, SealSource, messagize
from keri.kering import MissingAnchorError, MissingChainError, ValidationError
from keri.peer import exchanging
from keri.vdr import eventing as legacy, verifying
from kfobserver.core.evidence import Context as Observer
from kfobserver.core.evidence_observing import ObservationBaser


SERVER_TLS = Path(__file__).with_name('tls') / 'server.pem'


def observerTrust(url):
    """Return explicit source trust for historical-mode contexts."""
    return dict(url=url, cafilepath=str(SERVER_TLS))


def frame_v2_events(*events):
    """Frame public ACDC v2 messages with explicit empty attachment groups."""
    foot = Counter(Codens.AttachmentGroup, count=0, version=Vrsn_2_0).qb64b
    return b''.join(event.raw + foot for event in events)


def test_retained_grant_opaque_successor_stays_historical_and_pending(tmp_path, monkeypatch):
    """A later undisclosed state cannot erase retained proof or authorize a current hook."""
    received = []

    class Hook:
        def on_post(self, req, rep):
            received.append(req.media)
            rep.media = {'received': True}

    app = falcon.App()
    app.add_route('/hook', Hook())
    server = http.Server(servant=tcp.Server(ha=('127.0.0.1', 0)), app=app)
    assert server.reopen()
    server.servant.eha = server.servant.ha
    hook = f'http://127.0.0.1:{server.servant.ha[1]}/hook'

    def habery(name):
        kwa = dict(name=name, headDirPath=str(tmp_path), temp=False, reopen=True)
        return Habery(name=name, temp=True, version=Vrsn_2_0,
                      ks=Keeper(**kwa), db=Baser(**kwa), cf=Configer(**kwa))

    try:
        for phase in range(2):
            source, verifier, observer = (habery(name) for name in
                ('opaque-source', 'opaque-dolly', 'opaque-observer'))
            issuer = source.habByName('issuer') or source.makeHab(name='issuer')
            dhab = verifier.habByName('dolly') or verifier.makeHab(name='dolly')
            rgy = Regery(source, baser=RegBaser(name=source.name,
                headDirPath=str(tmp_path), temp=False))
            dolly = Dolly(verifier, dhab, issuers=[issuer.pre], schemas=[],
                fields={'shown': 'a/shown'}, required=['shown'],
                observer=observerTrust('https://observer.test/'), webhook=hook,
                db=DollyBaser(name=verifier.name, headDirPath=str(tmp_path), temp=False),
                evidence=EvidenceContext(verifier, reger=RegBaser(name=verifier.name,
                    headDirPath=str(tmp_path), temp=False)),
                legacy=verifying.Verifier(verifier, reger=legacy.Reger(name=verifier.name,
                    headDirPath=str(tmp_path), temp=False)),
                sections=SectionBaser(name=verifier.name, headDirPath=str(tmp_path), temp=False))
            sourceURL = 'https://registrar.test/'
            obs = Observer(observer, readers=[dhab.pre], sources=[observerTrust(sourceURL)],
                reger=RegBaser(name=observer.name, headDirPath=str(tmp_path), temp=False),
                observations=ObservationBaser(name=observer.name,
                    headDirPath=str(tmp_path), temp=False))
            try:
                paths = [owner.path for hby in (source, verifier, observer)
                         for owner in (hby.ks, hby.db, hby.cf)]
                paths += [rgy.baser.path, dolly.db.path, dolly.evidence.reger.path,
                          dolly.legacy.reger.path, dolly.sections.path,
                          obs.reger.path, obs.observations.path]
                assert all(Path(path).is_relative_to(tmp_path) for path in paths)
                if phase == 0:
                    registry = rgy.makeRegistry('issuer-registry', issuer.pre)
                    rip = rgy.store.event(registry.regk)
                    issuer.interact(data=[dict(d=rip.said)], version=Vrsn_2_0)
                    assert registry.anchorMsg(rip.said)
                    credential = acdcmap(israid=issuer.pre, regid=registry.regk,
                        attribute=dict(d='', shown='retained value'))
                    first, event1 = Registrar(rgy).issue(registry, acdc=credential)
                    issuer.interact(data=[dict(d=event1.said)], version=Vrsn_2_0)
                    assert registry.anchorMsg(event1.said)
                    public = issuer.replay(gvrsn=Vrsn_2_0) + frame_v2_events(rip, event1)
                    dolly.schemas.add(credential.schema['$id'])
                    dolly.ingest(public)
                    proofed = messagize(credential, bonds=[first.data], gvrsn=Vrsn_2_0)
                    exn, atc = grant(issuer, dhab.pre, 'retain first state', origin=proofed)
                    assert dolly.ingest(exn.raw + atc) == [dict(grant=exn.said, state='pending')]
                    expected = dolly.inspectHistorical(exn.said)
                    retained = tuple(verifier.db.enst.get((exn.said,)))
                    _, opaque = Registrar(rgy).issue(registry, acdc=credential, state='revoked')
                    issuer.interact(data=[dict(d=opaque.said)], version=Vrsn_2_0)
                    assert registry.anchorMsg(opaque.said)
                    public = issuer.replay(gvrsn=Vrsn_2_0) + frame_v2_events(rip, event1, opaque)
                    dolly.ingest(public)
                else:
                    registry = rgy.registryByName('issuer-registry')
                    dolly.schemas.add(credential.schema['$id'])
                assert dolly.inspectHistorical(exn.said) == expected
                assert tuple(verifier.db.enst.get((exn.said,))) == retained
                obs.ingest(dhab.replay(gvrsn=Vrsn_2_0))
                assert not obs.observe(sourceURL, public)['rejected']
                response = testing.TestClient(obs.app).simulate_post('/',
                    body=signedQuery(dhab, 'tels', {'i': registry.regk}),
                    headers={'Content-Type': CESR_CONTENT_TYPE})
                assert dolly.observe(registry.regk, dict(status=response.status_code,
                    body=response.content, headers={k.lower(): v for k, v in response.headers.items()}))
                assert dolly.fresh(registry.regk)
                # Inject only the application's current verifier boundary. Core
                # recovery/anchor verification is exercised in its own real-owner tests.
                missing = MissingAnchorError('current registry anchor is unavailable')

                def missing_anchor(*args, **kwa):
                    raise missing

                with monkeypatch.context() as patch:
                    patch.setattr('dolly.serving.vetBinds', missing_anchor)
                    dolly.process()
                    assert dolly.db.submissions.get((exn.said,)).state == 'pending'
                    with pytest.raises(MissingChainError) as error:
                        dolly._acdcV2GrantCredential(verifier.db.exns.get((exn.said,)))
                    assert error.value.__cause__ is missing
                dolly.process()
                submission = dolly.db.submissions.get((exn.said,))
                assert submission.state == 'pending'
                assert not submission.payload and not submission.delivered
                with pytest.raises(MissingChainError, match='undisclosed'):
                    dolly._acdcV2GrantCredential(verifier.db.exns.get((exn.said,)))
                doing.Doist(real=True, tock=0.01, limit=0.2).do(
                    doers=[http.ServerDoer(server=server), dolly])
                assert received == []
            finally:
                obs.close()
                dolly.close()
                rgy.close()
                for hby in (observer, verifier, source):
                    hby.close()
    finally:
        server.close()


def test_historical_bound_graph_inspection_is_not_current_reporting(tmp_path):
    """Inspect valid historical authority after revocation without issuing a hook.

    Far issuance binds Issuee event 0, near issuance anchors in event 1, and far
    revocation binds event 1. The core establishes that historical relationship;
    Dolly's default still refuses current reporting of the revoked far node.
    Inspection makes no observation/freshness claim and survives a full reopen.
    """
    received = []

    class Hook:
        """Record any attempted acceptance delivery through a real HTTP server."""

        def on_post(self, req, rep):
            """Capture the request so inspection cannot hide an accidental hook."""
            received.append(req.media)
            rep.media = {'received': True}

    app = falcon.App()
    app.add_route('/hook', Hook())
    server = http.Server(servant=tcp.Server(ha=('127.0.0.1', 0)), app=app)
    assert server.reopen()
    server.servant.eha = server.servant.ha
    hook = f'http://127.0.0.1:{server.servant.ha[1]}/hook'
    try:
        with (openHby(name='historical-source', version=Vrsn_2_0) as source,
              openHby(name='historical-observer', version=Vrsn_2_0) as observer):
            authority = source.makeHab(name='authority')
            issuer = source.makeHab(name='issuer')
            rgy = Regery(source, name=source.name, temp=True)
            try:
                registry = Registrar(rgy).makeRegistry(name='authority', prefix=authority.pre)
                rip = rgy.store.event(registry.regk)
                authority.interact(data=[dict(s=rip.sad['n'], d=rip.said)])
                assert registry.anchorMsg(rip.said)
                far = acdcmap(israid=authority.pre, iseaid=issuer.pre, regid=registry.regk,
                              attribute=dict(d='', role='historical delegation'))
                full = acdcmap(israid=issuer.pre, uuid=Noncer().qb64,
                    edge=dict(d='', authority=dict(n=far.said)),
                    attribute={'d': '', 'u': Noncer().qb64,
                        'shown': {'d': '', 'value': 'historically authorized'},
                        'private': {'d': '', 'value': 'not-in-this-grant'}})
                compact = Compactor(mad=deepcopy(full.sad['a']), makify=True, kind=Kinds.json)
                compact.compact(paths=['a/shown/'], root='a')
                near = acdcmap(israid=issuer.pre, uuid=full.sad['u'], schema=full.schema,
                    edge=full.sad['e'], attribute=compact.partials[('a/shown/',)].mad)
                assert near.said == full.said

                def publish(state):
                    """Anchor a real far-state update bound to the Issuee's current KEL event."""
                    keyEvent = issuer.kever.serder
                    opening = Blinder.blind(acdc=far.said, state=state, bound=True,
                                           bsn=keyEvent.sn, bd=keyEvent.said)
                    event = blindate(registry.regk, registry.regd, opening.said,
                                     sn=registry.sn + 1)
                    registry.processEvent(event)
                    authority.interact(data=[dict(s=event.sad['n'], d=event.said)])
                    assert registry.anchorMsg(event.said)
                    return opening, event

                issued, issueEvent = publish('issued')
                issuer.interact(data=[dict(d=near.said)])
                nearSource = SealSource(Number(num=issuer.kever.sn), Diger(qb64=issuer.kever.serder.said))
                revoked, revokeEvent = publish('revoked')
                public = authority.replay(gvrsn=Vrsn_2_0) + issuer.replay(gvrsn=Vrsn_2_0)
                public += frame_v2_events(rip, issueEvent, revokeEvent)
                proofNear = messagize(near, bonds=[nearSource], framed=False, gvrsn=Vrsn_2_0)
                proofFar = messagize(far, bonds=[issued.data, revoked.data], framed=False, gvrsn=Vrsn_2_0)
                plan = {'dp': [[near.schema['$id'], '/', []],
                               [far.schema['$id'], '/e/authority/_/', []]]}
                expected = None
                for phase in range(2):
                    with openHby(name='historical-dolly', temp=False,
                                 headDirPath=str(tmp_path), version=Vrsn_2_0) as verifier:
                        dhab = verifier.habByName('dolly') or verifier.makeHab(name='dolly')
                        dolly = Dolly(verifier, dhab, issuers=[issuer.pre, authority.pre],
                            schemas=[near.schema['$id']], fields={'shown': 'a/shown/value',
                            'private': 'a/private/value'}, required=['shown'],
                            observer=observerTrust(f'https://observer-{phase}.test/'), webhook=hook,
                            db=DollyBaser(name=verifier.name, headDirPath=str(tmp_path), temp=False),
                            evidence=EvidenceContext(verifier, reger=RegBaser(name=verifier.name,
                                headDirPath=str(tmp_path), temp=False)),
                            legacy=verifying.Verifier(verifier, reger=legacy.Reger(name=verifier.name,
                                headDirPath=str(tmp_path), temp=False)),
                            sections=SectionBaser(name=verifier.name, headDirPath=str(tmp_path), temp=False))
                        try:
                            if phase == 0:
                                dolly.ingest(public)
                                exn, atc = grant(issuer, dhab.pre, 'historical bound graph',
                                    origin=proofNear, artifacts=[proofFar], modifiers=plan)
                                assert dolly.ingest(exn.raw + atc) == [dict(grant=exn.said, state='pending')]
                            assert dolly.acdcV2Ipex.verifyAccepted(exn.said, historical=True)
                            assert not dolly.fresh(registry.regk)
                            before = asdict(dolly.db.submissions.get((exn.said,)))
                            inspected = dolly.inspectHistorical(exn.said)
                            assert asdict(dolly.db.submissions.get((exn.said,))) == before
                            assert inspected['purpose'] == 'historical-evidence'
                            assert inspected['proofValidity'] == 'valid'
                            assert inspected['currentStanding'] == 'not-evaluated'
                            assert inspected['business'] == {'shown': 'historically authorized', 'private': None}
                            assert inspected['disclosure']['private'] == 'undisclosed'
                            assert 'not-in-this-grant' not in json.dumps(inspected)
                            assert 'acceptedAt' not in inspected
                            nearRef, farRef = inspected['sources']
                            assert nearRef == dict(credential=near.said, view=Diger(ser=near.raw).qb64,
                                                   boundEvents=[])
                            assert farRef == dict(credential=far.said, view=Diger(ser=far.raw).qb64,
                                boundEvents=[dict(registry=registry.regk, s=event.sad['n'], d=event.said,
                                    blid=proof.said, issuee=issuer.pre,
                                    keyEvent=dict(s=proof.bnh, d=proof.bd))
                                    for proof, event in [(issued, issueEvent), (revoked, revokeEvent)]])
                            if phase == 0:
                                expected = inspected
                                sourceURL = 'https://registrar.test/'
                                obs = Observer(observer, readers=[dhab.pre],
                                    sources=[observerTrust(sourceURL)])
                                try:
                                    obs.ingest(dhab.replay(gvrsn=Vrsn_2_0))
                                    assert not obs.observe(sourceURL, public)['rejected']
                                    response = testing.TestClient(obs.app).simulate_post('/',
                                        body=signedQuery(dhab, 'tels', {'i': registry.regk}),
                                        headers={'Content-Type': CESR_CONTENT_TYPE})
                                    report = dict(status=response.status_code, body=response.content,
                                        headers={key.lower(): value for key, value in response.headers.items()})
                                    assert dolly.observe(registry.regk, report)
                                finally:
                                    obs.close()
                                dolly.process()
                                refused = dolly.db.submissions.get((exn.said,))
                                assert refused.state == 'rejected'
                                assert refused.reason == 'credential is not currently issued'
                                assert refused.payload == {} and not refused.delivered
                                assert dolly.inspectHistorical(exn.said) == expected
                                # An undisclosed later authority update cannot rewrite
                                # the retained bound graph's selected proof prefix.
                                _, opaqueEvent = publish('issued')
                                dolly.ingest(authority.replay(gvrsn=Vrsn_2_0)
                                    + frame_v2_events(opaqueEvent))
                                assert dolly.inspectHistorical(exn.said) == expected
                                # Generic EXN authentication retains this real envelope,
                                # but its missing issuance opening cannot prove the graph.
                                incomplete = messagize(far, bonds=[revoked.data],
                                                       framed=False, gvrsn=Vrsn_2_0)
                                invalid, invalidAtc = grant(issuer, dhab.pre, 'incomplete bound graph',
                                    origin=proofNear, artifacts=[incomplete], modifiers=plan)
                                generic = exchanging.Exchanger(verifier, handlers=[])
                                dolly._parser(Vrsn_2_0).parse(ims=bytearray(invalid.raw + invalidAtc), exc=generic)
                                assert generic.complete(invalid.said)
                            else:
                                assert inspected == expected  # No KEL/TEL/grant replay on reopen.
                                with pytest.raises(MissingChainError, match='observer evidence'):
                                    dolly._acdcV2GrantCredential(exn)
                            with pytest.raises(ValidationError, match='proof or semantics'):
                                dolly.inspectHistorical(invalid.said)
                            assert dolly.db.submissions.get((invalid.said,)) is None
                            # Fuller cached evidence cannot widen historical inspection.
                            dolly.ingest(frame_v2_events(sectattr(full.sad['a'])))
                            assert dolly.inspectHistorical(exn.said) == expected
                            doing.Doist(real=True, tock=0.01, limit=0.2).do(
                                doers=[http.ServerDoer(server=server), dolly])
                            assert received == []
                        finally:
                            dolly.close()
            finally:
                rgy.close()
    finally:
        server.close()
