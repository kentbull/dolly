"""Dolly acceptance requires actual protocol proofs and actual webhook HTTP."""
import json
from dataclasses import asdict
from pathlib import Path
import ssl

import falcon
import pytest
from hio.base import doing
from hio.core import http, tcp

from keri import Vrsn_1_0, Vrsn_2_0, Kinds
from keri.acdc import acdcmap, blindate, regcept, grant
from keri.app.evidencing import EvidenceContext, signedQuery
from keri.app.habbing import openHby
from dolly.serving import Context as Dolly, TcpIntake
from keri.app.httping import CESR_CONTENT_TYPE, CESR_ATTACHMENT_HEADER
from keri.core import (Blinder, Noncer, Compactor, messagize, Counter, Codens, Number, Diger,
                       SealSource, SealEvent, SerderKERI, Schemer, Parser)
from keri.peer import exchanging
from keri.vdr import eventing as legacy, verifying
from keri.vc import proving, protocoling
from keri.acdc import Regery, Registrar as AcdcV2Registrar, apply, offer, agree, admit
from keri.acdc.sectioning import SectionBaser
from keri.app.credentialing import Wallet
from keri.cli.common.acdc_v2_ipex import Peer, Intake
from keri.help import helping
from kfobserver.core.evidence import Context as Observer
from kfobserver.core.evidence_observing import RegistrarPuller, SourceTrust
from kfregistrar.core.serving import makeContext as makeRegistrar


TLS_DIR = Path(__file__).with_name('tls')
SERVER_TLS = TLS_DIR / 'server.pem'
WRONG_TLS = TLS_DIR / 'client.pem'


def observerTrust(url, *, cafilepath=SERVER_TLS, certedhost=None):
    """Return the explicit HTTPS source trust used by Dolly tests."""
    trust = dict(url=url, cafilepath=str(cafilepath))
    if certedhost is not None:
        trust['certedhost'] = certedhost
    return trust


def tlsServer(app, certificate=SERVER_TLS):
    """Open an HIO HTTPS server with the repository's one-way TLS fixture."""
    servant = tcp.ServerTls(host='127.0.0.1', port=0, keypath=str(certificate),
                            certpath=str(certificate), certify=ssl.CERT_NONE)
    server = http.Server(servant=servant, app=app)
    assert server.reopen()
    server.servant.eha = server.servant.ha
    return server


def registrarContext(hby, *, observers=()):
    """Return the KF registrar's observer-facing full-evidence service."""
    ctx = makeRegistrar(hby, observers=observers, fullEvidence=True)
    ctx.app = ctx.externalApp
    return ctx


def frame_v2_events(*events):
    """Frame ACDC v2 public evidence with an explicit empty attachment group."""
    empty = Counter(Codens.AttachmentGroup, count=0, version=Vrsn_2_0).qb64b
    return b''.join(event.raw + empty for event in events)


def test_empty_grant_is_refused_and_later_grants_report_after_reopen(tmp_path):
    """Refuse an empty bare Grant and prove valid later hooks across a full reopen.

    Independent sender and persistent verifier stores exercise real EXN/KRAM
    verification. Each run refuses an empty bare Grant at authoring, then sends
    a reportable Grant through the normal intake/Doer path.
    """
    from keri.acdc.regbasing import RegBaser
    from dolly.serving import DollyBaser

    received = []

    class Hook:
        """Record webhook requests received by a real local HTTP server."""

        def on_post(self, req, rep):
            """Capture the delivered projection and acknowledge it to Dolly."""
            received.append(req.media)
            rep.media = {'received': True}

    app = falcon.App()
    app.add_route('/hook', Hook())
    server = http.Server(servant=tcp.Server(ha=('127.0.0.1', 0)), app=app)
    assert server.reopen()
    server.servant.eha = server.servant.ha
    url = f'http://127.0.0.1:{server.servant.ha[1]}/hook'
    try:
        with openHby(name='empty-grant-issuer', version=Vrsn_2_0) as issuer:
            ihab = issuer.makeHab(name='issuer')
            credential = acdcmap(israid=ihab.pre, attribute=dict(d='', status='authorized'))
            proof = messagize(credential, tsgs=[(ihab.kever.prefixer,
                Number(sn=ihab.kever.lastEst.s), Diger(qb64=ihab.kever.lastEst.d),
                ihab.sign(credential.raw))], framed=False, gvrsn=Vrsn_2_0)
            grants = []
            for phase in range(2):
                with openHby(name='empty-grant-dolly', temp=False,
                             headDirPath=str(tmp_path), version=Vrsn_2_0) as verifier:
                    dhab = verifier.habByName('dolly') or verifier.makeHab(name='dolly')
                    evidence = EvidenceContext(verifier, reger=RegBaser(name='empty-grant-dolly',
                        headDirPath=str(tmp_path), temp=False))
                    dolly = Dolly(verifier, dhab, issuers=[ihab.pre],
                        schemas=[credential.schema['$id']], fields={'status': 'a/status'},
                        observer=observerTrust('https://unused.test/'), webhook=url, evidence=evidence,
                        legacy=verifying.Verifier(
                            verifier, reger=legacy.Reger(name='empty-grant-dolly',
                                headDirPath=str(tmp_path), temp=False)),
                        db=DollyBaser(name='empty-grant-dolly', headDirPath=str(tmp_path), temp=False))
                    try:
                        if phase:
                            for normal in grants:
                                assert dolly.db.submissions.get((normal.said,)).delivered
                        with pytest.raises(ValueError, match='bare Grant'):
                            grant(ihab, dhab.pre, f'empty {phase}')
                        normal, natc = grant(ihab, dhab.pre, f'normal {phase}', origin=proof)
                        result = dolly.ingest(
                            ihab.replay(gvrsn=Vrsn_2_0) + normal.raw + natc)
                        assert result == [dict(grant=normal.said, state='accepted')]
                        doing.Doist(real=True, tock=0.01, limit=0.4).do(
                            doers=[http.ServerDoer(server=server), dolly])
                        assert [item['grant'] for item in received] == [
                            item.said for item in [*grants, normal]]
                        assert dolly.db.submissions.get((normal.said,)).delivered
                        grants.append(normal)
                    finally:
                        dolly.close()
    finally:
        server.close()


@pytest.mark.parametrize('attachmentHeader', [False, True])
def test_http_json_acdc_v2_registry_first_and_invalid_framing(attachmentHeader):
    """Accept JSON ACDC before KEL and reject malformed raw/header framing.

    Both transport forms preserve serialized evidence exactly. Acknowledged
    registry evidence remains unaccepted until the independently arriving KEL
    anchors it; rejected framing cannot alter the accepted registry head.
    """
    from falcon import testing
    from dolly.serving import IntakeEnd

    with (openHby(name='json-registry-issuer', version=Vrsn_2_0) as issuer,
          openHby(name='json-registry-dolly', version=Vrsn_2_0) as verifier):
        ihab, dhab = issuer.makeHab(name='issuer'), verifier.makeHab(name='dolly')
        rip = regcept(israid=ihab.pre, kind=Kinds.json)
        ihab.interact(data=[dict(s=rip.sad['n'], d=rip.said)])
        issued = blindate(regid=rip.said, prior=rip.said,
                         blid=Blinder.blind(acdc=Diger(ser=b'credential').qb64, state='issued').said)
        ihab.interact(data=[dict(s=issued.sad['n'], d=issued.said)])
        dolly = Dolly(verifier, dhab, issuers=[ihab.pre], schemas=[], fields={},
                      observer=observerTrust('https://unused.test/'), webhook='http://unused.test/')
        try:
            client = testing.TestClient(dolly.app)
            headers = {'Content-Type': CESR_CONTENT_TYPE}
            if attachmentHeader:
                atc = frame_v2_events(rip)[len(rip.raw):].decode('ascii')
                body, headers[CESR_ATTACHMENT_HEADER] = rip.raw, atc
                decoded, version = IntakeEnd.decode(body, atc, None)
                assert decoded == frame_v2_events(rip) and version == Vrsn_2_0
            else:
                body = frame_v2_events(rip, issued)
                assert IntakeEnd.decode(body, None, None) == (body, Vrsn_2_0)
            response = client.simulate_post('/ingest', body=body, headers=headers)
            assert response.status_code == 202
            assert dolly.rgy.store.head(rip.said) is None  # No KEL anchor yet.
            if attachmentHeader:
                assert client.simulate_post('/ingest', body=frame_v2_events(issued),
                    headers={'Content-Type': CESR_CONTENT_TYPE}).status_code == 202
            assert client.simulate_post('/ingest', body=ihab.replay(gvrsn=Vrsn_2_0),
                headers={'Content-Type': CESR_CONTENT_TYPE}).status_code == 202
            assert dolly.rgy.store.head(rip.said).qb64 == issued.said
            invalid = [
                (frame_v2_events(rip), {'CESR-Genus': '1'}),
                (frame_v2_events(rip), {'CESR-Genus': '3'}),
                (rip.raw[:-1], {}),
                (b'{broken', {}),
                (rip.raw, {CESR_ATTACHMENT_HEADER: '-???'}),
                (frame_v2_events(rip, issued), {CESR_ATTACHMENT_HEADER: ''}),
            ]
            for body, extra in invalid:
                response = client.simulate_post('/ingest', body=body,
                    headers={'Content-Type': CESR_CONTENT_TYPE, **extra})
                assert response.status_code == 400, (body, extra, response.text)
            assert client.simulate_post('/ingest', body=frame_v2_events(rip),
                headers={'Content-Type': 'application/json'}).status_code == 415
            assert dolly.rgy.store.head(rip.said).qb64 == issued.said
            assert list(dolly.db.submissions.getTopItemIter()) == []
        finally:
            dolly.close()


@pytest.mark.parametrize('arrival', ['before', 'after', 'restart'])
@pytest.mark.parametrize('schemaUse', ['own', 'edge'])
def test_dolly_independent_schema_http_arrival_preserves_disclosure(tmp_path, arrival, schemaUse):
    """Resolve own/edge schemas through HTTP and the reopened section owner.

    Arrival selects schema-before-grant, schema-after-grant, or schema after a
    full service/identity restart. The schema exists only in section messages;
    no legacy schema-cache preload or accepted-state injection is involved.
    A fuller cached attribute section must not enrich retained grants/hooks.
    """
    from copy import deepcopy
    from falcon import testing
    from keri.acdc import sectschema, sectattr
    from keri.acdc.regbasing import RegBaser
    from dolly.serving import DollyBaser

    name = f'dolly-sections-{schemaUse}-{arrival}'
    schemaMessage = sectschema({'$id': '', 'version': '1.0.0',
        'title': 'independently supplied Dolly schema', 'type': 'object'})
    schema = schemaMessage.sad['s']['$id']
    wrongSchema = sectschema({'$id': '', 'version': '1.0.0',
        'title': 'different schema does not satisfy the reference', 'type': 'object'})
    received = []

    class Hook:
        """Receive actual HTTP projections after the schema dependency clears."""

        def on_post(self, req, rep):
            """Capture the exact payload and acknowledge its delivery."""
            received.append(req.media)
            rep.media = {'received': True}

    hookApp = falcon.App()
    hookApp.add_route('/hook', Hook())
    server = http.Server(servant=tcp.Server(ha=('127.0.0.1', 0)), app=hookApp)
    assert server.reopen()
    server.servant.eha = server.servant.ha
    webhook = f'http://127.0.0.1:{server.servant.ha[1]}/hook'
    try:
        with openHby(name=f'{name}-issuer', version=Vrsn_2_0) as issuer:
            ihab = issuer.makeHab(name='issuer')
            child = acdcmap(israid=ihab.pre, attribute=dict(d='', role='member'))
            edge = ({'d': '', 'member': {'d': '', 'n': child.said, 's': schema, 'o': 'NI2I'}}
                    if schemaUse == 'edge' else None)
            full = acdcmap(israid=ihab.pre, uuid=Noncer().qb64,
                schema=schema if schemaUse == 'own' else None, edge=edge,
                attribute={'d': '', 'u': Noncer().qb64,
                    'shown': {'d': '', 'value': 'visible'},
                    'private': {'d': '', 'value': 'only-in-cached-section'}})
            compact = Compactor(mad=deepcopy(full.sad['a']), makify=True, kind=Kinds.json)
            compact.compact(paths=['a/shown/'], root='a')
            partial = acdcmap(israid=full.israid, uuid=full.sad['u'], schema=full.schema,
                edge=edge, attribute=compact.partials[('a/shown/',)].mad)
            assert partial.said == full.said

            def signed(credential):
                """Attach a real independent issuer signature to one graph node."""
                return messagize(credential, tsgs=[(ihab.kever.prefixer,
                    Number(sn=ihab.kever.lastEst.s), Diger(qb64=ihab.kever.lastEst.d),
                    ihab.sign(credential.raw))], framed=False, gvrsn=Vrsn_2_0)

            for phase in range(2):
                with openHby(name=name, temp=False, headDirPath=str(tmp_path),
                             version=Vrsn_2_0) as verifier:
                    dhab = verifier.habByName('dolly') or verifier.makeHab(name='dolly')
                    sections = SectionBaser(name=name, headDirPath=str(tmp_path), temp=False)
                    dolly = Dolly(verifier, dhab, issuers=[ihab.pre],
                        schemas=[schema if schemaUse == 'own' else partial.schema['$id']],
                        fields={'shown': 'a/shown/value', 'private': 'a/private/value'},
                        required=['shown'], observer=observerTrust('https://unused.test/'), webhook=webhook,
                        evidence=EvidenceContext(verifier, reger=RegBaser(name=name,
                            headDirPath=str(tmp_path), temp=False)),
                        legacy=verifying.Verifier(verifier, reger=legacy.Reger(name=name,
                            headDirPath=str(tmp_path), temp=False)),
                        db=DollyBaser(name=name, headDirPath=str(tmp_path), temp=False),
                        sections=sections)
                    try:
                        client = testing.TestClient(dolly.app)

                        def post(raw, attachment=None):
                            """Pass raw/attachment-header evidence through actual WSGI intake."""
                            headers = {'Content-Type': CESR_CONTENT_TYPE}
                            if attachment is not None:
                                headers[CESR_ATTACHMENT_HEADER] = attachment
                            response = client.simulate_post('/ingest', body=raw, headers=headers)
                            assert response.status_code == 202, response.text

                        def section(message):
                            """Exercise JSON-first section framing in both HTTP forms."""
                            if schemaUse == 'edge':
                                post(message.raw, frame_v2_events(message)[len(message.raw):].decode('ascii'))
                            else:
                                post(frame_v2_events(message))

                        assert verifier.db.schema.get(schema) is None
                        if phase == 0:
                            post(ihab.replay(gvrsn=Vrsn_2_0))
                            # Framing success cannot turn an incomplete section
                            # or a wrong stream genus into schema evidence.
                            for raw, extra in [(schemaMessage.raw[:-1], {}),
                                    (frame_v2_events(schemaMessage), {'CESR-Genus': '1'})]:
                                response = client.simulate_post('/ingest', body=raw,
                                    headers={'Content-Type': CESR_CONTENT_TYPE, **extra})
                                assert response.status_code == 400
                            assert sections.messages.get(schemaMessage.said) is None
                            section(wrongSchema)
                            assert not list(sections.parts.getTopItemIter(('s', schema, '')))
                            if arrival == 'before':
                                section(schemaMessage)
                            plan = [[schema if schemaUse == 'own' else partial.schema['$id'], '/', []]]
                            if edge:
                                plan.append([child.schema['$id'], '/e/member/_/', []])
                            exn, atc = grant(ihab, dhab.pre, 'independent schema disclosure',
                                origin=signed(partial), artifacts=[signed(child)] if edge else None,
                                modifiers={'dp': plan})
                            post(exn.raw + atc)
                        if ((arrival != 'before' and phase == 0)
                                or (arrival == 'restart' and phase == 1)):
                            if schemaUse == 'own':
                                assert not dolly.exc.complete(exn.said)
                                assert verifier.db.emse.get((exn.said, schema)) is not None
                            else:
                                # An edge pin is a use dependency. Authentic Grant
                                # retention and historical inspection already succeed.
                                assert dolly.exc.complete(exn.said)
                                assert verifier.db.emse.get((exn.said, schema)) is None
                                assert dolly.inspectHistorical(exn.said)['proofValidity'] == 'valid'
                            assert dolly.db.submissions.get((exn.said,)).state == 'pending'
                            assert received == []
                            exact = exchanging.serializeMessage(verifier, exn.said) if schemaUse == 'edge' else None
                            if arrival == 'after' or phase:
                                section(schemaMessage)
                                if exact is not None:
                                    assert exchanging.serializeMessage(verifier, exn.said) == exact
                        if arrival == 'restart' and phase == 0:
                            continue
                        assert dolly.exc.complete(exn.said)
                        assert dolly.acdcV2Ipex.verifyAccepted(exn.said)
                        before = dolly.db.submissions.get((exn.said,)).payload
                        retained = exchanging.loadParsedNestedSubstreams(verifier, exn.said)[0].serder.raw
                        section(sectattr(full.sad['a']))
                        assert sections.messages.get(sectattr(full.sad['a']).said) is not None
                        assert dolly.acdcV2Ipex.verifyAccepted(exn.said)
                        assert exchanging.loadParsedNestedSubstreams(verifier, exn.said)[0].serder.raw == retained
                        assert dolly.db.submissions.get((exn.said,)).payload == before
                        doing.Doist(real=True, tock=0.01, limit=0.3).do(
                            doers=[http.ServerDoer(server=server), dolly])
                        assert received == [before]
                        assert before['business'] == {'shown': 'visible', 'private': None}
                        assert before['disclosure']['private'] == 'undisclosed'
                        assert 'only-in-cached-section' not in json.dumps(before)
                        assert verifier.db.schema.get(schema) is None
                    finally:
                        dolly.close()
                        assert not sections.opened
    finally:
        server.close()


def test_reopened_dolly_requires_active_observer_observation(tmp_path):
    """Keep authentic retained history while requiring the currently configured observer.

    Reopen the actual application/registry stores, change observer policy, and
    require a new eligible observation before current reporting is fresh."""
    from falcon import testing
    from keri.acdc.regbasing import RegBaser
    from dolly.serving import DollyBaser

    oldURL, newURL = 'https://observer.old.test/', 'https://observer.new.test/'
    with (openHby(name='dolly-source-issuer', version=Vrsn_2_0) as issuer,
          openHby(name='dolly-source-observer', version=Vrsn_2_0) as observer,
          openHby(name='dolly-source-reader', version=Vrsn_2_0) as verifier):
        ihab, dhab = issuer.makeHab(name='issuer'), verifier.makeHab(name='dolly')
        rip = regcept(israid=ihab.pre)
        ihab.interact(data=[dict(s=rip.sad['n'], d=rip.said)])
        credential = acdcmap(israid=ihab.pre, regid=rip.said, attribute=dict(d='', value='public'))
        blinder = Blinder.blind(acdc=credential.said, state='issued')
        issued = blindate(regid=rip.said, prior=rip.said, blid=blinder.said)
        ihab.interact(data=[dict(s=issued.sad['n'], d=issued.said)])
        public = ihab.replay(gvrsn=Vrsn_2_0) + frame_v2_events(rip, issued)
        sourceURL = 'https://registrar.test/'
        obs = Observer(observer, readers=[dhab.pre],
                       sources=[observerTrust(sourceURL)])
        obs.ingest(dhab.replay(gvrsn=Vrsn_2_0))
        assert not obs.observe(sourceURL, public)['rejected']
        cache = testing.TestClient(obs.app)
        response = cache.simulate_post('/', body=signedQuery(dhab, 'tels', {'i': rip.said}),
                                      headers={'Content-Type': CESR_CONTENT_TYPE})
        assert response.status_code == 200
        report = dict(status=response.status_code, body=response.content,
                      headers={key.lower(): value for key, value in response.headers.items()})

        def context(url):
            """Build the same persistent evidence/submission stores under the selected observer URL."""
            evidence = EvidenceContext(verifier, reger=RegBaser(name='dolly-source',
                headDirPath=str(tmp_path), temp=False))
            return Dolly(verifier, dhab, issuers=[ihab.pre], schemas=[credential.schema['$id']],
                fields={'value': 'a/value'}, observer=observerTrust(url), webhook='http://hook.test/',
                evidence=evidence, db=DollyBaser(name='dolly-source', headDirPath=str(tmp_path), temp=False))

        dolly = context(oldURL)
        try:
            assert dolly.observe(rip.said, report)
            assert dolly.synchronized(rip.said)
            previous = dolly.db.observed.get((rip.said,))
        finally:
            dolly.close()
        dolly = context(newURL)
        try:
            assert dolly.rgy.store.head(rip.said).qb64 == issued.said
            assert dolly.db.observed.get((rip.said,)) == previous
            assert not dolly.synchronized(rip.said)
            # The same authenticated evidence may be observed afresh through
            # the newly configured endpoint, without discarding public history.
            assert dolly.observe(rip.said, report)
            assert dolly.db.observed.get((rip.said,)).observer == newURL
            assert dolly.synchronized(rip.said)
        finally:
            dolly.close()
            obs.close()


@pytest.mark.parametrize('observer, message', [
    ('https://observer.test/', 'configure url and cafilepath'),
    ({'url': 'http://observer.test/', 'cafilepath': str(SERVER_TLS)}, 'must be an HTTPS URL'),
    ({'url': 'https://observer.test/', 'cafilepath': ''}, 'CA bundle'),
    ({'url': 'https://observer.test/', 'cafilepath': '/missing/dolly-ca.pem'}, 'existing file'),
    ({'url': 'https://observer.test/', 'cafilepath': str(SERVER_TLS),
      'certedhost': 'alternate.test'}, 'override requires an IP URL'),
])
def test_observer_source_trust_fails_closed_at_configuration(observer, message):
    """Reject absent trust, plaintext, and absent CA material before opening stores."""
    with openHby(name='dolly-observer-config', version=Vrsn_2_0) as verifier:
        dhab = verifier.makeHab(name='dolly')
        with pytest.raises(ValueError, match=message):
            Dolly(verifier, dhab, issuers=[], schemas=[], fields={}, observer=observer,
                  webhook='http://hook.test/')


def test_ip_observer_may_use_certificate_ip_identity_without_override():
    """Leave certedhost unset when an IP URL is expected to match a certificate IP SAN."""
    with openHby(name='dolly-observer-ip-config', version=Vrsn_2_0) as verifier:
        dhab = verifier.makeHab(name='dolly')
        dolly = Dolly(verifier, dhab, issuers=[], schemas=[], fields={},
            observer=observerTrust('https://127.0.0.1/'), webhook='http://hook.test/')
        try:
            assert dolly.observerTrust.certedhost is None
        finally:
            dolly.close()


@pytest.mark.parametrize('cafilepath, certedhost', [
    (WRONG_TLS, 'localhost'),
    (SERVER_TLS, 'wrong-source.test'),
])
def test_observer_worker_survives_wrong_ca_or_hostname(cafilepath, certedhost):
    """Reject copied source bytes at TLS while the same Dolly worker delivers its webhook."""
    sourceRequests, hooks = [], []

    class Source:
        def on_post(self, req, rep):
            sourceRequests.append(bytes(req.bounded_stream.read()))
            rep.data = b'copied old observer response'

    class Hook:
        def on_post(self, req, rep):
            hooks.append(req.media)
            rep.media = {'received': True}

    sourceApp, hookApp = falcon.App(), falcon.App()
    sourceApp.add_route('/', Source())
    hookApp.add_route('/hook', Hook())
    server = tlsServer(sourceApp)
    hook = http.Server(servant=tcp.Server(ha=('127.0.0.1', 0)), app=hookApp)
    assert hook.reopen()
    hook.servant.eha = hook.servant.ha
    try:
        url = f'https://127.0.0.1:{server.servant.ha[1]}/'
        with openHby(name=f'dolly-wrong-tls-{certedhost}', version=Vrsn_2_0) as verifier:
            dhab = verifier.makeHab(name='dolly')
            dolly = Dolly(verifier, dhab, issuers=[], schemas=[], fields={},
                observer=observerTrust(url, cafilepath=cafilepath, certedhost=certedhost),
                webhook=f'http://127.0.0.1:{hook.servant.ha[1]}/hook', timeout=0.2)
            result = []

            def fetch(tymth=None, tock=0.01, **kwa):
                yield tock
                result.append((yield from dolly.request(dolly.observer, body=b'query',
                    trust=dolly.observerTrust)))
                result.append((yield from dolly.request(dolly.webhook, data={'survived': True})))

            try:
                doing.Doist(real=True, tock=0.01, limit=0.5).do(doers=[
                    http.ServerDoer(server=server), http.ServerDoer(server=hook),
                    dolly, doing.doify(fetch)])
                assert result[0] is None
                assert result[1]['status'] == 200
                assert sourceRequests == []
                assert hooks == [{'survived': True}]
            finally:
                dolly.close()
    finally:
        server.close()
        hook.close()


def test_observer_https_accepts_configured_identity_and_rejects_copied_response():
    """Accept the pinned source, then reject the same bytes behind a different TLS identity."""
    copied = b'copied old observer response'
    requests = []

    class Source:
        def on_post(self, req, rep):
            requests.append(bytes(req.bounded_stream.read()))
            rep.data = copied

    def fetch(server, verifier):
        url = f'https://127.0.0.1:{server.servant.ha[1]}/'
        dhab = verifier.habByName('dolly') or verifier.makeHab(name='dolly')
        dolly = Dolly(verifier, dhab, issuers=[], schemas=[], fields={},
                observer=observerTrust(url, cafilepath=SERVER_TLS, certedhost='localhost'),
                webhook='http://hook.test/', timeout=0.2)
        result = []

        def request(tymth=None, tock=0.01, **kwa):
            yield tock
            result.append((yield from dolly.request(dolly.observer, body=b'signed query',
                trust=dolly.observerTrust)))

        try:
            doing.Doist(real=True, tock=0.01, limit=0.5).do(doers=[
                http.ServerDoer(server=server), dolly, doing.doify(request)])
            return result
        finally:
            dolly.close()

    app = falcon.App()
    app.add_route('/', Source())
    with openHby(name='dolly-source-identity', version=Vrsn_2_0) as verifier:
        server = tlsServer(app)
        try:
            result = fetch(server, verifier)
            assert len(result) == 1 and bytes(result[0]['body']) == copied
            assert requests == [b'signed query']
        finally:
            server.close()

        impostor = tlsServer(app, certificate=WRONG_TLS)
        try:
            assert fetch(impostor, verifier) == [None]
            assert requests == [b'signed query']
        finally:
            impostor.close()


@pytest.mark.parametrize('binding', ['top', 'inner', 'oneway'])
@pytest.mark.parametrize('transport', ['http', 'tcp'])
def test_acdc_v2_partial_full_grants_observer_acquisition_and_real_webhooks(binding, transport):
    """Preserve actual disclosure hooks while the evidence child owns pruning.

    The selected upstream IPEX profile authenticates top-level rd using
    independently acquired observer evidence. Inner and rd-free TEL-only forms
    select no supported issuer factor and must reject without escrow or hooks;
    generic TEL binding support is tested by the core verifier's own tests.
    The real scheduler must start exactly one KRAM pruner and cancel it with
    Dolly, while replay cannot enrich an earlier retained disclosure.
    """
    with (openHby(name='dolly-issuer', version=Vrsn_2_0) as issuer,
          openHby(name='dolly-registrar', version=Vrsn_2_0) as registrar,
          openHby(name='dolly-observer', version=Vrsn_2_0) as observer,
          openHby(name='dolly-verifier', version=Vrsn_2_0) as verifier):
        ihab = issuer.makeHab(name='issuer')
        ohab = observer.makeHab(name='observer')
        dhab = verifier.makeHab(name='dolly')
        rip = regcept(israid=ihab.pre)
        ihab.interact(data=[{'s': rip.sad['n'], 'd': rip.said}])
        attribute = {'d': '', 'u': Noncer().qb64,
                'status': {'d': '', 'u': Noncer().qb64, 'value': 'authorized'},
                'private': {'d': '', 'u': Noncer().qb64, 'value': 'secret-full-only'},
                'note': {'d': '', 'u': Noncer().qb64, 'value': None}}
        if binding == 'inner':
            attribute['rd'] = rip.said
        full = acdcmap(israid=ihab.pre, regid=rip.said if binding == 'top' else None,
                       uuid=Noncer().qb64, attribute=attribute)
        opening = Blinder.blind(acdc=full.said, state='issued')
        update = blindate(regid=rip.said, prior=rip.said, blid=opening.said)
        bonds = [opening.data]
        if binding == 'oneway':
            bonds.append(SealEvent(rip.said, '1', update.said))
        ihab.interact(data=[{'s': update.sad['n'], 'd': update.said}])
        compact = Compactor(mad=dict(full.sad['a']), makify=True, kind=Kinds.json)
        compact.compact(paths=['a/status/'], root='a')
        partial = acdcmap(israid=full.israid, regid=full.sad.get('rd'), uuid=full.sad['u'], schema=full.sad['s'],
                         attribute=dict(compact.partials[('a/status/',)].mad))
        assert partial.said == full.said
        reg = registrarContext(registrar, observers=[ohab.pre])
        obs = Observer(observer, readers=[dhab.pre])
        received, observerRequests = [], []

        class Requests:
            """Count actual observer HTTP requests to detect unauthenticated fetches."""
            def process_request(self, req, rep):
                """Record the requested path without replacing protocol or authorization handling."""
                observerRequests.append(req.path)

        obs.app.add_middleware(Requests())

        class Hook:
            """Receive actual application HTTP hooks for exact payload assertions."""
            def on_post(self, req, rep):
                """Record the projected JSON body and acknowledge actual webhook delivery."""
                received.append(req.media)
                rep.media = {'received': True}

        hookApp = falcon.App()
        hookApp.add_route('/hook', Hook())
        servers = [
            http.Server(servant=tcp.ServerTls(host='127.0.0.1', port=0,
                keypath=str(SERVER_TLS), certpath=str(SERVER_TLS), certify=ssl.CERT_NONE), app=reg.app),
            http.Server(servant=tcp.ServerTls(host='127.0.0.1', port=0,
                keypath=str(SERVER_TLS), certpath=str(SERVER_TLS), certify=ssl.CERT_NONE), app=obs.app),
            http.Server(servant=tcp.Server(ha=('127.0.0.1', 0)), app=hookApp),
        ]
        dolly = client = rawServer = None
        try:
            assert not reg.ingest(ihab.replay(gvrsn=Vrsn_2_0) + frame_v2_events(rip, update))['rejected']
            assert not reg.ingest(ohab.replay(gvrsn=Vrsn_2_0))['rejected']
            assert not obs.ingest(dhab.replay(gvrsn=Vrsn_2_0))['rejected']
            for server in servers:
                assert server.reopen()
                server.servant.eha = server.servant.ha
            urls = [f'{"https" if server.secured else "http"}://127.0.0.1:{server.servant.ha[1]}/'
                    for server in servers]
            source = SourceTrust.fromConfig(
                observerTrust(urls[0], certedhost='localhost'))
            obs.sources = (source,)
            obs.urls = frozenset([source.url])
            dolly = Dolly(verifier, dhab, issuers=[ihab.pre], schemas=[full.schema['$id']],
                fields={'status': 'a/status/value', 'private': 'a/private/value', 'note': 'a/note/value'},
                required=['status'], observer=observerTrust(urls[1], certedhost='localhost'),
                webhook=urls[2] + 'hook')
            ingress = http.Server(servant=tcp.Server(ha=('127.0.0.1', 0)), app=dolly.app)
            assert ingress.reopen()
            ingress.servant.eha = ingress.servant.ha
            servers.append(ingress)
            grants, stream = [], bytearray(ihab.replay(gvrsn=Vrsn_2_0))
            for stage, credential in enumerate((partial, full), 1):
                proof = messagize(credential, bonds=bonds, framed=False, gvrsn=Vrsn_2_0)
                exn, atc = grant(ihab, dhab.pre, f'disclosure {stage}', origin=proof)
                grants.append(exn)
                stream.extend(exn.raw + atc)
            if transport == 'tcp':
                rawServer = tcp.Server(ha=('127.0.0.1', 0))
                assert rawServer.reopen()
                rawServer.eha = rawServer.ha
                client = tcp.Client(ha=rawServer.ha)
                sender = tcp.ClientDoer(client)
            else:
                client = http.clienting.Client(hostname='127.0.0.1', port=ingress.servant.ha[1])
                sender = http.clienting.ClientDoer(client)

            def send(raw):
                """Send unchanged CESR through the selected actual socket transport."""
                if transport == 'tcp':
                    client.tx(raw)
                else:
                    client.request(method='POST', path='/ingest', body=raw,
                                   headers={'Content-Type': CESR_CONTENT_TYPE})

            send(bytes(stream))
            puller = RegistrarPuller(ohab, obs, [source], interval=10, timeout=1)
            doers = [http.ServerDoer(server=server) for server in servers]
            doers.extend([sender, puller, dolly])
            if rawServer:
                doers.extend([tcp.ServerDoer(rawServer), TcpIntake(dolly, rawServer)])
            assert dolly.doers.count(dolly.evidence) == 1
            assert dolly.evidence.doers.count(dolly.evidence.pruner) == 1
            assert dolly.evidence.pruner.kramer is dolly.evidence.kvy.kramer
            assert dolly.evidence.pruner not in dolly.doers
            doing.Doist(real=True, tock=0.01, limit=2.5).do(doers=doers)
            # The child actually ran; forced parent cancellation drains its
            # scheduler and closes the pruner generator before stores close.
            assert dolly.evidence.pruner.tymth is not None
            assert not dolly.deeds and not dolly.evidence.deeds
            assert dolly.evidence.pruner.done is False
            if transport == 'http':
                assert client.responses.popleft()['status'] == 202
            if binding != 'top':
                assert received == []
                for exn in grants:
                    assert not dolly.exc.complete(exn.said)
                    assert verifier.db.exns.get((exn.said,)) is None
                    assert verifier.db.epse.get((exn.said,)) is None
                assert [cue for cue in dolly.exc.cues if cue['kin'] == 'proof'] == []
                return
            assert len(received) == 2
            payloads = {item['grant']: item for item in received}
            first, second = (payloads[exn.said] for exn in grants)
            assert first['credential'] == second['credential'] == full.said
            assert first['business'] == {'status': 'authorized', 'private': None, 'note': None}
            assert first['disclosure']['private'] == first['disclosure']['note'] == 'undisclosed'
            assert 'secret-full-only' not in json.dumps(first)
            assert second['business'] == {'status': 'authorized', 'private': 'secret-full-only', 'note': None}
            assert second['disclosure']['private'] == 'disclosed'
            assert second['disclosure']['note'] == 'disclosed_null'
            assert all(dolly.db.submissions.get((exn.said,)).delivered for exn in grants)
            # A sender can re-sign the same EXN body with a fuller attachment.
            # It must not enrich the already accepted first disclosure view.
            replay = messagize(grants[0], tsgs=[(ihab.kever.prefixer,
                Number(sn=ihab.kever.lastEst.s), Diger(qb64=ihab.kever.lastEst.d),
                ihab.sign(grants[0].raw))], nests=[messagize(full,
                bonds=bonds, nested=True, framed=False, gvrsn=Vrsn_2_0)],
                framed=False, gvrsn=Vrsn_2_0)
            send(replay)
            doing.Doist(real=True, tock=0.01, limit=0.4).do(doers=doers)
            if transport == 'http':
                assert client.responses.popleft()['status'] == 202
            old = exchanging.loadParsedNestedSubstreams(verifier, grants[0].said)[0].serder
            later = exchanging.loadParsedNestedSubstreams(verifier, grants[1].said)[0].serder
            assert isinstance(old.sad['a']['private'], str)
            assert later.sad['a']['private']['value'] == 'secret-full-only'
            assert len(received) == 2
            assert dolly.db.submissions.get((grants[0].said,)).payload == first
            count = len(observerRequests)
            unknown = acdcmap(israid=ihab.pre, regid=Diger(ser=b'unknown registry').qb64,
                attribute={'d': '', 'value': 'unauthenticated fetch hint'})
            unknownProof = messagize(unknown, bonds=[Blinder.blind(acdc=unknown.said,
                state='issued').data], framed=False, gvrsn=Vrsn_2_0)
            forged, _ = grant(ihab, dhab.pre, 'bad authentication', origin=unknownProof)
            wrong = messagize(forged, tsgs=[(ihab.kever.prefixer,
                Number(sn=ihab.kever.lastEst.s), Diger(qb64=ihab.kever.lastEst.d),
                dhab.sign(forged.raw))], nests=[messagize(unknown,
                bonds=[Blinder.blind(acdc=unknown.said, state='issued').data],
                nested=True, framed=False, gvrsn=Vrsn_2_0)],
                framed=False, gvrsn=Vrsn_2_0)
            send(wrong)
            doing.Doist(real=True, tock=0.01, limit=1.2).do(doers=doers)
            if transport == 'http':
                assert client.responses.popleft()['status'] == 202
            assert not dolly.exc.complete(forged.said)
            assert len(observerRequests) == count
            assert len(received) == 2
        finally:
            if client:
                client.close()
            if rawServer:
                rawServer.close()
            for server in servers:
                server.close()
            if dolly:
                dolly.close()
            obs.close()
            reg.close()


@pytest.mark.parametrize('attachmentHeader,transport', [(False, 'http'), (True, 'http'), (False, 'tcp')])
def test_legacy_current_source_tsn_and_same_real_webhook_contract(attachmentHeader, transport):
    """Require a fresh signed TSN before legacy raw/header EXN webhook delivery.

    Old issuance embeds authenticate history. Parameterized HTTP framing also
    proves that version inference handles a v1 EXN body without a KEL prefix.
    """
    with (openHby(name='dolly-old-issuer', version=Vrsn_1_0) as issuer,
          openHby(name='dolly-old-verifier', version=Vrsn_1_0) as verifier):
        ihab = issuer.makeHab(name='issuer', version=Vrsn_1_0)
        dhab = verifier.makeHab(name='dolly', version=Vrsn_1_0)
        vcp = legacy.incept(ihab.pre, cnfg=['NB'], version=Vrsn_1_0)
        ihab.interact(data=[SealEvent(vcp.pre, '0', vcp.said)._asdict()], version=Vrsn_1_0)
        vcpmsg = messagize(vcp, bonds=[SealSource(Number(num=ihab.kever.sn),
            Diger(qb64=ihab.kever.serder.said))], gvrsn=Vrsn_1_0, framed=False)
        from dolly.schemas import load
        schema = load('legacy-status-v1')
        credential = proving.credential(schema= schema.said, issuer=ihab.pre,
            status=vcp.pre, data={'status': 'authorized'}, version=Vrsn_1_0)
        iss = legacy.issue(credential.said, vcp.pre, version=Vrsn_1_0)
        ihab.interact(data=[SealEvent(credential.said, '0', iss.said)._asdict()], version=Vrsn_1_0)
        issmsg = messagize(iss, bonds=[SealSource(Number(num=ihab.kever.sn),
            Diger(qb64=ihab.kever.serder.said))], gvrsn=Vrsn_1_0, framed=False)
        proof = messagize(credential, bonds=[SealEvent(vcp.pre, '0', iss.said)],
            gvrsn=Vrsn_1_0, framed=True)
        grantExn, atc = protocoling.ipexGrantExn(ihab, dhab.pre, 'legacy disclosure',
            acdc=proof, iss=issmsg, anc=ihab.msgOwnEvent(sn=ihab.kever.sn,
            gvrsn=Vrsn_1_0), version=Vrsn_1_0, gvrsn=Vrsn_1_0)
        source = legacy.Reger(name='dolly-old-source', temp=True)
        tvy = legacy.Tevery(db=issuer.db, reger=source)
        Parser(tvy=tvy, version=Vrsn_1_0).parse(ims=bytearray(vcpmsg + issmsg))
        assert source.tevers[vcp.pre].vcState(credential.said).d == iss.said
        received, queries, outbox, allowReplies = [], [], [], [False]
        inflight, responses = [False], []
        dolly = None

        class Hook:
            """Receive actual application HTTP hooks for exact payload assertions."""
            def on_post(self, req, rep):
                """Record the projected JSON body and acknowledge actual webhook delivery."""
                received.append(req.media)
                rep.media = {'received': True}

        class Source:
            """Process legacy queries through actual KERIpy KEL/TEL processors."""
            def on_post(self, req, rep):
                """Parse and dispatch the actual legacy query, retaining replay/TSN cues for the source."""
                event = SerderKERI(sad=json.loads(req.bounded_stream.read()))
                stream = event.raw + req.get_header(CESR_ATTACHMENT_HEADER).encode()
                psr = Parser(kvy=issuer.kvy, tvy=tvy, version=Vrsn_1_0)
                dom = psr.parseOne(ims=bytearray(stream), processive=False)
                psr.msgProcess(asdict(dom), kvy=issuer.kvy, tvy=tvy, exc=None, rvy=None, vry=None)
                if event.ilk == 'qry':
                    queries.append(event.route)
                rep.status = falcon.HTTP_202

        sourceApp, hookApp = falcon.App(), falcon.App()
        sourceApp.add_route('/', Source())
        hookApp.add_route('/hook', Hook())
        servers = [http.Server(servant=tcp.Server(ha=('127.0.0.1', 0)), app=app)
                   for app in (sourceApp, hookApp)]
        client = replyClient = rawServer = None
        try:
            for server in servers:
                assert server.reopen()
                server.servant.eha = server.servant.ha
            sourceURL = f'http://127.0.0.1:{servers[0].servant.ha[1]}/'
            hookURL = f'http://127.0.0.1:{servers[1].servant.ha[1]}/hook'
            dolly = Dolly(verifier, dhab, issuers=[ihab.pre], schemas=[schema.said],
                fields={'status': 'a/status'}, required=['status'], observer=observerTrust(
                    'https://unused.test/'),
                legacySources=[ihab.pre], webhook=hookURL)
            verifier.db.schema.pin((schema.said,), schema)
            # Public KEL, registry inception and signed endpoint metadata are
            # ordinary bootstrap inputs. Credential issuance still comes via grant.
            dolly.ingest(ihab.replay(gvrsn=Vrsn_1_0) + vcpmsg + ihab.makeLocScheme(
                url=sourceURL, version=Vrsn_1_0, gvrsn=Vrsn_1_0), version=Vrsn_1_0)
            ingress = http.Server(servant=tcp.Server(ha=('127.0.0.1', 0)), app=dolly.app)
            assert ingress.reopen()
            ingress.servant.eha = ingress.servant.ha
            servers.append(ingress)
            if transport == 'tcp':
                rawServer = tcp.Server(ha=('127.0.0.1', 0))
                assert rawServer.reopen()
                rawServer.eha = rawServer.ha
                client = tcp.Client(ha=rawServer.ha)
                client.tx(grantExn.raw + atc)
                sender = tcp.ClientDoer(client)
            else:
                client = http.clienting.Client(hostname='127.0.0.1', port=ingress.servant.ha[1])
                headers = {'Content-Type': CESR_CONTENT_TYPE}
                if attachmentHeader:
                    headers[CESR_ATTACHMENT_HEADER] = atc.decode('ascii')
                client.request(method='POST', path='/ingest',
                    body=grantExn.raw if attachmentHeader else grantExn.raw + atc, headers=headers)
                sender = http.clienting.ClientDoer(client)
            replyClient = http.clienting.Client(hostname='127.0.0.1', port=ingress.servant.ha[1])

            def replies(tymth=None, tock=0.01, **kwa):
                """Serve real source replay/TSN cues only after the test enables fresh replies.

                Reply HTTP responses remain observable; queued issuance history alone
                cannot establish the verifier's current-standing policy."""
                yield tock
                while True:
                    if allowReplies[0]:
                        while replyClient.responses:
                            responses.append(replyClient.responses.popleft())
                            inflight[0] = False
                        while tvy.cues:
                            cue = tvy.cues.popleft()
                            if cue['kin'] == 'replay':
                                # Preserve the old peer's requested attachment
                                # genus instead of the library's current default.
                                outbox.append(b''.join(source.clonePreIter(vcp.pre, gvrsn=Vrsn_1_0))
                                    + b''.join(source.clonePreIter(credential.said, gvrsn=Vrsn_1_0)))
                            elif cue['kin'] == 'reply':
                                # Source composition turns the conventional cue
                                # into a real source-endorsed core reply message.
                                outbox.append(ihab.reply(route=cue['route'] + '/' + ihab.pre,
                                    data=cue['data'], version=Vrsn_1_0, gvrsn=Vrsn_1_0))
                        if outbox and not inflight[0]:
                            replyClient.request(method='POST', path='/ingest', body=outbox.pop(0),
                                headers={'Content-Type': CESR_CONTENT_TYPE, 'CESR-Genus': '1'})
                            inflight[0] = True
                    yield tock

            doers = [http.ServerDoer(server=server) for server in servers]
            doers += [sender, http.clienting.ClientDoer(replyClient),
                      doing.doify(replies), dolly]
            if rawServer:
                doers.extend([tcp.ServerDoer(rawServer), TcpIntake(dolly, rawServer)])
            doing.Doist(real=True, tock=0.01, limit=1.3).do(doers=doers)
            if transport == 'http':
                assert client.responses.popleft()['status'] == 202
            assert dolly.legacy.reger.saved.get((credential.said,)) is not None
            assert dolly.db.submissions.get((grantExn.said,)).state == 'pending'
            assert received == []
            allowReplies[0] = True
            doing.Doist(real=True, tock=0.01, limit=3).do(doers=doers)
            assert 'tsn' in queries and 'tels' in queries
            assert len(responses) == 3 and all(r['status'] == 202 for r in responses)
            assert len(received) == 1, dict(
                reason=dolly.db.submissions.get((grantExn.said,)).reason,
                responses=[(r['status'], bytes(r['body'])) for r in responses],
                query=vars(dolly.db.legacyQueries.get((credential.said,))),
                observation=dolly.db.observed.get(('legacy', credential.said)),
                current=str(dolly.legacy.reger.txnsb.current((credential.said, ihab.pre))),
                replies=[s.sad for _, s in dolly.legacy.reger.txnsb.serderdb.getTopItemIter()])
            payload = received[0]
            assert payload['schema'] == 'dolly.accepted-credential/v1'
            assert payload['protocol'] == 1 and payload['standing'] == 'issued'
            assert payload['business'] == {'status': 'authorized'}
            assert payload['disclosure'] == {'status': 'disclosed'}
            assert dolly.db.submissions.get((grantExn.said,)).delivered
            assert dolly.db.observed.get(('legacy', credential.said)).head == iss.said
        finally:
            if rawServer:
                rawServer.close()
            for connection in (client, replyClient):
                if connection:
                    connection.close()
            for server in servers:
                server.close()
            if dolly:
                dolly.close()
            source.close()


def test_two_node_chain_declared_presentation_registry_and_full_ipex_over_http():
    """The actual app evaluates a rotated issuer/holder graph and exact grant binding."""
    with (openHby(name='graph-issuer', version=Vrsn_2_0) as issuer,
          openHby(name='graph-holder', bran='0123456789abcdefghijk', version=Vrsn_2_0) as holder,
          openHby(name='graph-registrar', version=Vrsn_2_0) as registrar,
          openHby(name='graph-observer', version=Vrsn_2_0) as observer,
          openHby(name='graph-dolly', bran='0123456789abcdefghijk', version=Vrsn_2_0) as verifier):
        authority, ihab = issuer.makeHab(name='authority'), issuer.makeHab(name='issuer')
        hhab, ohab, dhab = holder.makeHab(name='holder'), observer.makeHab(name='observer'), verifier.makeHab(name='dolly')
        irgy, hrgy = Regery(hby=issuer, temp=True), Regery(hby=holder, temp=True)
        irar, hrar = AcdcV2Registrar(irgy), AcdcV2Registrar(hrgy)
        farReg = irar.makeRegistry(name='authority', prefix=authority.pre)
        nearReg = irar.makeRegistry(name='entitlement', prefix=ihab.pre)
        presentationReg = hrar.makeRegistry(name='presentation', prefix=hhab.pre)

        def anchor(hab, registry, event):
            """Anchor the exact registry event in its controlling KEL and return that key event."""
            hab.interact(data=[dict(i=registry.regk, s=event.sad['n'], d=event.said)])
            assert registry.anchorMsg(event.said)
            return hab.kever.serder

        rips = (irgy.store.event(farReg.regk), irgy.store.event(nearReg.regk),
                hrgy.store.event(presentationReg.regk))
        for hab, registry, rip in zip((authority, ihab, hhab), (farReg, nearReg, presentationReg), rips):
            anchor(hab, registry, rip)
        far = acdcmap(israid=authority.pre, regid=farReg.regk, iseaid=ihab.pre,
                      attribute=dict(d='', authority='may-issue-entitlement'))
        full = acdcmap(israid=ihab.pre, regid=nearReg.regk, iseaid=hhab.pre, uuid=Noncer().qb64,
            attribute={'d': '', 'rd': presentationReg.regk, 'u': Noncer().qb64,
                'entitlement': {'d': '', 'u': Noncer().qb64, 'value': 'use-service'},
                'private': {'d': '', 'u': Noncer().qb64, 'value': 'not-negotiated'}},
            edge={'d': '', 'authority': {'d': '', 'n': far.said, 's': far.schema['$id'], 'o': 'I2I'}})
        farProof, farIss = irar.issue(farReg, acdc=far)
        nearProof, nearIss = irar.issue(nearReg, acdc=full)
        anchor(authority, farReg, farIss)
        anchor(ihab, nearReg, nearIss)
        ihab.rotate(version=Vrsn_2_0, gvrsn=Vrsn_2_0)
        compact = Compactor(mad=dict(full.sad['a']), makify=True, kind=Kinds.json)
        compact.compact(paths=['a/entitlement/'], root='a')
        partial = acdcmap(israid=ihab.pre, regid=nearReg.regk, iseaid=hhab.pre,
            uuid=full.sad['u'], schema=full.sad['s'], edge=full.sad['e'],
            attribute=dict(compact.partials[('a/entitlement/',)].mad))
        assert partial.said == full.said and isinstance(partial.sad['a']['private'], str)
        reg = registrarContext(registrar, observers=[ohab.pre])
        obs = Observer(observer, readers=[dhab.pre])
        sections = SectionBaser(name=holder.name, temp=True)
        hwallet, dwallet = Wallet(holder, hrgy), None
        peer = Peer(holder, hrgy, hwallet, sections)
        public = bytes(authority.replay(gvrsn=Vrsn_2_0) + ihab.replay(gvrsn=Vrsn_2_0)
                       + hhab.replay(gvrsn=Vrsn_2_0) + frame_v2_events(*rips, farIss, nearIss))
        received = []

        class Hook:
            """Receive actual application HTTP hooks for exact payload assertions."""
            def on_post(self, req, rep):
                """Record the projected JSON body and acknowledge actual webhook delivery."""
                received.append(req.media)
                rep.media = {'received': True}

        holderApp, hookApp = falcon.App(), falcon.App()
        holderApp.add_route('/ingest', Intake(peer))
        hookApp.add_route('/hook', Hook())
        servers = [
            http.Server(servant=tcp.ServerTls(host='127.0.0.1', port=0,
                keypath=str(SERVER_TLS), certpath=str(SERVER_TLS), certify=ssl.CERT_NONE), app=reg.app),
            http.Server(servant=tcp.ServerTls(host='127.0.0.1', port=0,
                keypath=str(SERVER_TLS), certpath=str(SERVER_TLS), certify=ssl.CERT_NONE), app=obs.app),
            http.Server(servant=tcp.Server(ha=('127.0.0.1', 0)), app=holderApp),
            http.Server(servant=tcp.Server(ha=('127.0.0.1', 0)), app=hookApp),
        ]
        dolly, clients = None, []
        try:
            assert not reg.ingest(public)['rejected']
            assert not reg.ingest(ohab.replay(gvrsn=Vrsn_2_0))['rejected']
            assert not obs.ingest(dhab.replay(gvrsn=Vrsn_2_0))['rejected']
            assert not peer.evidence.ingest(public)['rejected']
            for server in servers:
                assert server.reopen()
                server.servant.eha = server.servant.ha
            urls = [f'{"https" if server.secured else "http"}://127.0.0.1:{server.servant.ha[1]}/'
                    for server in servers]
            source = SourceTrust.fromConfig(
                observerTrust(urls[0], certedhost='localhost'))
            obs.sources = (source,)
            obs.urls = frozenset([source.url])
            dolly = Dolly(verifier, dhab, issuers=[ihab.pre, authority.pre],
                schemas=[full.schema['$id']], fields={'entitlement': 'a/entitlement/value',
                    'private': 'a/private/value'}, required=['entitlement'],
                observer=observerTrust(urls[1], certedhost='localhost'), webhook=urls[3] + 'hook')
            dwallet = Wallet(verifier, dolly.rgy, exc=dolly.exc)
            ingress = http.Server(servant=tcp.Server(ha=('127.0.0.1', 0)), app=dolly.app)
            assert ingress.reopen()
            ingress.servant.eha = ingress.servant.ha
            servers.append(ingress)
            dollyURL = f'http://127.0.0.1:{ingress.servant.ha[1]}/ingest'
            puller = RegistrarPuller(ohab, obs, [source], interval=0.1, timeout=1)
            doers = [http.ServerDoer(server=server) for server in servers] + [puller, dolly]

            def send(url, raw, duration=0.25):
                """Transmit one CESR body to the actual HTTP listener and require intake acknowledgement."""
                from urllib.parse import urlsplit
                target = urlsplit(url)
                client = http.clienting.Client(hostname=target.hostname, port=target.port)
                clients.append(client)
                client.request(method='POST', path=target.path, body=raw,
                               headers={'Content-Type': CESR_CONTENT_TYPE})
                owner = http.clienting.ClientDoer(client)
                doing.Doist(real=True, tock=0.01, limit=duration).do(doers=[*doers, owner])
                assert client.responses and client.responses.popleft()['status'] == 202

            plan = [[full.schema['$id'], '/', []],
                    [far.schema['$id'], '/e/authority/_/', []]]
            application, aatc = apply(dhab, hhab.pre, 'request entitlement chain', modifiers={'dp': plan})
            dolly.ingest(application.raw + aatc)
            send(urls[2] + 'ingest', dhab.replay(gvrsn=Vrsn_2_0) + application.raw + aatc)
            assert peer.exc.complete(application.said)
            offered, oatc = offer(hhab, 'disclose selected entitlement', origin=partial,
                                  artifacts=[far], apply=application)
            peer.ingest(offered.raw + oatc)
            send(dollyURL, hhab.replay(gvrsn=Vrsn_2_0) + offered.raw + oatc)
            assert dolly.exc.complete(offered.said)
            agreed, gatc = agree(dhab, 'agree to this chain disclosure', offered)
            dolly.ingest(agreed.raw + gatc)
            send(urls[2] + 'ingest', agreed.raw + gatc)
            assert peer.exc.complete(agreed.said)
            hhab.rotate(version=Vrsn_2_0, gvrsn=Vrsn_2_0)
            stamp = helping.nowIso8601()
            draft, _ = grant(hhab, dhab.pre, 'present selected entitlement chain',
                origin=partial, artifacts=[far], agree=agreed, dt=stamp)
            # Commit the already final grant body into the holder's public TEL.
            # The public bup and the Grant carry the same exact expanded opening.
            presentationOpening, presented = presentationReg.present(draft)
            source = anchor(hhab, presentationReg, presented)
            proofedNear = messagize(partial, bonds=[nearProof.data,
                SealEvent(hhab.pre, source.snh, source.said), presentationOpening.data],
                gvrsn=Vrsn_2_0)
            proofedFar = messagize(far, bonds=[farProof.data], gvrsn=Vrsn_2_0)
            final, fatc = grant(hhab, dhab.pre, 'present selected entitlement chain',
                origin=proofedNear, artifacts=[proofedFar], agree=agreed, dt=stamp)
            assert final.raw == draft.raw and final.said == draft.said
            peer.ingest(final.raw + fatc)
            assert peer.exc.complete(final.said)
            presentationFrame = presented.raw + Counter.enclose(
                qb64=Blinder.enclose([presentationOpening]),
                code=Codens.AttachmentGroup, version=Vrsn_2_0)
            assert not reg.ingest(hhab.replay(gvrsn=Vrsn_2_0) + presentationFrame)['rejected']
            send(dollyURL, hhab.replay(gvrsn=Vrsn_2_0) + final.raw + fatc, duration=2.5)
            assert dolly.exc.complete(final.said)
            assert len(received) == 1, dolly.db.submissions.get((final.said,))
            assert received[0]['credential'] == full.said
            assert received[0]['business'] == {'entitlement': 'use-service', 'private': None}
            assert received[0]['disclosure']['private'] == 'undisclosed'
            assert 'not-negotiated' not in json.dumps(received[0])
            assert all(dolly.synchronized(regid) for regid in (farReg.regk, nearReg.regk, presentationReg.regk))
            assert verifier.kevers[ihab.pre].lastEst.d == ihab.kever.lastEst.d
            assert verifier.kevers[hhab.pre].lastEst.d == hhab.kever.lastEst.d
            admitted, iatc = admit(dhab, 'admit the verified entitlement chain', final)
            dolly.ingest(admitted.raw + iatc)
            assert dolly.exc.complete(admitted.said)
            assert dwallet.recordAdmission(final.said, admitted.said, consent=True).credential == full.said
            send(urls[2] + 'ingest', admitted.raw + iatc)
            assert peer.exc.complete(admitted.said)
        finally:
            for client in clients:
                client.close()
            for server in servers:
                server.close()
            if dwallet:
                dwallet.close()
            if dolly:
                dolly.close()
            hwallet.close()
            sections.close()
            reg.close()
            obs.close()
            irgy.close()
            hrgy.close()
