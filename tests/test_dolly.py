"""Dolly acceptance requires actual protocol proofs and actual webhook HTTP."""
import json
from pathlib import Path
import ssl

import falcon
import pytest
from hio.base import doing
from hio.core import http, tcp

from keri import Vrsn_1_0, Vrsn_2_0, Kinds
from keri.acdc import acdcmap, blindate, regcept, grant
from dolly.serving import signedQuery
from keri.app.habbing import openHby
from keri.app import forwarding
from dolly.serving import Context as Dolly, Notices, TcpIntake, _RequestPolicy
from keri.app.httping import CESR_CONTENT_TYPE, CESR_ATTACHMENT_HEADER
from keri.core import (Blinder, Noncer, Compactor, messagize, Counter, Codens, Number, Diger,
                       BlindState, BoundState, SealEvent, Parser, Kevery)
from keri.peer import exchanging
from keri.vdr import eventing, verifying
from keri.acdc import Regery, Registrar as AcdcV2Registrar, apply, offer, agree, admit, ipexing
from keri.acdc.unblinding import Unblind
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


def test_empty_grant_is_non_reportable_and_later_grants_report_after_reopen(tmp_path):
    """Keep a valid vacuous Grant out of reporting, then deliver later credential hooks.

    Independent sender and persistent verifier stores exercise real EXN/KRAM
    verification. Each run accepts an empty Grant as non-reportable, then sends
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
            grants, oldRows = [], []
            historical = None
            for phase in range(2):
                with openHby(name='empty-grant-dolly', temp=False,
                             headDirPath=str(tmp_path), version=Vrsn_2_0) as verifier:
                    dhab = verifier.habByName('dolly') or verifier.makeHab(name='dolly')
                    evidence = RegBaser(name='empty-grant-dolly',
                        headDirPath=str(tmp_path), temp=False)
                    dolly = Dolly(verifier, dhab, issuers=[ihab.pre],
                        schemas=[credential.schema['$id']], fields={'status': 'a/status'},
                        observer=observerTrust('https://unused.test/'), webhook=url, baser=evidence,
                        vry=verifying.Verifier(
                            verifier, reger=eventing.Reger(name='empty-grant-dolly',
                                headDirPath=str(tmp_path), temp=False)),
                        db=DollyBaser(name='empty-grant-dolly', headDirPath=str(tmp_path), temp=False))
                    try:
                        if phase:
                            for normal in grants:
                                assert dolly.db.submissions.get((normal.said,)).delivered
                        empty, eatc = grant(ihab, dhab.pre, f'empty {phase}')
                        assert dolly.ingest(ihab.replay(gvrsn=Vrsn_2_0) + empty.raw + eatc) == [
                            dict(grant=empty.said, state='non-reportable')]
                        assert dolly.exc.complete(empty.said)
                        assert not dolly.db.submissions.get((empty.said,)).payload
                        normal, natc = grant(ihab, dhab.pre, f'normal {phase}', origin=proof)
                        result = dolly.ingest(
                            ihab.replay(gvrsn=Vrsn_2_0) + normal.raw + natc)
                        assert result == [dict(grant=normal.said, state='accepted')]
                        doing.Doist(real=True, tock=0.01, limit=0.4).do(
                            doers=[http.ServerDoer(server=server), dolly])
                        expected = {item.said for item in [*grants, normal]}
                        if phase:
                            expected.add(oldRows[1][0].said)
                        assert {item['grant'] for item in received} == expected
                        assert len(received) == len(expected)
                        assert dolly.db.submissions.get((normal.said,)).delivered
                        grants.append(normal)
                        if phase == 0:
                            # Write the application's earlier JSON format, with
                            # actual core-accepted Grants and no synthetic proofs.
                            def oldRow(message, payload, delivered=False):
                                value = dict(grant=message.said, registries=[], state='accepted',
                                    reason='', payload=payload, delivered=delivered)
                                raw = json.dumps(value).encode()
                                dolly.db.setVal(db=dolly.db.submissions.sdb,
                                    key=message.said.encode(), val=raw)
                                return raw

                            previous = dict(dolly.db.submissions.get((normal.said,)).payload)
                            previous.pop('admit')
                            historical = oldRow(normal, previous, delivered=True)
                            for recover in (False, True):
                                old, attachment = grant(ihab, dhab.pre,
                                    f'old accepted row {recover}', origin=proof)
                                dolly._parser(Vrsn_2_0).parse(
                                    ims=bytearray(old.raw + attachment), framed=False)
                                assert dolly.exc.complete(old.said)
                                response = None
                                if recover:
                                    response, attachment = admit(dhab, 'accepted before restart', old)
                                    dolly._parser(Vrsn_2_0).parse(
                                        ims=bytearray(response.raw + attachment), framed=False)
                                    assert dolly.exc.complete(response.said)
                                payload = dict(previous, grant=old.said,
                                    acceptedAt=helping.nowIso8601())
                                oldRow(old, payload)
                                oldRows.append((old, payload, response.said if response else None))
                        else:
                            refused = dolly.db.submissions.get((oldRows[0][0].said,))
                            assert refused.state == 'non-reportable' and not refused.delivered
                            assert 'fresh Grant required' in refused.reason
                            assert verifier.db.erpy.get((refused.grant,)) is None
                            assert refused.payload == oldRows[0][1]
                            recovered = dolly.db.submissions.get((oldRows[1][0].said,))
                            assert recovered.delivered and recovered.admit == oldRows[1][2]
                            assert recovered.payload == dict(oldRows[1][1], admit=oldRows[1][2])
                            assert dolly.db.getVal(db=dolly.db.submissions.sdb,
                                key=grants[0].said.encode()) == historical
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
        ihab.interact(data=[dict(i=rip.said, s=rip.sad['n'], d=rip.said)])
        issued = blindate(regid=rip.said, prior=rip.said,
                         blid=Blinder.blind(acdc=Diger(ser=b'credential').qb64, state='issued').said)
        ihab.interact(data=[dict(i=rip.said, s=issued.sad['n'], d=issued.said)])
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
            # A v1 protocol body remains unsupported even in CESR v2 attachments.
            old, _ = exchanging.specialExchange(sender=ihab.pre, route='/ipex/grant',
                attributes={'i': dhab.pre}, version=Vrsn_1_0, gvrsn=Vrsn_1_0)
            oldWire = ihab.endorse(old, last=False, framed=False, gvrsn=Vrsn_2_0)
            refused = client.simulate_post('/ingest', body=oldWire,
                headers={'Content-Type': CESR_CONTENT_TYPE, 'CESR-Genus': '2'})
            assert refused.status_code == 400 and 'only v2 protocol' in refused.text
            assert verifier.db.exns.get((old.said,)) is None
            assert verifier.db.epse.get((old.said,)) is None
            assert dolly.db.submissions.get((old.said,)) is None
            # Old unaccepted escrow work is rejected before replay evicts its body.
            from dolly.serving import Submission
            verifier.db.epse.put((old.said,), old)  # Unaccepted stored body, no proof or deadline.
            dolly.db.submissions.put((old.said,), Submission(old.said))
            dolly.process()
            refused = dolly.db.submissions.get((old.said,))
            assert refused.state == 'rejected' and 'only v2 protocol' in refused.reason
            assert not refused.delivered and verifier.db.exns.get((old.said,)) is None
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
            assert [record.grant for _, record in dolly.db.submissions.getTopItemIter()] == [old.said]
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
                    dolly = Dolly(verifier, dhab, issuers=[ihab.pre],
                        schemas=[schema if schemaUse == 'own' else partial.schema['$id']],
                        fields={'shown': 'a/shown/value', 'private': 'a/private/value'},
                        required=['shown'], observer=observerTrust('https://unused.test/'), webhook=webhook,
                        baser=RegBaser(name=name,
                            headDirPath=str(tmp_path), temp=False),
                        vry=verifying.Verifier(verifier, reger=eventing.Reger(name=name,
                            headDirPath=str(tmp_path), temp=False)),
                        db=DollyBaser(name=name, headDirPath=str(tmp_path), temp=False))
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

                        if phase == 0:
                            assert verifier.db.schema.get(schema) is None
                            post(ihab.replay(gvrsn=Vrsn_2_0))
                            # Framing success cannot turn an incomplete section
                            # or a wrong stream genus into schema evidence.
                            for raw, extra in [(schemaMessage.raw[:-1], {}),
                                    (frame_v2_events(schemaMessage), {'CESR-Genus': '1'})]:
                                response = client.simulate_post('/ingest', body=raw,
                                    headers={'Content-Type': CESR_CONTENT_TYPE, **extra})
                                assert response.status_code == 400
                            assert dolly.vry.reger.sections.get(schemaMessage.said) is None
                            section(wrongSchema)
                            assert not list(dolly.vry.reger.sectionIds.getTopItemIter(('s', schema)))
                            if arrival == 'before':
                                section(schemaMessage)
                            plan = [[schema if schemaUse == 'own' else partial.schema['$id'], '/', []]]
                            if edge:
                                plan.append([child.schema['$id'], '/e/member/_/', []])
                            exn, atc = grant(ihab, dhab.pre, 'independent schema disclosure',
                                origin=signed(partial), artifacts=[signed(child)] if edge else None,
                                modifiers={'dp': [plan]})
                            post(exn.raw + atc)
                        if ((arrival != 'before' and phase == 0)
                                or (arrival == 'restart' and phase == 1)):
                            # Both own-schema and edge-pin dependencies belong to
                            # ordinary native IPEX admission, before acceptance.
                            assert not dolly.exc.complete(exn.said)
                            assert verifier.db.emse.get((exn.said, schema)) is not None
                            assert dolly.db.submissions.get((exn.said,)).state == 'pending'
                            assert received == []
                            exact = tuple(verifier.db.enst.get((exn.said,)))
                            if arrival == 'after' or phase:
                                section(schemaMessage)
                                assert tuple(verifier.db.enst.get((exn.said,))) == exact
                        if arrival == 'restart' and phase == 0:
                            continue
                        assert dolly.exc.complete(exn.said)
                        assert dolly.exc.reverifyGrant(exn.said)[2].verdict == 'valid'
                        before = dolly.db.submissions.get((exn.said,)).payload
                        retained = exchanging.loadParsedNestedSubstreams(verifier, exn.said)[0].serder.raw
                        section(sectattr(full.sad['a']))
                        assert dolly.vry.reger.sections.get(sectattr(full.sad['a']).said) is not None
                        assert dolly.exc.reverifyGrant(exn.said)[2].verdict == 'valid'
                        assert exchanging.loadParsedNestedSubstreams(verifier, exn.said)[0].serder.raw == retained
                        assert dolly.db.submissions.get((exn.said,)).payload == before
                        doing.Doist(real=True, tock=0.01, limit=0.3).do(
                            doers=[http.ServerDoer(server=server), dolly])
                        assert received == [before]
                        assert before['business'] == {'shown': 'visible', 'private': None}
                        assert before['disclosure']['private'] == 'undisclosed'
                        assert 'only-in-cached-section' not in json.dumps(before)
                        assert verifier.db.schema.get(schema).sed == schemaMessage.sad['s']
                        if phase == 0:
                            # Reconcile the held verified sch on startup without
                            # resubmitting it or filling any credential fields.
                            verifier.db.schema.rem((schema,))
                            assert verifier.db.schema.get(schema) is None
                    finally:
                        dolly.close()
                        assert not dolly.vry.reger.opened
    finally:
        server.close()


@pytest.mark.parametrize('kind', [Kinds.cbor, Kinds.mgpk, Kinds.cesr])
def test_non_json_schema_sections_stay_held_without_transcoding(kind):
    """Hold exact non-JSON schema evidence without inventing a JSON schema ID."""
    from keri.acdc import sectschema

    with openHby(name='held-schema', version=Vrsn_2_0) as verifier:
        hab = verifier.makeHab(name='dolly')
        dolly = Dolly(verifier, hab, issuers=[], schemas=[], fields={},
                      observer=observerTrust('https://unused.test/'), webhook='http://unused.test/')
        try:
            message = sectschema({'$id': '', 'version': '1.0.0', 'type': 'object'}, kind=kind)
            dolly.ingest(frame_v2_events(message))
            assert dolly.vry.reger.sections.get(message.said).raw == message.raw
            assert verifier.db.schema.get(message.schema['$id']) is None
        finally:
            dolly.close()


def test_reopened_dolly_tracks_configured_source_head_without_reporting_authority(tmp_path):
    """Keep source/head telemetry separate from current proof and reporting authority.

    Reopen the actual application/registry stores, change observer policy, and
    require a matching source/head before labeling the acquisition synchronized."""
    from falcon import testing
    from keri.acdc.regbasing import RegBaser
    from dolly.serving import DollyBaser

    oldURL, newURL = 'https://observer.old.test/', 'https://observer.new.test/'
    with (openHby(name='dolly-source-issuer', version=Vrsn_2_0) as issuer,
          openHby(name='dolly-source-observer', version=Vrsn_2_0) as observer,
          openHby(name='dolly-source-reader', version=Vrsn_2_0) as verifier):
        ihab, dhab = issuer.makeHab(name='issuer'), verifier.makeHab(name='dolly')
        rip = regcept(israid=ihab.pre)
        ihab.interact(data=[dict(i=rip.said, s=rip.sad['n'], d=rip.said)])
        credential = acdcmap(israid=ihab.pre, regid=rip.said, attribute=dict(d='', value='public'))
        blinder = Blinder.blind(acdc=credential.said, state='issued')
        issued = blindate(regid=rip.said, prior=rip.said, blid=blinder.said)
        ihab.interact(data=[dict(i=rip.said, s=issued.sad['n'], d=issued.said)])
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
            evidence = RegBaser(name='dolly-source',
                headDirPath=str(tmp_path), temp=False)
            return Dolly(verifier, dhab, issuers=[ihab.pre], schemas=[credential.schema['$id']],
                fields={'value': 'a/value'}, observer=observerTrust(url), webhook='http://hook.test/',
                baser=evidence, db=DollyBaser(name='dolly-source', headDirPath=str(tmp_path), temp=False))

        dolly = context(oldURL)
        try:
            dolly.ingest(public)
            proof = messagize(credential, bonds=[blinder.data], framed=False, gvrsn=Vrsn_2_0)
            exn, atc = grant(ihab, dhab.pre, 'verified before source telemetry', origin=proof)
            assert dolly.ingest(exn.raw + atc) == [dict(grant=exn.said, state='accepted')]
            assert dolly.db.observed.get((rip.said,)) is None
            waiting = regcept(israid=ihab.pre, uuid=Noncer().qb64)
            dolly.ingest(frame_v2_events(waiting))
            assert dolly.rgy.store.head(waiting.said) is None
            # Unrelated global dependencies do not invalidate this response.
            assert dolly.observe(rip.said, report)
            assert dolly.synchronized(rip.said)
            previous = dolly.db.observed.get((rip.said,))
            # A dependency actually carried by this response does prevent its marker.
            assert not dolly.observe(rip.said, dict(report,
                body=bytes(report['body']) + frame_v2_events(waiting)))
            assert dolly.db.observed.get((rip.said,)) == previous
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
            later = blindate(regid=rip.said, prior=issued.said, sn=2,
                blid=Blinder.blind(sn=2, acdc=credential.said, state='revoked').said)
            ihab.interact(data=[dict(i=rip.said, s=later.sad['n'], d=later.said)])
            dolly.ingest(ihab.replay(gvrsn=Vrsn_2_0) + frame_v2_events(later))
            assert not dolly.synchronized(rip.said)
            assert not dolly.observe(rip.said, report)
            assert dolly.rgy.store.head(rip.said).qb64 == later.said
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
    """Preserve actual disclosure hooks while Dolly owns its single pruner.

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
        ihab.interact(data=[{'i': rip.said, 's': rip.sad['n'], 'd': rip.said}])
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
        ihab.interact(data=[{'i': rip.said, 's': update.sad['n'], 'd': update.said}])
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
            assert dolly.doers.count(dolly.pruner) == 1
            assert dolly.pruner.kramer is dolly.kvy.kramer
            doing.Doist(real=True, tock=0.01, limit=2.5).do(doers=doers)
            # The pruner actually ran; forced cancellation closes its generator
            # before the enclosing application's stores close.
            assert dolly.pruner.tymth is not None
            assert not dolly.deeds
            assert dolly.pruner.done is False
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
        holderKvy = Kevery(db=holder.db, cf=_RequestPolicy(), enableKram=True,
                           lax=False, local=False)
        holderExc = exchanging.Exchanger(holder, handlers=[])
        ipexing.loadHandlers(holder, holderExc, Notices(), rgy=hrgy)
        holderUnblind = Unblind(hhab, holderExc, hrgy, states=('issued', 'revoked', ''))
        holderKvy.qvy = holderUnblind
        holderKvy.rvy = hhab.rvy
        hhab.rvy.rtr.addRoute(Unblind.Route, holderUnblind, blinders=True, attachments=True)
        holderParser = Parser(kvy=holderKvy, rgy=hrgy, exc=holderExc,
                              rvy=hhab.rvy, version=Vrsn_2_0)
        holderQueries = []

        def holderIngest(raw):
            """Run the holder's actual native processors without a retired wallet facade."""
            holderParser.parse(ims=bytearray(raw), framed=False)
            holderKvy.processEscrows()
            hrgy.processEscrows()
            holderExc.processEscrow()

        class HolderIntake:
            """Expose the same real protocol intake to the independent holder over HTTP."""
            def on_post(self, req, rep):
                raw = req.bounded_stream.read()
                for parsed in Parser(version=Vrsn_2_0).parse(
                        ims=bytearray(raw), framed=False, processive=False):
                    if parsed.serder.ilk == 'qry':
                        holderQueries.append(parsed.serder)
                holderIngest(raw)
                rep.status = falcon.HTTP_202

            on_put = on_post

        def holderReplies(tymth, tock=0.01, **kwa):
            """Send native reply cues through ordinary authenticated endpoint transport."""
            yield tock
            while True:
                while holderUnblind.cues:
                    cue = holderUnblind.cues.popleft()
                    parsed = Parser(version=Vrsn_2_0).parseOne(
                        ims=bytearray(cue['msg']), processive=False)
                    wire = messagize(parsed.serder, sigers=parsed.sigers, tsgs=parsed.tsgs,
                        lsgs=parsed.lsgs, cigars=parsed.cigars,
                        bonds=[BlindState(*value) for value in parsed.bsqs]
                            + [BoundState(*value) for value in parsed.bsss], gvrsn=Vrsn_2_0)
                    poster = forwarding.StreamPoster(hby=holder, hab=hhab,
                        recp=cue['dest'], topic='credential', version=Vrsn_2_0)
                    poster.send(parsed.serder, attachment=wire[parsed.serder.size:])
                    delivery = doing.DoDoer(doers=poster.deliver(), tymth=tymth)
                    delivery.enter()
                    try:
                        while not delivery.recur(tyme=tymth()):
                            yield tock
                    finally:
                        delivery.exit()
                yield tock
        public = bytes(authority.replay(gvrsn=Vrsn_2_0) + ihab.replay(gvrsn=Vrsn_2_0)
                       + hhab.replay(gvrsn=Vrsn_2_0) + frame_v2_events(*rips, farIss, nearIss))
        received = []

        class Hook:
            """Receive actual application HTTP hooks for exact payload assertions."""
            def on_post(self, req, rep):
                """Record the projected JSON body and acknowledge actual webhook delivery."""
                payload = req.media
                admitted = verifier.db.exns.get((payload['admit'],))
                assert admitted is not None and dolly.exc.complete(admitted.said)
                assert admitted.sad['p'] == payload['grant']
                assert verifier.db.erpy.get((payload['grant'],)).qb64 == admitted.said
                assert holderExc.complete(admitted.said)
                received.append(payload)
                rep.media = {'received': True}

        holderApp, hookApp = falcon.App(), falcon.App()
        holderApp.add_route('/ingest', HolderIntake())
        holderApp.add_route('/', HolderIntake())
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
            holderIngest(public)
            assert hrgy.store.head(farReg.regk).qb64 == farIss.said
            assert hrgy.store.head(nearReg.regk).qb64 == nearIss.said
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
            ingress = http.Server(servant=tcp.Server(ha=('127.0.0.1', 0)), app=dolly.app)
            assert ingress.reopen()
            ingress.servant.eha = ingress.servant.ha
            servers.append(ingress)
            dollyURL = f'http://127.0.0.1:{ingress.servant.ha[1]}/ingest'
            puller = RegistrarPuller(ohab, obs, [source], interval=0.1, timeout=1)
            doers = [http.ServerDoer(server=server) for server in servers] + [
                puller, dolly, doing.doify(holderReplies)]

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

            # Publish the newer issuer head before the existing negotiation
            # network turns, so the configured observer actually knows the tail
            # when this presentation later needs its missing opening.
            tailOpening, tail = irar.vacate(nearReg)
            anchor(ihab, nearReg, tail)
            tailPublic = ihab.replay(gvrsn=Vrsn_2_0) + frame_v2_events(tail)
            assert not reg.ingest(tailPublic)['rejected']

            plan = [[full.schema['$id'], '/', []],
                    [far.schema['$id'], '/e/authority/_/', []]]
            application, aatc = apply(dhab, hhab.pre, 'request entitlement chain', modifiers={'dp': [plan]})
            dolly.ingest(application.raw + aatc)
            send(urls[2] + 'ingest', dhab.replay(gvrsn=Vrsn_2_0)
                + dhab.makeEndRole(eid=dhab.pre, version=Vrsn_2_0, gvrsn=Vrsn_2_0)
                + dhab.makeLocScheme(url=dollyURL, version=Vrsn_2_0, gvrsn=Vrsn_2_0)
                + application.raw + aatc)
            assert holderExc.complete(application.said)
            offered, oatc = offer(hhab, 'disclose selected entitlement', origin=partial,
                                  artifacts=[far], apply=application)
            holderIngest(offered.raw + oatc)
            send(dollyURL, hhab.replay(gvrsn=Vrsn_2_0) + offered.raw + oatc)
            assert dolly.exc.complete(offered.said)
            agreed, gatc = agree(dhab, 'agree to this chain disclosure', offered)
            dolly.ingest(agreed.raw + gatc)
            send(urls[2] + 'ingest', agreed.raw + gatc)
            assert holderExc.complete(agreed.said)
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
            holderIngest(final.raw + fatc)
            assert holderExc.complete(final.said)
            # A newer public head makes the accepted old issuance proof stale.
            # Holder receives the one exact opening separately; Dolly receives
            # only authenticated public evidence through its configured observer.
            holderIngest(tailPublic)
            hrgy.store.putOpening(tail.said, tailOpening)
            holderUnblind.approve(final.said)
            assert obs.rgy.store.head(nearReg.regk).qb64 == tail.said
            endpoint = hhab.makeEndRole(eid=hhab.pre, version=Vrsn_2_0, gvrsn=Vrsn_2_0)
            endpoint += hhab.makeLocScheme(url=urls[2], version=Vrsn_2_0, gvrsn=Vrsn_2_0)
            presentationFrame = presented.raw + Counter.enclose(
                qb64=Blinder.enclose([presentationOpening]),
                code=Codens.AttachmentGroup, version=Vrsn_2_0)
            assert not reg.ingest(hhab.replay(gvrsn=Vrsn_2_0) + presentationFrame)['rejected']
            # Intake alone cannot report the stale proof or ask for openings.
            dolly.ingest(hhab.replay(gvrsn=Vrsn_2_0) + endpoint + final.raw + fatc)
            assert received == [] and not holderQueries and not dolly._unblinds
            assert dolly.db.submissions.get((final.said,)).state == 'pending'
            exact = [nest.serder.raw for nest in exchanging.loadParsedNestedSubstreams(verifier, final.said)]
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
            assert len(holderQueries) == 1
            assert holderQueries[0].sad['q']['re'] == {nearReg.regk: [tail.said]}
            assert [nest.serder.raw for nest in exchanging.loadParsedNestedSubstreams(verifier, final.said)] == exact
            record = dolly.db.submissions.get((final.said,))
            assert record.admit == received[0]['admit'] and record.admitSubmitted and record.delivered
            assert holderExc.complete(record.admit)
            # Replayed old Grant bytes cannot expand its view or renew approval.
            send(dollyURL, final.raw + fatc)
            assert len(received) == len(holderQueries) == 1
            assert dolly.db.submissions.get((final.said,)).payload == received[0]
        finally:
            for client in clients:
                client.close()
            for server in servers:
                server.close()
            if dolly:
                dolly.close()
            reg.close()
            obs.close()
            irgy.close()
            hrgy.close()


def test_observer_request_uses_only_configured_ca():
    from cryptography import x509
    from cryptography.hazmat.primitives.serialization import Encoding
    with openHby(name='dolly-exclusive-ca', version=Vrsn_2_0) as verifier:
        hab = verifier.makeHab(name='dolly')
        dolly = Dolly(verifier, hab, issuers=[], schemas=[], fields={},
            observer=observerTrust('https://127.0.0.1:1/', certedhost='localhost'), webhook='http://hook.test/')
        clock = doing.Doist(tock=.03125)
        clock.enter(doers=[dolly])
        request = dolly.request(dolly.observer, body=b'query', trust=dolly.observerTrust)
        try:
            next(request)
            client, = dolly.clients
            context = client.connector.context
            assert context.get_ca_certs(binary_form=True) == [x509.load_pem_x509_certificate(SERVER_TLS.read_bytes()).public_bytes(Encoding.DER)]
            assert context.check_hostname and context.verify_mode == ssl.CERT_REQUIRED
        finally:
            request.close()
            clock.exit()
            dolly.close()
