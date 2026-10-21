"""Sally-like application policy over native and legacy KERIpy verification.

Composition informed by Sally ed789de (Apache-2.0); cryptographic verification
remains in Exchanger, native IPEX/Rever, and legacy Tevery/Verifier.
"""
from dataclasses import asdict, dataclass, field
import math
from urllib.parse import urlsplit

import falcon
from hio.base import doing
from hio.core import http, tcp

from keri import Vrsn_1_0, Vrsn_2_0, Kinds
from keri.acdc import Regery
from keri.acdc.regeventing import issuerRegistry, vetBlind, vetBound
from keri.acdc.sectioning import SectionBaser, Sectioner
from keri.app import ipexing, agenting
from dolly.projecting import project
from keri.app.httping import CESR_CONTENT_TYPE, CESR_ATTACHMENT_HEADER
from keri.app.indirecting import createHttpServer
from keri.app.registrar.serving import Context as EvidenceContext, signedQuery, KEL_DEPENDENCIES
from keri.core import Parser, SerderACDC, SerderKERI, Serdery, GenDex, Revery, BoundState, Diger
from keri.db import dbing, koming
from keri.db.basing import BaserDoer
from keri.help import helping
from keri.kering import (ValidationError, ExtractionError, ShortageError, MissingChainError, MissingSchemaError,
                         MissingRegistryError, MissingAnchorError, MissingSenderKeyStateError)
from keri.peer import exchanging
from keri.vdr import verifying, eventing as legacyEventing


@dataclass
class Submission:
    """Persist one grant reporting decision and its exact projected payload.

    Pending records retry dependencies; terminal decisions survive reopen.
    delivered records webhook acknowledgement, not protocol acceptance."""
    grant: str
    registries: list = field(default_factory=list)
    state: str = 'pending'
    reason: str = ''
    payload: dict = field(default_factory=dict)
    delivered: bool = False


@dataclass
class Observation:
    """Retain a locally verified registry head and configured observer observation.

    observed is that report's time; head identifies accepted evidence. The
    record does not establish global latest state or publication time."""
    observed: str
    head: str
    observer: str


@dataclass
class LegacyQuery:
    """Track one conventional TEL/TSN acquisition attempt for a legacy credential.

    started gates fresh replies from configured sources; reply avoids consuming
    the same source report twice. This is application observation policy."""
    credential: str
    registry: str
    issuer: str
    started: str
    reply: str = ''


class DollyBaser(dbing.LMDBer):
    """Own durable submissions, observer reports, and legacy query bookkeeping.

    Core KEL/TEL/EXN evidence stays in its existing KERIpy stores."""
    TailDirPath = 'keri/dolly'
    AltTailDirPath = '.keri/dolly'

    def reopen(self, **kwa):
        """Open application tables and return whether the LMDB environment opened.

        Keyword arguments follow LMDBer, including explicit readonly inspection.
        Existing state is retained; reopen does not reissue reporting decisions."""
        super().reopen(**kwa)
        self.submissions = koming.Komer(db=self, subkey='submissions.', klas=Submission)
        self.observed = koming.Komer(db=self, subkey='observed.', klas=Observation)
        self.legacyQueries = koming.Komer(db=self, subkey='legacy-queries.', klas=LegacyQuery)
        return self.opened


class Notices:
    """Adapt the core notifier contract while durable EXNs drive application work."""
    def add(self, attrs):
        # Durable EXN state, not notification delivery, drives application work.
        """Ignore transient attrs notifications; Context reads durable verified EXNs.

        No notification is an acceptance or delivery acknowledgement."""
        pass


class Context(doing.DoDoer):
    """Compose core verification with explicit reporting, projection, and delivery.

    One section owner and enabled KRAM owner serve both direct transports.
    Historical inspection is separate from current reporting policy."""
    def __init__(self, hby, hab, *, issuers, schemas, fields, required=(),
                 observer, webhook, maximumAge=15.0, timeout=5.0,
                 db=None, evidence=None, legacy=None, legacySources=(), graphPolicy=None,
                 sections=None):
        """Compose verification, section evidence, reporting, and delivery owners.

        ``hby`` and ``hab`` supply the identity; issuers/schemas and field paths
        define reporting policy. Observer/webhook URLs and positive finite
        maximumAge/timeout configure evidence freshness and HTTP delivery.
        Optional db/evidence/legacy/sections stores support persistent reopen;
        this context closes them. The shared SectionBaser feeds parser intake
        and graphPolicy-aware native verification, without expanding retained
        credential projections. EvidenceContext is scheduled once as a child,
        owning its single KRAM pruner until cancellation. Invalid timeouts
        raise ValueError.
        """
        if any(not math.isfinite(value) or value <= 0 for value in (maximumAge, timeout)):
            raise ValueError('Dolly freshness and request timeouts must be finite and positive')
        self.hby, self.hab = hby, hab
        self.issuers, self.schemas = set(issuers), set(schemas)
        self.fields, self.required = dict(fields), tuple(required)
        self.observer, self.webhook = observer, webhook
        self.maximumAge, self.timeout = maximumAge, timeout
        self.legacySources = tuple(legacySources)
        self.db = db if db is not None else DollyBaser(name=hby.name, base=hby.base, temp=hby.temp)
        self.evidence = evidence if evidence is not None else EvidenceContext(hby)
        self.rgy = Regery(hby, name=hby.name, baser=self.evidence.reger)
        self.legacy = legacy if legacy is not None else verifying.Verifier(hby,
            reger=legacyEventing.Reger(name=hby.name, base=hby.base, temp=hby.temp))
        self.rvy = Revery(db=hby.db)
        self.evidence.kvy.rvy = self.rvy
        self.evidence.kvy.registerReplyRoutes(self.rvy.rtr)
        self.legacy.tvy.rvy = self.rvy
        self.legacy.tvy.registerReplyRoutes(self.rvy.rtr)
        self.inquisitor = agenting.WitnessInquisitor(hby=hby)
        self.exc = exchanging.Exchanger(hby, handlers=[])
        self.sections = sections if sections is not None else SectionBaser(
            name=hby.name, base=hby.base, temp=hby.temp)
        self.scy = Sectioner(db=hby.db, sections=self.sections)
        ipexing.loadHandlers(hby, self.exc, Notices(), self.rgy,
                            graphPolicy=graphPolicy, sections=self.sections)
        self.native = self.exc.routes['/ipex/grant'].native
        self.app = falcon.App()
        self.app.add_route('/ingest', IntakeEnd(self))
        self.app.add_route('/', IntakeEnd(self))
        self.app.add_route('/health', HealthEnd())
        self.clients = set()
        super().__init__(doers=[self.evidence, self.inquisitor, doing.doify(self.workDo)])

    def _parser(self, version, *, stream=False):
        """Return a parser sharing this context's processors and section owner.

        ``version`` selects the initial CESR stream genus. ``stream`` adds only
        the application dispatch hook to the same core parser for live TCP.
        Protocol checks remain in Parser; parsing does not imply acceptance.
        """
        klass = StreamParser if stream else Parser
        extra = {"context": self} if stream else {}
        return klass(**extra, kvy=self.evidence.kvy, rgy=self.evidence.rever,
            tvy=self.legacy.tvy, vry=self.legacy, exc=self.exc, rvy=self.rvy,
            scy=self.scy, local=False, version=version)

    def ingest(self, raw, version=Vrsn_2_0):
        """Dispatch CESR evidence and return states for grants received in raw.

        ``raw`` may contain consecutive KEL, registry, credential, section, or
        EXN frames. ``version`` selects the initial stream genus. Independent
        schema sections enter the same store used for live and retained native
        verification; they never replace the grant's revealed view. Incomplete
        framing or invalid evidence raises ValidationError; concrete processor
        escrows retain retryable dependencies. HTTP success means intake only.
        """
        parser, ims, received = self._parser(version), bytearray(raw), []
        while ims:
            size = len(ims)
            dom = parser.parseOne(ims=ims, processive=False, local=False)
            if dom is None or dom.serder is None or len(ims) >= size:
                raise ValidationError('incomplete credential evidence stream')
            if (said := self.dispatch(parser, asdict(dom))) is not None:
                received.append(said)
        self.process()
        return [{'grant': said, 'state': self.db.submissions.get((said,)).state}
                for said in received]

    def dispatch(self, parser, exts):
        """Send one parsed frame to shared core processors and track its grant.

        ``parser`` owns only transport parsing state; ``exts`` is its complete
        parsed frame. Return the submitted grant SAID or None. Both transports
        use the same recipient checks and dependency escrows. Invalid evidence
        raises its core error; dependency failures remain pending. The core
        Parser method is called directly to avoid the TCP dispatch hook recursing.
        """
        serder, submitted, submission = exts['serder'], None, None
        if serder.ilk in ('vcp', 'vrt', 'iss', 'bis', 'rev', 'brv'):
            if self.legacy.reger.tels.get(keys=serder.pre, on=serder.sn) == serder.said:
                return None  # Exact already-verified legacy TEL replay.
        if serder.ilk == 'exn' and serder.route == '/ipex/grant':
            recipient = serder.sad.get('ri') if serder.pvrsn.major == 2 else serder.sad['a'].get('i')
            if recipient != self.hab.pre:
                raise ValidationError('grant is addressed to a different disclosee')
            registries = sorted({regid for item in exts.get('nests', [])
                                 if (regid := issuerRegistry(item['serder']))})
            submission = Submission(serder.said, registries)
            submitted = serder.said
        try:
            Parser.msgProcess(parser, exts, kvy=self.evidence.kvy, rgy=self.evidence.rever,
                tvy=self.legacy.tvy, vry=self.legacy, exc=self.exc, rvy=self.rvy, scy=self.scy)
        except KEL_DEPENDENCIES + (MissingChainError, MissingSchemaError):
            pass  # Concrete processors already retained their dependencies.
        # Missing bootstrap raises before KRAM retains this request. Do not
        # manufacture a pending row that would survive a refused HTTP request.
        if submission is not None:
            self.db.submissions.put((submitted,), submission)
        return submitted

    def fresh(self, regid):
        """Return whether regid has a matching fresh report from the current observer.

        A different configured URL, missing/moved local head, future timestamp,
        or report older than maximumAge fails freshness. No global latest-state
        inference follows from this application observation."""
        record = self.db.observed.get((regid,))
        head = self.rgy.store.head(regid)
        if (record is None or record.observer != self.observer
                or head is None or record.head != head.qb64):
            return False
        age = (helping.nowUTC() - helping.fromIso8601(record.observed)).total_seconds()
        return 0 <= age <= self.maximumAge

    def observe(self, regid, response):
        """Retain a configured observer report only after locally verifying its head."""
        headers = response.get('headers', {})
        if (response['status'] != 200 or headers.get('observer-evidence-state') != 'fresh'
                or headers.get('content-type', '').split(';')[0] != CESR_CONTENT_TYPE):
            return False
        stamp, head = headers.get('observer-observed-at'), headers.get('observer-registry-head')
        try:
            age = (helping.nowUTC() - helping.fromIso8601(stamp)).total_seconds()
        except (ValueError, TypeError):
            return False
        if not 0 <= age <= self.maximumAge:
            return False
        result = self.evidence.ingest(response['body'])
        accepted = self.rgy.store.head(regid)
        if (result['rejected'] or result['pending'] or accepted is None
                or accepted.qb64 != head or result['heads'].get(regid) != head):
            return False
        self.db.observed.pin((regid,), Observation(stamp, head, self.observer))
        return True

    def _nativeCredential(self, exn):
        """Return the retained origin credential, or None for an empty grant.

        ``exn`` is the accepted native grant. Revalidate its proof and semantics
        before making any application decision, then apply current standing to
        every disclosed node. Missing evidence remains retryable; invalid proof
        or current standing raises ValidationError. Selection never resolves a
        fuller cached disclosure in place of this grant's retained material.
        """
        credential, nests = self._nativeDisclosure(exn)
        if credential is not None:
            self._nativeCurrentStanding(nests)
        return credential

    def _nativeDisclosure(self, exn):
        """Return the core-verified retained origin and its disclosed graph nodes.

        ``exn`` must name a retained native grant. Empty disclosures return
        (None, []). Invalid semantics/proofs raise ValidationError; unavailable
        dependencies retain their core exception. This boundary applies no
        Dolly current-reporting or observation policy and never expands a view.
        """
        if not self.native.verifyAccepted(exn.said):
            raise ValidationError('native IPEX proof or semantics failed')
        origins = exn.sad['a']['o']
        if not origins:
            return None, []
        nests = exchanging.loadParsedNestedSubstreams(self.hby, exn.said)
        return next(nest.serder for nest in nests if nest.serder.said == origins[0]), nests

    def inspectHistorical(self, grant):
        """Inspect a retained authenticated native grant without reporting it.

        ``grant`` is its EXN SAID. Return selected retained values, disclosure
        facts, exact view references and authenticated bound-event references.
        Empty grants have no credential or business projection. This explicit
        historical-evidence purpose makes no current-standing, freshness, or
        independent publication-time claim; it creates no submission, policy
        acceptance, timestamp, or hook. Reporting allowlists and required fields
        apply to current reporting; inspection uses only configured field paths.

        Unknown/non-native grants or invalid proofs raise ValidationError;
        unavailable dependencies retain their core exception. Core graph proof
        verification remains authoritative, including its configured graphPolicy.
        """
        exn = self.hby.db.exns.get((grant,))
        if exn is None or exn.pvrsn.major != 2 or exn.route != '/ipex/grant':
            raise ValidationError('historical inspection requires a retained native grant')
        credential, nests = self._nativeDisclosure(exn)
        values, disclosure = project(credential, self.fields) if credential else ({}, {})
        return dict(purpose='historical-evidence', proofValidity='valid',
            currentStanding='not-evaluated', grant=grant,
            credential=credential.said if credential else None,
            business=values, disclosure=disclosure, sources=self._historicalSources(nests))

    def _historicalSources(self, nests):
        """Reference only exact retained node views and authenticated bound events.

        ``nests`` are already core-verified grant nodes. Each result identifies
        its node and serialized disclosure view. Bound references additionally
        require a matching accepted TEL bup, its exact BLID opening, and the
        accepted Issuee KEL event. Missing/invalid evidence raises the existing
        core error. Never infer a reference from a receiver clock or a cache's
        latest head, and never include opening nonces or cached fuller bodies.
        """
        sources = []
        for nest in nests:
            credential = nest.serder
            bound = []
            proofs = [proof for proof in self.native._blindProofs(nest)
                      if proof.clan == BoundState and proof.acdc == credential.said]
            if proofs and (regid := self.native._graphRegistry(credential, nest)):
                _, events = self.native._registryEvidence(regid)
                for event in events:
                    for proof in proofs:
                        if event.ilk != 'bup' or event.sad['b'] != proof.said:
                            continue
                        vetBlind(proof, blid=event.sad['b'])
                        keyEvent = vetBound(proof, acdc=credential, db=self.hby.db)
                        if keyEvent is not None:
                            bound.append(dict(registry=regid, s=event.sad['n'], d=event.said,
                                blid=proof.said, issuee=credential.iseaid,
                                keyEvent=dict(s=proof.bnh, d=keyEvent.said)))
            sources.append(dict(credential=credential.said,
                view=Diger(ser=credential.raw).qb64, boundEvents=bound))
        return sources

    def _nativeCurrentStanding(self, nests):
        """Require current standing for every node in retained parsed ``nests``.

        Historical bound-edge validity remains the native verifier's decision.
        This additional application rule uses the configured current observer.
        Return None after all nodes pass; raise MissingChainError for stale or
        absent observations, or ValidationError for a node no longer issued.
        """
        for nest in nests:
            credential = nest.serder
            declared = issuerRegistry(credential)
            registries = ({declared} if declared else {pre.qb64 for pre, _, _ in nest.ssts
                if pre.qb64 != credential.israid and pre.qb64 not in self.hby.kevers})
            for regid in registries:
                if not self.fresh(regid):
                    raise MissingChainError('observer evidence is missing or stale')
                state = self.native._vetRegistry(regid, self.native._blindProofs(nest),
                                                 credential.said, acdc=credential)
                if state is None or state.state != 'issued':
                    raise ValidationError('credential is not currently issued')
            for _, regid in self.native._presentationRegistries(credential) or []:
                if not self.fresh(regid):
                    raise MissingChainError('presentation registry observation is missing or stale')

    def _legacyCredential(self, exn):
        """Return a core-verified legacy credential only with fresh source standing.

        exn is a retained v1 grant. Embedded issuance proves history; configured
        source-authenticated TEL state notification proves application freshness.
        Missing evidence raises MissingChainError and starts normal TEL queries;
        invalid proof or a non-issued current state raises ValidationError."""
        exchanging.verify(self.hby, exn)
        _, pathed = exchanging.cloneMessage(self.hby, exn.said)
        embeds = exn.sad.get('e', {})
        if 'acdc' not in embeds:
            raise ValidationError('legacy grant has no credential')
        parser = self._parser(Vrsn_1_0)
        credential = SerderACDC(sad=embeds['acdc'])
        for label in ('anc', 'iss', 'acdc'):
            if label not in embeds:
                continue
            serder = (SerderACDC if label == 'acdc' else SerderKERI)(sad=embeds[label])
            if label == 'iss' and self.legacy.reger.tels.get(keys=serder.pre, on=serder.sn) == serder.said:
                continue
            if label == 'acdc' and self.legacy.reger.saved.get((credential.said,)) is not None:
                continue
            try:
                parser.parseOne(ims=bytearray(serder.raw) + pathed.get(label, b''))
            except KEL_DEPENDENCIES + (MissingRegistryError, MissingAnchorError, MissingSenderKeyStateError) as error:
                self._queryLegacy(credential)
                raise MissingChainError(str(error)) from error
        self.legacy.tvy.processEscrows()
        self.legacy.processEscrows()
        if self.legacy.reger.saved.get((credential.said,)) is None:
            raise MissingChainError('legacy credential verification is pending')
        tever = self.legacy.tevers.get(credential.regid)
        state = tever.vcState(credential.said) if tever else None
        if state is None or state.et not in ('iss', 'bis'):
            raise ValidationError('credential is not currently issued')
        observation = self.db.observed.get(('legacy', credential.said))
        if observation is not None and observation.head == state.d and observation.observer in self.legacySources:
            age = (helping.nowUTC() - helping.fromIso8601(observation.observed)).total_seconds()
            if 0 <= age <= self.maximumAge:
                return credential
        self._queryLegacy(credential)
        raise MissingChainError('legacy issuance is authentic; current TEL observation is not established')

    def _queryLegacy(self, credential):
        """Use conventional legacy TEL replay and TSN queries to configured sources."""
        if not self.legacySources:
            return
        previous = self.db.legacyQueries.get((credential.said,))
        if previous is not None:
            age = (helping.nowUTC() - helping.fromIso8601(previous.started)).total_seconds()
            if age < self.maximumAge:
                return
        record = LegacyQuery(credential.said, credential.regid, credential.israid, helping.nowIso8601())
        self.db.legacyQueries.pin((credential.said,), record)
        for route in ('tels', 'tsn'):
            self.inquisitor.telquery(ri=credential.regid, i=credential.said, pre=credential.israid,
                src=self.hab.pre, hab=self.hab, wits=list(self.legacySources), r=route,
                version=Vrsn_1_0, pvrsn=Vrsn_1_0, gvrsn=Vrsn_1_0, kind=Kinds.json)

    def _legacyReports(self):
        """Consume only core source-authenticated BADA-accepted credential TSNs.

        This is application freshness relative to the configured source's report,
        not cryptographic proof of global latest state or historical authority.
        """
        for keys, query in self.db.legacyQueries.getTopItemIter():
            for source in self.legacySources:
                current = self.legacy.reger.txnsb.current((query.credential, source))
                if current is None:
                    continue
                reply = self.legacy.reger.txnsb.serderdb.get((current.qb64,))
                if reply is None or reply.said == query.reply:
                    continue
                stamp = helping.fromIso8601(reply.sad['dt'])
                age = (helping.nowUTC() - stamp).total_seconds()
                if stamp < helping.fromIso8601(query.started) or not 0 <= age <= self.maximumAge:
                    continue
                state = self.legacy.tevers[query.registry].vcState(query.credential)
                if state is None or state.d != current.qb64:
                    continue
                self.db.observed.pin(('legacy', query.credential),
                    Observation(reply.sad['dt'], current.qb64, source))
                query.reply = reply.said
                self.db.legacyQueries.pin(keys, query)

    def process(self):
        """Retry core dependencies and persist each pending reporting decision.

        Return None. Missing chain/schema evidence keeps a submission pending;
        invalid credentials become rejected, valid empty grants non-reportable,
        and configured credential projections accepted. Terminal decisions are
        skipped on later turns and reopen. HTTP delivery belongs to workDo.
        """
        self.evidence.kvy.processEscrows()
        self.evidence.rever.processEscrows()
        self.legacy.tvy.processEscrows()
        self.legacy.processEscrows()
        self.rvy.processEscrowReply()
        self._legacyReports()
        self.scy.processEscrows()
        self.exc.processEscrow()
        for keys, record in self.db.submissions.getTopItemIter():
            if record.state != 'pending' or not self.exc.complete(record.grant):
                continue
            exn = self.hby.db.exns.get((record.grant,))
            try:
                credential = (self._nativeCredential(exn) if exn.pvrsn.major == 2
                              else self._legacyCredential(exn))
                if credential is None:
                    # Protocol-valid empty disclosure is terminal reporting work,
                    # so it cannot poison retries or enter credential delivery.
                    record.state, record.reason = 'non-reportable', 'grant discloses no credential'
                    self.db.submissions.pin(keys, record)
                    continue
                schema = credential.sad.get('s')
                schema = schema.get('$id') if isinstance(schema, dict) else schema
                if credential.israid not in self.issuers or schema not in self.schemas:
                    raise ValidationError('issuer or schema is outside application policy')
                values, disclosure = project(credential, self.fields, self.required)
                record.payload = dict(schema='dolly.accepted-credential/v1',
                    decision='accepted', credential=credential.said, grant=exn.said,
                    issuer=credential.israid, presenter=exn.pre, verifier=self.hab.pre,
                    credentialSchema=schema, protocol=exn.pvrsn.major,
                    business=values, disclosure=disclosure, standing='issued',
                    acceptedAt=helping.nowIso8601())
                record.state, record.reason = 'accepted', ''
            except (MissingChainError, MissingSchemaError) as error:
                record.reason = str(error)
            except ValidationError as error:
                record.state, record.reason = 'rejected', str(error)
            self.db.submissions.pin(keys, record)

    def request(self, url, *, body=None, data=None):
        """Send one bounded CESR-evidence or JSON-webhook POST and yield while waiting.

        url selects the endpoint; body is raw CESR and data is a JSON payload.
        Return the actual HTTP response, or None on timeout. The client/doer is
        removed and closed even on cancellation; response status determines the
        caller's observation or delivery decision."""
        target = urlsplit(url)
        client = http.clienting.Client(scheme=target.scheme, hostname=target.hostname,
            port=target.port or (443 if target.scheme == 'https' else 80))
        doer = http.clienting.ClientDoer(client)
        self.clients.add(client)
        self.extend([doer])
        try:
            client.request(method='POST', path=target.path or '/', body=body, data=data,
                headers={'Content-Type': CESR_CONTENT_TYPE if body is not None else 'application/json'})
            deadline = self.tyme + self.timeout
            while not client.responses and self.tyme < deadline:
                yield self.tock
            return client.responses.popleft() if client.responses else None
        finally:
            self.remove([doer])
            client.close()
            self.clients.discard(client)

    def workDo(self, tymth=None, tock=0.03125, **kwa):
        """Run observer acquisition, pending verification, and accepted hook retries.

        tymth/tock follow hio scheduling. Only authenticated retained grant
        evidence authorizes registry fetch hints; only accepted undelivered
        submissions enter webhook delivery. Acknowledged delivery is persisted.
        Cancellation unwinds live request owners; no exactly-once guarantee is
        made for a lost HTTP acknowledgement."""
        self.wind(tymth)
        yield tock
        while True:
            registries = set()
            for _, record in self.db.submissions.getTopItemIter():
                if record.state != 'pending':
                    continue
                exn = (self.hby.db.exns.get((record.grant,))
                       or self.hby.db.epse.get((record.grant,)))
                if exn is None or exn.pvrsn.major != 2:
                    continue
                try:
                    # Missing TEL does not authorize unauthenticated fetch hints.
                    # Authentication and retained nests belong to core Exchanger.
                    exchanging.verify(self.hby, exn)
                except ValidationError:
                    continue
                for nest in exchanging.loadParsedNestedSubstreams(self.hby, exn.said):
                    if (regid := issuerRegistry(nest.serder)) and not self.fresh(regid):
                        registries.add(regid)
                    registries.update(regid for _, regid in
                        self.native._presentationRegistries(nest.serder) or []
                        if not self.fresh(regid))
                    # Nonissuer source triples are untrusted fetch hints until
                    # the core validates their exact accepted TEL event.
                    registries.update(pre.qb64 for pre, _, _ in nest.ssts
                        if pre.qb64 != nest.serder.israid and pre.qb64 not in self.hby.kevers
                        and not self.fresh(pre.qb64))
            for regid in sorted(registries):
                response = yield from self.request(self.observer,
                    body=signedQuery(self.hab, 'tels', {'i': regid}))
                if response is not None:
                    self.observe(regid, response)
            self.process()
            for keys, record in self.db.submissions.getTopItemIter():
                if record.state == 'accepted' and not record.delivered:
                    response = yield from self.request(self.webhook, data=record.payload)
                    if response is not None and 200 <= response['status'] < 300:
                        record.delivered = True
                        self.db.submissions.pin(keys, record)
            # Ordinary application retry; no distributed exactly-once promise.
            started = self.tyme
            while self.tyme < started + 1.0:
                yield tock

    def close(self):
        """Close HTTP clients and owned stores, including independent sections.

        Reopening requires a fresh context over the same configured stores.
        Habery ownership remains with the caller.
        """
        for client in tuple(self.clients):
            client.close()
        self.db.close()
        self.evidence.close()
        self.legacy.reger.close()
        self.sections.close()


class IntakeEnd:
    """Expose framed CESR intake with explicit HTTP acknowledgement semantics."""
    def __init__(self, ctx):
        """Bind the Dolly context that owns evidence verification and submissions."""
        self.ctx = ctx

    @staticmethod
    def decode(raw, attachment, genus):
        """Return original evidence bytes and their initial parser genus version.

        ``raw`` is the HTTP body; optional ``attachment`` and ``genus`` are the
        CESR attachment and genus headers. Serdery selects the JSON protocol
        from its serialized metadata. Header form requires exactly one body;
        stream form retains consecutive messages and attachments untouched.
        The core parser checks message/stream compatibility and authentication.
        Malformed metadata, framing, or unsupported genus raises the decoder's
        extraction/value error or ValidationError for the HTTP boundary.
        """
        first = None
        if attachment is not None or raw.startswith(b'{'):
            remaining = bytearray(raw)
            first = Serdery().reap(ims=remaining, genus=GenDex.KERI, svrsn=Vrsn_2_0)
            if attachment is not None:
                if remaining:
                    raise ValidationError('attachment-header body must contain exactly one message')
                raw += attachment.encode('ascii')
        default = str((first.gvrsn or first.pvrsn).major) if first else '2'
        genus = genus if genus is not None else default
        if genus not in ('1', '2'):
            raise ValidationError('CESR-Genus must be 1 or 2')
        return raw, Vrsn_1_0 if genus == '1' else Vrsn_2_0

    def on_post(self, req, rep):
        """Acknowledge parsed intake with 202; map media/framing errors to HTTP.

        ``req`` and ``rep`` are Falcon request/response objects. A successful
        response describes submission states and never promises hook delivery.
        Unsupported media produces 415; malformed evidence produces 400.
        """
        if (req.content_type or '').split(';')[0] != CESR_CONTENT_TYPE:
            raise falcon.HTTPUnsupportedMediaType()
        raw = req.bounded_stream.read()
        try:
            raw, version = self.decode(raw, req.get_header(CESR_ATTACHMENT_HEADER),
                                       req.get_header('CESR-Genus'))
            rep.media = self.ctx.ingest(raw, version=version)
        except (ValidationError, ExtractionError, MissingSenderKeyStateError, ValueError, TypeError) as error:
            raise falcon.HTTPBadRequest(description=str(error)) from error
        rep.status = falcon.HTTP_202

    on_put = on_post


class HealthEnd:
    """Expose process readiness independently of any credential decision."""
    def on_get(self, req, rep):
        """Return application readiness in the Falcon response; no proof is evaluated."""
        rep.media = {'application': 'dolly', 'status': 'ready'}


class StreamParser(Parser):
    """Keep incremental CESR framing in core and add Dolly's dispatch boundary."""

    def __init__(self, *, context, **kwa):
        """Bind one connection's parser to the shared application processors."""
        self.context = context
        super().__init__(**kwa)

    def msgProcess(self, exts, **kwa):
        """Dispatch one complete core-parsed frame; no version/authentication override."""
        return self.context.dispatch(self, exts)


class TcpIntake(doing.Doer):
    """Own one live core parser/generator per hio TCP remoter buffer.

    Adapted from KERIpy Directant's remoter lifecycle; no protocol decoder is
    copied. Partial frames stay in that connection's parser until completed.
    """

    def __init__(self, context, server, **kwa):
        """Bind a Dolly context and separately scheduled hio ServerDoer server."""
        self.context, self.server = context, server
        self.sessions = {}
        super().__init__(**kwa)

    def recur(self, tyme):
        """Advance each client once; discard only its own malformed/closed stream.

        Initial JSON metadata selects that connection's parser genus. Native
        CESR starts at genus 2 and may carry core genus-version counters. A
        malformed initial body closes its connection; incomplete bodies wait.
        No connection toggles the shared enabled KRAM policy.
        """
        for address, remoter in list(self.server.ixes.items()):
            if address not in self.sessions and remoter.rxbs:
                try:
                    _, version = IntakeEnd.decode(bytes(remoter.rxbs), None, None)
                except ShortageError:
                    if remoter.cutoff:
                        self.server.removeIx(address)
                    continue
                except (ExtractionError, ValidationError, ValueError, TypeError):
                    self.server.removeIx(address)
                    continue
                parser = self.context._parser(version, stream=True)
                self.sessions[address] = parser.parsator(ims=remoter.rxbs,
                    framed=False, processive=True, local=False)
            if address in self.sessions:
                next(self.sessions[address])
            if remoter.cutoff or remoter.tymeout > 0 and remoter.tymer.expired:
                self._close(address)
        return False

    def _close(self, address):
        """Close one connection's suspended parser and its socket, if present."""
        if (session := self.sessions.pop(address, None)) is not None:
            session.close()
        if address in self.server.ixes:
            self.server.removeIx(address)

    def exit(self):
        """Cancel all parser generators before the enclosing server/store shutdown."""
        for address in list(self.sessions):
            self._close(address)


def setup(hby, hab, *, host='127.0.0.1', port=6644, tcpPort=None,
          keypath=None, certpath=None, cafilepath=None, **kwa):
    """Return context and lifecycle Doers for independently selected HTTP/TCP.

    ``port`` selects HTTP (None disables it); ``tcpPort`` selects raw TCP (None
    disables it). HTTP TLS paths pass to KERIpy's server factory. Context owns
    protocol/application stores. hio server Doers own sockets and TcpIntake
    owns only connection-local parser generators; shutdown reverses that order.
    """
    context = Context(hby, hab, **kwa)
    doers = [BaserDoer(baser=context.db), BaserDoer(baser=context.evidence.reger),
             BaserDoer(baser=context.legacy.reger), BaserDoer(baser=context.sections), context]
    if port is not None:
        server = createHttpServer(host=host, port=port, app=context.app,
                                 keypath=keypath, certpath=certpath, cafilepath=cafilepath)
        doers.append(http.ServerDoer(server=server))
    if tcpPort is not None:
        server = tcp.Server(ha=(host, tcpPort))
        if not server.reopen():
            raise OSError('cannot open Dolly TCP listener')
        server.eha = server.ha
        doers.extend([tcp.ServerDoer(server=server), TcpIntake(context, server)])
    return context, doers
