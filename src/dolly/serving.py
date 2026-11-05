"""Sally-like application policy over v2 ACDC and upstream verification.

Composition informed by Sally ed789de (Apache-2.0); cryptographic verification
remains in Exchanger and v2 Regery/IPEX; Verifier retains sections.
"""
from dataclasses import asdict, dataclass, field
import json
import ipaddress
import math
from pathlib import Path
from urllib.parse import urlsplit

import falcon
from hio.base import doing
from hio.core import http, tcp

from keri import Vrsn_2_0, Kinds
from keri.acdc import Regery, ipexing, chaining
from keri.acdc.unblinding import Unblind
from keri.app import agenting, forwarding
from keri.app.indirecting import createHttpServer
from dolly.projecting import project
from keri.app.httping import CESR_CONTENT_TYPE, CESR_ATTACHMENT_HEADER
from keri.core import (Parser, SerderACDC, SerderKERI, Serdery, GenDex,
                       BlindState, BoundState, Diger, Kevery, Number, NumDex, Schemer, SealSource,
                       messagize, query as makeQuery)
from keri.core.kraming import Pruner
from keri.db import dbing, koming
from keri.db.basing import BaserDoer
from keri.db.dbing import snKey
from keri.help import helping
from keri.kering import (ValidationError, ExtractionError, ShortageError, MissingChainError, MissingSchemaError,
                         MissingAnchorError, MissingSenderKeyStateError,
                         MissingSignatureError, MissingWitnessSignatureError,
                         MissingDelegationError, OutOfOrderError, MissingDelegableApprovalError,
                         UnverifiedReceiptError, UnverifiedWitnessReceiptError,
                         UnverifiedTransferableReceiptError)
from keri.peer import exchanging
from keri.vdr import verifying, eventing


MAX_OUTBOUND_REQUESTS_PER_TURN = 8
OUTBOUND_RETRY_INITIAL = 5.0
OUTBOUND_RETRY_MAXIMUM = 300.0


KEL_DEPENDENCIES = (MissingSignatureError, MissingWitnessSignatureError,
    MissingDelegationError, OutOfOrderError, MissingDelegableApprovalError,
    UnverifiedReceiptError, UnverifiedWitnessReceiptError, UnverifiedTransferableReceiptError)


class _RequestPolicy:
    """Configure Dolly's authenticated native requests without denial exemptions."""
    def get(self):
        return {'kram': {'enabled': True, 'denials': [],
            'caches': {'~': [1000, 5000, 60000, 300000, 5000, 60000, 300000]}}}


def signedQuery(hab, route, attributes=None):
    """Sign one native observer query using this application's habitat."""
    serder = makeQuery(pre=hab.pre, route=route, query=attributes or {},
                   stamp=helping.nowIso8601(), version=Vrsn_2_0)
    return bytes(hab.endorse(serder, last=True, framed=False, gvrsn=Vrsn_2_0))


@dataclass
class Submission:
    """Persist one grant reporting decision and its exact projected payload.

    Pending records retry dependencies; terminal decisions survive reopen.
    admit identifies the locally accepted native response. admitSubmitted is
    transport acknowledgement; delivered is webhook acknowledgement. Neither
    establishes the presenter's protocol acceptance."""
    grant: str
    registries: list = field(default_factory=list)
    state: str = 'pending'
    reason: str = ''
    payload: dict = field(default_factory=dict)
    delivered: bool = False
    admit: str = ''
    admitSubmitted: bool = False


@dataclass
class Observation:
    """Retain a locally verified registry head and configured observer observation.

    observed is that report's time; head identifies accepted evidence. The
    record does not establish global latest state or publication time."""
    observed: str
    head: str
    observer: str


@dataclass(frozen=True)
class SourceTrust:
    """Bind one observer URL to the CA and certificate identity Dolly trusts.

    The URL is retained as the observation-source identity. ``cafilepath`` is
    an explicit PEM CA bundle; ``certedhost`` overrides TLS hostname checking
    when the URL connects to an IP address.
    """
    url: str
    cafilepath: str
    certedhost: str | None = None

    @classmethod
    def fromConfig(cls, value):
        """Return a strictly validated configured HTTPS observer trust anchor."""
        if not isinstance(value, dict):
            raise ValueError('Dolly observer must configure url and cafilepath')
        unknown = set(value) - {'url', 'cafilepath', 'certedhost'}
        if unknown:
            raise ValueError(f'unknown Dolly observer trust fields: {sorted(unknown)}')
        url, cafilepath = value.get('url'), value.get('cafilepath')
        certedhost = value.get('certedhost')
        if not isinstance(url, str) or not url.strip():
            raise ValueError('Dolly observer URL must be a non-empty string')
        if not isinstance(cafilepath, str) or not cafilepath.strip():
            raise ValueError('Dolly observer CA bundle must be a non-empty path')
        if certedhost is not None and (not isinstance(certedhost, str) or not certedhost.strip()):
            raise ValueError('Dolly observer certificate hostname must be a non-empty string')
        url, capath = url.strip(), Path(cafilepath).expanduser()
        if not capath.is_absolute():
            raise ValueError('Dolly observer CA bundle path must be absolute')
        cafilepath = str(capath.resolve())
        certedhost = certedhost.strip() if certedhost is not None else None
        try:
            target = urlsplit(url)
            target.port  # Force validation of a malformed explicit port.
        except ValueError as error:
            raise ValueError('Dolly observer URL is invalid') from error
        if (target.scheme != 'https' or not target.hostname or target.username is not None
                or target.password is not None or target.query or target.fragment):
            raise ValueError('Dolly observer must be an HTTPS URL without credentials, query, or fragment')
        if not Path(cafilepath).is_file():
            raise ValueError('Dolly observer CA bundle must be an existing file')
        try:
            ipaddress.ip_address(target.hostname)
        except ValueError:
            if certedhost is not None:
                raise ValueError('Dolly observer certificate hostname override requires an IP URL')
        return cls(url=url, cafilepath=cafilepath, certedhost=certedhost)


class DollyBaser(dbing.LMDBer):
    """Own durable submissions and observer reports.

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
        return self.opened


class Notices:
    """Adapt the core notifier contract while durable EXNs drive application work."""
    def add(self, attrs):
        # Durable EXN state, not notification delivery, drives application work.
        """Ignore transient attrs notifications; Context reads durable verified EXNs.

        No notification is an acceptance or delivery acknowledgement."""
        pass


class RequestClientDoer(http.clienting.ClientDoer):
    """Contain socket and decoder failures for one observer or webhook request."""
    def __init__(self, client, **kwa):
        super().__init__(client, **kwa)
        self.error = None

    def recur(self, tyme):
        """Service once, retaining expected socket/TLS and decoder failures."""
        try:
            return super().recur(tyme)
        except (OSError, ValueError) as error:
            self.error = error
            return True


def rotated(items, cursor, limit, *, key=lambda item: item):
    """Select a deterministic bounded slice after the prior turn's cursor.

    The cursor is intentionally session-local. Durable queue rows remain the
    source of truth across restart, while every live session eventually wraps
    through candidates that remain eligible.
    """
    ordered = sorted(items, key=key)
    if not ordered or limit <= 0:
        return [], cursor
    start = 0
    if cursor is not None:
        start = next((index for index, item in enumerate(ordered)
                      if key(item) > cursor), 0)
    selected = (ordered[start:] + ordered[:start])[:limit]
    return selected, key(selected[-1])


class Context(doing.DoDoer):
    """Compose core verification with explicit reporting, projection, and delivery.

    One native registry owner and enabled KRAM owner serve both direct transports.
    Historical inspection is separate from current reporting policy."""
    def __init__(self, hby, hab, *, issuers, schemas, fields, required=(),
                 observer, webhook, timeout=5.0,
                 db=None, baser=None, vry=None):
        """Own v2 KERI/TEL/IPEX and independent section processors once.

        ``baser`` is the v2 RegBaser; vry.reger retains independent sections.
        Exact Grant views stay in Baser.enst. One enabled KRAM pruner shares the
        application's processor lifecycle; timeout bounds outbound requests.
        """
        if not math.isfinite(timeout) or timeout <= 0:
            raise ValueError('Dolly request timeout must be finite and positive')
        self.observerTrust = SourceTrust.fromConfig(observer)
        self.hby, self.hab = hby, hab
        self.issuers, self.schemas = set(issuers), set(schemas)
        self.fields, self.required = dict(fields), tuple(required)
        self.observer, self.webhook = self.observerTrust.url, webhook
        self.timeout = timeout
        self._deliveryFailures, self._deliveryRetry = {}, {}
        self._registryCursor = self._deliveryCursor = None
        self._unblinds = {}
        self._liveGrants = set()
        self.db = db if db is not None else DollyBaser(name=hby.name, base=hby.base, temp=hby.temp)
        self.kvy = Kevery(db=hby.db, cf=_RequestPolicy(), enableKram=True,
                          lax=False, local=False)
        self.rgy = Regery(hby, name=hby.name, base=hby.base, temp=hby.temp, baser=baser)
        self.pruner = Pruner(self.kvy.kramer, tock=1.0)
        self.vry = vry if vry is not None else verifying.Verifier(hby,
            reger=eventing.Reger(name=hby.name, base=hby.base, temp=hby.temp))
        # Native Unblind authenticates through hab.rvy: use that same owner for
        # intake, endpoint evidence, reply escrows and auxiliary attachments.
        self.rvy = hab.rvy
        self.kvy.rvy = self.rvy
        self.kvy.registerReplyRoutes(self.rvy.rtr)
        self.exc = exchanging.Exchanger(hby, handlers=[])
        ipexing.loadHandlers(hby, self.exc, Notices(), rgy=self.rgy)
        self.acdcV2Ipex = self.exc.routes['/ipex/grant']
        self.unblind = Unblind(hab, self.exc, self.rgy, states=('issued', 'revoked', ''))
        self.kvy.qvy = self.unblind
        self.rvy.rtr.addRoute(Unblind.Route, self.unblind, blinders=True, attachments=True)
        self._promoteSchemas()
        self.app = falcon.App()
        self.app.add_route('/ingest', IntakeEnd(self))
        self.app.add_route('/', IntakeEnd(self))
        self.app.add_route('/health', HealthEnd())
        self.clients = set()
        super().__init__(doers=[self.pruner, doing.doify(self.workDo)])

    def _parser(self, version, *, stream=False):
        """Return a parser sharing this context's processors and section owner.

        ``version`` selects the initial CESR stream genus. ``stream`` adds only
        the application dispatch hook to the same core parser for live TCP.
        Protocol checks remain in Parser; parsing does not imply acceptance.
        """
        klass = StreamParser if stream else Parser
        extra = {"context": self} if stream else {}
        return klass(**extra, kvy=self.kvy, rgy=self.rgy,
            vry=self.vry, exc=self.exc, rvy=self.rvy,
            local=False, version=version)

    def ingest(self, raw, version=Vrsn_2_0):
        """Dispatch CESR evidence and return states for grants received in raw.

        ``raw`` may contain consecutive KEL, registry, credential, section, or
        EXN frames. ``version`` selects the initial stream genus. Independent
        schema sections enter the same store used for live and retained ACDC v2 IPEX
        verification; they never replace the grant's revealed view. Incomplete
        framing or invalid evidence raises ValidationError; concrete processor
        escrows retain retryable dependencies. HTTP success means intake only.
        """
        parser, ims, received = self._parser(version), bytearray(raw), []
        while ims:
            size = len(ims)
            dom = parser.parseOneBare(ims=ims, processive=False, local=False)
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
        if serder.pvrsn != Vrsn_2_0:
            raise ValidationError('Dolly accepts only v2 protocol messages')
        if serder.ilk in ('xip', 'exn') and serder.route == '/ipex/grant':
            recipient = serder.sad.get('ri')
            if recipient != self.hab.pre:
                raise ValidationError('grant is addressed to a different disclosee')
            registries = sorted({regid for item in exts.get('nests', [])
                                 if (regid := item['serder'].sad.get('rd'))})
            submission = Submission(serder.said, registries)
            submitted = serder.said
        try:
            Parser.msgProcess(parser, exts, kvy=self.kvy,
                tvy=None, vry=self.vry, exc=self.exc, rvy=self.rvy)
        except KEL_DEPENDENCIES + (MissingChainError, MissingSchemaError):
            pass  # Concrete processors already retained their dependencies.
        self._promoteSchemas()
        # Missing bootstrap raises before KRAM retains this request. Do not
        # manufacture a pending row that would survive a refused HTTP request.
        if submission is not None and self.db.submissions.put((submitted,), submission):
            self._liveGrants.add(submitted)
        return submitted

    def _promoteSchemas(self):
        """Cache verified expanded JSON schema documents held by ordinary section intake.

        Other section kinds stay held material. Non-JSON schema commitments are
        not transcoded into a different $id, and no held section expands enst.
        """
        for _, message in self.vry.reger.sections.getTopItemIter():
            if message.ilk != 'sch' or message.kind != Kinds.json:
                continue
            if not message.verify():
                raise ValidationError('held schema section has invalid commitments')
            document = message.sad.get('s')
            if not isinstance(document, dict):
                continue
            schemer = Schemer(raw=json.dumps(document, separators=(',', ':'),
                                             ensure_ascii=False).encode())
            if schemer.said != document.get('$id'):
                raise ValidationError('held schema $id does not match its document')
            self.hby.db.schema.pin((schemer.said,), schemer)

    def synchronized(self, regid):
        """Report configured-source/head correspondence, without an age or validity claim."""
        record = self.db.observed.get((regid,))
        head = self.rgy.store.head(regid)
        return bool(record and record.observer == self.observer
                    and head and record.head == head.qb64)

    def observe(self, regid, response):
        """Record source telemetry only after all supplied public evidence accepts.

        TLS identity belongs to request(). Neither remote freshness headers nor
        local observation time authorize reporting. Match the highest accepted
        head actually carried by this response, never a newer unrelated cache row.
        """
        if (response['status'] != 200 or response.get('headers', {}).get(
                'content-type', '').split(';')[0] != CESR_CONTENT_TYPE):
            return False
        ims, events = bytearray(response['body']), []
        parser = self._parser(Vrsn_2_0)
        try:
            while ims:
                size = len(ims)
                dom = parser.parseOneBare(ims=ims, processive=False, local=False)
                if dom is None or dom.serder is None or len(ims) >= size:
                    return False
                event = dom.serder
                if event.ilk not in ('rip', 'bup', 'icp', 'dip', 'rot', 'drt', 'ixn', 'rct'):
                    return False
                events.append(event)
            self.ingest(response['body'])
        except (ValidationError, ExtractionError, ValueError, TypeError):
            return False
        heads = []
        for event in events:
            if isinstance(event, SerderACDC):
                registry = event.said if event.ilk == 'rip' else event.sad['rd']
                sequence = Number(numh=event.sad['n']).num
                accepted = self.rgy.store.seqSaider(registry, sequence)
                if accepted is None or accepted.qb64 != event.said:
                    return False
                if registry == regid:
                    heads.append((sequence, event.said))
            elif event.ilk != 'rct' and self.hby.db.kels.getLast(
                    keys=event.pre, on=event.sn) != event.said:
                return False
            elif event.ilk == 'rct' and self._receiptPending(event):
                return False
        head = self.rgy.store.head(regid)
        if not heads or head is None or max(heads)[1] != head.qb64:
            return False
        self.db.observed.pin((regid,), Observation(helping.nowIso8601(), head.qb64, self.observer))
        return True

    def _receiptPending(self, event):
        """Match unresolved receipts from this response, rather than global escrow counts."""
        db = self.hby.db
        if any(said == event.said for said, _ in db.uwes.get(keys=event.pre, on=event.sn)):
            return True
        receipts = db.ures.get(keys=(event.pre, Number(num=event.sn, code=NumDex.Huge).qb64))
        receipts += db.vres.get(keys=snKey(event.pre, event.sn))
        return any(receipt[0].qb64 == event.said for receipt in receipts)

    def _acdcV2GrantCredential(self, exn):
        """Recheck exact retained proof, then apply Dolly's current issued-state policy."""
        try:
            _, nests, verdict, records = self.exc.reverifyGrant(exn.said)
        except (MissingAnchorError, MissingSenderKeyStateError) as error:
            raise MissingChainError(str(error)) from error
        if verdict is None:
            raise ValidationError('ACDC v2 Grant verification refused')
        if verdict.verdict == chaining.Verdicts.unknown and verdict.retryable:
            raise MissingChainError(verdict.reason)
        if verdict.verdict != chaining.Verdicts.valid:
            raise ValidationError(verdict.reason)
        for nest in nests:
            credential = nest.serder
            if not credential.sad.get('rd'):
                continue
            state = records.get(credential.said)
            if state is None:
                raise MissingChainError('current registry state is not authenticated')
            if state.state != 'issued':
                raise ValidationError('credential is not currently issued')
        return self._acdcV2GrantDisclosure(exn, nests)[0]

    def _acdcV2GrantDisclosure(self, exn, nests=None):
        """Select the exact retained origin, without asserting current proof validity."""
        origins = exn.sad['a']['o']
        if not origins:
            return None, []
        if nests is None:
            nests = exchanging.loadParsedNestedSubstreams(self.hby, exn.said)
        origin = next((nest.serder for nest in nests if nest.serder.said == origins[0]), None)
        if origin is None:
            raise ValidationError('retained Grant has no disclosed origin')
        return origin, nests

    def inspectHistorical(self, grant):
        """Inspect retained views and recorded observations without rechecking current validity.

        No reporting decision, fresh authority, or hook follows from this display.
        Independent cached sections never expand the retained disclosure.
        """
        exn = self.hby.db.exns.get((grant,))
        if exn is None or exn.pvrsn != Vrsn_2_0 or exn.route != '/ipex/grant':
            raise ValidationError('historical inspection requires a retained ACDC v2 IPEX grant')
        credential, nests = self._acdcV2GrantDisclosure(exn)
        values, disclosure = project(credential, self.fields) if credential else ({}, {})
        return dict(purpose='historical-evidence', currentStanding='not-evaluated', grant=grant,
            credential=credential.said if credential else None,
            business=values, disclosure=disclosure, sources=self._historicalSources(grant, nests))

    def _historicalSources(self, grant, nests):
        """Identify exact retained views and optional five-field recorded observations."""
        sources = []
        for nest in nests:
            credential = nest.serder
            record = self.hby.db.exrs.get((grant, credential.said))
            sources.append(dict(credential=credential.said,
                view=Diger(ser=credential.raw).qb64,
                recordedObservation=asdict(record) if record is not None else None))
        return sources

    def _policy(self, exn, credential):
        """Apply the same exact-view application policy before approval and Admit."""
        if exn.sad.get('ri') != self.hab.pre:
            raise ValidationError('grant is addressed to a different disclosee')
        schema = credential.sad.get('s')
        schema = schema.get('$id') if isinstance(schema, dict) else schema
        if credential.israid not in self.issuers or schema not in self.schemas:
            raise ValidationError('issuer or schema is outside application policy')
        values, disclosure = project(credential, self.fields, self.required)
        return schema, values, disclosure

    def _registryHints(self, nests):
        """Read acquisition hints from already authenticated exact retained nests."""
        registries = set()
        for nest in nests:
            if regid := nest.serder.sad.get('rd'):
                registries.add(regid)
            registries.update(regid for _, regid in
                self.acdcV2Ipex._presentationRegistries(nest.serder) or [])
            registries.update(pre.qb64 for pre, _, _ in nest.ssts
                if pre.qb64 != nest.serder.israid and pre.qb64 not in self.hby.kevers)
        return registries

    def _openings(self, record, exn):
        """Approve once, only after observer evidence and exact application policy.

        Core owns the original deadline, transaction status and frozen public
        heads. A reopened process cannot renew an interrupted approval.
        """
        operation = self._unblinds.get(record.grant)
        if operation is not None:
            if self.unblind.complete(operation['x']):
                operation['finished'] = bool(self.unblind.finish(operation['x']))
            else:
                self.unblind.start(record.grant)  # Recheck frozen heads/lifetime only.
            return
        nests = exchanging.loadParsedNestedSubstreams(self.hby, exn.said)
        hints = self._registryHints(nests)
        if not hints or not all(self.synchronized(regid) for regid in hints):
            return
        origin, _ = self._acdcV2GrantDisclosure(exn, nests)
        if origin is None:
            return
        self._policy(exn, origin)
        if record.grant not in self._liveGrants:
            raise MissingChainError('interrupted presentation requires a fresh Grant')
        xid = exn.said if exn.ilk == 'xip' else exn.sad.get('x')
        context = self.exc.presentationContext(exn.said, xid=xid,
            sender=exn.pre, recipient=self.hab.pre)
        if context is None:
            deadline = self.hby.db.epsd.get((exn.said,))
            if (deadline is not None and helping.nowUTC() >= deadline.datetime
                    or self.hby.db.erpy.get((exn.said,)) is not None):
                raise ValidationError('presentation is unavailable, terminated or expired')
            return  # Ordinary schema/chain dependencies have not authorized approval.
        # start() refuses an already sufficient Grant; callers reach here only
        # when ordinary verification still needs current issuer openings.
        self.unblind.approve(exn.said)
        operation = dict(x=xid, query=None, sent=False, finished=False)
        self._unblinds[record.grant] = operation
        operation['query'] = self.unblind.start(exn.said)

    def _acceptedAdmit(self, exn):
        """Read and authenticate only this native Grant's exact retained response."""
        link = self.hby.db.erpy.get((exn.said,))
        admitted = self.hby.db.exns.get((link.qb64,)) if link else None
        xid = exn.said if exn.ilk == 'xip' else exn.sad.get('x')
        if (exn.pvrsn != Vrsn_2_0 or exn.route != '/ipex/grant'
                or exn.sad.get('ri') != self.hab.pre
                or admitted is None or admitted.said != link.qb64 or admitted.pvrsn != Vrsn_2_0
                or admitted.route != '/ipex/admit' or admitted.sad.get('p') != exn.said
                or admitted.pre != self.hab.pre or admitted.sad.get('ri') != exn.pre
                or admitted.sad.get('x') != xid):
            return None
        exchanging.verify(self.hby, admitted)
        return admitted

    def _admit(self, record, exn):
        """Accept one local Admit and retain its exact SAID before reporting."""
        if self.hby.db.erpy.get((exn.said,)) is None:
            admitted, attachment = ipexing.admit(self.hab, 'admit verified presentation', exn)
            self._parser(Vrsn_2_0).parse(ims=bytearray(admitted.raw + attachment), framed=False)
        admitted = self._acceptedAdmit(exn)
        if admitted is None:
            raise ValidationError('presentation lacks its exact accepted local Admit')
        record.admit = admitted.said
        return admitted.said

    def _deliveryAdmission(self, keys, record):
        """Gate old undelivered v2 IPEX presentations using upstream evidence.

        This never creates a response, renews approval or reprojects a credential.
        Successfully delivered history is left as recorded.
        """
        if record.delivered:
            return True
        exn = self.hby.db.exns.get((record.grant,))
        try:
            admitted = self._acceptedAdmit(exn) if exn is not None else None
        except (ValidationError, MissingSenderKeyStateError):
            admitted = None
        if admitted is None:
            record.state = 'non-reportable'
            record.reason = 'v2 IPEX presentation lacks an accepted Admit; fresh Grant required'
            self.db.submissions.pin(keys, record)
            self._abandon(record.grant)
            return False
        if record.admit != admitted.said or record.payload.get('admit') != admitted.said:
            record.admit = admitted.said
            record.payload['admit'] = admitted.said
            self.db.submissions.pin(keys, record)
        return True

    def process(self):
        """Verify current standing, locally accept Admit, then persist reporting.

        Native auxiliary readiness never substitutes for ordinary Grant/DAG and
        application policy verification. Terminal submissions are never renewed.
        """
        self.kvy.processEscrows()
        self.rgy.processEscrows()
        self.rvy.processEscrowReply()
        self._promoteSchemas()
        # Decide unsupported retained work before core escrow replay can evict
        # its body. Delivered history and terminal decisions remain untouched.
        for keys, record in self.db.submissions.getTopItemIter():
            if record.state != 'pending':
                continue
            exn = self.hby.db.exns.get((record.grant,)) or self.hby.db.epse.get((record.grant,))
            if exn is not None and exn.pvrsn != Vrsn_2_0:
                record.state = 'rejected'
                record.reason = 'Dolly accepts only v2 protocol messages'
                self.db.submissions.pin(keys, record)
                self._abandon(record.grant)
        self.exc.processEscrow()
        for keys, record in self.db.submissions.getTopItemIter():
            if record.state != 'pending':
                continue
            exn = self.hby.db.exns.get((record.grant,)) or self.hby.db.epse.get((record.grant,))
            if exn is None:
                if record.grant in self._unblinds:
                    record.state = 'rejected'
                    record.reason = 'presentation is unavailable, terminated or expired'
                    self.db.submissions.pin(keys, record)
                    self._abandon(record.grant)
                continue
            try:
                operation = self._unblinds.get(record.grant)
                if operation is not None and not operation['finished']:
                    self._openings(record, exn)
                if not self.exc.complete(record.grant):
                    self._openings(record, exn)
                    raise MissingChainError('Grant awaits current issuer-registry openings')
                try:
                    credential = self._acdcV2GrantCredential(exn)
                except MissingChainError:
                    self._openings(record, exn)
                    raise
                if credential is None:
                    record.state, record.reason = 'non-reportable', 'grant discloses no credential'
                    self.db.submissions.pin(keys, record)
                    self._abandon(record.grant)
                    continue
                schema, values, disclosure = self._policy(exn, credential)
                admit = self._admit(record, exn)
                record.payload = dict(schema='dolly.accepted-credential/v1',
                    decision='accepted', credential=credential.said, grant=exn.said,
                    issuer=credential.israid, presenter=exn.pre, verifier=self.hab.pre,
                    credentialSchema=schema, protocol=exn.pvrsn.major,
                    business=values, disclosure=disclosure, standing='issued',
                    acceptedAt=helping.nowIso8601(), admit=admit)
                record.state, record.reason = 'accepted', ''
            except (MissingChainError, MissingSchemaError) as error:
                record.reason = str(error)
            except ValidationError as error:
                record.state, record.reason = 'rejected', str(error)
            self.db.submissions.pin(keys, record)
            if record.state != 'pending':
                self._abandon(record.grant)

    def _sendProtocol(self, destination, wire, grant):
        """Submit exact protocol bytes through ordinary endpoint/mailbox routing.

        Transport completion is separate from reply intake and peer acceptance.
        Public KEL/TEL support accompanies the message; openings and roots are
        never inferred from the support stream. Cancellation closes child I/O.
        """
        delivery = None
        try:
            parsed = Parser(version=Vrsn_2_0).parseOne(ims=bytearray(wire), processive=False)
            message = parsed.serder
            if not wire.startswith(message.raw):
                wire = messagize(message, sigers=parsed.sigers, tsgs=parsed.tsgs,
                    lsgs=parsed.lsgs, cigars=parsed.cigars,
                    bonds=[BlindState(*value) for value in parsed.bsqs]
                        + [BoundState(*value) for value in parsed.bsss],
                    nests=[exchanging.serializeParsedSubstream(nest) for nest in parsed.nests],
                    gvrsn=Vrsn_2_0)
            poster = forwarding.StreamPoster(hby=self.hby, hab=self.hab,
                recp=destination, topic='credential', version=Vrsn_2_0)
            nests = exchanging.loadParsedNestedSubstreams(self.hby, grant)
            for pre in dict.fromkeys([self.hab.pre, *(nest.serder.israid for nest in nests)]):
                for raw in self.hby.db.cloneDelegation(self.hby.kevers[pre], gvrsn=Vrsn_2_0):
                    event = SerderKERI(raw=raw)
                    poster.send(serder=event, attachment=raw[event.size:])
                for raw in self.hby.db.clonePreIter(pre, gvrsn=Vrsn_2_0):
                    event = SerderKERI(raw=raw)
                    poster.send(serder=event, attachment=raw[event.size:])
            for regid in sorted(self._registryHints(nests)):
                for raw in self.rgy.store.cloneTelIter(regid):
                    event = SerderACDC(raw=raw)
                    # RegistryStore yields bare bodies. Carry their already
                    # verified public source in a complete attachment group.
                    number, diger = self.rgy.store.anchor(event.said)
                    framed = messagize(event, bonds=[SealSource(s=number.snh,
                        d=diger.qb64)], gvrsn=Vrsn_2_0)
                    poster.send(serder=event, attachment=framed[event.size:])
            poster.send(serder=message, attachment=wire[message.size:])
            doers = poster.deliver()
            if not doers:
                return False
            delivery = doing.DoDoer(doers=doers, tymth=self.tymth)
            delivery.enter()
            deadline = self.tyme + self.timeout
            while not delivery.recur(tyme=self.tyme):
                if self.tyme >= deadline:
                    return False
                yield self.tock
            return all(not isinstance(messenger, agenting.HTTPStreamMessenger)
                or messenger.rep is not None and 200 <= messenger.rep.status < 300
                for messenger in poster.messagers)
        except (OSError, ValueError, ValidationError):
            return False
        finally:
            if delivery is not None:
                delivery.exit()

    def _abandon(self, grant):
        """Drop process-local auxiliary authority when application work terminates."""
        self._liveGrants.discard(grant)
        operation = self._unblinds.pop(grant, None)
        if operation is not None:
            self.unblind.abandon(operation['x'])

    def request(self, url, *, body=None, data=None, trust=None):
        """Send one bounded CESR-evidence or JSON-webhook POST and yield while waiting.

        url selects the endpoint; body is raw CESR and data is a JSON payload.
        ``trust`` supplies observer-only CA and certificate-hostname validation.
        Return the actual HTTP response, or None on timeout. The client/doer is
        removed and closed even on cancellation; response status determines the
        caller's observation or delivery decision."""
        target = urlsplit(url)
        tls = ({'cafilepath': trust.cafilepath, 'certedhost': trust.certedhost}
               if trust is not None else {})
        client = http.clienting.Client(scheme=target.scheme, hostname=target.hostname,
            port=target.port or (443 if target.scheme == 'https' else 80),
            redirectable=trust is None, **tls)
        doer = RequestClientDoer(client)
        self.clients.add(client)
        self.extend([doer])
        try:
            client.request(method='POST', path=target.path or '/', body=body, data=data,
                headers={'Content-Type': CESR_CONTENT_TYPE if body is not None else 'application/json'})
            deadline = self.tyme + self.timeout
            while not client.responses and getattr(doer, 'error', None) is None and self.tyme < deadline:
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
            now = self.tyme
            waitingDelivery = any(
                record.state == 'accepted' and (not record.delivered
                    or record.admit and not record.admitSubmitted)
                and now >= self._deliveryRetry.get(record.grant, 0)
                for _, record in self.db.submissions.getTopItemIter())
            registryBudget = (MAX_OUTBOUND_REQUESTS_PER_TURN // 2
                              if waitingDelivery or self._unblinds
                              else MAX_OUTBOUND_REQUESTS_PER_TURN)
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
                registries.update(self._registryHints(
                    exchanging.loadParsedNestedSubstreams(self.hby, exn.said)))
            selected, self._registryCursor = rotated(
                registries, self._registryCursor,
                registryBudget)
            outbound = 0
            for regid in selected:
                try:
                    response = yield from self.request(self.observer,
                        body=signedQuery(self.hab, 'tels', {'i': regid}), trust=self.observerTrust)
                except OSError:
                    response = None
                if response is not None:
                    self.observe(regid, response)
                outbound += 1
                if outbound >= MAX_OUTBOUND_REQUESTS_PER_TURN:
                    break
            self.process()
            for grant, operation in tuple(self._unblinds.items()):
                record = self.db.submissions.get((grant,))
                if (outbound >= MAX_OUTBOUND_REQUESTS_PER_TURN or operation['sent']
                        or record.state != 'pending'):
                    continue
                exn = self.hby.db.exns.get((grant,)) or self.hby.db.epse.get((grant,))
                if not self.hab.endsFor(exn.pre):
                    continue
                try:
                    self.unblind.start(grant)  # Never renew the frozen request.
                    operation['sent'] = yield from self._sendProtocol(
                        exn.pre, operation['query'], grant)
                except ValidationError as error:
                    record.state, record.reason = 'rejected', str(error)
                    self.db.submissions.pin((grant,), record)
                    self._abandon(grant)
                outbound += 1
            self.process()
            now = self.tyme
            deliveries = [(keys, record)
                          for keys, record in self.db.submissions.getTopItemIter()
                          if (record.state == 'accepted' and (not record.delivered
                              or record.admit and not record.admitSubmitted)
                              and now >= self._deliveryRetry.get(record.grant, 0))]
            selected, self._deliveryCursor = rotated(
                deliveries, self._deliveryCursor,
                MAX_OUTBOUND_REQUESTS_PER_TURN - outbound,
                key=lambda item: item[1].grant)
            for keys, record in selected:
                if outbound >= MAX_OUTBOUND_REQUESTS_PER_TURN:
                    break
                if not self._deliveryAdmission(keys, record):
                    continue
                if record.admit and not record.admitSubmitted:
                    exn = self.hby.db.exns.get((record.grant,))
                    record.admitSubmitted = yield from self._sendProtocol(exn.pre,
                        bytes(exchanging.serializeMessage(self.hby, record.admit)), record.grant)
                    self.db.submissions.pin(keys, record)
                    outbound += 1
                    if outbound >= MAX_OUTBOUND_REQUESTS_PER_TURN:
                        continue
                if record.delivered:
                    continue
                try:
                    response = yield from self.request(
                        self.webhook, data=record.payload)
                except OSError:
                    response = None
                if response is not None and 200 <= response['status'] < 300:
                    record.delivered = True
                    self.db.submissions.pin(keys, record)
                    self._deliveryFailures.pop(record.grant, None)
                    self._deliveryRetry.pop(record.grant, None)
                else:
                    failures = self._deliveryFailures.get(record.grant, 0) + 1
                    self._deliveryFailures[record.grant] = failures
                    exponent = min(failures - 1, 6)
                    delay = min(OUTBOUND_RETRY_INITIAL * (2 ** exponent),
                                OUTBOUND_RETRY_MAXIMUM)
                    self._deliveryRetry[record.grant] = self.tyme + delay
                outbound += 1
            # Ordinary application retry; no distributed exactly-once promise.
            started = self.tyme
            while self.tyme < started + 1.0:
                # A native reply can accept its Admit through intake while this
                # worker is idle. Deliver new reporting work on the next turn.
                if self.tyme > started and any(
                        record.state == 'accepted' and not record.delivered
                        and self.tyme >= self._deliveryRetry.get(record.grant, 0)
                        for _, record in self.db.submissions.getTopItemIter()):
                    break
                yield tock

    def close(self):
        """Close HTTP clients and the v2, section, and application stores.

        Reopening requires a fresh context over the same configured stores.
        Habery ownership remains with the caller.
        """
        for grant in tuple(self._unblinds):
            self._abandon(grant)
        self._liveGrants.clear()
        self.rvy.rtr.routes[:] = [route for route in self.rvy.rtr.routes
                                 if route.resource is not self.unblind]
        for client in tuple(self.clients):
            client.close()
        self.db.close()
        self.rgy.close()
        self.vry.reger.close()


class IntakeEnd:
    """Expose framed CESR intake with explicit HTTP acknowledgement semantics."""
    def __init__(self, ctx):
        """Bind HTTP intake to one caller-owned Dolly context.

        Args:
            ctx (Context): Shared verifier, exact retained views, and submission tracker.

        Returns:
            None. Opens no stores/parsers/sockets and starts no scheduling lifecycle."""
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
        if genus != '2':
            raise ValidationError('Dolly requires CESR-Genus 2')
        return raw, Vrsn_2_0

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
        """Answer HTTP readiness without evaluating evidence or disclosing private state.

        Args:
            req (falcon.Request): Incoming health request, unused by this endpoint.
            rep (falcon.Response): Response receiving application/status JSON.

        Returns:
            None. A ready response is an application liveness fact, not proof of issuer,
            observer freshness, credential acceptance, or completed webhook delivery."""
        rep.media = {'application': 'dolly', 'status': 'ready'}


class StreamParser(Parser):
    """Keep incremental CESR framing in core and add Dolly's dispatch boundary."""

    def __init__(self, *, context, **kwa):
        """Bind connection-local parsing state to the shared application dispatcher.

        Args:
            context (Context): Caller-owned shared processors and submission state.
            **kwa: Core Parser options, including input buffer and framing/version owners.

        Returns:
            None. Retains context and delegates core parser construction. It opens no
            independent database and supplies no authentication-policy override."""
        self.context = context
        super().__init__(**kwa)

    def msgProcess(self, exts, **kwa):
        """Dispatch one complete parsed frame through the application's shared owners.

        Args:
            exts (dict): Core-parsed message and attachment fields for exactly one frame.
            **kwa: Parser processor keywords accepted for compatibility; dispatch chooses
            the concrete shared context owners rather than trusting alternate handlers.

        Returns:
            str | None: Submitted Grant SAID, or None for non-Grant input, as returned by
            Context.dispatch. This result alone does not establish semantic acceptance.

        Core validation errors propagate to ordinary parser handling; retryable evidence
        stays in existing dependency escrows. No input extraction or yielding occurs here."""
        return self.context.dispatch(self, exts)


class TcpIntake(doing.Doer):
    """Own one live core parser/generator per hio TCP remoter buffer.

    Adapted from KERIpy Directant's remoter lifecycle; no protocol decoder is
    copied. Partial frames stay in that connection's parser until completed.
    """

    def __init__(self, context, server, **kwa):
        """Compose connection-local incremental parsing over a separately owned TCP server.

        Args:
            context (Context): Shared authenticated evidence and application processors.
            server (hio.tcp.Server): Listener/remoter owner scheduled by its ServerDoer.
            **kwa: HIO Doer scheduling options.

        Returns:
            None. Starts with no parser sessions; recur creates one per accepted remoter.
            This doer owns those generators and removes connection I/O, while ServerDoer
            retains listener lifecycle ownership. Construction authenticates no messages."""
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
        """Remove one remoter's suspended parsing generator and connection socket.

        Args:
            address: Connection key in this intake's sessions and server.ixes mappings.

        Returns:
            None. Missing generator/socket entries are harmless; present parser cleanup
            and server.removeIx failures propagate through the owning lifecycle.

        Cancel parsing before removing its connection so one malformed/disconnected
        stream cannot retain state or interfere with another remoter's evidence."""
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
    doers = [BaserDoer(baser=context.db), BaserDoer(baser=context.rgy.baser),
             BaserDoer(baser=context.vry.reger), context]
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
