"""Installed direct HTTP/TCP verifier command, adapted from the extracted KLI command."""
from dataclasses import asdict
import argparse
import json
from pathlib import Path
import signal

from hio.base import doing

from dolly import serving
from dolly.schemas import load as loadSchema
from keri import Vrsn_1_0, Vrsn_2_0
from keri.app.habbing import HaberyDoer
from keri.app.keeping import Keeper
from keri.app.oobiing import Oobiery
from keri.cli.common import Parsery, setupHby
from keri.core import Schemer
from keri.kering import AuthError, ConfigurationError


def buildParser():
    """Return the standalone command parser with existing KERI identity options."""
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    server = commands.add_parser('server')
    actions = server.add_subparsers(dest='action', required=True)
    start = actions.add_parser('start', parents=[Parsery.keystore()])
    start.add_argument('--alias', '-a', required=True)
    start.add_argument('--config', required=True, help='JSON reporting/observer/webhook policy')
    start.add_argument('--direct', action='store_true', required=True, help='enable direct evidence intake')
    start.add_argument('--http', type=int, help='HTTP listen port; default 6644 when neither port is given')
    start.add_argument('--tcp', type=int, help='independent raw CESR TCP listen port')
    start.add_argument('--host', default='127.0.0.1')
    start.add_argument('--kel', action='append', default=[], help='signed public KEL bootstrap file')
    start.add_argument('--kel-genus', type=int, choices=(1, 2), default=2)
    start.add_argument('--schema', action='append', default=[], help='explicit legacy JSON schema file')
    start.add_argument('--packaged-schema', action='append', default=[], help='verified Dolly schema manifest name')
    start.add_argument('--no-prompt', action='store_true')
    inspect = commands.add_parser('inspect', parents=[Parsery.keystore()])
    inspect.add_argument('--grant', required=True, help='retained submission EXN SAID')
    inspect.add_argument('--no-prompt', action='store_true')
    return parser


def openIdentity(args):
    """Authenticate the requested existing identity without changing encryption.

    Only an already encrypted Keeper receives the supplied passcode. Missing
    stores and invalid authentication fail through the established core path.
    The caller owns closing the returned Habery.
    """
    keeper = Keeper(name=args.name, base=args.base, reopen=True)
    try:
        aeid = keeper.gbls.get('aeid')
        if aeid is None:
            raise ConfigurationError('Dolly requires an existing KERI identity')
    finally:
        keeper.close()
    return setupHby(args.name, args.base, args.bran if aeid else None, noPrompt=args.no_prompt)

def handler(args):
    """Authenticate an existing identity and return owned service lifecycle Doers.

    Encrypted identities keep their normal authentication; unencrypted identities
    are opened with bran=None to prevent accidental encryption migration. Dolly
    needs its signing identity, not registry derivation custody. Config, schema,
    bootstrap, or alias errors close any opened stores and propagate normally.
    """
    policy = json.loads(Path(args.config).read_text())
    hby = openIdentity(args)
    context = None
    try:
        hab = hby.habByName(args.alias)
        if hab is None:
            raise ConfigurationError('Dolly requires an existing alias')
        httpPort = args.http if args.http is not None else (6644 if args.tcp is None else None)
        context, doers = serving.setup(hby, hab, host=args.host, port=httpPort, tcpPort=args.tcp, **policy)
        for path in args.schema:
            schema = Schemer(raw=Path(path).read_bytes())
            hby.db.schema.pin((schema.said,), schema)
        for name in args.packaged_schema:
            schema = loadSchema(name)
            hby.db.schema.pin((schema.said,), schema)
        for path in args.kel:
            context.ingest(Path(path).read_bytes(),
                version=Vrsn_1_0 if args.kel_genus == 1 else Vrsn_2_0)
        return [HaberyDoer(habery=hby), *Oobiery(hby).doers, *doers]
    except BaseException:
        if context is not None:
            context.close()
        hby.close()
        raise


def inspectSubmission(args):
    """Print one persisted submission through a local authenticated read-only handle.

    This exposes current state/reason/payload/delivered for operator scripts;
    it neither revalidates historical proof nor changes reporting/delivery.
    Unknown grants print state=unknown. No unauthenticated HTTP endpoint exists.
    """
    hby = openIdentity(args)
    db = serving.DollyBaser(name=args.name, base=args.base, reopen=False)
    try:
        db.reopen(readonly=True)
        record = db.submissions.get((args.grant,))
        print(json.dumps(asdict(record) if record else dict(grant=args.grant, state='unknown'),
                         sort_keys=True), flush=True)
    finally:
        db.close()
        hby.close()
    return 0


def main(argv=None):
    """Run installed Dolly; SIGINT/SIGTERM unwind hio owners before process exit.

    ``argv`` optionally supplies command arguments. Return zero after orderly
    cancellation. Startup/authentication errors return one with a concise error;
    no recovery path weakens identity authentication or protocol verification.
    """
    args = buildParser().parse_args(argv)
    def stop(signum, frame):
        """Translate process termination into the scheduler's normal cancellation."""
        raise KeyboardInterrupt
    previous = signal.signal(signal.SIGTERM, stop)
    try:
        if args.command == 'inspect':
            return inspectSubmission(args)
        doers = handler(args)
        doing.Doist(real=True, tock=0.01).do(doers=doers)
    except KeyboardInterrupt:
        return 0
    except (AuthError, ConfigurationError, ValueError, OSError) as error:
        print(f'ERR: {error}', flush=True)
        return 1
    finally:
        signal.signal(signal.SIGTERM, previous)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
