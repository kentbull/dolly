"""Connection isolation, packaged schemas, and installed service lifecycle."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import importlib.util
import json
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import threading
import time
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
from uuid import uuid4

import falcon
from hio.base import doing
from hio.core import http, tcp
import pytest

from dolly.schemas import load, manifest
from dolly.serving import Context, TcpIntake
from keri import Vrsn_2_0
from keri.acdc import acdcmap, grant
from keri.app.habbing import openHby
from keri.core import Diger, Number, messagize


SERVER_TLS = Path(__file__).with_name('tls') / 'server.pem'


def observerTrust(url='https://unused.test/'):
    """Return explicit HTTPS trust for tests whose observer path stays idle."""
    return dict(url=url, cafilepath=str(SERVER_TLS))


def signed(credential, hab):
    """Attach real current-establishment issuer signatures to exact credential bytes.

    Args:
        credential (SerderACDC): Disclosed node view to authenticate.
        hab (Hab): Issuer habitat with the matching current signing keys.

    Returns:
        bytearray: ACDC v2 credential node stream with its transferable signature group, using
        production messagize and no imports from KERIpy protocol test fixtures."""
    return messagize(credential, tsgs=[(hab.kever.prefixer,
        Number(sn=hab.kever.lastEst.s), Diger(qb64=hab.kever.lastEst.d),
        hab.sign(credential.raw))], framed=False, gvrsn=Vrsn_2_0)


def test_packaged_schema_manifest_and_no_application_in_keripy():
    """Verify installed fixture commitments and removal of the old core package."""
    for name, entry in manifest().items():
        assert load(name).said == entry['said']
    assert importlib.util.find_spec('keri.app.dolly') is None
    assert 'site-packages' in str(Path(__import__('dolly').__file__))


def test_tcp_fragmented_consecutive_and_malformed_connections_are_isolated():
    """A stalled/malformed connection cannot consume another client's evidence."""
    received = []

    class Hook:
        """Record real HTTP delivery from the raw TCP presentations."""

        def on_post(self, req, rep):
            """Record one actual projected webhook and acknowledge its receipt.

            Args:
                req (falcon.Request): Incoming hook request carrying the public projection.
                rep (falcon.Response): JSON acknowledgement response.

            Returns:
                None. Appends req.media to the test recorder; it creates no protocol state
                and is reached only after the application decides to emit the hook."""
            received.append(req.media)
            rep.media = {'received': True}

    app = falcon.App()
    app.add_route('/hook', Hook())
    hook = http.Server(servant=tcp.Server(ha=('127.0.0.1', 0)), app=app)
    raw = tcp.Server(ha=('127.0.0.1', 0))
    assert hook.reopen() and raw.reopen()
    hook.servant.eha, raw.eha = hook.servant.ha, raw.ha
    clients = [tcp.Client(ha=raw.ha) for _ in range(3)]
    with (openHby(name='tcp-source', version=Vrsn_2_0) as source,
          openHby(name='tcp-reader', version=Vrsn_2_0) as reader):
        issuer, verifier = source.makeHab(name='issuer'), reader.makeHab(name='verifier')
        schema = load('entitlement-v2')
        credential = acdcmap(israid=issuer.pre, schema=schema.sed,
                             attribute=dict(d='', entitlement='read'))
        dolly = Context(reader, verifier, issuers=[issuer.pre], schemas=[schema.said],
            fields={'entitlement': 'a/entitlement'}, required=['entitlement'],
            observer=observerTrust(), webhook=f'http://127.0.0.1:{hook.servant.ha[1]}/hook')
        try:
            grants = [grant(issuer, verifier.pre, f'connection {index}',
                            origin=signed(credential, issuer)) for index in range(3)]
            first = issuer.replay(gvrsn=Vrsn_2_0) + grants[0][0].raw + grants[0][1]
            # Client 0 is stalled within the first JSON body. Client 1 sends
            # bootstrap plus consecutive grants; client 2 supplies malformed bytes.
            clients[0].tx(first[:17])
            clients[1].tx(issuer.replay(gvrsn=Vrsn_2_0) + b''.join(exn.raw + atc for exn, atc in grants[1:]))
            clients[2].tx(b'not-a-CESR-frame')

            def finish(tymth, tock=0.01, **kwa):
                """Release the final fragmented bytes only after independent clients complete.

                Args:
                    tymth (Callable): HIO injected clock used for deterministic transfer stages.
                    tock (float): Cooperative scheduling delay.
                    **kwa: Additional scheduler metadata, unused by this test driver.

                Yields:
                    float: Delay between checks and the final-fragment transmission.

                Returns:
                    None. Assertions require other grants to deliver before the partial frame
                    creates any submission, then require all grants after its missing bytes arrive."""
                yield tock
                while tymth() < 1.2:
                    yield tock
                assert {item['grant'] for item in received} == {exn.said for exn, _ in grants[1:]}
                assert dolly.db.submissions.get((grants[0][0].said,)) is None
                clients[0].tx(first[17:])
                while tymth() < 2.4:
                    yield tock
                assert {item['grant'] for item in received} == {exn.said for exn, _ in grants}

            intake = TcpIntake(dolly, raw)
            doers = [http.ServerDoer(hook), tcp.ServerDoer(raw),
                     *[tcp.ClientDoer(client) for client in clients], intake, dolly, doing.doify(finish)]
            doing.Doist(real=True, tock=0.01, limit=2.5).do(doers=doers)
            assert intake.sessions == {}
            assert all(item['business'] == {'entitlement': 'read'} for item in received)
        finally:
            dolly.close()
            for client in clients:
                client.close()
            raw.close()
            hook.close()


def freePort():
    """Reserve an ephemeral test port long enough to select a process listener."""
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


@pytest.mark.parametrize('encrypted', [False, True])
def test_installed_wheel_dual_listener_start_stop_restart_and_local_inspect(tmp_path, encrypted):
    """Run the actual console executable outside source with persistent identity.

    Both transports report a packaged non-vLEI credential. SIGTERM cancels the
    service; restart preserves delivered state and accepts a freshly authored TCP
    grant without KEL replay or relaxing the enabled KRAM acceptance window.
    Encrypted authentication remains required, and passing a passcode to an
    unencrypted identity cannot migrate its Keeper.
    """
    received = []

    class Hook(BaseHTTPRequestHandler):
        """Serve actual callback requests while the installed process runs."""

        def do_POST(self):
            """Capture and acknowledge one complete JSON projection."""
            received.append(json.loads(self.rfile.read(int(self.headers['Content-Length']))))
            self.send_response(200)
            self.send_header('Content-Length', '2')
            self.end_headers()
            self.wfile.write(b'{}')

        def log_message(self, format, *args):
            """Suppress routine fixture HTTP logs without concealing capture failures.

            Args:
                format (str): BaseHTTPRequestHandler log format, unused.
                *args: Formatting values, unused.

            Returns:
                None. Public hook data is checked through the explicit test capture file."""
            pass

    hook = ThreadingHTTPServer(('127.0.0.1', 0), Hook)
    thread = threading.Thread(target=hook.serve_forever, daemon=True)
    thread.start()
    name = f'dolly-installed-{uuid4().hex}'
    passcode = '0123456789abcdefghijk'
    with openHby(name=name, temp=False, bran=passcode if encrypted else None,
                 version=Vrsn_2_0) as hby:
        verifier = hby.makeHab(name='verifier').pre
        aeid = hby.mgr.aeid
    with openHby(name=f'{name}-source', version=Vrsn_2_0) as source:
        issuer = source.makeHab(name='issuer')
        schema = load('entitlement-v2')
        credential = acdcmap(israid=issuer.pre, schema=schema.sed,
                             attribute=dict(d='', entitlement='installed-wheel'))
        grants = [grant(issuer, verifier, f'installed {index}', origin=signed(credential, issuer))
                  for index in range(2)]
        policy = tmp_path / 'policy.json'
        policy.write_text(json.dumps(dict(issuers=[issuer.pre], schemas=[schema.said],
            fields={'entitlement': 'a/entitlement'}, required=['entitlement'],
            observer=observerTrust(), webhook=f'http://127.0.0.1:{hook.server_port}/hook')))
        httpPort, tcpPort = freePort(), freePort()
        executable = shutil.which('dolly')
        auth = ['--name', name, '--passcode', passcode, '--no-prompt']
        command = [executable, 'server', 'start', '--direct', *auth, '--alias', 'verifier',
                   '--config', str(policy), '--http', str(httpPort), '--tcp', str(tcpPort)]
        process = None

        def waitFor(predicate):
            """Await a real installed-process condition with a five-second wall-clock bound.

            Args:
                predicate (Callable[[], bool]): Observable transport/accepted/delivered state.

            Returns:
                None once predicate is true.

            Raises:
                AssertionError: The owned process exits early or the bounded wait expires.
                The enclosing test finally block owns service/listener termination."""
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                if predicate():
                    return
                if process is not None and process.poll() is not None:
                    raise AssertionError(process.communicate())
                time.sleep(0.025)
            raise AssertionError('installed Dolly did not reach expected state')

        def ready():
            """Read the actual installed HTTP listener's readiness response."""
            try:
                with urlopen(f'http://127.0.0.1:{httpPort}/health', timeout=0.2) as response:
                    return response.status == 200
            except (URLError, TimeoutError):
                return False

        def inspect(said):
            """Read persisted submission state through the installed read-only Dolly CLI.

            Args:
                said (str): Grant identifier passed to the authenticated inspect command.

            Returns:
                dict: Parsed JSON from an actual successful subprocess invocation.

            Raises:
                AssertionError: The CLI reports failure.
                TimeoutExpired, JSONDecodeError: Five-second process or output handling fails.
                This helper inspects persisted evidence without a hidden Python store mutation."""
            result = subprocess.run([executable, 'inspect', *auth, '--grant', said],
                cwd=tmp_path, capture_output=True, text=True, timeout=5)
            assert result.returncode == 0, result.stdout + result.stderr
            return json.loads(result.stdout)

        try:
            if encrypted:
                wrong = command.copy()
                wrong[wrong.index(passcode)] = 'wrong-passcode-value1'
                refused = subprocess.run(wrong, cwd=tmp_path, capture_output=True, text=True, timeout=5)
                assert refused.returncode != 0
            for phase in range(2):
                process = subprocess.Popen(command, cwd=tmp_path, stdout=subprocess.PIPE,
                                           stderr=subprocess.PIPE, text=True)
                waitFor(ready)
                if phase == 0:
                    # There is no retained core request when the outer sender's
                    # KEL is absent: refuse, expose no fake pending submission,
                    # and allow an explicit retry after real bootstrap succeeds.
                    request = Request(f'http://127.0.0.1:{httpPort}/ingest',
                        data=grants[1][0].raw + grants[1][1], headers={'Content-Type': 'application/cesr'})
                    with pytest.raises(HTTPError) as refused:
                        urlopen(request, timeout=2)
                    assert refused.value.code == 400
                    assert inspect(grants[1][0].said)['state'] == 'unknown'
                    with socket.create_connection(('127.0.0.1', tcpPort)) as connection:
                        wire = issuer.replay(gvrsn=Vrsn_2_0) + grants[0][0].raw + grants[0][1]
                        connection.sendall(wire[:23])
                        time.sleep(0.05)
                        connection.sendall(wire[23:])
                    waitFor(lambda: len(received) == 1)
                    request = Request(f'http://127.0.0.1:{httpPort}/ingest',
                        data=grants[1][0].raw + grants[1][1], headers={'Content-Type': 'application/cesr'})
                    with urlopen(request, timeout=2) as response:
                        assert response.status == 202
                    waitFor(lambda: len(received) == 2)
                    for exn, _ in grants[:2]:
                        record = inspect(exn.said)
                        assert record['state'] == 'accepted' and record['delivered']
                else:
                    assert inspect(grants[0][0].said)['delivered']
                    # This is a new live request after restart. Signing it before
                    # startup/inspection can correctly expire its KRAM window.
                    grants.append(grant(issuer, verifier, 'installed 2',
                                        origin=signed(credential, issuer)))
                    with socket.create_connection(('127.0.0.1', tcpPort)) as connection:
                        connection.sendall(grants[2][0].raw + grants[2][1])
                    waitFor(lambda: len(received) == 3)
                    assert inspect(grants[2][0].said)['delivered']
                process.send_signal(signal.SIGTERM)
                stdout, stderr = process.communicate(timeout=5)
                assert process.returncode == 0, stdout + stderr
                process = None
            assert {item['grant'] for item in received} == {exn.said for exn, _ in grants}
            with openHby(name=name, temp=False, bran=passcode if encrypted else None,
                         version=Vrsn_2_0) as hby:
                assert hby.mgr.aeid == aeid  # Starting an unencrypted verifier did not migrate it.
        finally:
            if process is not None and process.poll() is None:
                process.send_signal(signal.SIGTERM)
                process.communicate(timeout=5)
            hook.shutdown()
            hook.server_close()
            thread.join(timeout=2)
