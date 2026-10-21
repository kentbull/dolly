"""Handle config OUTPUT ISSUER SCHEMA SOURCE HOOK, hooks PATH COUNT SAID ISSUER,
and result ROOT SAID SCHEMA HTTP_GRANT TCP_GRANT REVOKED_GRANT ISSUER DOLLY.

Write policy/result JSON or assert exact accepted hook projections. Return through
process exit; malformed input, missing artifacts or mismatches raise ordinary
JSON/I/O/Assertion errors. This artifact helper imports no KERI protocol APIs and
performs no credential authoring, protocol authentication or database mutation.
"""
import hashlib
import json
from pathlib import Path
import re
import sys


if __name__ == '__main__':
    operation, *args = sys.argv[1:]
    if operation == 'config':
        output, issuer, schema, source, hook = args
        Path(output).write_text(json.dumps(dict(issuers=[issuer], schemas=[schema],
            fields={'status': 'a/status'}, required=['status'], observer=source,
            legacySources=[issuer], webhook=hook, maximumAge=2, timeout=2)))
    elif operation == 'hooks':
        path, count, credential, presenter = args
        values = [json.loads(line) for line in Path(path).read_text().splitlines()]
        assert len(values) == int(count), values
        for value in values:
            assert value['protocol'] == 1 and value['decision'] == 'accepted', value
            assert value['credential'] == credential and value['presenter'] == presenter, value
            assert value['business'] == {'status': 'authorized'}, value
            assert value['disclosure'] == {'status': 'disclosed'}, value
    elif operation == 'result':
        root, credential, schema, first, second, revoked, issuer, dolly = args
        folder = Path(root)
        # This is an artifact index, never an acceptance or authentication claim.
        decoder, bodies = json.JSONDecoder(), []
        for path in folder.glob('*.cesr'):
            text = path.read_text()
            for start in re.finditer(r'\{"v"\s*:', text):
                value, _ = decoder.raw_decode(text[start.start():])
                if value.get('t') in ('icp', 'ixn', 'vcp', 'iss', 'rev'):
                    assert value['v'].startswith('KERI10'), value
                    bodies.append(dict(file=path.name, t=value['t'], i=value['i'],
                                       d=value['d'], s=value['s']))
        result = dict(scenario='legacy-v1-operator', protocol=1, transports=['http', 'tcp'],
            topology=dict(witnesses=3, quorum=2),
            actors={path.stem: path.read_text().strip() for path in folder.glob("*.aid")},
            kliVersion=(folder / "kli-version.txt").read_text().strip(),
            issuer=issuer, recipient=dolly,
            verifier=dolly, credential=credential, schema=schema,
            grants=dict(http=first, tcp=second, revoked=revoked),
            admissions=dict(scope='locally authored and verified; remote acceptance not asserted',
                http='admit-http.cesr', tcp='admit-tcp.cesr',
                handoff='included in subsequent issuer command input through the ordinary Parser'),
            hooks=[json.loads(line) for line in (folder / 'hooks.jsonl').read_text().splitlines()],
            revocation=json.loads((folder / 'revoked.json').read_text()),
            artifacts=json.loads(Path('/artifacts/manifest.json').read_text()),
            publicStreams={path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                           for path in folder.glob('*.cesr')}, artifactBodies=bodies, result='passed')
        (folder / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    else:
        raise SystemExit('unknown operator JSON operation')
