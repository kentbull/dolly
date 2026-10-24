"""Pinned application fixture schemas; these resources confer no issuer trust."""
from importlib.resources import files
import json

from keri.core import Schemer
from keri.kering import ConfigurationError


def manifest():
    """Return the packaged name/file/expected-SAID/provenance manifest."""
    return json.loads(files(__package__).joinpath('manifest.json').read_text())


def load(name):
    """Return a Schemer only after its exact packaged resource verifies.

    ``name`` is a manifest entry, never an arbitrary filesystem path. Missing
    entries or digest disagreement raise ConfigurationError. Availability does
    not admit a credential, allow a schema, or authenticate an issuer.
    """
    entry = manifest().get(name)
    if entry is None:
        raise ConfigurationError(f'unknown packaged schema: {name}')
    schema = Schemer(raw=files(__package__).joinpath(entry['file']).read_bytes())
    if schema.said != entry['said']:
        raise ConfigurationError(f'packaged schema commitment mismatch: {name}')
    return schema
