ARG KERI_IMAGE=keripy-v1-operator:base
FROM ${KERI_IMAGE}
WORKDIR /dolly
COPY pyproject.toml README.md LICENSE NOTICE /dolly/
COPY src /dolly/src
COPY scripts/operator /dolly/scripts/operator
ARG KERI_REVISION
ARG DOLLY_REVISION
ARG KERI_DIRTY
ARG DOLLY_DIRTY
ENV OPERATOR_KERI_REVISION=${KERI_REVISION} OPERATOR_DOLLY_REVISION=${DOLLY_REVISION} OPERATOR_KERI_DIRTY=${KERI_DIRTY} OPERATOR_DOLLY_DIRTY=${DOLLY_DIRTY}
RUN mkdir -p /artifacts && python -m pip wheel --no-deps --no-build-isolation /workspace /dolly -w /artifacts && python -m pip install --force-reinstall --no-deps --no-build-isolation /artifacts/*.whl
RUN python -c 'import os,json,hashlib,pathlib,importlib.metadata; p=pathlib.Path("/artifacts"); value={"keripy_revision":os.environ["OPERATOR_KERI_REVISION"],"dolly_revision":os.environ["OPERATOR_DOLLY_REVISION"],"keripy_worktree_dirty":os.environ["OPERATOR_KERI_DIRTY"] == "true","dolly_worktree_dirty":os.environ["OPERATOR_DOLLY_DIRTY"] == "true","installed_versions":{name:importlib.metadata.version(name) for name in ("keri","dolly")},"wheels":{f.name:hashlib.sha256(f.read_bytes()).hexdigest() for f in p.glob("*.whl")}}; (p/"manifest.json").write_text(json.dumps(value,indent=2))'
WORKDIR /tmp
ENTRYPOINT ["bash", "/dolly/scripts/operator/legacy-v1.sh"]
