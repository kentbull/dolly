ARG KERI_IMAGE=keripy-v2-refactor:dolly-dependency
FROM ${KERI_IMAGE}
WORKDIR /dolly
COPY pyproject.toml README.md LICENSE NOTICE /dolly/
COPY src /dolly/src
COPY tests /dolly/tests
COPY scripts /dolly/scripts
RUN mkdir -p /artifacts && python -m pip wheel --no-deps --no-build-isolation /dolly -w /artifacts && python -m pip install --no-deps /artifacts/dolly-*.whl
RUN cd /tmp && python -c "import dolly,keri; print('installed Dolly:',dolly.__file__); print('installed KERIpy:',keri.__file__)"
WORKDIR /tmp
CMD ["python", "-m", "pytest", "-p", "no:cacheprovider", "-q", "/dolly/tests"]
