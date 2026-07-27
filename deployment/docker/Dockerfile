# syntax=docker/dockerfile:1.7
FROM python:3.14-slim AS builder
WORKDIR /build
ENV PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_NO_CACHE_DIR=1
COPY pyproject.toml README.md LICENSE MANIFEST.in ./
COPY src ./src
RUN python -m pip wheel --no-deps --wheel-dir /wheels .

FROM python:3.14-slim AS runtime
RUN groupadd --system agentroi && useradd --system --gid agentroi --home /app agentroi
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
COPY --from=builder /wheels /wheels
RUN WHEEL="$(ls /wheels/*.whl)" && \
    python -m pip install --no-cache-dir "${WHEEL}[enterprise]" && \
    rm -rf /wheels
USER agentroi
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=2)"
ENTRYPOINT ["agent-roi-control-plane"]
CMD ["--host", "0.0.0.0", "--port", "8080"]
