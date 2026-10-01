# Dockerfile - ExtensionGuard container image
#
# Multi-stage build:
#   1. builder - install deps + build the wheel
#   2. runtime - slim image with just the runtime artefacts
#
# Build:
#   docker build -t extensionguard:0.3.0 .
#
# Run individual services:
#   docker run --rm extensionguard:0.3.0 extguard <crx-or-manifest>
#   docker run -p 127.0.0.1:5000:5000 extensionguard:0.3.0   # dashboard, localhost only
#
# For a full SOC deployment (dashboard + monitor pipe + dispatcher), use the
# bundled docker-compose.yml which wires up the appropriate networks and
# volume mounts.

# ----------------------------------------------------------------------------
# Stage 1: builder
# ----------------------------------------------------------------------------

FROM python:3.13-slim AS builder

WORKDIR /build

# Build tooling for any optional C-extension wheels (cryptography, etc.)
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy only the files needed to build the wheel - keeps the layer cache hot
# when only test files change.
COPY pyproject.toml ./
COPY README.md LICENSE ./
# The whole package - code, dashboard templates/static and the baseline TTP
# library all live under extguard/ and are declared as package data
COPY extguard/ ./extguard/

RUN pip install --no-cache-dir build && python -m build --wheel


# ----------------------------------------------------------------------------
# Stage 2: runtime
# ----------------------------------------------------------------------------

FROM python:3.13-slim AS runtime

# Non-root user for the running process. SOC tools must NOT run as root.
RUN groupadd --system --gid 1000 extguard \
 && useradd --system --uid 1000 --gid extguard --home /home/extguard --create-home extguard

WORKDIR /opt/extensionguard

# Copy the wheel from the builder stage, install, then delete it to keep the
# image small. The wheel contains all the templates / static / TTP files via
# package_data in pyproject.toml.
COPY --from=builder /build/dist/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl && rm /tmp/*.whl

# Quarantine + remediation queue live under /var/lib/extguard so docker
# volume mounts have a stable target. Owned by the extguard user so writes
# work without root.
RUN mkdir -p /var/lib/extguard/quarantine \
 && mkdir -p /var/lib/extguard/ttp/library \
 && mkdir -p /var/lib/extguard/webhook \
 && chown -R extguard:extguard /var/lib/extguard

# Run as non-root for everything below this line.
USER extguard
WORKDIR /var/lib/extguard

# Environment defaults that work out of the box. Override at run time.
# EXTGUARD_HOME makes every tool agree on the data directory: config
# (extguard.conf.json), quarantine/ and the remediation queue.
# EXTGUARD_TTP_DIR puts the active library AND its pending copy
# (ttp/library.pending) inside one volume, so a staged sync can be reviewed
# and activated across container restarts.
ENV EXTGUARD_HOME=/var/lib/extguard \
    EXTGUARD_TTP_DIR=/var/lib/extguard/ttp/library \
    EXTGUARD_LOG_LEVEL=INFO \
    EXTGUARD_LOG_JSON=1 \
    PYTHONUNBUFFERED=1

# Healthcheck for the dashboard. Falls back gracefully if the container is
# running a different command (the healthcheck just returns "no service").
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request, sys; \
                   r = urllib.request.urlopen('http://localhost:5000/api/health', timeout=2); \
                   sys.exit(0 if r.status == 200 else 1)" || exit 0

# Default command: launch the dashboard. Override with:
#   docker run extensionguard extguard <crx-path>
EXPOSE 5000
CMD ["extguard-dashboard", "--host", "0.0.0.0", "--port", "5000", \
     "--quarantine", "/var/lib/extguard/quarantine"]
