# =============================================================================
# Stage 1: builder — install runtime dependencies with uv.
# The uv image and its tooling are discarded from the final image.
# =============================================================================
FROM ghcr.io/astral-sh/uv:python3.12-bookworm@sha256:85d4cb1afa769a7338e095b927bee941cf5ec92266c7424b3f6c0f2748567248 AS builder

WORKDIR /app

# Copy dependency manifests first for better caching.
COPY pyproject.toml uv.lock ./

# Create the project virtual environment with dependencies only.  The
# project install MUST wait until its sources are copied below: an editable
# install attempted without src/ccdb_mcp silently produces the dist-info but
# no import path, which is how the 0.3.0 image shipped without a usable
# `import ccdb_mcp`.
ENV UV_PROJECT_ENVIRONMENT=/app/.venv
RUN uv sync --frozen --no-dev --no-cache --no-install-project

# Copy the remainder of the application source.
COPY . .

# Install the project itself (non-editable) into the same environment, now
# that the source is present.  The package lands in site-packages and imports
# from any working directory.
RUN uv sync --frozen --no-dev --no-cache --no-editable

# =============================================================================
# Stage 2: runtime — minimal Python image without uv or build tooling.
# =============================================================================
FROM python:3.12-slim-trixie@sha256:aa943ce411423c7582288f18707ff66eddcbaeb510502d747a72aeb34f30d159

WORKDIR /app

# tzdata so the logger can render timestamps in America/Toronto.
RUN DEBIAN_FRONTEND=noninteractive apt-get update \
    && apt-get install --no-install-recommends -y ca-certificates tzdata \
    && rm -rf /var/lib/apt/lists/* \
    && rm -rf /usr/local/lib/python3.12/site-packages/pip /usr/local/lib/python3.12/site-packages/pip-*.dist-info \
       /usr/local/lib/python3.12/ensurepip \
    && rm -f /usr/local/bin/pip /usr/local/bin/pip3 /usr/local/bin/pip3.12

# The server only reads its installed package and talks to CCDB; it needs no
# writable application directory.  Keep a writable home for temporary files
# and library caches, but run the process unprivileged.
RUN groupadd --gid 10001 app \
    && useradd --uid 10001 --gid app --create-home --shell /usr/sbin/nologin app
ENV HOME=/home/app

# Ensure the environment is on PATH for runtime commands.
ENV PATH="/app/.venv/bin:${PATH}"
ENV PYTHONUNBUFFERED=1

COPY --from=builder /app/.venv /app/.venv
COPY --from=builder /app/app.py /app/app.py
COPY --from=builder /app/docker-entrypoint.sh /app/docker-entrypoint.sh

# Make the entrypoint executable (just in case git permissions are lost).
RUN chmod +x docker-entrypoint.sh

USER app

EXPOSE 8081

CMD ["/app/docker-entrypoint.sh"]
