FROM python:3.11-slim-bookworm
COPY --from=ghcr.io/astral-sh/uv:0.6.11 /uv /uvx /bin/

LABEL org.opencontainers.image.source=https://github.com/elfkuzco/protonvpn-wireguard-config-downloader

WORKDIR /app

# Enable bytecode compilation
ENV UV_COMPILE_BYTECODE=1
# Copy from the cache instead of linking since it's a mounted volume
ENV UV_LINK_MODE=copy

# We need gnupg2 for python-gnupg used in Proton libraries to work properly.
RUN apt-get update && apt-get install -y gnupg2

# Install dependencies
RUN --mount=type=cache,target=/root/.cache/uv \
    --mount=type=bind,source=uv.lock,target=uv.lock \
    --mount=type=bind,source=pyproject.toml,target=pyproject.toml \
    uv sync --frozen --no-install-project --no-dev

# Copy the project into the image
COPY pyproject.toml uv.lock README.md /app
COPY src /app/src

# Sync the project
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev

# Place executables in the environment at the front of the path
ENV PATH="/app/.venv/bin:$PATH"

RUN mkdir /data

CMD ["protonvpn-wireguard-configs", "--help"]
