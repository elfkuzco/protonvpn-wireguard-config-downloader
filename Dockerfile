FROM python:3.11-slim-bookworm
LABEL org.opencontainers.image.source=https://github.com/kiwix/mirrors-qa

# We need gnupg2 for python-gnupg used in Proton libraries to work properly.
RUN apt-get update && apt-get install -y gnupg2

COPY src /src/src

COPY pyproject.toml README.md /src/

RUN pip install --no-cache-dir /src \
 && rm -rf /src

RUN mkdir /data

CMD ["protonvpn-wireguard-configs", "--help"]
