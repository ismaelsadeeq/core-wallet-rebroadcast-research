# Regtest/signet deanonymization lab: official Bitcoin Core (with wallet) + python.
# Runs the whole simulation inside one debian container so the generic Core release
# binary runs natively (host is NixOS, which can't run generic ELF without patching).
FROM debian:bookworm-slim

ARG VER=32.1
RUN apt-get update \
 && apt-get install -y --no-install-recommends wget ca-certificates python3 python3-requests \
 && wget -q https://bitcoincore.org/bin/bitcoin-core-${VER}/bitcoin-${VER}-x86_64-linux-gnu.tar.gz \
 && tar xzf bitcoin-${VER}-x86_64-linux-gnu.tar.gz -C /usr/local --strip-components=1 \
 && rm bitcoin-${VER}-x86_64-linux-gnu.tar.gz \
 && apt-get purge -y wget && apt-get autoremove -y && rm -rf /var/lib/apt/lists/*

ENV BITCOIND=/usr/local/bin/bitcoind
WORKDIR /work
