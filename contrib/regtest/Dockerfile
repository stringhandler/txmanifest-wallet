# Bitcoin Core fork with Simplicity activated on regtest.
# Node only: no GUI, no wallet, no tests — `generatetoaddress` and `scantxoutset`
# are node RPCs, so nothing we need requires the wallet.
FROM debian:bookworm-slim AS build
RUN apt-get update && apt-get install -y --no-install-recommends \
      git ca-certificates cmake ninja-build g++ pkg-config \
      libevent-dev libboost-dev python3 \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /src
RUN git clone --depth 1 --branch simplicity-inquisition \
      https://github.com/delta1/bitcoin.git .
RUN cmake -B build -G Ninja \
      -DCMAKE_BUILD_TYPE=Release \
      -DBUILD_GUI=OFF -DENABLE_WALLET=OFF \
      -DBUILD_TESTS=OFF -DBUILD_BENCH=OFF -DBUILD_FUZZ_BINARY=OFF
RUN cmake --build build -j"$(nproc)" --target bitcoind bitcoin-cli

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
      libevent-2.1-7 libevent-extra-2.1-7 libevent-pthreads-2.1-7 ca-certificates \
 && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/build/bin/bitcoind /usr/local/bin/
COPY --from=build /src/build/bin/bitcoin-cli /usr/local/bin/
EXPOSE 18443 18444
ENTRYPOINT ["bitcoind"]
