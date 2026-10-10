FROM debian:bookworm-slim AS zmap

ARG ZMAP_VERSION=v4.4.0

RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential cmake libgmp3-dev gengetopt libpcap-dev flex byacc libjson-c-dev pkg-config libunistring-dev libjudy-dev git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN git clone --depth 1 --branch ${ZMAP_VERSION} https://github.com/zmap/zmap /src \
    && cd /src \
    && cmake . -DRESPECT_INSTALL_PREFIX_CONFIG=ON \
    && cmake --build . --parallel "$(nproc)" \
    && cmake --install . --prefix /opt/zmap

FROM golang:1.27.1-bookworm AS build

ARG ZGRAB2_VERSION=v1.0.0
ARG VERSION=dev

RUN CGO_ENABLED=0 go install github.com/zmap/zgrab2/cmd/zgrab2@${ZGRAB2_VERSION}

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X github.com/boidscan/boidscan/internal/policy.Version=${VERSION}" -o /out/boidscan ./cmd/boidscan

FROM scratch AS bin
COPY --from=build /out/boidscan /boidscan

FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends libpcap0.8 libjson-c5 libjudydebian1 libgmp10 libunistring2 ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=zmap /opt/zmap /opt/zmap
COPY --from=build /go/bin/zgrab2 /usr/local/bin/zgrab2
COPY --from=build /out/boidscan /usr/local/bin/boidscan

ENV PATH="/opt/zmap/sbin:${PATH}"

ENTRYPOINT ["boidscan"]
