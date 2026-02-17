# syntax=docker/dockerfile:1.7

FROM golang:1.23-alpine AS build
WORKDIR /src

# Build context is repo root (see gateway/docker-compose.yml).
COPY apps/gateway/service ./apps/gateway/service
COPY sdks/sdk-go ./sdks/sdk-go

WORKDIR /src/apps/gateway/service
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go mod download
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -mod=mod -ldflags="-s -w" -o /out/sigilum-gateway ./cmd/sigilum-gateway
RUN mkdir -p /out/data

FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /app

COPY --from=build /out/sigilum-gateway /usr/local/bin/sigilum-gateway
COPY --from=build --chown=65532:65532 /out/data /var/lib/sigilum-gateway

ENV GATEWAY_ADDR=:38100
ENV GATEWAY_DATA_DIR=/var/lib/sigilum-gateway

EXPOSE 38100
VOLUME ["/var/lib/sigilum-gateway"]

ENTRYPOINT ["/usr/local/bin/sigilum-gateway"]
