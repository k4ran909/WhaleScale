# syntax=docker/dockerfile:1
# Whalescale server image. The web console is prebuilt in web/dist.
FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
ARG COMMIT=none
RUN CGO_ENABLED=0 go build -trimpath \
      -ldflags "-s -w -X github.com/k4ran909/whalescale/internal/version.Version=${VERSION} -X github.com/k4ran909/whalescale/internal/version.Commit=${COMMIT}" \
      -o /out/ ./cmd/whalescale ./cmd/ws \
 && mkdir -p /out/data

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/whalescale /out/ws /usr/local/bin/
# Named volumes inherit this ownership, so the non-root user can write.
COPY --from=build --chown=65532:65532 /out/data /var/lib/whalescale
ENV WHALESCALE_DB=/var/lib/whalescale/whalescale.db \
    WHALESCALE_LISTEN=:8080 \
    WHALESCALE_STUN_LISTEN=:3478,:3479 \
    WHALESCALE_METRICS_LISTEN=:9090
VOLUME /var/lib/whalescale
EXPOSE 8080/tcp 3478/udp 3479/udp 9090/tcp
USER nonroot
ENTRYPOINT ["whalescale"]
CMD ["serve"]
