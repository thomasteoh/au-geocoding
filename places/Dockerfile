# Build from the repository root so the shared module is in the context:
#   docker build -f places/Dockerfile .
# Build stage: static binaries, CGO-free (modernc.org/sqlite), no runtime deps.
FROM golang:1.26-alpine AS build
# Build the module standalone; its replace directive resolves ../shared.
ENV GOWORK=off
WORKDIR /src/places
# Cache deps first for faster rebuilds.
COPY shared/ /src/shared/
COPY places/go.mod places/go.sum ./
RUN go mod download
COPY places/ ./
# Build both binaries (D-019): the serving server and the loader (only writer).
# Also build buildsuggest (Step 7 / S-13): the FTS5 street+locality suggestion
# index. CGO_ENABLED=0 keeps them static and portable.
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/auplaces-server ./cmd/server
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/auplaces-load ./cmd/buildaddr
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/auplaces-suggest ./cmd/buildsuggest

# Runtime stage: minimal, runs as non-root, mounts data read-only.
# curl is needed for the compose healthcheck (alpine base image ships no curl).
FROM alpine:3.20
RUN apk add --no-cache curl && addgroup -g 10001 auplaces && adduser -D -u 10001 -G auplaces auplaces
COPY --from=build /out/auplaces-server /usr/local/bin/auplaces-server
COPY --from=build /out/auplaces-load /usr/local/bin/auplaces-load
COPY --from=build /out/auplaces-suggest /usr/local/bin/auplaces-suggest
USER auplaces
EXPOSE 8080
# The data volume is mounted read-only (D-019 / INV-4). Default path; override
# via AUGEO_DB or -db. The server never writes — only the loader does.
ENTRYPOINT ["/usr/local/bin/auplaces-server"]
CMD ["-db", "/data/vic.db", "-addr", ":8080"]
