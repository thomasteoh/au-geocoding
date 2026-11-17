# Build from the repository root so the shared module is in the context:
#   docker build -f places/Dockerfile .
# Build stage: static binaries, CGO-free (modernc.org/sqlite), no runtime deps.
# Base images are pinned by multi-arch index digest (reproducible builds). To
# bump: docker buildx imagetools inspect <image>:<tag> and update both the tag
# and the digest.
#
# The build stage runs on the build host's platform and cross-compiles for the
# target (TARGETOS/TARGETARCH, set by buildx), so a multi-arch build needs no
# QEMU. The runtime stage has no RUN steps for the same reason.
FROM --platform=$BUILDPLATFORM golang:1.26-alpine@sha256:ecb67f987aa1a57794c91d19ade7ae0209f2f0f5496aaef9e6ae85ddf92d02ab AS build
ARG TARGETOS=linux
ARG TARGETARCH
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
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -w" -o /out/auplaces-server ./cmd/server
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -w" -o /out/auplaces-load ./cmd/buildaddr
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -w" -o /out/auplaces-suggest ./cmd/buildsuggest
# /data for the runtime stage, created here so the runtime stage needs no RUN.
RUN mkdir -p /out/data

# Runtime stage: minimal, runs as non-root uid/gid 10001. The compose
# healthcheck uses busybox wget, which alpine ships, so no packages are added.
FROM alpine:3.22@sha256:49340b346798875b5592e5d420241f2f9cfba5f47e62ebb1446a1b34734e898f
COPY --from=build /out/auplaces-server /usr/local/bin/auplaces-server
COPY --from=build /out/auplaces-load /usr/local/bin/auplaces-load
COPY --from=build /out/auplaces-suggest /usr/local/bin/auplaces-suggest
# /data holds vic.db. Owned by the runtime user so a fresh named volume (which
# copies this directory's ownership) is writable by the loader; the server
# mounts it read-only.
COPY --from=build --chown=10001:10001 /out/data /data
VOLUME /data
USER 10001:10001
EXPOSE 8080
# The data volume is mounted read-only (D-019 / INV-4). Default path; override
# via AUGEO_DB or -db. The server never writes — only the loader does.
ENTRYPOINT ["/usr/local/bin/auplaces-server"]
CMD ["-db", "/data/vic.db", "-addr", ":8080"]
