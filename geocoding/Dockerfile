# Build from the repository root so the shared module is in the context:
#   docker build -f geocoding/Dockerfile .
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
WORKDIR /src/geocoding
# Cache deps first for faster rebuilds.
COPY shared/ /src/shared/
COPY geocoding/go.mod geocoding/go.sum ./
RUN go mod download
COPY geocoding/ ./
# Build the serving server and the operator tool (keygen). The geocoder never
# writes the geocoding DBs — it reads through the contract. CGO_ENABLED=0 keeps
# them static and portable.
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -w" -o /out/augeo ./cmd/augeo
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -w" -o /out/keygen ./cmd/keygen
# /data for the runtime stage, created here so the runtime stage needs no RUN.
RUN mkdir -p /out/data

# Runtime stage: minimal, runs as non-root uid/gid 10001. The compose
# healthcheck uses busybox wget, which alpine ships, so no packages are added.
FROM alpine:3.22@sha256:49340b346798875b5592e5d420241f2f9cfba5f47e62ebb1446a1b34734e898f
COPY --from=build /out/augeo /usr/local/bin/augeo
COPY --from=build /out/keygen /usr/local/bin/keygen
# /data holds app.db. Owned by the runtime user so a fresh named volume (which
# copies this directory's ownership) is writable by uid 10001.
COPY --from=build --chown=10001:10001 /out/data /data
VOLUME /data
USER 10001:10001
# 8080: public API. 9100: optional internal metrics listener
# (AUGEO_METRICS_ADDR); do not publish it.
EXPOSE 8080
# Split mode is the default deployment: the geocoder calls au-places over the
# contract. Override via AUGEO_PLACES_URL. app.db holds keys/quota and is
# operator-provided (issue keys with keygen before first boot).
ENTRYPOINT ["/usr/local/bin/augeo"]
CMD ["-addr", ":8080"]
