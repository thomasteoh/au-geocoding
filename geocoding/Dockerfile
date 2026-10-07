# Build from the repository root so the shared module is in the context:
#   docker build -f geocoding/Dockerfile .
# Build stage: static binaries, CGO-free (modernc.org/sqlite), no runtime deps.
FROM golang:1.26-alpine AS build
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
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/augeo ./cmd/augeo
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/keygen ./cmd/keygen

# Runtime stage: minimal, runs as non-root. curl is needed for the compose
# healthcheck (alpine base image ships no curl).
# alpine:3.20 is past end of support; 3.22 is a supported release.
# TODO: pin by digest for reproducible builds. Look the digest up with
#   docker buildx imagetools inspect alpine:3.22
# and write FROM alpine:3.22@sha256:<digest>.
FROM alpine:3.22
RUN apk add --no-cache curl && addgroup -g 10001 augeo && adduser -D -u 10001 -G augeo augeo
COPY --from=build /out/augeo /usr/local/bin/augeo
COPY --from=build /out/keygen /usr/local/bin/keygen
# /data holds app.db. Create it owned by the runtime user so a fresh named
# volume (which copies this directory's ownership) is writable by uid 10001.
RUN mkdir -p /data && chown 10001:10001 /data
VOLUME /data
USER augeo
EXPOSE 8080
# Split mode is the default deployment: the geocoder calls au-places over the
# contract. Override via AUGEO_PLACES_URL. app.db holds keys/quota and is
# operator-provided (issue keys with keygen before first boot).
ENTRYPOINT ["/usr/local/bin/augeo"]
CMD ["-addr", ":8080"]
