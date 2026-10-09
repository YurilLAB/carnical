# Build from the repository root. The official builder index supports amd64 and arm64.
FROM --platform=$BUILDPLATFORM golang:1.26.9-bookworm@sha256:d9c68c2c51161e12fd77e4c6320687c9cd86e1af1e3ad6e6cd63ff970641453c AS build
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
COPY carnical/go.mod carnical/go.sum ./carnical/
RUN GOWORK=off go -C carnical mod download
COPY . .
RUN test "$TARGETOS" = linux && CGO_ENABLED=0 GOWORK=off GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go -C carnical build -mod=readonly -trimpath -buildvcs=false -o /out/carnical ./cmd/carnical
RUN mkdir -p /out/uploads && chown 65532:65532 /out/uploads && chmod 0700 /out/uploads

FROM scratch
COPY --from=build /out/carnical /carnical
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build --chown=65532:65532 /out/uploads /var/lib/carnical/uploads
USER 65532:65532
ENV TMPDIR=/var/lib/carnical/uploads
EXPOSE 8443
STOPSIGNAL SIGTERM
HEALTHCHECK --interval=10s --timeout=5s --start-period=20s --retries=3 \
    CMD ["/carnical", "-health-listen", "127.0.0.1:8082", "-probe", "ready"]
ENTRYPOINT ["/carnical"]
CMD ["-config", "/etc/carnical/site.json", "-listen", ":8443", "-health-listen", "127.0.0.1:8082", "-upload-dir", "/var/lib/carnical/uploads", "-drain-delay", "5s", "-shutdown-timeout", "30s"]
