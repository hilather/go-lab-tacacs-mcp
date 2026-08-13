# syntax=docker/dockerfile:1.7
# Multi-stage 1.0 lab image. Final stage is non-root, no toolchain, no secrets.
# Tag: ghcr.io/hilather/go-lab-tacacs-mcp:<version-or-digest>

ARG GO_VERSION=1.25.12
ARG NODE_VERSION=22.14.0

FROM node:${NODE_VERSION}-bookworm AS frontend
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/ ./
RUN npm run build

FROM golang:${GO_VERSION}-bookworm AS backend
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=frontend /src/web/dist /src/web/dist
RUN mkdir -p internal/ui/dist && cp -a /src/web/dist/. internal/ui/dist/
ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILDTIME=unknown
ARG UI_VERSION=0.0.0
RUN CGO_ENABLED=0 go build -trimpath \
    -ldflags="-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.buildTime=${BUILDTIME} -X main.uiVersion=${UI_VERSION}" \
    -o /out/taclabd ./cmd/taclabd

FROM golang:${GO_VERSION}-bookworm AS labtest-build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/labtest ./tools/labtest

FROM gcr.io/distroless/static-debian12:nonroot AS labtest
COPY --from=labtest-build /out/labtest /labtest
USER 65532:65532
ENTRYPOINT ["/labtest"]

FROM gcr.io/distroless/static-debian12:nonroot AS runtime-distroless
ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILDTIME=unknown
ARG UI_VERSION=0.0.0
ARG GO_VERSION=1.25.12
WORKDIR /taclab
COPY --from=backend /out/taclabd /usr/local/bin/taclabd
COPY --from=backend /src/go.mod /taclab/go.mod
COPY --from=backend /src/api/operations.yaml /taclab/api/operations.yaml
COPY --from=backend /src/LICENSE /licenses/LICENSE
USER 10001:10001
EXPOSE 4949 4300 8080
ENTRYPOINT ["/usr/local/bin/taclabd"]
CMD ["serve", "--config", "/etc/taclab/taclab.yaml"]
HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=6 \
    CMD ["/usr/local/bin/taclabd", "healthcheck", "--url=http://127.0.0.1:8080/health/ready"]
LABEL org.opencontainers.image.title="TacLab" \
      org.opencontainers.image.description="All-in-one TACACS+ / MCP lab appliance (taclabd)" \
      org.opencontainers.image.source="https://github.com/hilather/go-lab-tacacs-mcp" \
      org.opencontainers.image.url="https://github.com/hilather/go-lab-tacacs-mcp" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${COMMIT}" \
      org.opencontainers.image.created="${BUILDTIME}" \
      org.opencontainers.image.vendor="hilather" \
      org.opencontainers.image.documentation="https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/LAB_DEPLOYMENT.md" \
      taclab.go.version="${GO_VERSION}" \
      taclab.ui.version="${UI_VERSION}" \
      taclab.config.schema="1" \
      taclab.mcp.specification="2026-07-28" \
      taclab.tacacs.conformance="RFC 8907; RFC 9887" \
      taclab.runtime.variant="distroless"

FROM ubuntu:24.04 AS runtime-ubuntu
ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILDTIME=unknown
ARG UI_VERSION=0.0.0
ARG GO_VERSION=1.25.12
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends ca-certificates tzdata \
    && useradd --uid 10001 --system --no-create-home --shell /usr/sbin/nologin taclab \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /taclab
COPY --from=backend /out/taclabd /usr/local/bin/taclabd
COPY --from=backend /src/go.mod /taclab/go.mod
COPY --from=backend /src/api/operations.yaml /taclab/api/operations.yaml
COPY --from=backend /src/LICENSE /licenses/LICENSE
USER 10001:10001
EXPOSE 4949 4300 8080
ENTRYPOINT ["/usr/local/bin/taclabd"]
CMD ["serve", "--config", "/etc/taclab/taclab.yaml"]
HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=6 \
    CMD ["/usr/local/bin/taclabd", "healthcheck", "--url=http://127.0.0.1:8080/health/ready"]
LABEL org.opencontainers.image.title="TacLab" \
      org.opencontainers.image.description="All-in-one TACACS+ / MCP lab appliance (taclabd)" \
      org.opencontainers.image.source="https://github.com/hilather/go-lab-tacacs-mcp" \
      org.opencontainers.image.url="https://github.com/hilather/go-lab-tacacs-mcp" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${COMMIT}" \
      org.opencontainers.image.created="${BUILDTIME}" \
      org.opencontainers.image.vendor="hilather" \
      org.opencontainers.image.documentation="https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/LAB_DEPLOYMENT.md" \
      taclab.go.version="${GO_VERSION}" \
      taclab.ui.version="${UI_VERSION}" \
      taclab.config.schema="1" \
      taclab.mcp.specification="2026-07-28" \
      taclab.tacacs.conformance="RFC 8907; RFC 9887" \
      taclab.runtime.variant="ubuntu"

FROM rockylinux/rockylinux:9-minimal AS runtime-rocky
ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILDTIME=unknown
ARG UI_VERSION=0.0.0
ARG GO_VERSION=1.25.12
RUN microdnf install -y ca-certificates tzdata shadow-utils \
    && useradd --uid 10001 --system --no-create-home --shell /sbin/nologin taclab \
    && microdnf clean all
WORKDIR /taclab
COPY --from=backend /out/taclabd /usr/local/bin/taclabd
COPY --from=backend /src/go.mod /taclab/go.mod
COPY --from=backend /src/api/operations.yaml /taclab/api/operations.yaml
COPY --from=backend /src/LICENSE /licenses/LICENSE
USER 10001:10001
EXPOSE 4949 4300 8080
ENTRYPOINT ["/usr/local/bin/taclabd"]
CMD ["serve", "--config", "/etc/taclab/taclab.yaml"]
HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=6 \
    CMD ["/usr/local/bin/taclabd", "healthcheck", "--url=http://127.0.0.1:8080/health/ready"]
LABEL org.opencontainers.image.title="TacLab" \
      org.opencontainers.image.description="All-in-one TACACS+ / MCP lab appliance (taclabd)" \
      org.opencontainers.image.source="https://github.com/hilather/go-lab-tacacs-mcp" \
      org.opencontainers.image.url="https://github.com/hilather/go-lab-tacacs-mcp" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${COMMIT}" \
      org.opencontainers.image.created="${BUILDTIME}" \
      org.opencontainers.image.vendor="hilather" \
      org.opencontainers.image.documentation="https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/LAB_DEPLOYMENT.md" \
      taclab.go.version="${GO_VERSION}" \
      taclab.ui.version="${UI_VERSION}" \
      taclab.config.schema="1" \
      taclab.mcp.specification="2026-07-28" \
      taclab.tacacs.conformance="RFC 8907; RFC 9887" \
      taclab.runtime.variant="rocky"

# Last stage is the default target. Keep distroless last so untargeted
# Compose / lab-test / docker build stay on the documented default.
FROM runtime-distroless AS runtime
