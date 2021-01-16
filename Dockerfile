FROM devopsworks/golang-upx:1.15 as builder

ARG version
ARG builddate

WORKDIR /go/src/github.com/devops-works/phpsecscan

RUN apt-get update && apt-get install -y ca-certificates

# We want to populate the module cache based on the go.{mod,sum} files.
COPY go.mod .
COPY go.sum .

RUN go mod download

COPY . .

ENV GOPATH=/go/src \
    GOOS=linux \
    GOARCH=amd64 \
    CGO_ENABLED=0 \
    GO111MODULE=on

RUN go build \
    -a \
    -installsuffix cgo \
    -ldflags "-X main.version=${version} -X main.buildDate=${builddate}" \
    -o /go/bin/phpsecscan \
    cmd/phpsecscan.go && \
    strip /go/bin/phpsecscan && \
    /usr/local/bin/upx -9 /go/bin/phpsecscan

RUN touch /tmp/.keep

# buster-slim alternative

FROM debian:buster-slim

RUN groupadd -r phpsecscanner && useradd --no-log-init -r -g phpsecscanner phpsecscanner

# hadolint ignore=DL3008
RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates && \
    rm -rf /var/lib/apt/lists/*

RUN update-ca-certificates

EXPOSE 8000

USER phpsecscanner

ENTRYPOINT ["/app/body-replacer"]

# Distroless alternative

# FROM gcr.io/distroless/base

# EXPOSE 8000

# COPY --from=builder /go/bin/phpsecscan /usr/local/bin/
# COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
# COPY --from=builder /tmp/.keep /tmp/.keep

# ENTRYPOINT ["/usr/local/bin/phpsecscan"]

# Scratch alternative

# FROM scratch

# EXPOSE 8000

# COPY --from=builder /go/bin/phpsecscan /usr/local/bin/
# COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
# COPY --from=builder /tmp/.keep /tmp/.keep

# ENTRYPOINT ["/usr/local/bin/phpsecscan"]

