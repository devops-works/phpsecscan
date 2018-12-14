FROM golang:1.11 as builder

ENV GO111MODULE=on

RUN apt-get update && apt-get install -y ca-certificates
WORKDIR /go/src/github.com/leucos/phpsecscan

# We want to populate the module cache based on the go.{mod,sum} files.
COPY go.mod .
COPY go.sum .

RUN go mod download

COPY . .

ENV GOPATH=/go/src
ENV GOOS=linux
ENV GOARCH=amd64
ENV CGO_ENABLED=0

RUN go build -ldflags '-w -extldflags "-static"' -o /go/bin/phpsecscan cmd/phpsecscan.go
RUN strip /go/bin/phpsecscan

RUN touch /tmp/.keep

FROM scratch

COPY --from=builder /go/bin/phpsecscan /usr/local/bin/
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /tmp/.keep /tmp/.keep

ENTRYPOINT ["/usr/local/bin/phpsecscan"]

