# --- build stage ---
FROM golang:1.24-alpine AS builder
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

# CGO disabled + static binaries so the runtime image can be a minimal,
# dependency-free base with no C library / dynamic linker attack surface.
ENV CGO_ENABLED=0 GOOS=linux
RUN go build -trimpath -ldflags="-s -w" -o /out/node ./cmd/node && \
    go build -trimpath -ldflags="-s -w" -o /out/wallet ./cmd/wallet && \
    go build -trimpath -ldflags="-s -w" -o /out/tx ./cmd/tx

# --- runtime stage ---
FROM alpine:3.20
RUN apk add --no-cache ca-certificates && \
    adduser -D -u 10001 -h /app chain
WORKDIR /app
COPY --from=builder /out/node /out/wallet /out/tx /usr/local/bin/

# Run as an unprivileged, non-root user - the node process never needs
# root and shouldn't have it.
USER chain

EXPOSE 26656
ENTRYPOINT ["node"]
