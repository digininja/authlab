# Stage 1: Build binary
FROM golang:1.24-alpine AS builder

WORKDIR /build

# Cache dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy source code and build
COPY main.go ./
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o authlab main.go

# Stage 2: Minimal runtime environment
FROM alpine:3.20

WORKDIR /app

RUN apk --no-cache add ca-certificates

# Copy compiled binary from builder
COPY --from=builder /build/authlab .

# Copy runtime assets
COPY app/views/ ./app/views/
COPY public/ ./public/

ENV PORT=9000
EXPOSE 9000

ENTRYPOINT ["./authlab"]
