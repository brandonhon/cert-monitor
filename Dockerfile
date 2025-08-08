# Multi-stage Dockerfile for cert-monitor

# Build stage
FROM golang:1.21-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git make

# Set working directory
WORKDIR /app

# Copy go modules files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN make build-static

# Final stage
FROM alpine:latest

# Install runtime dependencies
RUN apk --no-cache add ca-certificates tzdata

# Create non-root user
RUN addgroup -g 1001 -S certmonitor && \
    adduser -u 1001 -S certmonitor -G certmonitor

# Create directories
RUN mkdir -p /var/log/cert-monitor /var/lib/cert-monitor /etc/cert-monitor

# Set ownership
RUN chown -R certmonitor:certmonitor /var/log/cert-monitor /var/lib/cert-monitor /etc/cert-monitor

# Copy binary from builder
COPY --from=builder /app/cert-monitor-static /usr/local/bin/cert-monitor

# Copy configuration example
COPY --from=builder /app/config.example.yaml /etc/cert-monitor/

# Switch to non-root user
USER certmonitor

# Expose port
EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD /usr/local/bin/cert-monitor -config /etc/cert-monitor/config.yaml -check-config || exit 1

# Set entrypoint
ENTRYPOINT ["/usr/local/bin/cert-monitor"]

# Default command
CMD ["-config", "/etc/cert-monitor/config.yaml"]