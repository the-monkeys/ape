# Build stage
FROM golang:1.24.4-alpine AS builder

WORKDIR /app

# Install dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o ape main.go

# Final stage
FROM alpine:latest

RUN apk --no-cache add ca-certificates tzdata
WORKDIR /root/

# Copy the binary from builder stage
COPY --from=builder /app/ape .

# Copy config file
COPY --from=builder /app/config.yaml .

# Create logs directory
RUN mkdir -p logs

# Expose port
EXPOSE 8080

# Run the application
CMD ["./ape", "-config", "config.yaml"]
