FROM golang:1.15 as builder

WORKDIR /workspace

# Get the dependencies so it can be cached into a layer
COPY go.mod go.sum ./
RUN go mod download

# Now copy all the source...
COPY . .

ARG revisionID=unknown
ARG buildTimestamp=unknown

# ...and build it.
RUN CGO_ENABLED=0 go build -o ./iam/bin/monolith \
    -ldflags="-s -w -X main.revisionID=${revisionID} -X main.buildTimestamp=${buildTimestamp}" \
    ./examples/monolith

# Build the runtime image
FROM alpine:3.13
RUN apk --no-cache add ca-certificates
WORKDIR /root/

# Include resources required by IAM server
COPY ./iam-server/resources ./resources

# Include our service's resources
COPY ./examples/monolith/resources/monolith-webui ./resources/monolith-webui

COPY --from=builder /workspace/iam/bin/monolith ./service

# HTTP
EXPOSE 8080

ENTRYPOINT ["./service"]
