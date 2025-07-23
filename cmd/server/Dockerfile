FROM --platform=$BUILDPLATFORM golang:1.24.5-alpine3.22@sha256:48ee313931980110b5a91bbe04abdf640b9a67ca5dea3a620f01bacf50593396 AS builder
WORKDIR /go/src/app
COPY go.mod go.sum .
RUN go mod download
COPY cmd ./cmd
COPY pkg ./pkg
ARG TARGETOS
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -ldflags '-w -s -extldflags "-static"' -tags timetzdata \
    -o /go/bin/server ./cmd/server/main.go

FROM scratch
COPY --from=builder /go/bin/server /server
ENTRYPOINT ["/server"]
