# syntax=docker/dockerfile:1

# saltlick builds to a single static binary. The SQLite driver is
# modernc.org/sqlite, which is pure Go, so CGO_ENABLED=0 holds and the runtime
# image needs no libc, no shell and no package manager.
FROM golang:1.25-alpine AS build
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOFLAGS=-trimpath go build \
      -ldflags="-s -w" \
      -o /out/saltlick ./cmd/saltlick

# The data directory is created here so the runtime image, which has no shell,
# does not have to.
RUN mkdir -p /out/data && chown -R 65532:65532 /out/data

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/saltlick /saltlick
COPY --from=build --chown=65532:65532 /out/data /data

# One SQLite file. Mount a volume here and the directory survives the container.
VOLUME ["/data"]
ENV SALTLICK_DB=/data/saltlick.db \
    SALTLICK_ADDR=:8080
EXPOSE 8080
USER 65532:65532
ENTRYPOINT ["/saltlick"]
CMD ["serve"]
