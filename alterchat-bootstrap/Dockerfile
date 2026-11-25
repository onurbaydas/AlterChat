# Build context: repository root
#   docker build -f alterchat-bootstrap/Dockerfile -t alterchat-bootstrap .
FROM rust:1.96-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release -p alterchat-bootstrap

FROM debian:bookworm-slim
RUN useradd --system --uid 10001 --home /data alterchat \
    && mkdir -p /data && chown alterchat /data
COPY --from=build /src/target/release/alterchat-bootstrap /usr/local/bin/alterchat-bootstrap
USER alterchat
ENV ALTERCHAT_DATA_DIR=/data \
    ALTERCHAT_BOOTSTRAP_PORT=4001
VOLUME ["/data"]
EXPOSE 4001/tcp 4001/udp
ENTRYPOINT ["/usr/local/bin/alterchat-bootstrap"]
