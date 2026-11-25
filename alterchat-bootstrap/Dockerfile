# Build context: repository root
#   docker build -f alterchat-bootstrap/Dockerfile -t alterchat-bootstrap .
FROM rust:1.96-bookworm@sha256:a339861ae23e9abb272cea45dfafde21760d2ce6577a70f8a926153677902663 AS build
WORKDIR /src
COPY . .
RUN cargo build --release -p alterchat-bootstrap

FROM debian:bookworm-slim@sha256:e67eeead736ff7bbe258ef088bff683635c561b1fcfefad0806c1df4ab49ce0e
RUN useradd --system --uid 10001 --home /data alterchat \
    && mkdir -p /data && chown alterchat /data
COPY --from=build /src/target/release/alterchat-bootstrap /usr/local/bin/alterchat-bootstrap
USER alterchat
ENV ALTERCHAT_DATA_DIR=/data \
    ALTERCHAT_BOOTSTRAP_PORT=4001
VOLUME ["/data"]
EXPOSE 4001/tcp 4001/udp
ENTRYPOINT ["/usr/local/bin/alterchat-bootstrap"]
