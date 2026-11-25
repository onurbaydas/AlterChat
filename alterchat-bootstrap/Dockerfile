# Build context: repository root
#   docker build -f alterchat-bootstrap/Dockerfile -t alterchat-bootstrap .
FROM rust:1.99-bookworm@sha256:e6f2cff35d0f309acf8433b4f05878ed77092602c5065cc81801177da0bb3a9c AS build
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
