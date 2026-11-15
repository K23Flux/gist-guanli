FROM rust:1-slim-bookworm AS build
RUN apt-get update && apt-get install -y --no-install-recommends gcc libc6-dev pkg-config && rm -rf /var/lib/apt/lists/*
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY migrations ./migrations
COPY src ./src
COPY templates ./templates
COPY static ./static
RUN cargo build --locked --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/* && useradd --uid 10001 --create-home gateway && install -d -o gateway -g gateway -m 0700 /data
COPY --from=build /build/target/release/gist-gateway /usr/local/bin/gist-gateway
USER 10001:10001
EXPOSE 4387
ENTRYPOINT ["gist-gateway", "--data-dir", "/data"]
CMD ["serve", "--bind", "0.0.0.0:4387"]
