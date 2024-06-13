# Builder layer
FROM python:3.12-alpine as builder

# Install compilation dependencies
RUN apk --no-cache add \
    bash \
    alpine-sdk \
    libffi-dev \
    libsodium \
    libsodium-dev

SHELL ["/bin/bash", "-c"]

# Setup Rust for blake3 dependency build
RUN curl https://sh.rustup.rs -sSf | bash -s -- -y
