FROM python:3.10.4-alpine3.16

RUN apk update
RUN apk add bash alpine-sdk libffi-dev libsodium libsodium-dev 
SHELL ["/bin/bash", "-c"]

# Setup Rust for blake3 dependency build
RUN curl https://sh.rustup.rs -sSf | bash -s -- -y

WORKDIR /keripy
COPY ./ ./ 
RUN source "$HOME/.cargo/env" && pip install -r requirements.txt
