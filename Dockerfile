
FROM python:3.10.4-buster

SHELL ["/bin/bash", "-c"]

RUN apt-get update && \
    apt-get install -y ca-certificates libsodium23

# Setup Rust for blake3 dependency build
RUN curl https://sh.rustup.rs -sSf | bash -s -- -y

COPY ./ /keripy
WORKDIR /keripy

# Install KERIpy dependencies
# Must source the Cargo environment for the blake3 library to see the Rust intallation during requirements install
RUN source "$HOME/.cargo/env" && pip install -r requirements.txt

