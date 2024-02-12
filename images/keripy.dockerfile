# Builder layer
FROM python:3.10-alpine as builder

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

WORKDIR /keripy

RUN python -m venv venv

ENV PATH=/keripy/venv/bin:${PATH}

RUN pip install --upgrade pip && \
    mkdir /keripy/src

# Copy Python dependency files in
COPY requirements.txt setup.py ./

# Set up Rust environment and install Python dependencies
# Must source the Cargo environment for the blake3 library to see
# the Rust intallation during requirements install
RUN . ${HOME}/.cargo/env && \
    pip install -r requirements.txt

# Runtime layer
FROM python:3.10.13-alpine3.18

RUN apk --no-cache add \
    bash \
    alpine-sdk \
    libsodium-dev

WORKDIR /keripy

COPY --from=builder /keripy /keripy
COPY src/ src/

ENV PATH=/keripy/venv/bin:${PATH}


ENTRYPOINT [ "kli" ]
