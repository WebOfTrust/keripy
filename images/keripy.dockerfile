# Use the official Alpine base image
FROM python:3.10.14-alpine3.20 as builder

# Install bash
RUN apk add --no-cache bash

# Set the default shell to bash
SHELL ["/bin/bash", "-c"]

# Install dependencies
RUN apk add --no-cache \
    curl \
    build-base \
    alpine-sdk \
    libffi-dev \
    libsodium \
    libsodium-dev    

# Install Rust using rustup
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

WORKDIR /keripy

RUN python -m venv venv

ENV PATH=/keripy/venv/bin:${PATH}

RUN pip install --upgrade pip
RUN mkdir /keripy/src

COPY requirements.txt setup.py ./

RUN . ${HOME}/.cargo/env
RUN pip install -r requirements.txt

# Runtime layer
FROM python:3.10.14-alpine3.20

RUN apk --no-cache add \
    bash \
    alpine-sdk \
    libsodium-dev

WORKDIR /keripy

COPY --from=builder /keripy /keripy
COPY src/ src/

ENV PATH="/keripy/venv/bin:${PATH}"

ENTRYPOINT [ "kli" ]
