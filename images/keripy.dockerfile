
FROM python:3.10.4-alpine3.16 as builder

RUN apk update
RUN apk add bash
SHELL ["/bin/bash", "-c"]

RUN apk add alpine-sdk
RUN apk add libffi-dev
RUN apk add libsodium
RUN apk add libsodium-dev

# Setup Rust for blake3 dependency build
RUN curl https://sh.rustup.rs -sSf | bash -s -- -y

WORKDIR /keripy

RUN python -m venv venv

ENV PATH=/keripy/venv/bin:${PATH}

RUN pip install --upgrade pip

COPY requirements.txt setup.py .
COPY src/ src/
RUN . ${HOME}/.cargo/env && pip install -r requirements.txt

FROM python:3.10.4-alpine3.16

RUN apk add alpine-sdk
RUN apk add libsodium-dev

ENV PATH=/keripy/venv/bin:${PATH}

COPY --from=builder /keripy /keripy

WORKDIR /keripy

# Install KERIpy dependencies
# Must source the Cargo environment for the blake3 library to see the Rust intallation during requirements install
ENTRYPOINT [ "kli" ]
