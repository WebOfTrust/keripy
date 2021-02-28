FROM python:3.9.1-buster

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get dist-upgrade -y

# Install dependencies and required tools
RUN apt-get install -y \
    git \
    libsodium-dev \
    python3-nacl

RUN git clone https://github.com/decentralized-identity/keripy.git

WORKDIR /keripy

RUN python3 -m pip install --upgrade pip
RUN if [ -f requirements.txt ]; then pip install -r requirements.txt; fi
