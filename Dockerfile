FROM python:3.10.4

RUN apt-get update
RUN apt-get install -y ca-certificates

RUN apt-get install -y libsodium23
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | bash -s -- -y

ENV PATH="/root/.cargo/bin:${PATH}"
ENV PYTHONUNBUFFERED=1
ENV PYTHONIOENCODING=UTF-8

COPY ./ /keripy
WORKDIR /keripy

RUN pip install -r requirements.txt
