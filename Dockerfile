FROM python:3.9.7-buster

RUN apt-get update
RUN apt-get install -y ca-certificates

RUN apt-get install -y libsodium23

COPY ./ /keripy
WORKDIR /keripy

RUN pip install -r requirements.txt
