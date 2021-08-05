FROM python:3.9.6-buster

RUN apt-get update
RUN apt-get install -y ca-certificates

RUN apt-get install -y libsodium23

COPY ./ /usr/local/var/keripy
WORKDIR /usr/local/var/keripy

RUN pip install -r requirements.txt
