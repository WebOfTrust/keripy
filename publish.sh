#!/bin/bash

docker build -t keripy .
docker tag keripy:latest pfeairheller/keripy:latest
docker push pfeairheller/keripy:latest