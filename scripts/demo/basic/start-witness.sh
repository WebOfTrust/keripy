#!/bin/bash

kli init --name witness --nopasscode
kli incept --name witness --alias=wil --file tests/app/cli/wil-witness-sample.json
kli witness start --name witness --alias=wil
