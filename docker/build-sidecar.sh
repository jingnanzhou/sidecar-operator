#!/bin/bash


docker build -t caasguru/sidecar-operator  -f ./Dockerfile_sidecar .
docker push caasguru/sidecar-operator
