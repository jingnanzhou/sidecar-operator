#!/bin/bash

docker build -t caasguru/secret  -f ./Dockerfile.secret_job .

docker push caasguru/secret
