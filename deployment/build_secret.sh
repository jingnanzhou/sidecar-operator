#!/bin/bash

docker build -t caasguru/secret  -f ../docker/Dockerfile.secret_job .

docker push caasguru/secret
