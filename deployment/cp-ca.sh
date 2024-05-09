#!/bin/bash

ROOT=$(cd $(dirname $0)/../../; pwd)

set -o errexit
set -o nounset
set -o pipefail

export CA_BUNDLE=$(cat cert.pem | base64 | tr -d '\n')

#export CA_BUNDLE=$(kubectl get secret  sidecar-injector-webhook-certs -n default  -o=jsonpath='{.data.cert-pem}' |tr -d '\n')

if command -v envsubst >/dev/null 2>&1; then
    envsubst
else
    sed -e "s|\${CA_BUNDLE}|${CA_BUNDLE}|g"
fi
