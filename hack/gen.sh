#!/bin/bash

# ROOT_PACKAGE :: the package (relative to $GOPATH/src) that is the target for code generation
ROOT_PACKAGE="github.com/jingnanzhou/sidecar-operator"
# CUSTOM_RESOURCE_NAME :: the name of the custom resource that we're generating client code for
CUSTOM_RESOURCE_NAME="incubation"
# CUSTOM_RESOURCE_VERSION :: the version of the resource
CUSTOM_RESOURCE_VERSION="v1alpha1"

#go get k8s.io/code-generator
#go get k8s.io/apimachinery


# run the code-generator entrypoint script
$GOPATH/src/k8s.io/code-generator/generate-groups.sh all \
    "$ROOT_PACKAGE/pkg/generated" \
    "$ROOT_PACKAGE/pkg/apis" \
    "$CUSTOM_RESOURCE_NAME:$CUSTOM_RESOURCE_VERSION" \
    "$@"
