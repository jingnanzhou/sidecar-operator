
#!/bin/bash
 
rm -rf ../docker/bin
mkdir ../docker/bin

GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -v -i -o ../docker/bin/sidecar-operator  ../cmd/webhook
