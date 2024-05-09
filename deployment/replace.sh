rm ./mutatingwebhook-ca-bundle.yaml

cat ./mutatingwebhook.yaml | \
    ./cp-ca.sh > \
    ./mutatingwebhook-ca-bundle.yaml
