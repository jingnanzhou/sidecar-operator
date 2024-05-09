#!/bin/bash


echo " start to create secrets"
while [[ $# -gt 0 ]]; do
    case ${1} in
        --service)
            service="$2"
            shift
            ;;
        --secret)
            secret="$2"
            shift
            ;;
        --namespace)
            namespace="$2"
            shift
            ;;
        *)
            ;;
    esac
    shift
done


if [ -z "$namespace" ]
then
      echo "namespace is required, use --namespace yournamespace"
      exit
else
  echo "the enter namespace is $namespace"
fi

[ -z ${service} ] && service=sidecar-injector-webhook-svc
[ -z ${secret} ] && secret=sidecar-injector-webhook-certs


tmpdir=$(mktemp -d)
echo "creating certs in tmpdir ${tmpdir} "

cat <<EOF >> ${tmpdir}/csr.conf

[req]
default_bits = 2048
prompt = no
default_md = sha256
x509_extensions = v3_req
distinguished_name = dn

[dn]
CN = ${service}.${namespace}.svc

[v3_req]
subjectAltName = @alt_names

[alt_names]
DNS.1 = ${service}
DNS.2 = ${service}.${namespace}
DNS.3 = ${service}.${namespace}.svc

EOF


openssl req -new -x509 -newkey rsa:2048 -sha256 -nodes -keyout ${tmpdir}/key.pem -days 3560 -out ${tmpdir}/cert.pem -config ${tmpdir}/csr.conf

kubectl create secret generic ${secret} \
        --from-file=key.pem=${tmpdir}/key.pem \
        --from-file=cert-chain.pem=${tmpdir}/cert.pem \
        --dry-run -o yaml > ${tmpdir}/secret.yaml

kubectl -n ${namespace} delete -f ${tmpdir}/secret.yaml

kubectl -n ${namespace} apply -f ${tmpdir}/secret.yaml

#kubectl create secret generic ${secret} \
#        --from-file=key.pem=${tmpdir}/key.pem \
#        --from-file=cert-chain.pem=${tmpdir}/cert.pem \
#        --dry-run -o yaml | kubectl -n ${namespace} apply -f -


echo "clean up the temp directory"
rm -rf ${tmpdir}

echo "done"
