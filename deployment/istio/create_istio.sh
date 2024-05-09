helm template install/kubernetes/helm/istio --name istio --namespace istio-system \
  --values install/kubernetes/helm/istio/values-istio-demo.yaml  --set sidecarInjectorWebhook.enabled=false | kubectl apply -f -
