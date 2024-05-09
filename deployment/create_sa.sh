oc label namespace default sidecar-injector=enabled
oc adm policy add-scc-to-user anyuid -z sidecar-service-account -n default
#oc adm policy add-scc-to-user privileged -z sidecar-service-account -n default

oc adm policy add-scc-to-user privileged -z default -n default
