module github.com/jingnanzhou/sidecar-operator

go 1.12

require (
	contrib.go.opencensus.io/exporter/prometheus v0.1.0
	github.com/envoyproxy/go-control-plane v0.8.6
	github.com/ghodss/yaml v1.0.0
	github.com/gogo/protobuf v1.2.2-0.20190730201129-28a6bbf47e48
	github.com/golang/glog v0.0.0-20160126235308-23def4e6c14b
	github.com/hashicorp/go-multierror v1.0.0
	github.com/howeyc/fsnotify v0.9.0
	github.com/juju/errors v0.0.0-20190806202954-0232dcc7464d
	github.com/openshift/api v0.0.0-20190322043348-8741ff068a47
	github.com/pkg/errors v0.8.1
	github.com/prometheus/client_golang v0.9.3-0.20190127221311-3c4408c8b829
	github.com/sirupsen/logrus v1.4.2
	github.com/spf13/cobra v0.0.5
	github.com/spf13/pflag v1.0.3
	go.opencensus.io v0.21.0
	google.golang.org/grpc v1.23.0
	istio.io/api v0.0.0-20190822024358-9dc74657c53e
	istio.io/istio v0.0.0-20190822134628-92d8d8a67b66
	istio.io/pkg v0.0.0-20190822055426-2ef536f1ce36

	k8s.io/api v0.0.0-20190222213804-5cb15d344471
	k8s.io/apimachinery v0.0.0-20190221213512-86fb29eff628
	k8s.io/client-go v10.0.0+incompatible
	k8s.io/kubernetes v1.13.1

)
