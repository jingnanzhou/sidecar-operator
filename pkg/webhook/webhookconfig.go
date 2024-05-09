package webhook


import (
	"bytes"
	"fmt"
	"io/ioutil"
	"path/filepath"

	"github.com/howeyc/fsnotify"
	"k8s.io/api/admissionregistration/v1beta1"
	"k8s.io/apimachinery/pkg/fields"
	_ "k8s.io/client-go/plugin/pkg/client/auth/gcp"
	"k8s.io/client-go/tools/cache"
  "k8s.io/client-go/kubernetes"
  
	"istio.io/istio/pkg/kube"

  "github.com/sirupsen/logrus"

)


var (
  log = logrus.StandardLogger()

)

type WebhookConfig struct {
	Kubeconfig string
	CertFile string          // path to the x509 certificate for https

  WebhookConfigName   string
  WebhookName         string
}


func (wc *WebhookConfig) PatchCertLoop(stopCh <-chan struct{}) error {

  logger := log.WithField("context", "WebhookConfig.PatchCertLoop")

  client, err := kube.CreateClientset(wc.Kubeconfig, "")
	if err != nil {
		return err
	}

	caCertPem, err := ioutil.ReadFile(wc.CertFile)
	if err != nil {
		return err
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}
	watchDir, _ := filepath.Split(wc.CertFile)
	if err = watcher.Watch(watchDir); err != nil {
		return fmt.Errorf("could not watch %v: %v", wc.CertFile, err)
	}

	if err = PatchMutatingWebhookConfig(client.AdmissionregistrationV1beta1().MutatingWebhookConfigurations(),
		wc.WebhookConfigName, wc.WebhookName, caCertPem); err != nil {
		return err
	}

	shouldPatch := make(chan struct{})

	watchlist := cache.NewListWatchFromClient(
		client.AdmissionregistrationV1beta1().RESTClient(),
		"mutatingwebhookconfigurations",
		"",
		fields.ParseSelectorOrDie(fmt.Sprintf("metadata.name=%s", wc.WebhookConfigName)))

	_, controller := cache.NewInformer(
		watchlist,
		&v1beta1.MutatingWebhookConfiguration{},
		0,
		cache.ResourceEventHandlerFuncs{
			UpdateFunc: func(oldObj, newObj interface{}) {
				config := newObj.(*v1beta1.MutatingWebhookConfiguration)
				for i, w := range config.Webhooks {
					if w.Name == wc.WebhookName && !bytes.Equal(config.Webhooks[i].ClientConfig.CABundle, caCertPem) {
						logger.Infof("Detected a change in CABundle, patching MutatingWebhookConfiguration again")
						shouldPatch <- struct{}{}
						break
					}
				}
			},
		},
	)
	go controller.Run(stopCh)

	go func() {
		for {
			select {
			case <-shouldPatch:
				wc.doPatch(client, caCertPem)

			case <-watcher.Event:
				if b, err := ioutil.ReadFile(wc.CertFile); err == nil {
					logger.Infof("Detected a change in CABundle (via secret), patching MutatingWebhookConfiguration again")
					caCertPem = b
					wc.doPatch(client, caCertPem)
				} else {
					logger.Errorf("CA bundle file read error: %v", err)
				}
			}
		}
	}()

  return nil
}

func (wc *WebhookConfig) doPatch(client *kubernetes.Clientset, caCertPem []byte) {
	if err := PatchMutatingWebhookConfig(client.AdmissionregistrationV1beta1().MutatingWebhookConfigurations(),
		wc.WebhookConfigName, wc.WebhookName, caCertPem); err != nil {
		log.WithField("context", "WebhookConfig.doPatch").Errorf("Patch webhook failed: %v", err)
	}
}
