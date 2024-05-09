/*
Copyright The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package app

import (

	"context"
	"sync"
	"math/rand"
	"time"

	kubeinformers "k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

	operatoropts "github.com/jingnanzhou/sidecar-operator/pkg/options"
	signals "github.com/jingnanzhou/sidecar-operator/pkg/signals"

	clientset "github.com/jingnanzhou/sidecar-operator/pkg/generated/clientset/versioned"
	informers "github.com/jingnanzhou/sidecar-operator/pkg/generated/informers/externalversions"
	sidecar  "github.com/jingnanzhou/sidecar-operator/pkg/controllers/sidecar"

	"github.com/sirupsen/logrus"
)

var (
	log = logrus.StandardLogger()
)

// resyncPeriod computes the time interval a shared informer waits before
// resyncing with the api server.

func resyncPeriod(s *operatoropts.OperatorOpts) func() time.Duration {
	return func() time.Duration {
		factor := rand.Float64() + 1
		return time.Duration(float64(s.MinResyncPeriod.Nanoseconds()) * factor)
	}
}

// Run starts the operator controllers. This should never exit.
func Run(s *operatoropts.OperatorOpts) error {

	logger := log.WithField("context", "app.Run")

	kubeconfig, err := clientcmd.BuildConfigFromFlags(s.Master, s.KubeConfig)
	if err != nil {
		return err
	}
	logger.Infof("kubeconfig %v \n", kubeconfig)
	ctx, cancelFunc := context.WithCancel(context.Background())

	// Set up signals so we handle the first shutdown signal gracefully.
	signals.SetupSignalHandler(cancelFunc)

	kubeClient := kubernetes.NewForConfigOrDie(kubeconfig)

	opClient := clientset.NewForConfigOrDie(kubeconfig)

	// Shared informers (non namespace specific).
//	kubeInformerFactory := kubeinformers.NewFilteredSharedInformerFactory(kubeClient, resyncPeriod(s)(), s.Namespace, nil)
	kubeInformerFactory := kubeinformers.NewSharedInformerFactory(kubeClient, resyncPeriod(s)())

	operatorInformerFactory := informers.NewFilteredSharedInformerFactory(opClient, resyncPeriod(s)(), s.Namespace, nil)

	var wg sync.WaitGroup

	sidecarController := sidecar.NewController(
		*s,
		opClient,
		kubeClient,
		operatorInformerFactory.Incubation().V1alpha1().Sidecars(),
		kubeInformerFactory.Core().V1().Namespaces(),
		kubeInformerFactory.Core().V1().ConfigMaps(),
		kubeInformerFactory.Core().V1().Pods(),
		30*time.Second,
		s.Namespace,
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		sidecarController.Run(ctx, 5)
	}()


	// Shared informers have to be started after ALL controllers.
	go kubeInformerFactory.Start(ctx.Done())
	go operatorInformerFactory.Start(ctx.Done())

	<-ctx.Done()

	logger.Info("Waiting for all controllers to shut down gracefully")
	wg.Wait()

	return nil
}
