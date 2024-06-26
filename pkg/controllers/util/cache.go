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

package util

import (

	"k8s.io/client-go/tools/cache"
	"github.com/sirupsen/logrus"
)
var (
	log = logrus.StandardLogger()
)

// WaitForCacheSync is a wrapper around cache.WaitForCacheSync that generates
// log messages indicating that the controller identified by controllerName is
// waiting for syncs, followed by either a successful or failed sync.
func WaitForCacheSync(controllerName string, stopCh <-chan struct{}, cacheSyncs ...cache.InformerSynced) bool {

	logger :=log.WithField("context", "Controller.WaitForCacheSync")

	logger.Infof("Waiting for caches to sync for %s controller", controllerName)

	if !cache.WaitForCacheSync(stopCh, cacheSyncs...) {
		logger.Errorf("Unable to sync caches for %s controller", controllerName)
		return false
	}

	logger.Infof("Caches are synced for %s controller", controllerName)
	return true
}
