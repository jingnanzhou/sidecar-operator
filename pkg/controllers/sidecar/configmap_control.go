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

package sidecar

import (
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
	corelistersv1 "k8s.io/client-go/listers/core/v1"
)

// ServiceControlInterface defines the interface that the ClusterController
// uses to create Services. It is implemented as an interface to enable testing.
type ConfigMapControlInterface interface {
	CreateConfigMap(cm *corev1.ConfigMap) error
}

type realConfigMapControl struct {
	client        kubernetes.Interface
	configmapLister corelistersv1.ConfigMapLister
}

// NewRealServiceControl creates a concrete implementation of the
// ServiceControlInterface.
func NewRealConfigMapControl(client kubernetes.Interface, configmapLister corelistersv1.ConfigMapLister) ConfigMapControlInterface {
	return &realConfigMapControl{client: client, configmapLister: configmapLister}
}

func (rsc *realConfigMapControl) CreateConfigMap(cm *corev1.ConfigMap) error {
	_, err := rsc.client.CoreV1().ConfigMaps(cm.Namespace).Create(cm)
	return err
}
