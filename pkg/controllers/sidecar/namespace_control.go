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
	"github.com/jingnanzhou/sidecar-operator/pkg/controllers/util"
	corev1 "k8s.io/api/core/v1"
	kubernetes "k8s.io/client-go/kubernetes"
	corelistersv1 "k8s.io/client-go/listers/core/v1"
)

// StatefulSetControlInterface defines the interface that the
// ClusterController uses to create and update StatefulSets. It
// is implemented as an interface to enable testing.
type NamespaceControlInterface interface {
	CreateNamespace(dp *corev1.Namespace) error
	Patch(old *corev1.Namespace, new *corev1.Namespace) error
}

type realNamespaceControl struct {
	client            kubernetes.Interface
	namespaceLister corelistersv1.NamespaceLister
}

// NewRealStatefulSetControl creates a concrete implementation of the
// StatefulSetControlInterface.
func NewRealNamespaceControl(client kubernetes.Interface, namespaceLister corelistersv1.NamespaceLister) NamespaceControlInterface {
	return &realNamespaceControl{client: client, namespaceLister: namespaceLister}
}

func (rssc *realNamespaceControl) CreateNamespace(dp *corev1.Namespace) error {
	_, err := rssc.client.CoreV1().Namespaces().Create(dp)
	return err
}

func (rssc *realNamespaceControl) Patch(old *corev1.Namespace, new *corev1.Namespace) error {
	_, err := util.PatchNamespace(rssc.client, old, new)
	return err
}
