// Copyright 2018 Oracle and/or its affiliates. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package configmaps

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	v1alpha1 "github.com/jingnanzhou/sidecar-operator/pkg/apis/incubation/v1alpha1"



)


func NewDefCM(nsName string, cmName string ) *corev1.ConfigMap {
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name: cmName,
			Namespace: nsName,
		},
	}
	return cm
}

// NewSidecarCM will return a new Kubernetes ConfigMap for a Sidecar
func NewSidecarCM(sidecar *v1alpha1.Sidecar, cmName string) *corev1.ConfigMap {

	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      cmName,
			Namespace: sidecar.Namespace,
			OwnerReferences: []metav1.OwnerReference{
				*metav1.NewControllerRef(sidecar, schema.GroupVersionKind{
					Group:   v1alpha1.SchemeGroupVersion.Group,
					Version: v1alpha1.SchemeGroupVersion.Version,
					Kind:    v1alpha1.SidecarCRDResourceKind,
				}),
			},
		},
		Data: sidecar.Spec.Data,
	}
	return cm
}
