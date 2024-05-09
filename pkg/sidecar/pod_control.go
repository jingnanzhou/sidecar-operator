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

package sidecar

import (
//	"fmt"
//	"encoding/json"
	"strings"

	 corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
	corelistersv1 "k8s.io/client-go/listers/core/v1"
	"github.com/jingnanzhou/sidecar-operator/pkg/controllers/util"

	inject	"istio.io/istio/pkg/kube/inject"
	"istio.io/istio/pilot/cmd/pilot-agent/status"

)

// PodControlInterface defines the interface that the
// ClusterController uses to create, update, and delete mysql pods. It
// is implemented as an interface to enable testing.
type PodControlInterface interface {
	PatchPod(old *corev1.Pod, new *corev1.Pod) error
}

type realPodControl struct {
	client    kubernetes.Interface
	podLister corelistersv1.PodLister
}

// NewRealPodControl creates a concrete implementation of the
// PodControlInterface.
func NewRealPodControl(client kubernetes.Interface, podLister corelistersv1.PodLister) PodControlInterface {
	return &realPodControl{client: client, podLister: podLister}
}

func (rpc *realPodControl) PatchPod(old *corev1.Pod, new *corev1.Pod) error {
	_, err := util.PatchPod(rpc.client, old, new)
	return err
}


// It would be great to use https://github.com/mattbaird/jsonpatch to
// generate RFC6902 JSON patches. Unfortunately, it doesn't produce
// correct patches for object removal. Fortunately, our patching needs
// are fairly simple so generating them manually isn't horrible (yet).
type rfc6902PatchOperation struct {
	Op    string      `json:"op"`
	Path  string      `json:"path"`
	Value interface{} `json:"value,omitempty"`
}


// JSONPatch `remove` is applied sequentially. Remove items in reverse
// order to avoid renumbering indices.

/*
func removeContainers(containers []corev1.Container, removed []string, path string) (patch []rfc6902PatchOperation) {
	names := map[string]bool{}
	for _, name := range removed {
		names[name] = true
	}
	for i := len(containers) - 1; i >= 0; i-- {
		if _, ok := names[containers[i].Name]; ok {
			patch = append(patch, rfc6902PatchOperation{
				Op:   "remove",
				Path: fmt.Sprintf("%v/%v", path, i),
			})
		}
	}
	return patch
}
*/

func removeContainers(pod *corev1.Pod, removed []string, path string)  {
	names := map[string]bool{}
	for _, name := range removed {
		names[name] = true
	}
	var containers []corev1.Container

	if path == "/spec/initContainers" {
		containers=pod.Spec.InitContainers

	}else if path == "/spec/containers" {
		containers=pod.Spec.Containers
	}
	total :=len(containers)
	for i := total - 1; i >= 0; i-- {
		if _, ok := names[containers[i].Name]; ok {

			if i == (total-1) {
			 	containers = containers[:i]
			} else {
				containers = append(containers[:i], containers[i+1:]...)
			}
		}
	}
	if path == "/spec/initContainers"  {

		pod.Spec.InitContainers=containers

	} else if path == "/spec/containers" {
		pod.Spec.Containers=containers
	}
}

/*
func removeVolumes(volumes []corev1.Volume, removed []string, path string) (patch []rfc6902PatchOperation) {
	names := map[string]bool{}
	for _, name := range removed {
		names[name] = true
	}
	for i := len(volumes) - 1; i >= 0; i-- {
		if _, ok := names[volumes[i].Name]; ok {
			patch = append(patch, rfc6902PatchOperation{
				Op:   "remove",
				Path: fmt.Sprintf("%v/%v", path, i),
			})
		}
	}
	return patch
}
*/

func removeVolumes(pod *corev1.Pod,  removed []string, path string) {

	var volumes []corev1.Volume=pod.Spec.Volumes

	names := map[string]bool{}
	for _, name := range removed {
		names[name] = true
	}
	total :=len(volumes)
	for i :=  total - 1; i >= 0; i-- {
		if _, ok := names[volumes[i].Name]; ok {
			if i >= (total-1) {
				volumes=volumes[:i]
			} else {
				volumes = append(volumes[:i], volumes[i+1:]...)
			}
		}
	}
	pod.Spec.Volumes=volumes
}
/*
func removeImagePullSecrets(imagePullSecrets []corev1.LocalObjectReference, removed []string, path string) (patch []rfc6902PatchOperation) {
	names := map[string]bool{}
	for _, name := range removed {
		names[name] = true
	}
	for i := len(imagePullSecrets) - 1; i >= 0; i-- {
		if _, ok := names[imagePullSecrets[i].Name]; ok {
			patch = append(patch, rfc6902PatchOperation{
				Op:   "remove",
				Path: fmt.Sprintf("%v/%v", path, i),
			})
		}
	}
	return patch
}
patch = append(patch, removeImagePullSecrets(pod.Spec.ImagePullSecrets, prevStatus.ImagePullSecrets, "/spec/imagePullSecrets")...)

*/

func removeImagePullSecrets(pod *corev1.Pod, removed []string, path string) {

  var imagePullSecrets []corev1.LocalObjectReference =pod.Spec.ImagePullSecrets

	names := map[string]bool{}
	for _, name := range removed {
		names[name] = true
	}
	total :=len(imagePullSecrets)
	for i :=  total- 1; i >= 0; i-- {
		if _, ok := names[imagePullSecrets[i].Name]; ok {

			if i >= (total-1) {
				imagePullSecrets=imagePullSecrets[:i]

			} else {
				imagePullSecrets = append(imagePullSecrets[:i], imagePullSecrets[i+1:]...)
			}
		}
	}
	pod.Spec.ImagePullSecrets = imagePullSecrets
}



/*
func addContainer(target, added []corev1.Container, basePath string) (patch []rfc6902PatchOperation) {
	saJwtSecretMountName := ""
	var saJwtSecretMount corev1.VolumeMount
	// find service account secret volume mount(/var/run/secrets/kubernetes.io/serviceaccount,
	// https://kubernetes.io/docs/reference/access-authn-authz/service-accounts-admin/#service-account-automation) from app container
	for _, add := range target {
		for _, vmount := range add.VolumeMounts {
			if vmount.MountPath == "/var/run/secrets/kubernetes.io/serviceaccount" {
				saJwtSecretMountName = vmount.Name
				saJwtSecretMount = vmount
			}
		}
	}
	first := len(target) == 0
	var value interface{}
	for _, add := range added {
		if add.Name == "istio-proxy" && saJwtSecretMountName != "" {
			// add service account secret volume mount(/var/run/secrets/kubernetes.io/serviceaccount,
			// https://kubernetes.io/docs/reference/access-authn-authz/service-accounts-admin/#service-account-automation) to istio-proxy container,
			// so that envoy could fetch/pass k8s sa jwt and pass to sds server, which will be used to request workload identity for the pod.
			add.VolumeMounts = append(add.VolumeMounts, saJwtSecretMount)
		}
		value = add
		path := basePath
		if first {
			first = false
			value = []corev1.Container{add}
		} else {
			path += "/-"
		}
		patch = append(patch, rfc6902PatchOperation{
			Op:    "add",
			Path:  path,
			Value: value,
		})
	}
	return patch
}

*/

func addContainer(pod *corev1.Pod, added []corev1.Container, path string) {

	var containers []corev1.Container

	if path == "/spec/initContainers" {
		containers=pod.Spec.InitContainers

	}else if path == "/spec/containers" {
		containers=pod.Spec.Containers
	}
	if len(containers) ==0 {
		containers=[]corev1.Container{}
	}

	saJwtSecretMountName := ""
	var saJwtSecretMount corev1.VolumeMount
	// find service account secret volume mount(/var/run/secrets/kubernetes.io/serviceaccount,
	// https://kubernetes.io/docs/reference/access-authn-authz/service-accounts-admin/#service-account-automation) from app container
	for _, add := range containers {
		for _, vmount := range add.VolumeMounts {
			if vmount.MountPath == "/var/run/secrets/kubernetes.io/serviceaccount" {
				saJwtSecretMountName = vmount.Name
				saJwtSecretMount = vmount
			}
		}
	}

	for _, add := range added {
		if add.Name == "istio-proxy" && saJwtSecretMountName != "" {
			// add service account secret volume mount(/var/run/secrets/kubernetes.io/serviceaccount,
			// https://kubernetes.io/docs/reference/access-authn-authz/service-accounts-admin/#service-account-automation) to istio-proxy container,
			// so that envoy could fetch/pass k8s sa jwt and pass to sds server, which will be used to request workload identity for the pod.
			add.VolumeMounts = append(add.VolumeMounts, saJwtSecretMount)
		}
		containers=append(containers, add)
	}
	if path == "/spec/initContainers"  {

		pod.Spec.InitContainers=containers

	} else if path == "/spec/containers" {
		pod.Spec.Containers=containers
	}
}



func addSecurityContext(target *corev1.PodSecurityContext, basePath string) (patch []rfc6902PatchOperation) {
	patch = append(patch, rfc6902PatchOperation{
		Op:    "add",
		Path:  basePath,
		Value: target,
	})
	return patch
}

/*
func addVolume(target, added []corev1.Volume, basePath string) (patch []rfc6902PatchOperation) {
	first := len(target) == 0
	var value interface{}
	for _, add := range added {
		value = add
		path := basePath
		if first {
			first = false
			value = []corev1.Volume{add}
		} else {
			path += "/-"
		}
		patch = append(patch, rfc6902PatchOperation{
			Op:    "add",
			Path:  path,
			Value: value,
		})
	}
	return patch
}
*/

func addVolume(pod *corev1.Pod, added []corev1.Volume, basePath string) {
	var volumes []corev1.Volume =pod.Spec.Volumes
	if len (volumes) ==0 {
		volumes = []corev1.Volume {}
	}
	for _, add := range added {
		volumes=append(volumes, add)
	}
	pod.Spec.Volumes=volumes
}
/*
func addImagePullSecrets(target, added []corev1.LocalObjectReference, basePath string) (patch []rfc6902PatchOperation) {
	first := len(target) == 0
	var value interface{}
	for _, add := range added {
		value = add
		path := basePath
		if first {
			first = false
			value = []corev1.LocalObjectReference{add}
		} else {
			path += "/-"
		}
		patch = append(patch, rfc6902PatchOperation{
			Op:    "add",
			Path:  path,
			Value: value,
		})
	}
	return patch
}
*/

func addImagePullSecrets(pod *corev1.Pod, added []corev1.LocalObjectReference, basePath string) {

	var secrets []corev1.LocalObjectReference = pod.Spec.ImagePullSecrets

	if len(secrets) ==0 {
		secrets=[]corev1.LocalObjectReference{}
	}
	for _, add := range added {
		secrets=append(secrets, add)
	}
	pod.Spec.ImagePullSecrets=secrets
}

func addPodDNSConfig(target *corev1.PodDNSConfig, basePath string) (patch []rfc6902PatchOperation) {
	patch = append(patch, rfc6902PatchOperation{
		Op:    "add",
		Path:  basePath,
		Value: target,
	})
	return patch
}

// escape JSON Pointer value per https://tools.ietf.org/html/rfc6901
func escapeJSONPointerValue(in string) string {
	step := strings.Replace(in, "~", "~0", -1)
	return strings.Replace(step, "/", "~1", -1)
}
/*
func updateAnnotation(target map[string]string, added map[string]string) (patch []rfc6902PatchOperation) {
	for key, value := range added {
		if target == nil {
			target = map[string]string{}
			patch = append(patch, rfc6902PatchOperation{
				Op:   "add",
				Path: "/metadata/annotations",
				Value: map[string]string{
					key: value,
				},
			})
		} else {
			op := "add"
			if target[key] != "" {
				op = "replace"
			}
			patch = append(patch, rfc6902PatchOperation{
				Op:    op,
				Path:  "/metadata/annotations/" + escapeJSONPointerValue(key),
				Value: value,
			})
		}
	}
	return patch
}

*/

func updateAnnotation(pod *corev1.Pod, added map[string]string)  {
	var annotations map[string]string = pod.Annotations
	if annotations ==nil {
		annotations = make(map[string]string)
		}

	for key, value := range added {
		annotations[key] =value
	}
	pod.Annotations=annotations
}

func createPatch(pod *corev1.Pod, prevStatus *inject.SidecarInjectionStatus, annotations map[string]string, sic *inject.SidecarInjectionSpec) (*corev1.Pod, error) {
//return nil,nil

//	var patch []rfc6902PatchOperation

	// Remove any containers previously injected by kube-inject using
	// container and volume name as unique key for removal.
//	patch = append(patch, removeContainers(pod.Spec.InitContainer, prevStatus.InitContainers, "/spec/initContainers")...)
//	patch = append(patch, removeContainers(pod.Spec.Containers, prevStatus.Containers, "/spec/containers")...)

	removeContainers(pod, prevStatus.InitContainers, "/spec/initContainers")
	removeContainers(pod, prevStatus.Containers, "/spec/containers")

//	patch = append(patch, removeVolumes(pod.Spec.Volumes, prevStatus.Volumes, "/spec/volumes")...)
//	patch = append(patch, removeImagePullSecrets(pod.Spec.ImagePullSecrets, prevStatus.ImagePullSecrets, "/spec/imagePullSecrets")...)
	removeVolumes(pod, prevStatus.Volumes, "/spec/volumes")
	removeImagePullSecrets(pod, prevStatus.ImagePullSecrets,"/spec/imagePullSecrets")

	rewrite := inject.ShouldRewriteAppHTTPProbers(pod.Annotations, sic)
	addAppProberCmd := func() {
		if !rewrite {
			return
		}
		sidecar := inject.FindSidecar(sic.Containers)
		if sidecar == nil {
			log.Errorf("sidecar not found in the template, skip addAppProberCmd")
			return
		}
		// We don't have to escape json encoding here when using golang libraries.
		if prober := inject.DumpAppProbers(&pod.Spec); prober != "" {
			sidecar.Env = append(sidecar.Env, corev1.EnvVar{Name: status.KubeAppProberEnvName, Value: prober})
		}
	}
	addAppProberCmd()
//	patch = append(patch, addContainer(pod.Spec.InitContainers, sic.InitContainers, "/spec/initContainers")...)
//	patch = append(patch, addContainer(pod.Spec.Containers, sic.Containers, "/spec/containers")...)

	addContainer(pod, sic.InitContainers, "/spec/initContainers")
	addContainer(pod, sic.Containers, "/spec/containers")

//	patch = append(patch, addVolume(pod.Spec.Volumes, sic.Volumes, "/spec/volumes")...)
	addVolume(pod, sic.Volumes, "/spec/volumes")

//	patch = append(patch, addImagePullSecrets(pod.Spec.ImagePullSecrets, sic.ImagePullSecrets, "/spec/imagePullSecrets")...)
	addImagePullSecrets(pod, sic.ImagePullSecrets, "/spec/imagePullSecrets")

	if sic.DNSConfig != nil {
//		patch = append(patch, addPodDNSConfig(sic.DNSConfig, "/spec/dnsConfig")...)
		pod.Spec.DNSConfig=sic.DNSConfig

	}
/*
	if pod.Spec.SecurityContext != nil {
		patch = append(patch, addSecurityContext(pod.Spec.SecurityContext, "/spec/securityContext")...)
	}
*/
//	patch = append(patch, updateAnnotation(pod.Annotations, annotations)...)
	updateAnnotation(pod, annotations)

//	if rewrite {
//		patch = append(patch, createProbeRewritePatch(pod.Annotations, &pod.Spec, sic)...)
//	}
return pod,nil
//	return json.Marshal(patch)

}
