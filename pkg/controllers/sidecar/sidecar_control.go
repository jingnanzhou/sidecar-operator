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
	"fmt"

	"github.com/golang/glog"

	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/util/retry"

	v1alpha1 "github.com/jingnanzhou/sidecar-operator/pkg/apis/incubation/v1alpha1"
	clientset "github.com/jingnanzhou/sidecar-operator/pkg/generated/clientset/versioned"
	listersv1alpha1 "github.com/jingnanzhou/sidecar-operator/pkg/generated/listers/incubation/v1alpha1"
)

type sidecarUpdaterInterface interface {
	UpdateSidecarLabels(sidecar *v1alpha1.Sidecar, lbls labels.Set) error
}

type sidecarUpdater struct {
	client clientset.Interface
	lister listersv1alpha1.SidecarLister
}

func newSidecarUpdater(client clientset.Interface, lister listersv1alpha1.SidecarLister) sidecarUpdaterInterface {
	return &sidecarUpdater{client: client, lister: lister}
}


func (cu *sidecarUpdater) UpdateSidecarLabels(sidecar *v1alpha1.Sidecar, lbls labels.Set) error {
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		sidecar.Labels = labels.Merge(labels.Set(sidecar.Labels), lbls)
		_, updateErr := cu.client.IncubationV1alpha1().Sidecars(sidecar.Namespace).Update(sidecar)
		if updateErr == nil {
			return nil
		}

		key := fmt.Sprintf("%s/%s", sidecar.GetNamespace(), sidecar.GetName())
		glog.V(4).Infof("Conflict updating Sidecar labels. Getting updated Sidecar %s from cache...", key)

		updated, err := cu.lister.Sidecars(sidecar.GetNamespace()).Get(sidecar.GetName())
		if err != nil {
			glog.Errorf("Error getting updated Sidecar %s: %v", key, err)
			return err
		}

		// Copy the Sidecar so we don't mutate the cache.
		sidecar = updated.DeepCopy()
		return updateErr
	})
}
