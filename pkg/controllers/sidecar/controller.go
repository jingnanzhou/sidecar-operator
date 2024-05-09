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

	"time"
	"context"
	"fmt"
	"strings"

	workqueue "k8s.io/client-go/util/workqueue"
	cache "k8s.io/client-go/tools/cache"
	record "k8s.io/client-go/tools/record"

	kubernetes "k8s.io/client-go/kubernetes"
	corelisters "k8s.io/client-go/listers/core/v1"

	coreinformers "k8s.io/client-go/informers/core/v1"
	scheme "k8s.io/client-go/kubernetes/scheme"
	corev1 "k8s.io/api/core/v1"
	typedcorev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	labels "k8s.io/apimachinery/pkg/labels"

	operatoropts "github.com/jingnanzhou/sidecar-operator/pkg/options"
	clientset "github.com/jingnanzhou/sidecar-operator/pkg/generated/clientset/versioned"


	listersv1alpha1 "github.com/jingnanzhou/sidecar-operator/pkg/generated/listers/incubation/v1alpha1"
	informersv1alpha1 "github.com/jingnanzhou/sidecar-operator/pkg/generated/informers/externalversions/incubation/v1alpha1"
	opscheme "github.com/jingnanzhou/sidecar-operator/pkg/generated/clientset/versioned/scheme"
	v1alpha1 "github.com/jingnanzhou/sidecar-operator/pkg/apis/incubation/v1alpha1"


	wait "k8s.io/apimachinery/pkg/util/wait"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	controllerutils "github.com/jingnanzhou/sidecar-operator/pkg/controllers/util"


//	"github.com/jingnanzhou/sidecar-operator/pkg/sidecar"



	"github.com/sirupsen/logrus"
	"github.com/juju/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	//apps "k8s.io/api/apps/v1"
	//appsinformers "k8s.io/client-go/informers/apps/v1"
	//appslisters "k8s.io/client-go/listers/apps/v1"

//	"k8s.io/apimachinery/pkg/types"
	//"github.com/pkg/errors"




/*
	constants "github.com/jingnanzhou/grafana-operator/pkg/constants"

	services "github.com/jingnanzhou/grafana-operator/pkg/resources/services"
	deployments "github.com/jingnanzhou/grafana-operator/pkg/resources/deployments"

*/
configmaps "github.com/jingnanzhou/sidecar-operator/pkg/resources/configmaps"


)
const controllerAgentName = "operator-sidecar-controller"

const (
	// SuccessSynced is used as part of the Event 'reason' when a sidecar is
	// synced.
	SuccessSynced = "Synced"

	// MessageResourceSynced is the message used for an Event fired when a
	// Sidecar is synced successfully
	MessageResourceSynced = "Sidecar synced successfully"

	// ErrResourceExists is used as part of the Event 'reason' when a
	// Sidecar fails to sync due to a resource of the same name already
	// existing.
	ErrResourceExists = "ErrResourceExists"

	// MessageResourceExists is the message used for Events when a resource
	// fails to sync due to a resource already existing.
	MessageResourceExists = "%s %s/%s already exists and is not managed by Sidecar"
)
var (
	log = logrus.StandardLogger()
)


// The Controller watches the Kubernetes API for changes to sidecar resources
type Controller struct {
	// Global Operator configuration options.
	opConfig operatoropts.OperatorOpts

	kubeClient kubernetes.Interface
	opClient   clientset.Interface

	shutdown bool
	queue    workqueue.RateLimitingInterface

	// sidecarLister is able to list/get Sidecar from a shared informer's
	// store.
	sidecarLister listersv1alpha1.SidecarLister
	// sidecarListerSynced returns true if the Sidecar shared informer has
	// synced at least once.
	sidecarListerSynced cache.InformerSynced

	// sidecarUpdater implements control logic for updating Sidecar
	// statuses. Implemented as an interface to enable testing.
	sidecarUpdater sidecarUpdaterInterface

	// serviceLister is able to list/get Services from a shared informer's
	// store.
	namespaceLister corelisters.NamespaceLister
	// serviceListerSynced returns true if the Service shared informer
	// has synced at least once.
	namespaceListerSynced cache.InformerSynced
	// serviceControl enables control of Services associated with Grafanas.
	namespaceControl NamespaceControlInterface



	// configmapLister is able to list/get ConfigMaps from a shared
	// informer's store.
	configmapLister corelisters.ConfigMapLister
	// configmapListerSynced returns true if the ConfigMap shared informer
	// has synced at least once.
	configmapListerSynced cache.InformerSynced
	// configmapControl enables control of ConfigMaps associated with
	// Grafanas.
	configmapControl ConfigMapControlInterface




	podLister corelisters.PodLister
	// serviceListerSynced returns true if the Service shared informer
	// has synced at least once.
	podListerSynced cache.InformerSynced
	// serviceControl enables control of Services associated with Grafanas.
	podControl PodControlInterface


	// recorder is an event recorder for recording Event resources to the
	// Kubernetes API.
	recorder record.EventRecorder
}

// NewController creates a new Controller.
func NewController(
	opConfig operatoropts.OperatorOpts,
	opClient clientset.Interface,
	kubeClient kubernetes.Interface,
	sidecarInformer informersv1alpha1.SidecarInformer,
	namespaceInformer coreinformers.NamespaceInformer,
	configmapInformer coreinformers.ConfigMapInformer,
	podInformer coreinformers.PodInformer,
	resyncPeriod time.Duration,
	namespace string,
) *Controller {
	opscheme.AddToScheme(scheme.Scheme)

	logger := log.WithField("context", "Controller.NewController")

	// Create event broadcaster.
	logger.Info("Creating event broadcaster")

	eventBroadcaster := record.NewBroadcaster()
	eventBroadcaster.StartLogging(logger.Infof)
	eventBroadcaster.StartRecordingToSink(&typedcorev1.EventSinkImpl{Interface: kubeClient.CoreV1().Events("")})
	recorder := eventBroadcaster.NewRecorder(scheme.Scheme, corev1.EventSource{Component: controllerAgentName})

	m := Controller{
		opConfig: opConfig,

		opClient:   opClient,
		kubeClient: kubeClient,

		sidecarLister:       sidecarInformer.Lister(),
		sidecarListerSynced: sidecarInformer.Informer().HasSynced,
		sidecarUpdater:      newSidecarUpdater(opClient, sidecarInformer.Lister()),

		namespaceLister:       namespaceInformer.Lister(),
		namespaceListerSynced: namespaceInformer.Informer().HasSynced,
		namespaceControl:      NewRealNamespaceControl(kubeClient, namespaceInformer.Lister()),

		configmapLister:       configmapInformer.Lister(),
		configmapListerSynced: configmapInformer.Informer().HasSynced,
		configmapControl:      NewRealConfigMapControl(kubeClient, configmapInformer.Lister()),

		podLister:       podInformer.Lister(),
		podListerSynced: podInformer.Informer().HasSynced,
		podControl:      NewRealPodControl(kubeClient, podInformer.Lister()),

		queue:    workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "sidecar"),
		recorder: recorder,
	}

	sidecarInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: m.enqueueSidecar,
		UpdateFunc: func(old, new interface{}) {
			m.enqueueSidecar(new)
		},
		DeleteFunc: func(obj interface{}) {
			sidecar, ok := obj.(*v1alpha1.Sidecar)
			if ok {
				m.onSidecarDeleted(sidecar)
			}
		},
	})
	namespaceInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
			AddFunc: m.onNamespaceAdded,
			UpdateFunc: m.onNamespaceUpdated,
			DeleteFunc: m.onNamespaceDeleted,
		})

	configmapInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: m.handleObject,
		UpdateFunc: func(old, new interface{}) {
			newConfigMap := new.(*corev1.ConfigMap)
			oldConfigMap := old.(*corev1.ConfigMap)
			if newConfigMap.ResourceVersion == oldConfigMap.ResourceVersion {
				return
			}
			m.handleObject(new)
		},
		DeleteFunc: m.handleObject,
	})

	podInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: m.onPodUpdated,
			UpdateFunc: func(old, new interface{}) {
				m.onPodUpdated(new)
			},
			DeleteFunc: func(obj interface{}) {
			},
		})
	return &m
}
func (m *Controller) onPodUpdated(obj interface{}) {
	logger :=	log.WithField("contect", "Controller.onPodUpdated")

	object, ok := obj.(*corev1.Pod)
	if !ok {
		var errMsg string  ="error decoding object for Pod in onPodUpdated, invalid type"
		logger.Error(errMsg)
		utilruntime.HandleError(fmt.Errorf(errMsg))
		return
	}
	namespace, err := m.namespaceLister.Get(object.Namespace)
	if err != nil {
			logger.Infof("can not find name space for pod %s ", object.Namespace)
			return
	}

	label :=namespace.Labels[m.opConfig.InjectionName]

	if strings.Compare(label, "enabled") == 0 {
		 logger.Infof("Pod updated: %s in namespace %s  =%s", object.Name, namespace.Name, label)

		 	//	listOptions := metav1.ListOptions{}
		 	defLabels :=labels.NewSelector()
		 	//		defLabels := labels.SelectorFromSet(labels.Set{"folder": folder, })

		 	sidecarList, serr := m.sidecarLister.List(defLabels)
		 	if serr != nil {
		 			logger.Infof("ignoring processing sidecar list ")
		 			return
		 	}
		 	for _, sidecar := range sidecarList {
		 		logger.Infof(" sidecar name  %s for pod  %s", sidecar.Name, object.Name)
		 	}

 	}

	return
}

func (m *Controller) onNamespaceAdded(obj interface{}) {
	logger :=log.WithField("context", "Controller.onNamespaceAdded")
	object, ok := obj.(*corev1.Namespace)
	if !ok {
		var errMsg string ="error decoding object for namespace in onNamespaceAdded, invalid type"
		logger.Errorf(errMsg)
		utilruntime.HandleError(fmt.Errorf(errMsg))
		return
	}
	label :=object.Labels[m.opConfig.InjectionName]

 if strings.Compare(label, "enabled") == 0 {
		logger.Infof("Namespace added: %s", object.Name)
	}
		return
}
func (m *Controller) onNamespaceDeleted(obj interface{}) {
	logger :=log.WithField("context", "Controller.onNamespaceDeleted")

	object, ok := obj.(*corev1.Namespace)
	if !ok {
		var errMsg="error decoding object for namespace in onNamespaceDeleted, invalid type"
		logger.Error(errMsg)
		utilruntime.HandleError(fmt.Errorf(errMsg))
		return
	}
	logger.Infof("Namespace deleted: %s", object.Name)
		return
}

func (m *Controller) onNamespaceUpdated(old interface{}, new interface{}) {
	logger :=log.WithField("context", "Controller.onNamespaceUpdate")

	newNamespace,okN := new.(*corev1.Namespace)
	oldNamespace, okO := old.(*corev1.Namespace)

	if !okN || !okO {
		logger.Error("error decoding object for namespace in onNamespaceUpdate, invalid type")
		return
	}
	if newNamespace.ResourceVersion == oldNamespace.ResourceVersion {
		return
	}
	newLabel :=newNamespace.Labels[m.opConfig.InjectionName]
	oldLabel :=oldNamespace.Labels[m.opConfig.InjectionName]


 if strings.Compare(newLabel, oldLabel) != 0 {

		logger.Infof("auto injection label for namespace %s changed. The old label is %s and the new label isinject= %s", newNamespace.Name, oldLabel, newLabel)

		err :=m.kubeClient.CoreV1().Pods(newNamespace.Name).DeleteCollection(&metav1.DeleteOptions{}, metav1.ListOptions{})
		if err !=nil {
			logger.Errorf("Error while refreshing pods in namespace %s, err is %s", newNamespace.Name, err.Error())
		} else {
			logger.Infof("successfully refreshing pods in namespace %s ",  newNamespace.Name)
		}

/*
		defLabels :=labels.NewSelector()
		podList, err := m.podLister.Pods(newNamespace.Name).List(defLabels)
		if err != nil {
			logger.Infof("due to error %s, ignoring refresh pods in namespace %s ", err.Error(), newNamespace.Name )
			return
		}
		for _, pod := range podList {

			derr :=m.kubeClient.CoreV1().Pods(newNamespace.Name).Delete(pod.Name, &metav1.DeleteOptions{})
			if derr !=nil {
				logger.Errorf("Error while refreshing pod %s in namespace %s, err is %s", pod.Name, newNamespace.Name, derr.Error())
			} else {
				logger.Infof("successfully refreshing pod %s in namespace %s ", pod.Name, newNamespace.Name)
			}
		}
*/
	}
		return
}


// Run will set up the event handlers for types we are interested in, as well
// as syncing informer caches and starting workers. It will block until stopCh
// is closed, at which point it will shutdown the workqueue and wait for
// workers to finish processing their current work items.
func (m *Controller) Run(ctx context.Context, threadiness int) {
	defer utilruntime.HandleCrash()
	defer m.queue.ShutDown()

	logger :=log.WithField("context", "Controller.Run")

	logger.Info("Starting Sidecar controller")

	// Wait for the caches to be synced before starting workers
	logger.Info("Waiting for Sidecar controller informer caches to sync")
	if !controllerutils.WaitForCacheSync("Sidecar", ctx.Done(),
		m.sidecarListerSynced,
		m.podListerSynced,
		m.configmapListerSynced,
		m.namespaceListerSynced) {
		return
	}

/*
	defLabels :=labels.NewSelector()
	nsList, err := m.namespaceLister.List(defLabels)
	if err != nil {
			logger.Infof("ignoring processing namespace list ")
				return
	}

	for _, ns := range nsList {

 		if strings.Compare(ns.Name, "istio-demo") == 0 {
			logger.Infof(" namespace name %s ", ns.Name)

				podList, perr := m.podLister.Pods(ns.Name).List(defLabels)
				if perr != nil {
						glog.Infof("ignoring processing pod list ")
							return
				}
				for _, pod := range podList {
					logger.Infof(" pod name %s ", pod.Name)

					sidecar.InjectProxy(m.kubeClient, ns, pod)
				}
			}

	}

*/

	logger.Info("Starting Sidecar controller workers")
	// Launch two workers to process Sidecar resources
	for i := 0; i < threadiness; i++ {
		go wait.Until(m.runWorker, time.Second, ctx.Done())
	}

	logger.Info("Started Sidecar controller workers")
	defer logger.Info("Shutting down Sidecar controller workers")
	<-ctx.Done()
}

// worker runs a worker goroutine that invokes processNextWorkItem until the
// controller's queue is closed.
func (m *Controller) runWorker() {
	for m.processNextWorkItem() {
	}
}

// processNextWorkItem will read a single work item off the workqueue and
// attempt to process it, by calling the syncHandler.
func (m *Controller) processNextWorkItem() bool {
	logger :=log.WithField("context", "Controller.processNextWorkItem")

	obj, shutdown := m.queue.Get()
	if shutdown {
		return false
	}

	err := func(obj interface{}) error {
		defer m.queue.Done(obj)
		key, ok := obj.(string)
		if !ok {
			m.queue.Forget(obj)
			logger.Errorf("expected string in queue but got %#v", obj)
			return nil
		}
		if err := m.syncHandler(key); err != nil {
			logger.Errorf("error syncing '%s': %s", key, err.Error())
			return err
		}
		m.queue.Forget(obj)
		logger.Infof("Successfully synced '%s'", key)
		return nil
	}(obj)

	if err != nil {
		utilruntime.HandleError(err)
		return true
	}

	return true
}

// syncHandler compares the actual state with the desired, and attempts to
// converge the two. It then updates the Status block of the Grafana
// resource with the current status of the resource.
func (m *Controller) syncHandler(key string) error {

	logger :=log.WithField("context", "Controller.syncHandler")

	// Convert the namespace/name string into a distinct namespace and name.
	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		logger.Errorf("invalid resource key: %s", key)
		return nil
	}

	//nsName := types.NamespacedName{Namespace: namespace, Name: name}

	// Get the grafana resource with this namespace/name.
	sidecar, err := m.sidecarLister.Sidecars(namespace).Get(name)
	if err != nil {
		// The Sidecar resource may no longer exist, in which case we stop processing.
		if apierrors.IsNotFound(err) {
			logger.Errorf("sidecar '%s' in work queue no longer exists", key)
			return errors.Errorf("sidecar '%s' in work queue no longer exists", key)
		}
		return err
	}

	logger.Infof("sidecar name '%s'", sidecar.Name)

	var cmName string=""
	if sidecar.Spec.DataType == "inject" {
			cmName=m.opConfig.InjectCMName
		} else if sidecar.Spec.DataType =="app" {
			cmName = m.opConfig.AppCMName
		}

 if cmName != "" {

		cm, err := m.configmapLister.ConfigMaps(sidecar.Namespace).Get(cmName)
			// If the resource doesn't exist, we'll create it
			if apierrors.IsNotFound(err) {
				logger.Infof("Creating a new ConfigMap  for datasource %s", cmName)
				cm = configmaps.NewSidecarCM(sidecar, cmName)
				err = m.configmapControl.CreateConfigMap(cm)

				// If an error occurs during Get/Create, we'll requeue the item so we can
				// attempt processing again later. This could have been caused by a
				// temporary network failure, or any other transient reason.
				if err != nil {
					return err
				}
				// If the Service is not controlled by this Datasource resource, we should
				// log a warning to the event recorder and return.
				if !metav1.IsControlledBy(cm, sidecar) {
					msg := fmt.Sprintf(MessageResourceExists, "ConfigMap", cm.Namespace, cm.Name)
					m.recorder.Event(sidecar, corev1.EventTypeWarning, ErrResourceExists, msg)
					return errors.Errorf(msg)
				}
			} else {
				logger.Infof("updated ConfigMap %s for sidecar %s", cmName, sidecar.Name )
				m.updateConfigMap(sidecar, cm)
			}
	}


/*
	//	listOptions := metav1.ListOptions{}
	defLabels :=labels.NewSelector()
//		defLabels := labels.SelectorFromSet(labels.Set{"folder": folder, })

	nsList, err := m.namespaceLister.List(defLabels)
	if err != nil {
			logger.Infof("ignoring processing namespace list ")
				return err
	}

	for _, ns := range nsList {
		logger.Infof(" namespace name %s ", ns.Name)

		podList, perr := m.podLister.Pods(ns.Name).List(defLabels)
		if perr != nil {
				glog.Infof("ignoring processing pod list ")
					return perr
		}
		for _, pod := range podList {
			logger.Infof(" pod name %s ", pod.Name)
		}
	}
*/


	m.recorder.Event(sidecar, corev1.EventTypeNormal, SuccessSynced, MessageResourceSynced)

	return nil
}


func (m *Controller) updateConfigMap(sidecar *v1alpha1.Sidecar, cm *corev1.ConfigMap  )  {

	logger :=log.WithField("context", "Controller.updateConfigMap")

	//	listOptions := metav1.ListOptions{}
	defLabels :=labels.NewSelector()

	scList, err := m.sidecarLister.Sidecars(sidecar.Namespace).List(defLabels)
	if err != nil {
		logger.Errorf("Can not find sidecar list at '%s'  ", sidecar.Namespace)
		return
	}
	var data map[string]string =cm.Data
	if data == nil {
		data =make(map[string]string)
	}
	for _, sc := range scList {
		logger.Infof(" sidecar %s", sc.Name)
		if sc.Spec.Data != nil && len(sc.Spec.Data)>0 {
				for k,v :=range sc.Spec.Data {
					data[k]=v
				}
			}
		}
		cm.Data=data
		m.kubeClient.CoreV1().ConfigMaps(cm.Namespace).Update(cm)

}
func (m *Controller) deleteSidecar(sidecar *v1alpha1.Sidecar)  {

	logger :=log.WithField("context", "Controller. deleteSidecar")
	logger.Infof("Deleting sidecar '%s'", sidecar.Name)

	var cmName string=""
	if sidecar.Spec.DataType == "inject" {
			cmName=m.opConfig.InjectCMName
		} else if sidecar.Spec.DataType =="app" {
			cmName = m.opConfig.AppCMName
		}

 if cmName != "" {
	 cm, _ := m.configmapLister.ConfigMaps(sidecar.Namespace).Get(cmName)

	 if cm != nil  {

		 var data map[string]string =cm.Data
		 if data != nil {
			if sidecar.Spec.Data != nil && len(sidecar.Spec.Data)>0 {
					for k,_ :=range sidecar.Spec.Data {
						_, ok := data[k];
				    if ok {
				        delete(data, k);
				    }
					}
				}
			}

		cm.Data=data
		m.kubeClient.CoreV1().ConfigMaps(cm.Namespace).Update(cm)
	}
 }
}


// enqueueGrafana takes a Grafana resource and converts it into a
// namespace/name string which is then put onto the work queue. This method
// should *not* be passed resources of any type other than Grafana.
func (m *Controller) enqueueSidecar(obj interface{}) {
	key, err := cache.MetaNamespaceKeyFunc(obj)
	if err != nil {
		utilruntime.HandleError(err)
		return
	}
	m.queue.AddRateLimited(key)
}


func (m *Controller) onSidecarReady(sidecarName string) {
	log.WithField("context", "Controller.onSidecarReady").Infof("Sidecar %s ready", sidecarName)
}

func (m *Controller) onSidecarDeleted(sidecar *v1alpha1.Sidecar) {
	log.WithField("context", "Controller.onSidecarDeleted").Infof("Sidecar %s deleted", sidecar.Name)
	m.deleteSidecar(sidecar)
}

// handleObject will take any resource implementing metav1.Object and attempt
// to find the Resource that 'owns' it. It does this by looking at the
// objects metadata.ownerReferences field for an appropriate OwnerReference.
// It then enqueues that Grafana resource to be processed. If the object does not
// have an appropriate OwnerReference, it will simply be skipped.
func (m *Controller) handleObject(obj interface{}) {

	logger :=log.WithField("context", "Controller.handleObject")

	object, ok := obj.(metav1.Object)
	if !ok {
		tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			utilruntime.HandleError(fmt.Errorf("error decoding object, invalid type"))
			return
		}
		object, ok = tombstone.Obj.(metav1.Object)
		if !ok {
			utilruntime.HandleError(fmt.Errorf("error decoding object tombstone, invalid type"))
			return
		}
		logger.Infof("Recovered deleted object '%s' from tombstone", object.GetName())
	}

	logger.Infof("Processing object: %s", object.GetName())
	if ownerRef := metav1.GetControllerOf(object); ownerRef != nil {
		// If this object is not owned by a Grafana, we should not do
		// anything more with it.
		if ownerRef.Kind != v1alpha1.SidecarCRDResourceKind {
			return
		}

		sidecar, err := m.sidecarLister.Sidecars(object.GetNamespace()).Get(ownerRef.Name)
		if err != nil {
			logger.Infof("ignoring orphaned object '%s' of Grafana '%s'", object.GetSelfLink(), ownerRef.Name)
			return
		}

		m.enqueueSidecar(sidecar)
		return
	}
}
