package sidecar

import (
	"io/ioutil"
	"strings"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"



	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	kubernetes "k8s.io/client-go/kubernetes"
//	"k8s.io/apimachinery/pkg/types"


	"github.com/ghodss/yaml"
	meshconfig "istio.io/api/mesh/v1alpha1"
	"istio.io/istio/pilot/cmd"
	inject	"istio.io/istio/pkg/kube/inject"
	"istio.io/api/annotation"


	"github.com/sirupsen/logrus"

)

const (
	// InjectionPolicyDisabled specifies that the sidecar injector
	// will not inject the sidecar into resources by default for the
	// namespace(s) being watched. Resources can enable injection
	// using the "sidecar.istio.io/inject" annotation with value of
	// true.
	InjectionPolicyDisabled inject.InjectionPolicy = "disabled"

	// InjectionPolicyEnabled specifies that the sidecar injector will
	// inject the sidecar into resources by default for the
	// namespace(s) being watched. Resources can disable injection
	// using the "sidecar.istio.io/inject" annotation with value of
	// false.
	InjectionPolicyEnabled inject.InjectionPolicy = "enabled"
)

var (
	configFile string ="/data/test/istio/inject/config"
	meshFile string = "/data/test/istio/config/mesh"
	valuesFile string ="/data/test/istio/inject/values"

	log =logrus.StandardLogger()
)
/*
func Test() {

	sidecarConfig, meshConfig, valuesConfig, err := loadConfig(configFile, meshFile, valuesFile)
}
*/



// Retain deprecated hardcoded container and volumes names to aid in
// backwards compatible migration to the new SidecarInjectionStatus.
var (
	legacyInitContainerNames = []string{"istio-init", "enable-core-dump"}
	legacyContainerNames     = []string{"istio-proxy"}
	legacyVolumeNames        = []string{"istio-certs", "istio-envoy"}
)

func injectionStatus(pod *corev1.Pod) *inject.SidecarInjectionStatus {
	var statusBytes []byte
	if pod.ObjectMeta.Annotations != nil {
		if value, ok := pod.ObjectMeta.Annotations[annotation.SidecarStatus.Name]; ok {
			statusBytes = []byte(value)
		}
	}

	// default case when injected pod has explicit status
	var iStatus inject.SidecarInjectionStatus
	if err := json.Unmarshal(statusBytes, &iStatus); err == nil {
		// heuristic assumes status is valid if any of the resource
		// lists is non-empty.
		if len(iStatus.InitContainers) != 0 ||
			len(iStatus.Containers) != 0 ||
			len(iStatus.Volumes) != 0 ||
			len(iStatus.ImagePullSecrets) != 0 {
			return &iStatus
		}
	}

	// backwards compatibility case when injected pod has legacy
	// status. Infer status from the list of legacy hardcoded
	// container and volume names.
	return &inject.SidecarInjectionStatus{
		InitContainers: legacyInitContainerNames,
		Containers:     legacyContainerNames,
		Volumes:        legacyVolumeNames,
	}
}



func potentialPodName(metadata *metav1.ObjectMeta) string {
	if metadata.Name != "" {
		return metadata.Name
	}
	if metadata.GenerateName != "" {
		return metadata.GenerateName + "***** (actual name not yet known)"
	}
	return ""
}
func sidecarTemplateVersionHash(in string) string {
	hash := sha256.Sum256([]byte(in))
	return hex.EncodeToString(hash[:])
}

func injectRequired(ignored []string, config *inject.Config, podSpec *corev1.PodSpec, metadata *metav1.ObjectMeta) bool { // nolint: lll
	// Skip injection when host networking is enabled. The problem is
	// that the iptable changes are assumed to be within the pod when,
	// in fact, they are changing the routing at the host level. This
	// often results in routing failures within a node which can
	// affect the network provider within the cluster causing
	// additional pod failures.
	if podSpec.HostNetwork {
		return false
	}

	// skip special kubernetes system namespaces
	for _, namespace := range ignored {
		if metadata.Namespace == namespace {
			return false
		}
	}

	annos := metadata.GetAnnotations()
	if annos == nil {
		annos = map[string]string{}
	}

	var useDefault bool
	var inject bool
	switch strings.ToLower(annos[annotation.SidecarInject.Name]) {
	// http://yaml.org/type/bool.html
	case "y", "yes", "true", "on":
		inject = true
	case "":
		useDefault = true
	}

	// If an annotation is not explicitly given, check the LabelSelectors, starting with NeverInject
	if useDefault {
		for _, neverSelector := range config.NeverInjectSelector {
			selector, err := metav1.LabelSelectorAsSelector(&neverSelector)
			if err != nil {
				log.Warnf("Invalid selector for NeverInjectSelector: %v (%v)", neverSelector, err)
			} else if !selector.Empty() && selector.Matches(labels.Set(metadata.Labels)) {
				log.Debugf("Explicitly disabling injection for pod %s/%s due to pod labels matching NeverInjectSelector config map entry.",
					metadata.Namespace, potentialPodName(metadata))
				inject = false
				useDefault = false
				break
			}
		}
	}

	// If there's no annotation nor a NeverInjectSelector, check the AlwaysInject one
	if useDefault {
		for _, alwaysSelector := range config.AlwaysInjectSelector {
			selector, err := metav1.LabelSelectorAsSelector(&alwaysSelector)
			if err != nil {
				log.Warnf("Invalid selector for AlwaysInjectSelector: %v (%v)", alwaysSelector, err)
			} else if !selector.Empty() && selector.Matches(labels.Set(metadata.Labels)) {
				log.Debugf("Explicitly enabling injection for pod %s/%s due to pod labels matching AlwaysInjectSelector config map entry.",
					metadata.Namespace, potentialPodName(metadata))
				inject = true
				useDefault = false
				break
			}
		}
	}

	var required bool
	switch config.Policy {
	default: // InjectionPolicyOff
		log.Errorf("Illegal value for autoInject:%s, must be one of [%s,%s]. Auto injection disabled!",
			config.Policy, InjectionPolicyDisabled, InjectionPolicyEnabled)
		required = false
	case InjectionPolicyDisabled:
		if useDefault {
			required = false
		} else {
			required = inject
		}
	case InjectionPolicyEnabled:
		if useDefault {
			required = true
		} else {
			required = inject
		}
	}
/*
	if log.DebugEnabled() {
		// Build a log message for the annotations.
		annotationStr := ""
		for name := range annotationRegistry {
			value, ok := annos[name]
			if !ok {
				value = "(unset)"
			}
			annotationStr += fmt.Sprintf("%s:%s ", name, value)
		}

		log.Debugf("Sidecar injection policy for %v/%v: namespacePolicy:%v useDefault:%v inject:%v required:%v %s",
			metadata.Namespace,
			potentialPodName(metadata),
			config.Policy,
			useDefault,
			inject,
			required,
			annotationStr)
	}
*/
	return required
}

func InjectProxy(kubeClient kubernetes.Interface, ns *corev1.Namespace, pod *corev1.Pod )  {

	logger :=log.WithField("context", "sidecar.InjectProxy")

	sidecarConfig, meshConfig, valuesConfig, err := loadConfig(configFile, meshFile, valuesFile)

	if err != nil {
		logger.Errorf("loadConfig error '%s'  ", err.Error())
		return
	}


	// Deal with potential empty fields, e.g., when the pod is created by a deployment
	podName := potentialPodName(&pod.ObjectMeta)
	if pod.ObjectMeta.Namespace == "" {
		pod.ObjectMeta.Namespace = ns.Name
	}
	logger.Info(" the podName " +podName)


	if !injectRequired(ignoredNamespaces, sidecarConfig, &pod.Spec, &pod.ObjectMeta) {
		log.Infof("Skipping %s/%s due to policy check", pod.ObjectMeta.Namespace, podName)
		return
	}

	// due to bug https://github.com/kubernetes/kubernetes/issues/57923,
	// k8s sa jwt token volume mount file is only accessible to root user, not istio-proxy(the user that istio proxy runs as).
	// workaround by https://kubernetes.io/docs/tasks/configure-pod-container/security-context/#set-the-security-context-for-a-pod
	if meshConfig.SdsUdsPath != "" {
		var grp = int64(1337)
		pod.Spec.SecurityContext = &corev1.PodSecurityContext{
			FSGroup: &grp,
		}
	}

	// try to capture more useful namespace/name info for deployments, etc.
	// TODO(dougreid): expand to enable lookup of OWNERs recursively a la kubernetesenv
	deployMeta := pod.ObjectMeta.DeepCopy()
	deployMeta.Namespace = ns.Name

	typeMetadata := &metav1.TypeMeta{
		Kind:       "Pod",
		APIVersion: "v1",
	}

	if len(pod.GenerateName) > 0 {
		// if the pod name was generated (or is scheduled for generation), we can begin an investigation into the controlling reference for the pod.
		var controllerRef metav1.OwnerReference
		controllerFound := false
		for _, ref := range pod.GetOwnerReferences() {
			if *ref.Controller {
				controllerRef = ref
				controllerFound = true
				break
			}
		}
		if controllerFound {
			typeMetadata.APIVersion = controllerRef.APIVersion
			typeMetadata.Kind = controllerRef.Kind

			// heuristic for deployment detection
			if typeMetadata.Kind == "ReplicaSet" && strings.HasSuffix(controllerRef.Name, pod.Labels["pod-template-hash"]) {
				name := strings.TrimSuffix(controllerRef.Name, "-"+pod.Labels["pod-template-hash"])
				deployMeta.Name = name
				typeMetadata.Kind = "Deployment"
			} else {
				deployMeta.Name = controllerRef.Name
			}
		}
	}

	if deployMeta.Name == "" {
		// if we haven't been able to extract a deployment name, then just give it the pod name
		deployMeta.Name = pod.Name
	}

	sidecarTemplateVersion :=sidecarTemplateVersionHash(sidecarConfig.Template)

	spec, iStatus, err := inject.InjectionData(sidecarConfig.Template, valuesConfig, sidecarTemplateVersion, typeMetadata, deployMeta, &pod.Spec, &pod.ObjectMeta, meshConfig.DefaultConfig, meshConfig) // nolint: lll


	if err != nil {
		logger.Errorf("Injection data: err=%v spec=%v\n", err, iStatus)
	}

	annotations := map[string]string{annotation.SidecarStatus.Name: iStatus}

	patched, err := createPatch( pod, injectionStatus(pod), annotations, spec)
	if err != nil {
		logger.Errorf("AdmissionResponse: err=%v spec=%v\n", err, spec)
		return
	}
	logger.Infof(" patch=%v\n", patched.Name)



	deletePolicy := metav1.DeletePropagationForeground
	if err := kubeClient.CoreV1().Pods(patched.Namespace).Delete(patched.Name, &metav1.DeleteOptions{
		PropagationPolicy: &deletePolicy,
	}); err != nil {
		logger.Errorf( "failed to update pod, %v", err)
		return

	}



/*
	result, err := kubeClient.CoreV1().Pods(patched.Namespace).Update(patched)
	if err != nil {
		logger.Errorf( "failed to update pod, %v", err)
		return
	}

	logger.Infof("patched pod %s", result.Name)
*/
}

func loadConfig(injectFile, meshFile, valuesFile string) (*inject.Config, *meshconfig.MeshConfig, string, error) {
log = logrus.StandardLogger()
	data, err := ioutil.ReadFile(injectFile)
	if err != nil {
		return nil, nil, "", err
	}
	var c inject.Config
	if err := yaml.Unmarshal(data, &c); err != nil {
		log.Warnf("Failed to parse injectFile %s", string(data))
		return nil, nil, "", err
	}

	valuesConfig, err := ioutil.ReadFile(valuesFile)
	if err != nil {
		return nil, nil, "", err
	}

	meshConfig, err := cmd.ReadMeshConfig(meshFile)
	if err != nil {
		return nil, nil, "", err
	}

	log.Infof("New configuration: sha256sum %x", sha256.Sum256(data))
	log.Infof("Policy: %v", c.Policy)
	log.Infof("AlwaysInjectSelector: %v", c.AlwaysInjectSelector)
	log.Infof("NeverInjectSelector: %v", c.NeverInjectSelector)
	log.Infof("Template: |\n  %v", strings.Replace(c.Template, "\n", "\n  ", -1))

	return &c, meshConfig, string(valuesConfig), nil
}
