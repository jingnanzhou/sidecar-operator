package webhook


import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"k8s.io/client-go/kubernetes"

	"github.com/ghodss/yaml"
	"github.com/howeyc/fsnotify"

	"k8s.io/api/admission/v1beta1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"

  admissionregistrationv1beta1 "k8s.io/api/admissionregistration/v1beta1"

	"istio.io/istio/pilot/cmd/pilot-agent/status"
	"istio.io/api/annotation"
	"istio.io/istio/pilot/cmd"
	meshconfig "istio.io/api/mesh/v1alpha1"

)

var (
	runtimeScheme = runtime.NewScheme()
	codecs        = serializer.NewCodecFactory(runtimeScheme)
	deserializer  = codecs.UniversalDeserializer()

	// (https://github.com/kubernetes/kubernetes/issues/57982)
	defaulter = runtime.ObjectDefaulter(runtimeScheme)
)

const (
	admissionWebhookAnnotationInjectKey = "sidecar-injector-webhook.morven.me/inject"
	admissionWebhookAnnotationStatusKey = "sidecar-injector-webhook.morven.me/status"
)


const (
	watchDebounceDelay = 100 * time.Millisecond
)

var (
	legacyInitContainerNames = []string{"istio-init", "enable-core-dump"}
	legacyContainerNames     = []string{"istio-proxy"}
	legacyVolumeNames        = []string{"istio-certs", "istio-envoy"}
)


type patchOperation struct {
	Op    string      `json:"op"`
	Path  string      `json:"path"`
	Value interface{} `json:"value,omitempty"`
}

func init() {
	_ = corev1.AddToScheme(runtimeScheme)
	_ = admissionregistrationv1beta1.AddToScheme(runtimeScheme)
	_ = v1beta1.AddToScheme(runtimeScheme)

	// defaulting with webhooks:
	// https://github.com/kubernetes/kubernetes/issues/57982
//	_ = v1.AddToScheme(runtimeScheme)
}



type WebhookParameters struct {

	// ConfigFile is the path to the sidecar injection configuration file.
	ConfigFile string

	ValuesFile string

	// MeshFile is the path to the mesh configuration file.
	AppFile string

	// CertFile is the path to the x509 certificate for https.
	CertFile string

	// KeyFile is the path to the x509 private key matching `CertFile`.
	KeyFile string

	// Port is the webhook port, e.g. typically 443 for https.
	Port int

	// MonitoringPort is the webhook port, e.g. typically 15014.
	MonitoringPort int

	// HealthCheckInterval configures how frequently the health check
	// file is updated. Value of zero disables the health check
	// update.
	HealthCheckInterval time.Duration

	// HealthCheckFile specifies the path to the health check file
	// that is periodically updated.
	HealthCheckFile string
}




// Webhook implements a mutating webhook for automatic proxy injection.
type WebhookServer struct {
	mu                     sync.RWMutex
	sidecarConfig          *Config
	sidecarTemplateVersion string

	appConfig             *meshconfig.MeshConfig

	valuesConfig           string

	healthCheckInterval time.Duration
	healthCheckFile     string

	server     *http.Server
	port      int

	appFile   string
	configFile string
	valuesFile string

	watcher    *fsnotify.Watcher
	certFile   string
	keyFile    string
	cert       *tls.Certificate
//	mon        *monitor
}








// (https://github.com/kubernetes/kubernetes/issues/57982)
func applyDefaultsWorkaround(containers []corev1.Container, volumes []corev1.Volume) {
	defaulter.Default(&corev1.Pod {
		Spec: corev1.PodSpec {
			Containers:     containers,
			Volumes:        volumes,
		},
	})
}



/*
// Webhook implements a mutating webhook for automatic proxy injection.
type WebhookServer struct {
	mu                     sync.RWMutex
	sidecarCfgDir						string
	sidecarCfgFile					string
	sidecarCfgValue					string

  sidecarConfig    *SidecarConfig
	server           *http.Server

//	valuesConfig           string

//	healthCheckInterval time.Duration
//	healthCheckFile     string

//	meshFile   string
//	configFile string
//	valuesFile string
	watcher    *fsnotify.Watcher
//	certFile   string
//	keyFile    string
//	cert       *tls.Certificate
//	mon        *monitor
}

*/

// NewWebhook creates a new instance of a mutating webhook for automatic sidecar injection.

func NewWebhookServer(p WebhookParameters) (*WebhookServer, error) {

//  logger :=log.WithField("context", "NewWebhookServer")

/*
  pair, err := tls.LoadX509KeyPair(p.CertFile, p.KeyFile)
  if err != nil {
    logger.Errorf("Filed to load key pair: %v", err)
		return nil, err
  }

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}
	if err := watcher.Watch(p.ConfigDir); err != nil {
			return nil, fmt.Errorf("could not watch %v: %v", p.ConfigDir, err)
	}

	var sidecarPath string = p.ConfigDir+"/"+p.ConfigFile
	var sidecarConfig *SidecarConfig

	if _, err := os.Stat(sidecarPath); !os.IsNotExist(err) {

		logger.Infof("config file exists, run loadConfig: %s",  sidecarPath)

		sidecarConfig, _ = loadConfig(p.ConfigFile)
	}


  whsvr := &WebhookServer {

		sidecarConfig:          sidecarConfig,
//		sidecarTemplateVersion: sidecarTemplateVersionHash(sidecarConfig.Template),
//		meshConfig:             meshConfig,
		configFile:             p.ConfigFile,
		valuesFile:             p.ValuesFile,
//		valuesConfig:           valuesConfig,
		appFile:               p.AppFile,
		watcher:                watcher,
		healthCheckInterval:    p.HealthCheckInterval,
		healthCheckFile:        p.HealthCheckFile,
		certFile:               p.CertFile,
		keyFile:                p.KeyFile,
//		cert:                   &pair,


    port:     p.Port,
    server:           &http.Server {
      Addr:        fmt.Sprintf(":%v", p.Port),
      TLSConfig:   &tls.Config{Certificates: []tls.Certificate{pair}},
    },

  }

  // define http server and server handler
  mux := http.NewServeMux()
  mux.HandleFunc("/mutate", whsvr.serve)
  whsvr.server.Handler = mux

return whsvr, nil
*/


	sidecarConfig, appConfig, valuesConfig, err := loadConfig(p.ConfigFile, p.AppFile, p.ValuesFile)
	if err != nil {
		return nil, err
	}

	pair, err := tls.LoadX509KeyPair(p.CertFile, p.KeyFile)
	if err != nil {
		return nil, err
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}
	// watch the parent directory of the target files so we can catch
	// symlink updates of k8s ConfigMaps volumes.
	for _, file := range []string{p.ConfigFile, p.ValuesFile, p.AppFile, p.CertFile, p.KeyFile} {
		watchDir, _ := filepath.Split(file)
		if _, errf := os.Stat(watchDir); !os.IsNotExist(errf) {
			if err := watcher.Watch(watchDir); err != nil {
				return nil, fmt.Errorf("could not watch %v: %v", file, err)
			}
		}
	}


  whsvr := &WebhookServer {
		sidecarConfig:          sidecarConfig,
		sidecarTemplateVersion: sidecarTemplateVersionHash(sidecarConfig.Template),
		appConfig:             appConfig,
		configFile:             p.ConfigFile,
		valuesFile:             p.ValuesFile,
		valuesConfig:           valuesConfig,
		appFile:               p.AppFile,
		watcher:                watcher,
		healthCheckInterval:    p.HealthCheckInterval,
		healthCheckFile:        p.HealthCheckFile,
		certFile:               p.CertFile,
		keyFile:                p.KeyFile,
		cert:                   &pair,
    port:     							p.Port,
    server:           &http.Server {
      Addr:        fmt.Sprintf(":%v", p.Port),
    },

  }


	// mtls disabled because apiserver webhook cert usage is still TBD.
	whsvr.server.TLSConfig = &tls.Config{GetCertificate: whsvr.getCert}
	h := http.NewServeMux()
	h.HandleFunc("/inject", whsvr.serveInject)
//	h.HandleFunc("/inject", whsvr.serve)

/*
	mon, err := startMonitor(h, p.MonitoringPort)
	if err != nil {
		return nil, fmt.Errorf("could not start monitoring server %v", err)
	}
	whsvr.mon = mon
*/
	whsvr.server.Handler = h

	return whsvr, nil

}


// Run implements the webhook server
func (whsvr *WebhookServer) Run(stop <-chan struct{}) {

  logger := log.WithField("context", "WebhookServer.Run")
/*
  // start webhook server in new rountine
  go func() {
    logger.Infof("Start Webhook server at port %v", whsvr.port)
		if err := whsvr.server.ListenAndServeTLS("", ""); err != nil {
			logger.Errorf("failed to listen and serve webhook server: %v", err)
		}
  }()


	// Process events
	go func() {
		for {
			select {
			case event := <-whsvr.watcher.Event:
						// use a timer to debounce configuration updates
						if event.IsModify() || event.IsCreate() {

							var sidecarPath string = whsvr.sidecarCfgDir+"/"+whsvr.sidecarCfgFile
							if _, err := os.Stat(sidecarPath); !os.IsNotExist(err) {

							logger.Infof("Watcher notified for loadConfig: %s",  sidecarPath)

							  whsvr.sidecarConfig, _= loadConfig(sidecarPath)
							}
						}
					case err := <-whsvr.watcher.Error:
						logger.Errorf("Watcher error: %v", err)
			}
		}
	}()


	*/


	go func() {
		logger.Infof("Start Webhook server at port %v", whsvr.port)
		if err := whsvr.server.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			logger.Fatalf("admission webhook ListenAndServeTLS failed: %v", err)
		}
	}()

	defer whsvr.watcher.Close()
	defer whsvr.server.Close()
//	defer whsvr.mon.monitoringServer.Close()

	var healthC <-chan time.Time

	if whsvr.healthCheckInterval != 0 && whsvr.healthCheckFile != "" {
		t := time.NewTicker(whsvr.healthCheckInterval)
		healthC = t.C
		defer t.Stop()
	}
	var timerC <-chan time.Time

	for {
		select {
		case <-timerC:
			timerC = nil
			sidecarConfig, appConfig, valuesConfig, err := loadConfig(whsvr.configFile, whsvr.appFile, whsvr.valuesFile)
			if err != nil {
				log.Errorf("update error: %v", err)
				break
			}

			version := sidecarTemplateVersionHash(sidecarConfig.Template)
			pair, err := tls.LoadX509KeyPair(whsvr.certFile, whsvr.keyFile)
			if err != nil {
				log.Errorf("reload cert error: %v", err)
				break
			}
			whsvr.mu.Lock()
			whsvr.sidecarConfig = sidecarConfig
			whsvr.valuesConfig = valuesConfig
			whsvr.sidecarTemplateVersion = version
			whsvr.appConfig = appConfig
			whsvr.cert = &pair
			whsvr.mu.Unlock()
		case event := <-whsvr.watcher.Event:
			// use a timer to debounce configuration updates
			if (event.IsModify() || event.IsCreate()) && timerC == nil {
				timerC = time.After(watchDebounceDelay)
			}
		case err := <-whsvr.watcher.Error:
			logger.Errorf("Watcher error: %v", err)
		case <-healthC:
			content := []byte(`ok`)
			if err := ioutil.WriteFile(whsvr.healthCheckFile, content, 0644); err != nil {
				logger.Errorf("Health check update of %q failed: %v", whsvr.healthCheckFile, err)
			}
		case <-stop:
			return
		}
	}

}

func (whsvr *WebhookServer) getCert(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	whsvr.mu.Lock()
	defer whsvr.mu.Unlock()
	return whsvr.cert, nil
}


func (whsvr *WebhookServer) inject(ar *v1beta1.AdmissionReview) *v1beta1.AdmissionResponse {

	logger := log.WithField("context", "WebhookServer.inject")

	req := ar.Request
	var pod corev1.Pod
	if err := json.Unmarshal(req.Object.Raw, &pod); err != nil {
		handleError("WebhookServer.inject", fmt.Sprintf("Could not unmarshal raw object: %v %s", err,
			string(req.Object.Raw)))
		return toAdmissionResponse(err)
	}

	// Deal with potential empty fields, e.g., when the pod is created by a deployment
	podName := potentialPodName(&pod.ObjectMeta)
	if pod.ObjectMeta.Namespace == "" {
		pod.ObjectMeta.Namespace = req.Namespace
	}

	logger.Infof("AdmissionReview for Kind=%v Namespace=%v Name=%v (%v) UID=%v Rfc6902PatchOperation=%v UserInfo=%v",
		req.Kind, req.Namespace, req.Name, podName, req.UID, req.Operation, req.UserInfo)
	logger.Debugf("Object: %v", string(req.Object.Raw))
	logger.Debugf("OldObject: %v", string(req.OldObject.Raw))

	if !injectRequired(ignoredNamespaces, whsvr.sidecarConfig, &pod.Spec, &pod.ObjectMeta) {
		logger.Infof("Skipping %s/%s due to policy check", pod.ObjectMeta.Namespace, podName)
		totalSkippedInjections.Increment()
		return &v1beta1.AdmissionResponse{
			Allowed: true,
		}
	}

	// due to bug https://github.com/kubernetes/kubernetes/issues/57923,
	// k8s sa jwt token volume mount file is only accessible to root user, not istio-proxy(the user that istio proxy runs as).
	// workaround by https://kubernetes.io/docs/tasks/configure-pod-container/security-context/#set-the-security-context-for-a-pod
	if whsvr.appConfig != nil &&  whsvr.appConfig.SdsUdsPath != "" {
		var grp = int64(1337)
		pod.Spec.SecurityContext = &corev1.PodSecurityContext{
			FSGroup: &grp,
		}
	}

	// try to capture more useful namespace/name info for deployments, etc.
	// TODO(dougreid): expand to enable lookup of OWNERs recursively a la kubernetesenv
	deployMeta := pod.ObjectMeta.DeepCopy()
	deployMeta.Namespace = req.Namespace

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
	
	var proxyConfig *meshconfig.ProxyConfig=&meshconfig.ProxyConfig{}

	if whsvr.appConfig != nil {
		proxyConfig=whsvr.appConfig.DefaultConfig
	}
	spec, iStatus, err := InjectionData(whsvr.sidecarConfig.Template, whsvr.valuesConfig, whsvr.sidecarTemplateVersion, typeMetadata, deployMeta, &pod.Spec, &pod.ObjectMeta, proxyConfig, whsvr.appConfig) // nolint: lll
	if err != nil {
		handleError("WebhookServer.inject", fmt.Sprintf("Injection data: err=%v spec=%v\n", err, iStatus))
		return toAdmissionResponse(err)
	}

	annotations := map[string]string{annotation.SidecarStatus.Name: iStatus}

	patchBytes, err := createPatch(&pod, injectionStatus(&pod), annotations, spec)
	if err != nil {
		handleError("WebhookServer.inject", fmt.Sprintf("AdmissionResponse: err=%v spec=%v\n", err, spec))
		return toAdmissionResponse(err)
	}

	log.Infof("AdmissionResponse: patch=%v\n", string(patchBytes))

	reviewResponse := v1beta1.AdmissionResponse{
		Allowed: true,
		Patch:   patchBytes,
		PatchType: func() *v1beta1.PatchType {
			pt := v1beta1.PatchTypeJSONPatch
			return &pt
		}(),
	}
	totalSuccessfulInjections.Increment()
	return &reviewResponse
}

func (whsvr *WebhookServer) serveInject(w http.ResponseWriter, r *http.Request) {

	logger := log.WithField("context", "WebhookServer.serveInject")

	totalInjections.Increment()
	var body []byte
	if r.Body != nil {
		if data, err := ioutil.ReadAll(r.Body); err == nil {
			body = data
		}
	}
	if len(body) == 0 {
		handleError("WebhookServer.serveInject", "no body found")
		http.Error(w, "no body found", http.StatusBadRequest)
		return
	}

	// verify the content type is accurate
	contentType := r.Header.Get("Content-Type")
	if contentType != "application/json" {
		handleError("WebhookServer.serveInject", fmt.Sprintf("contentType=%s, expect application/json", contentType))
		http.Error(w, "invalid Content-Type, want `application/json`", http.StatusUnsupportedMediaType)
		return
	}

	var reviewResponse *v1beta1.AdmissionResponse
	ar := v1beta1.AdmissionReview{}
	if _, _, err := deserializer.Decode(body, nil, &ar); err != nil {
		handleError("WebhookServer.serveInject", fmt.Sprintf("Could not decode body: %v", err))
		reviewResponse = toAdmissionResponse(err)
	} else {
		reviewResponse = whsvr.inject(&ar)
	}

	response := v1beta1.AdmissionReview{}
	if reviewResponse != nil {
		response.Response = reviewResponse
		if ar.Request != nil {
			response.Response.UID = ar.Request.UID
		}
	}

	resp, err := json.Marshal(response)
	if err != nil {
		logger.Errorf("Could not encode response: %v", err)
		http.Error(w, fmt.Sprintf("could not encode response: %v", err), http.StatusInternalServerError)
	}
	if _, err := w.Write(resp); err != nil {
		logger.Errorf("Could not write response: %v", err)
		http.Error(w, fmt.Sprintf("could not write response: %v", err), http.StatusInternalServerError)
	}
}

func handleError(fName string, message string) {
	log.WithField("context", fName).Errorf(message)
	totalFailedInjections.Increment()
}

func toAdmissionResponse(err error) *v1beta1.AdmissionResponse {
	return &v1beta1.AdmissionResponse{Result: &metav1.Status{Message: err.Error()}}
}

func injectionStatus(pod *corev1.Pod) *SidecarInjectionStatus {
	var statusBytes []byte
	if pod.ObjectMeta.Annotations != nil {
		if value, ok := pod.ObjectMeta.Annotations[annotation.SidecarStatus.Name]; ok {
			statusBytes = []byte(value)
		}
	}

	// default case when injected pod has explicit status
	var iStatus SidecarInjectionStatus
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
	return &SidecarInjectionStatus{
		InitContainers: legacyInitContainerNames,
		Containers:     legacyContainerNames,
		Volumes:        legacyVolumeNames,
	}
}

// JSONPatch `remove` is applied sequentially. Remove items in reverse
// order to avoid renumbering indices.
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

func addSecurityContext(target *corev1.PodSecurityContext, basePath string) (patch []rfc6902PatchOperation) {
	patch = append(patch, rfc6902PatchOperation{
		Op:    "add",
		Path:  basePath,
		Value: target,
	})
	return patch
}

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



func createPatch(pod *corev1.Pod, prevStatus *SidecarInjectionStatus, annotations map[string]string, sic *SidecarInjectionSpec) ([]byte, error) {
	var patch []rfc6902PatchOperation

	logger :=log.WithField("context", "webhook.createPatch")

	logger.Infof(" sidecar injection spec %v", sic.Containers)

	// Remove any containers previously injected by kube-inject using
	// container and volume name as unique key for removal.
	patch = append(patch, removeContainers(pod.Spec.InitContainers, prevStatus.InitContainers, "/spec/initContainers")...)
	patch = append(patch, removeContainers(pod.Spec.Containers, prevStatus.Containers, "/spec/containers")...)
	patch = append(patch, removeVolumes(pod.Spec.Volumes, prevStatus.Volumes, "/spec/volumes")...)
	patch = append(patch, removeImagePullSecrets(pod.Spec.ImagePullSecrets, prevStatus.ImagePullSecrets, "/spec/imagePullSecrets")...)

	rewrite := ShouldRewriteAppHTTPProbers(pod.Annotations, sic)
	addAppProberCmd := func() {
		if !rewrite {
			return
		}
		sidecar := FindSidecar(sic.Containers)
		if sidecar == nil {
			logger.Errorf("sidecar not found in the template, skip addAppProberCmd")
			return
		}
		// We don't have to escape json encoding here when using golang libraries.
		if prober := DumpAppProbers(&pod.Spec); prober != "" {
			sidecar.Env = append(sidecar.Env, corev1.EnvVar{Name: status.KubeAppProberEnvName, Value: prober})
		}
	}
	addAppProberCmd()

	patch = append(patch, addContainer(pod.Spec.InitContainers, sic.InitContainers, "/spec/initContainers")...)
	patch = append(patch, addContainer(pod.Spec.Containers, sic.Containers, "/spec/containers")...)
	patch = append(patch, addVolume(pod.Spec.Volumes, sic.Volumes, "/spec/volumes")...)
	patch = append(patch, addImagePullSecrets(pod.Spec.ImagePullSecrets, sic.ImagePullSecrets, "/spec/imagePullSecrets")...)

	if sic.DNSConfig != nil {
		patch = append(patch, addPodDNSConfig(sic.DNSConfig, "/spec/dnsConfig")...)
	}

	if pod.Spec.SecurityContext != nil {
		patch = append(patch, addSecurityContext(pod.Spec.SecurityContext, "/spec/securityContext")...)
	}

	patch = append(patch, updateAnnotation(pod.Annotations, annotations)...)

	if rewrite {
		patch = append(patch, createProbeRewritePatch(pod.Annotations, &pod.Spec, sic)...)
	}

	return json.Marshal(patch)
}


func TestInject(kubeClient kubernetes.Interface, configFile string, valuesFile string, meshFile string, ns *corev1.Namespace, pod *corev1.Pod )  {

	logger :=log.WithField("context", "webhook.TestInject")

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
	if meshConfig !=nil && meshConfig.SdsUdsPath != "" {
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

	var proxyConfig *meshconfig.ProxyConfig=&meshconfig.ProxyConfig{}

	if meshConfig != nil {
		proxyConfig=meshConfig.DefaultConfig
	}

	spec, iStatus, err := InjectionData(sidecarConfig.Template, valuesConfig, sidecarTemplateVersion, typeMetadata, deployMeta, &pod.Spec, &pod.ObjectMeta, proxyConfig, meshConfig) // nolint: lll


	if err != nil {
		logger.Errorf("Injection data: err=%v spec=%v\n", err, iStatus)
	}

	annotations := map[string]string{annotation.SidecarStatus.Name: iStatus}


	patchBytes, err := createPatch(pod, injectionStatus(pod), annotations, spec)
	if err != nil {
		logger.Errorf("AdmissionResponse: err=%v spec=%v\n", err, spec)
		return
	}

	log.Infof("AdmissionResponse: patch=%v\n", string(patchBytes))


/*
	deletePolicy := metav1.DeletePropagationForeground
	if err := kubeClient.CoreV1().Pods(patched.Namespace).Delete(patched.Name, &metav1.DeleteOptions{
		PropagationPolicy: &deletePolicy,
	}); err != nil {
		logger.Errorf( "failed to update pod, %v", err)
		return
	}
*/


}





/*

// Serve method for webhook server
func (whsvr *WebhookServer) serve(w http.ResponseWriter, r *http.Request) {

	logger := log.WithField("context", "WebhookServer.serve")
	var body []byte
	if r.Body != nil {
		if data, err := ioutil.ReadAll(r.Body); err == nil {
			body = data
		}
	}
	if len(body) == 0 {
		logger.Error("empty body")
		http.Error(w, "empty body", http.StatusBadRequest)
		return
	}

	// verify the content type is accurate
	contentType := r.Header.Get("Content-Type")
	if contentType != "application/json" {
		logger.Errorf("Content-Type=%s, expect application/json", contentType)
		http.Error(w, "invalid Content-Type, expect `application/json`", http.StatusUnsupportedMediaType)
		return
	}

	var admissionResponse *v1beta1.AdmissionResponse
	ar := v1beta1.AdmissionReview{}
	if _, _, err := deserializer.Decode(body, nil, &ar); err != nil {
		logger.Errorf("Can't decode body: %v", err)
		admissionResponse = &v1beta1.AdmissionResponse {
			Result: &metav1.Status {
				Message: err.Error(),
			},
		}
	} else {
		admissionResponse = whsvr.mutate(&ar)
	}

	admissionReview := v1beta1.AdmissionReview{}
	if admissionResponse != nil {
		admissionReview.Response = admissionResponse
		if ar.Request != nil {
			admissionReview.Response.UID = ar.Request.UID
		}
	}

	resp, err := json.Marshal(admissionReview)
	if err != nil {
		logger.Errorf("Can't encode response: %v", err)
		http.Error(w, fmt.Sprintf("could not encode response: %v", err), http.StatusInternalServerError)
	}
	logger.Infof("Ready to write reponse ...")
	if _, err := w.Write(resp); err != nil {
		logger.Errorf("Can't write response: %v", err)
		http.Error(w, fmt.Sprintf("could not write response: %v", err), http.StatusInternalServerError)
	}
}
// main mutation process
func (whsvr *WebhookServer) mutate(ar *v1beta1.AdmissionReview) *v1beta1.AdmissionResponse {

	logger := log.WithField("context", "WebhookServer.mutate")

	req := ar.Request
	var pod corev1.Pod
	if err := json.Unmarshal(req.Object.Raw, &pod); err != nil {
		logger.Errorf("Could not unmarshal raw object: %v", err)
		return &v1beta1.AdmissionResponse {
			Result: &metav1.Status {
				Message: err.Error(),
			},
		}
	}

	logger.Infof("AdmissionReview for Kind=%v, Namespace=%v Name=%v (%v) UID=%v patchOperation=%v UserInfo=%v",
	req.Kind, req.Namespace, req.Name, pod.Name, req.UID, req.Operation, req.UserInfo)

if whsvr.sidecarConfig == nil {

  var errMsg string = "sidecar configuration is not available"
  logger.Errorf(errMsg)
  return &v1beta1.AdmissionResponse {
    Allowed: true,
    Result: &metav1.Status {
      Message: errMsg,
    },
  }
}



	// determine whether to perform mutation
	if !mutationRequired(ignoredNamespaces, &pod.ObjectMeta) {
		logger.Infof("Skipping mutation for %s/%s due to policy check", pod.Namespace, pod.Name)
		return &v1beta1.AdmissionResponse {
			Allowed: true,
		}
	}

	// Workaround: https://github.com/kubernetes/kubernetes/issues/57982
	applyDefaultsWorkaround(whsvr.sidecarConfig.Containers, whsvr.sidecarConfig.Volumes)
	annotations := map[string]string{admissionWebhookAnnotationStatusKey: "injected"}
	patchBytes, err := createPatch(&pod, whsvr.sidecarConfig, annotations)
	if err != nil {
		return &v1beta1.AdmissionResponse {
			Result: &metav1.Status {
				Message: err.Error(),
			},
		}
	}

	logger.Infof("AdmissionResponse: patch=%v\n", string(patchBytes))
	return &v1beta1.AdmissionResponse {
		Allowed: true,
		Patch:   patchBytes,
		PatchType: func() *v1beta1.PatchType {
			pt := v1beta1.PatchTypeJSONPatch
			return &pt
		}(),
	}
}
*/

func loadConfig(configFile string, meshFile string, valuesFile string) (*Config, *meshconfig.MeshConfig, string, error) {

logger := log.WithField("context", "loadConfig")

var config Config
var valuesConfig string
var meshConfig *meshconfig.MeshConfig

if configFile != "" {
	if _, errf := os.Stat(configFile); !os.IsNotExist(errf) {

	 logger.Infof("loading configFile %s", configFile)

		data, err := ioutil.ReadFile(configFile)

		if err != nil {
			return nil, nil, "", err
		}
		if err := yaml.Unmarshal(data, &config); err != nil {
			logger.Errorf("Failed to parse injectFile %v", err)
			return nil, nil, "", err
		}

		logger.Infof("New configuration: sha256sum %x", sha256.Sum256(data))

		logger.Infof("Policy: %v", config.Policy)
		logger.Infof("AlwaysInjectSelector: %v", config.AlwaysInjectSelector)
		logger.Infof("NeverInjectSelector: %v", config.NeverInjectSelector)
		logger.Infof("Template: |\n  %v", strings.Replace(config.Template, "\n", "\n  ", -1))

	}
}

if valuesFile != "" {
	if _, errf := os.Stat(valuesFile); !os.IsNotExist(errf) {

		valuestr, err := ioutil.ReadFile(valuesFile)
		if err != nil {
			return nil, nil, "", err
		} else {

			valuesConfig=string(valuestr)
		}
	}
}

if meshFile != "" {
	if _, errf := os.Stat(meshFile); !os.IsNotExist(errf) {

		meshObj, err := cmd.ReadMeshConfig(meshFile)
		if err != nil {
			return nil, nil, "", err
		} else {

			meshConfig=meshObj
		}
	}
}
	return &config, meshConfig, valuesConfig, nil
}
type rfc6902PatchOperation struct {
	Op    string      `json:"op"`
	Path  string      `json:"path"`
	Value interface{} `json:"value,omitempty"`
}

/*

func loadConfig(configFile string) (*SidecarConfig, error) {
	logger := log.WithField("context", "loadConfig")

	data, err := ioutil.ReadFile(configFile)
	if err != nil {
		return nil, err
	}
	logger.Infof("New configuration: sha256sum %x", sha256.Sum256(data))

	var cfg SidecarConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}
*/

/*
// Check whether the target resoured need to be mutated
func mutationRequired(ignoredList []string, metadata *metav1.ObjectMeta) bool {

	logger := log.WithField("context", "mutationRequired")

	// skip special kubernete system namespaces
	for _, namespace := range ignoredList {
		if metadata.Namespace == namespace {
			logger.Infof("Skip mutation for %v for it' in special namespace:%v", metadata.Name, metadata.Namespace)
			return false
		}
	}

	annotations := metadata.GetAnnotations()
	if annotations == nil {
		annotations = map[string]string{}
	}

	status := annotations[admissionWebhookAnnotationStatusKey]

	// determine whether to perform mutation based on annotation for the target resource
	var required bool
	if strings.ToLower(status) == "injected" {
		required = false;
	} else {
		switch strings.ToLower(annotations[admissionWebhookAnnotationInjectKey]) {
		default:
			required = false
		case "y", "yes", "true", "on":
			required = true
		}
	}

	logger.Infof("Mutation policy for %v/%v: status: %q required:%v", metadata.Namespace, metadata.Name, status, required)
	return required
}

func addContainer(target, added []corev1.Container, basePath string) (patch []patchOperation) {
	first := len(target) == 0
	var value interface{}
	for _, add := range added {
		value = add
		path := basePath
		if first {
			first = false
			value = []corev1.Container{add}
		} else {
			path = path + "/-"
		}
		patch = append(patch, patchOperation {
			Op:    "add",
			Path:  path,
			Value: value,
		})
	}
	return patch
}

func addVolume(target, added []corev1.Volume, basePath string) (patch []patchOperation) {
	first := len(target) == 0
	var value interface{}
	for _, add := range added {
		value = add
		path := basePath
		if first {
			first = false
			value = []corev1.Volume{add}
		} else {
			path = path + "/-"
		}
		patch = append(patch, patchOperation {
			Op:    "add",
			Path:  path,
			Value: value,
		})
	}
	return patch
}

func updateAnnotation(target map[string]string, added map[string]string) (patch []patchOperation) {
	for key, value := range added {
		if target == nil || target[key] == "" {
			target = map[string]string{}
			patch = append(patch, patchOperation {
				Op:   "add",
				Path: "/metadata/annotations",
				Value: map[string]string{
					key: value,
				},
			})
		} else {
			patch = append(patch, patchOperation {
				Op:    "replace",
				Path:  "/metadata/annotations/" + key,
				Value: value,
			})
		}
	}
	return patch
}

// create mutation patch for resoures
func createPatch(pod *corev1.Pod, sidecarConfig *SidecarConfig, annotations map[string]string) ([]byte, error) {
	var patch []patchOperation

	patch = append(patch, addContainer(pod.Spec.Containers, sidecarConfig.Containers, "/spec/containers")...)
	patch = append(patch, addVolume(pod.Spec.Volumes, sidecarConfig.Volumes, "/spec/volumes")...)
	patch = append(patch, updateAnnotation(pod.Annotations, annotations)...)

	return json.Marshal(patch)
}

*/
