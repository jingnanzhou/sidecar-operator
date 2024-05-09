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

package options

import (
	"os"
	"time"
	"github.com/golang/glog"
	"github.com/spf13/pflag"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// OperatorOpts holds the options for the Operator.
type OperatorOpts struct {
	// KubeConfig is the path to a kubeconfig file, specifying how to connect to
	// the API server.
	KubeConfig string `yaml:"kubeconfig"`

	// Master is the address of the Kubernetes API server (overrides any value
	// in kubeconfig).
	Master string `yaml:"master"`


	InjectCMName string `yaml:"injectCMName"`
	AppCMName string `yaml:"appCMName"`

	InjectionName string `yaml:"injectionName"`

	// Namespace is the (optional) namespace in which the Rocketmq operator will
	// manage Rocketmq Clusters. Defaults to metav1.NamespaceAll.
	Namespace string `yaml:"namespace"`

	// Hostname of the pod the operator is running in.
	Hostname string `yaml:"hostname"`

	// minResyncPeriod is the resync period in reflectors; will be random
	// between minResyncPeriod and 2*minResyncPeriod.
	MinResyncPeriod metav1.Duration `yaml:"minResyncPeriod"`
}

// NewOperatorOpts will create a new OperatorOpts. If a valid
// config file is specified and exists, it will be used to initialise the
// OperatorOpts. Otherwise, a default OperatorOpts will be created.
//
// The values specified by either default may later be customised and overidden
// by user specified commandline parameters.
func NewOperatorOpts(kubeConfig string, masterURL string, injectCMName string, appCMName string, injectionName string ) (*OperatorOpts, error) {
	config := OperatorOpts{
		KubeConfig: kubeConfig,
		Master: masterURL,
		InjectCMName: injectCMName,
		AppCMName: appCMName,
		InjectionName: injectionName,
	}

	config.EnsureDefaults()
	return &config, nil
}

// EnsureDefaults provides a default configuration when required values have
// not been set.
func (s *OperatorOpts) EnsureDefaults() {
	if s.Hostname == "" {
		hostname, err := os.Hostname()
		if err != nil {
			glog.Fatalf("Failed to get the hostname: %v", err)
		}
		s.Hostname = hostname
	}
	if s.MinResyncPeriod.Duration <= 0 {
		s.MinResyncPeriod = metav1.Duration{Duration: 12 * time.Hour}
	}
}

// AddFlags adds the operator flags to a given FlagSet.
func (s *OperatorOpts) AddFlags(fs *pflag.FlagSet) *pflag.FlagSet {

	fs.StringVar(&s.KubeConfig, "kubeconfig", s.KubeConfig, "Path to Kubeconfig file with authorization and master location information.")
	fs.StringVar(&s.Master, "master", s.Master, "The address of the Kubernetes API server (overrides any value in kubeconfig).")
	fs.StringVar(&s.InjectCMName, "injectCMName", s.InjectCMName, "sidecar configuration")
	fs.StringVar(&s.AppCMName, "appCMName", s.AppCMName, "app config")
	fs.StringVar(&s.InjectionName, "injectionName", s.InjectionName, "Injection Name")

	fs.StringVar(&s.Namespace, "namespace", metav1.NamespaceAll, "The namespace for which the operator manages Rocketmq clusters. Defaults to all.")
	fs.DurationVar(&s.MinResyncPeriod.Duration, "min-resync-period", s.MinResyncPeriod.Duration, "The resync period in reflectors will be random between MinResyncPeriod and 2*MinResyncPeriod.")
	return fs
}
