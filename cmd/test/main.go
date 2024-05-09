package main

import (
	"os"
	"time"
//	"os/signal"
//	"syscall"

	"github.com/spf13/cobra"
	"github.com/sirupsen/logrus"
	"istio.io/pkg/probe"

	"github.com/jingnanzhou/sidecar-operator/cmd/test/whclient"

)

var (

  params = struct {
  	masterURL  string
  	kubeconfig string

		appConfig          string
		injectConfigFile    string
		injectValuesFile    string
		certFile            string
		privateKeyFile      string
		caCertFile          string
		port                int
		healthCheckInterval time.Duration
		healthCheckFile     string
		probeOptions        probe.Options
		kubeconfigFile      string
		webhookConfigName   string
		webhookName         string
		monitoringPort      int

} {}

	log = logrus.StandardLogger()

	rootCmd = &cobra.Command {
		Use:          "whtest",
		Short:        "test for webhook",
		Long:         "test for wenhook",
		SilenceUsage: true,
		FParseErrWhitelist: cobra.FParseErrWhitelist{
			// Allow unknown flags for backward-compatibility.
			UnknownFlags: true,
		},
	}

	testCmd = &cobra.Command{
		Use:   "test",
		Short: "test inject",
		FParseErrWhitelist: cobra.FParseErrWhitelist{
			// Allow unknown flags for backward-compatibility.
			UnknownFlags: true,
		},

		RunE: func(c *cobra.Command, args []string) error {
			log.WithField("context", "main.testCmd").Infof(" start test wioth kubeconfig= %s", params.kubeconfig)
			whclient.RunClient(params.kubeconfig, params.masterURL, params.injectConfigFile, params.injectValuesFile, params.appConfig)
			return nil
		},
	}

)


func main(){

  if err := rootCmd.Execute(); err != nil {
		log.WithField("context", "main").Errorf( "error reading config: %v\n", err)
		os.Exit(1)
	}
}


func init() {
	rootCmd.PersistentFlags().StringVar(&params.kubeconfig, "kubeconfig", "", "Path to a kubeconfig. Only required if out-of-cluster.")
	log.WithField("context", "main.init").Infof(" provided kubeconfig %v \n", params.kubeconfig)
	rootCmd.PersistentFlags().StringVar(&params.masterURL, "master", "", "The address of the Kubernetes API server. Overrides any value in kubeconfig. Only required if out-of-cluster.")
	rootCmd.PersistentFlags().StringVar(&params.appConfig, "appConfig", "/data/etc/sidecar/app/mesh", "File containing the application configuration")

	rootCmd.PersistentFlags().StringVar(&params.injectConfigFile, "injectConfig", "/data/etc/sidecar/inject/config",
		"File containing the sidecar injection configuration and template")
	rootCmd.PersistentFlags().StringVar(&params.injectValuesFile, "injectValues", "/data/etc/sidecar/inject/values",
		"File containing the sidecar injection values, in yaml format")

	rootCmd.AddCommand(testCmd)

}
