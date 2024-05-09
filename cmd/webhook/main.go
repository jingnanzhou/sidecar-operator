package main

import (
	//  "context"
	//	"crypto/tls"
	"fmt"
	//	"net/http"
	"os"
	"time"
	//	"os/signal"
	//	"syscall"

	"github.com/juju/errors"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"istio.io/istio/pkg/cmd"
	"istio.io/pkg/probe"

	"github.com/jingnanzhou/sidecar-operator/pkg/webhook"
)

var (
	params = struct {
		masterURL  string
		kubeconfig string

		appConfig           string
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
	}{}

	log = logrus.StandardLogger()

	rootCmd = &cobra.Command{
		Use:          "sidecar-op",
		Short:        "sidecar operator.",
		Long:         "sidecar operator to inject sidecar",
		SilenceUsage: true,
		FParseErrWhitelist: cobra.FParseErrWhitelist{
			// Allow unknown flags for backward-compatibility.
			UnknownFlags: true,
		},
	}

	probeCmd = &cobra.Command{
		Use:   "probe",
		Short: "Check the liveness or readiness of a locally-running server",
		Args:  cobra.ExactArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !params.probeOptions.IsValid() {
				return errors.New("some options are not valid")
			}
			if params.probeOptions.IsValid() {
				var livenessProbe = probe.NewFileController(&params.probeOptions)
				Probe.RegisterProbe(livenessProbe, "webhook")
				Probe.SetAvailable(nil)
				livenessProbe.Start()
			}
		
			if err := probe.NewFileClient(&params.probeOptions).GetStatus(); err != nil {
				return fmt.Errorf("fail on inspecting path %s: %v", params.probeOptions.Path, err)
			}
			log.WithField("context", "probeCmd").Infof("OK")
			return nil
		},
	}

	injectCmd = &cobra.Command{
		Use:   "inject",
		Short: "inject sidecar",
		FParseErrWhitelist: cobra.FParseErrWhitelist{
			// Allow unknown flags for backward-compatibility.
			UnknownFlags: true,
		},

		RunE: func(c *cobra.Command, args []string) error {
			//			logger := log.WithField("context", "main.injectCmd")

			whparams := webhook.WebhookParameters{

				ConfigFile:          params.injectConfigFile,
				ValuesFile:          params.injectValuesFile,
				AppFile:             params.appConfig,
				CertFile:            params.certFile,
				KeyFile:             params.privateKeyFile,
				Port:                params.port,
				HealthCheckInterval: params.healthCheckInterval,
				HealthCheckFile:     params.healthCheckFile,
				MonitoringPort:      params.monitoringPort,
			}

			whServer, err := webhook.NewWebhookServer(whparams)
			if err != nil {
				return errors.Annotate(err, "failed to create injection webhook")
			}

			webhookConfig := webhook.WebhookConfig{
				Kubeconfig:        params.kubeconfig,
				CertFile:          params.certFile, // path to the x509 certificate for https
				WebhookConfigName: params.webhookConfigName,
				WebhookName:       params.webhookName,
			}
			stop := make(chan struct{})
			if err := webhookConfig.PatchCertLoop(stop); err != nil {
				return errors.Annotate(err, "failed to start patch cert loop")
			}
			go whServer.Run(stop)
			cmd.WaitSignal(stop)
			return nil
		},
	}
	// Probe is static.
	Probe = probe.NewProbe()
)

func main() {

	if err := rootCmd.Execute(); err != nil {
		log.WithField("context", "main").Errorf("error reading config: %v\n", err)
		os.Exit(1)
	}

}

func init() {
	rootCmd.PersistentFlags().StringVar(&params.kubeconfig, "kubeconfig", "", "Path to a kubeconfig. Only required if out-of-cluster.")
	log.WithField("context", "main.init").Infof(" provided kubeconfig %v \n", params.kubeconfig)
	rootCmd.PersistentFlags().StringVar(&params.masterURL, "master", "", "The address of the Kubernetes API server. Overrides any value in kubeconfig. Only required if out-of-cluster.")

	rootCmd.PersistentFlags().StringVar(&params.appConfig, "appConfig", "/Users/jingnanzhou/work/data/etc/sidecar/app/mesh", "File containing the application configuration")

	rootCmd.PersistentFlags().StringVar(&params.injectConfigFile, "injectConfig", "/Users/jingnanzhou/work/data/etc/sidecar/inject/config",
		"File containing the sidecar injection configuration and template")
	rootCmd.PersistentFlags().StringVar(&params.injectValuesFile, "injectValues", "/Users/jingnanzhou/work/data/etc/sidecar/inject/values",
		"File containing the sidecar injection values, in yaml format")

	injectCmd.PersistentFlags().StringVar(&params.certFile, "tlsCertFile", "/Users/jingnanzhou/work/data/etc/sidecar/certs/cert-chain.pem",
		"File containing the x509 Certificate for HTTPS.")
	injectCmd.PersistentFlags().StringVar(&params.privateKeyFile, "tlsKeyFile", "/Users/jingnanzhou/work/data/etc/sidecar/certs/key.pem",
		"File containing the x509 private key matching --tlsCertFile.")
	injectCmd.PersistentFlags().StringVar(&params.caCertFile, "caCertFile", "/Users/jingnanzhou/work/data/etc/sidecar/certs/root-cert.pem",
		"File containing the x509 Certificate for HTTPS.")
	injectCmd.PersistentFlags().IntVar(&params.port, "port", 443, "Webhook port")
	injectCmd.PersistentFlags().IntVar(&params.monitoringPort, "monitoringPort", 15014, "Webhook monitoring port")

	injectCmd.PersistentFlags().DurationVar(&params.healthCheckInterval, "healthCheckInterval", 0, "Configure how frequently the health check file specified by --healthCheckFile should be updated")
	injectCmd.PersistentFlags().StringVar(&params.healthCheckFile, "healthCheckFile", "", "File that should be periodically updated if health checking is enabled")

	injectCmd.PersistentFlags().StringVar(&params.webhookConfigName, "webhookConfigName", "sidecar-webhook-config", "Name of the mutatingwebhookconfiguration resource in Kubernetes.")
	injectCmd.PersistentFlags().StringVar(&params.webhookName, "webhookName", "sidecar-injector.jingnan.io", "Name of the webhook entry in the webhook config.")

	rootCmd.AddCommand(injectCmd)

	probeCmd.PersistentFlags().StringVar(&params.probeOptions.Path, "probe-path", "",
		"Path of the file for checking the availability.")
	probeCmd.PersistentFlags().DurationVar(&params.probeOptions.UpdateInterval, "interval", 0,
		"Duration used for checking the target file's last modified time.")
	rootCmd.AddCommand(probeCmd)

}
