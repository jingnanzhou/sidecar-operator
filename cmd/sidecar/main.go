package main

import (
  "os"
	"github.com/jingnanzhou/sidecar-operator/cmd/sidecar/app"
	operatoropts "github.com/jingnanzhou/sidecar-operator/pkg/options"
  "github.com/jingnanzhou/sidecar-operator/pkg/constants"

  "github.com/jingnanzhou/sidecar-operator/pkg/version"
	"github.com/spf13/cobra"

	"github.com/sirupsen/logrus"
	"github.com/juju/errors"

)
var (

  params = struct {
  	masterURL  string
  	kubeconfig string
    injectCMName string
    appCMName string
    injectionName string

} {}


	log = logrus.StandardLogger()

	rootCmd = &cobra.Command{
		Use:          "sidecar-op",
		Short:        "sidecar operator.",
		Long:         "sidecar operator to inject proxy to sidecar",
		SilenceUsage: true,
		FParseErrWhitelist: cobra.FParseErrWhitelist{
			// Allow unknown flags for backward-compatibility.
			UnknownFlags: true,
		},
	}

	injectCmd = &cobra.Command{
		Use:   "inject",
		Short: "inject proxy",
		FParseErrWhitelist: cobra.FParseErrWhitelist{
			// Allow unknown flags for backward-compatibility.
			UnknownFlags: true,
		},

		RunE: func(c *cobra.Command, args []string) error {

			logger := log.WithField("context", "main.injectCmd")

			logger.Infof( "Starting Sidecar-operator version '%s' kubeconfig=%s \n", version.GetBuildVersion(),params.kubeconfig)
				opts, err := operatoropts.NewOperatorOpts(params.kubeconfig, params.masterURL, params.injectCMName, params.appCMName, params.injectionName)
				if err != nil {
					logger.Errorf( "error reading config: %v\n", err)
					return errors.Trace(err)
			  }
					opts.AddFlags(rootCmd.PersistentFlags())

				if err := app.Run(opts); err != nil {
					logger.Errorf( "%v\n", err)
					return errors.Annotate(err, "app.Run")
				}
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
	injectCmd.PersistentFlags().StringVar(&params.kubeconfig, "kubeconfig", "", "Path to a kubeconfig. Only required if out-of-cluster.")
	log.WithField("context", "main.init").Infof(" provided kubeconfig %s \n", params.kubeconfig)
	injectCmd.PersistentFlags().StringVar(&params.masterURL, "master", "", "The address of the Kubernetes API server. Overrides any value in kubeconfig. Only required if out-of-cluster.")

  injectCmd.PersistentFlags().StringVar(&params.injectCMName, "injectCMName", constants.InjectConfigCMName, " Configmap name for injected sidecar configuration")
  injectCmd.PersistentFlags().StringVar(&params.appCMName, "appCMName", constants.AppConfigCMName, "configmap name for additional app configuration")

  injectCmd.PersistentFlags().StringVar(&params.injectionName, "injectionName", constants.InjectionName, "InjectionName for namespace label")

	rootCmd.AddCommand(injectCmd)
}
