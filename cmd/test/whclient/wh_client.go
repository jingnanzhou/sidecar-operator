package whclient
import (


	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	//labels "k8s.io/apimachinery/pkg/labels"
metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"github.com/sirupsen/logrus"
  "github.com/jingnanzhou/sidecar-operator/pkg/webhook"

)

var (
	log = logrus.StandardLogger()
)


// Run starts the operator controllers. This should never exit.
func RunClient(kubeConfig string, masterURL string, configFile string, valueFile string, appFile string) error {

	logger := log.WithField("context", "RunClient")

  logger.Infof("start runClient with kubeConfig= %s", kubeConfig)

	kubeconfig, err := clientcmd.BuildConfigFromFlags(masterURL, kubeConfig)
	if err != nil {
    logger.Errorf("load error %v", err)
		return err
	}
	logger.Infof("kubeconfig %v \n", kubeconfig)

  	kubeClient := kubernetes.NewForConfigOrDie(kubeconfig)
//  kubernetes.NewForConfigOrDie(kubeconfig)

listOptions := metav1.ListOptions{}
//  defLabels :=labels.NewSelector()

  nsList, err :=kubeClient.CoreV1().Namespaces().List(listOptions)

	if err != nil {
		 	logger.Infof("Error while get namespace list: %v", err)
		 	return err
	}
	for _, ns := range nsList.Items {
		 		logger.Infof(" namespace name  %s value is %v", ns.Name)
        if ns.Name =="test" {
          podList, errp :=kubeClient.CoreV1().Pods(ns.Name).List(listOptions)

          if errp == nil {
            for _, pod := range podList.Items {
              logger.Infof(" pod name  %s ", pod.Name)

              webhook.TestInject(kubeClient, configFile, valueFile, appFile, &ns, &pod )


            }
          }

        }
  }



	return nil
}
