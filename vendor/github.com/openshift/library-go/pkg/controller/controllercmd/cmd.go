package controllercmd

import (
	"context"
	"fmt"
	"k8s.io/utils/clock"
	"math/rand"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"
	"k8s.io/apiserver/pkg/server/healthz"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/version"
	"k8s.io/apiserver/pkg/server"
	"k8s.io/client-go/tools/record"
	"k8s.io/component-base/logs"

	"k8s.io/klog/v2"

	operatorv1alpha1 "github.com/openshift/api/operator/v1alpha1"

	"github.com/openshift/library-go/pkg/config/configdefaults"
	"github.com/openshift/library-go/pkg/controller/fileobserver"
	"github.com/openshift/library-go/pkg/crypto"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/serviceability"

	// load all the prometheus client-go metrics
	_ "k8s.io/component-base/metrics/prometheus/clientgo"
)

// ControllerCommandConfig holds values required to construct a command to run.
type ControllerCommandConfig struct {
	componentName string
	startFunc     StartFunc
	version       version.Info
	clock         clock.Clock

	basicFlags *ControllerFlags

	// DisableServing disables serving metrics, debug and health checks and so on.
	DisableServing bool

	// Allow enabling HTTP2
	EnableHTTP2 bool

	// DisableLeaderElection allows leader election to be suspended
	DisableLeaderElection bool

	// LeaseDuration is the duration that non-leader candidates will
	// wait to force acquire leadership. This is measured against time of
	// last observed ack.
	LeaseDuration metav1.Duration

	// RenewDeadline is the duration that the acting controlplane will retry
	// refreshing leadership before giving up.
	RenewDeadline metav1.Duration

	// RetryPeriod is the duration the LeaderElector clients should wait
	// between tries of actions.
	RetryPeriod metav1.Duration

	// TopologyDetector is used to plug in topology detection.
	TopologyDetector TopologyDetector

	ComponentOwnerReference *corev1.ObjectReference
	healthChecks            []healthz.HealthChecker
	eventRecorderOptions    record.CorrelatorOptions
}

// NewControllerConfig returns a new ControllerCommandConfig which can be used to wire up all the boiler plate of a controller
// TODO add more methods around wiring health checks and the like
func NewControllerCommandConfig(componentName string, version version.Info, startFunc StartFunc, clock clock.Clock) *ControllerCommandConfig {
	return &ControllerCommandConfig{
		startFunc:     startFunc,
		componentName: componentName,
		version:       version,
		clock:         clock,

		basicFlags: NewControllerFlags(),

		DisableServing:        false,
		DisableLeaderElection: false,
		eventRecorderOptions:  events.RecommendedClusterSingletonCorrelatorOptions(),
	}
}

// WithComponentOwnerReference overrides controller reference resolution for event recording
func (c *ControllerCommandConfig) WithComponentOwnerReference(reference *corev1.ObjectReference) *ControllerCommandConfig {
	c.ComponentOwnerReference = reference
	return c
}

func (c *ControllerCommandConfig) WithHealthChecks(healthChecks ...healthz.HealthChecker) *ControllerCommandConfig {
	c.healthChecks = append(c.healthChecks, healthChecks...)
	return c
}

func (c *ControllerCommandConfig) WithTopologyDetector(topologyDetector TopologyDetector) *ControllerCommandConfig {
	c.TopologyDetector = topologyDetector
	return c
}

func (c *ControllerCommandConfig) WithEventRecorderOptions(eventRecorderOptions record.CorrelatorOptions) *ControllerCommandConfig {
	c.eventRecorderOptions = eventRecorderOptions
	return c
}

// NewCommand returns a new command that a caller must set the Use and Descriptions on.  It wires default log, profiling,
// leader election and other "normal" behaviors.
// Deprecated: Use the NewCommandWithContext instead, this is here to be less disturbing for existing usages.
func (c *ControllerCommandConfig) NewCommand() *cobra.Command {
	return c.NewCommandWithContext(context.TODO())

}

// NewCommandWithContext returns a new command that a caller must set the Use and Descriptions on.  It wires default log, profiling,
// leader election and other "normal" behaviors.
// The context passed will be passed down to controller loops and observers and cancelled on SIGTERM and SIGINT signals.
func (c *ControllerCommandConfig) NewCommandWithContext(ctx context.Context) *cobra.Command {
	cmd := &cobra.Command{
		Run: func(cmd *cobra.Command, args []string) {
			// boiler plate for the "normal" command
			rand.Seed(time.Now().UTC().UnixNano())
			logs.InitLogs()

			// handle SIGTERM and SIGINT by cancelling the context.
			shutdownCtx, cancel := context.WithCancel(ctx)
			shutdownHandler := server.SetupSignalHandler()
			go func() {
				defer cancel()
				<-shutdownHandler
				klog.Infof("Received SIGTERM or SIGINT signal, shutting down controller.")
			}()

			defer logs.FlushLogs()
			defer serviceability.BehaviorOnPanic(os.Getenv("OPENSHIFT_ON_PANIC"), c.version)()
			defer serviceability.Profile(os.Getenv("OPENSHIFT_PROFILE")).Stop()

			serviceability.StartProfiler()

			if err := c.basicFlags.Validate(); err != nil {
				klog.Fatal(err)
			}

			ctx, terminate := context.WithCancel(shutdownCtx)
			defer terminate()

			if len(c.basicFlags.TerminateOnFiles) > 0 {
				// setup file observer to terminate when given files change
				obs, err := fileobserver.NewObserver(10 * time.Second)
				if err != nil {
					klog.Fatal(err)
				}
				files := map[string][]byte{}
				for _, fn := range c.basicFlags.TerminateOnFiles {
					fileBytes, err := os.ReadFile(fn)
					if err != nil {
						klog.Warningf("Unable to read initial content of %q: %v", fn, err)
						continue // intentionally ignore errors
					}
					files[fn] = fileBytes
				}
				obs.AddReactor(func(filename string, action fileobserver.ActionType) error {
					klog.Infof("exiting because %q changed", filename)
					terminate()
					return nil
				}, files, c.basicFlags.TerminateOnFiles...)

				go obs.Run(shutdownHandler)
			}

			if err := c.StartController(ctx); err != nil {
				klog.Fatal(err)
			}
		},
	}

	c.basicFlags.AddFlags(cmd)

	return cmd
}

// Config returns the configuration of this command. Use StartController if you don't need to customize the default operator.
// This method does not modify the receiver.
func (c *ControllerCommandConfig) Config() (*unstructured.Unstructured, *operatorv1alpha1.GenericOperatorConfig, []byte, error) {
	configContent, unstructuredConfig, err := c.basicFlags.ToConfigObj()
	if err != nil {
		return nil, nil, nil, err
	}
	config := &operatorv1alpha1.GenericOperatorConfig{}
	if unstructuredConfig != nil {
		// make a copy we can mutate
		configCopy := unstructuredConfig.DeepCopy()
		// force the config to our version to read it
		configCopy.SetGroupVersionKind(operatorv1alpha1.GroupVersion.WithKind("GenericOperatorConfig"))
		if err := runtime.DefaultUnstructuredConverter.FromUnstructured(configCopy.Object, config); err != nil {
			return nil, nil, nil, err
		}
	}
	return unstructuredConfig, config, configContent, nil
}

func hasServiceServingCerts(certDir string) bool {
	if _, err := os.Stat(filepath.Join(certDir, "tls.crt")); os.IsNotExist(err) {
		return false
	}
	if _, err := os.Stat(filepath.Join(certDir, "tls.key")); os.IsNotExist(err) {
		return false
	}
	return true
}

// AddDefaultRotationToConfig starts the provided builder with the default rotation set (config + serving info). Use StartController if
// you do not need to customize the controller builder. This method modifies config with self-signed default cert locations if
// necessary.
func (c *ControllerCommandConfig) AddDefaultRotationToConfig(config *operatorv1alpha1.GenericOperatorConfig, configContent []byte) (map[string][]byte, []string, error) {
	certDir := "/var/run/secrets/serving-cert"

	observedFiles := []string{
		// We observe these, so we they are created or modified by service serving cert signer, we can react and restart the process
		// that will pick these up instead of generating the self-signed certs.
		// NOTE: We are not observing the temporary, self-signed certificates.
		filepath.Join(certDir, "tls.crt"),
		filepath.Join(certDir, "tls.key"),
	}
	// startingFileContent holds hardcoded starting content.  If we generate our own certificates, then we want to specify empty
	// content to avoid a starting race.  When we consume them, the race is really about as good as we can do since we don't know
	// what's actually been read.
	startingFileContent := map[string][]byte{}

	// Since provision of a config filename is optional, only observe when one is provided.
	if len(c.basicFlags.ConfigFile) > 0 {
		observedFiles = append(observedFiles, c.basicFlags.ConfigFile)
		startingFileContent[c.basicFlags.ConfigFile] = configContent
	}

	// if we don't have any serving cert/key pairs specified and the defaults are not present, generate a self-signed set
	// TODO maybe this should be optional?  It's a little difficult to come up with a scenario where this is worse than nothing though.
	if len(config.ServingInfo.CertFile) == 0 && len(config.ServingInfo.KeyFile) == 0 {
		servingInfoCopy := config.ServingInfo.DeepCopy()
		configdefaults.SetRecommendedHTTPServingInfoDefaults(servingInfoCopy)

		if hasServiceServingCerts(certDir) {
			klog.Infof("Using service-serving-cert provided certificates")
			config.ServingInfo.CertFile = filepath.Join(certDir, "tls.crt")
			config.ServingInfo.KeyFile = filepath.Join(certDir, "tls.key")
		} else {
			klog.Warningf("Using insecure, self-signed certificates")
			// If we generate our own certificates, then we want to specify empty content to avoid a starting race.  This way,
			// if any change comes in, we will properly restart
			startingFileContent[filepath.Join(certDir, "tls.crt")] = []byte{}
			startingFileContent[filepath.Join(certDir, "tls.key")] = []byte{}

			temporaryCertDir, err := os.MkdirTemp("", "serving-cert-")
			if err != nil {
				return nil, nil, err
			}
			signerName := fmt.Sprintf("%s-signer@%d", c.componentName, time.Now().Unix())
			ca, err := crypto.MakeSelfSignedCA(
				filepath.Join(temporaryCertDir, "serving-signer.crt"),
				filepath.Join(temporaryCertDir, "serving-signer.key"),
				filepath.Join(temporaryCertDir, "serving-signer.serial"),
				signerName,
				0,
			)
			if err != nil {
				return nil, nil, err
			}

			// force the values to be set to where we are writing the certs
			config.ServingInfo.CertFile = filepath.Join(temporaryCertDir, "tls.crt")
			config.ServingInfo.KeyFile = filepath.Join(temporaryCertDir, "tls.key")
			// nothing can trust this, so we don't really care about hostnames
			servingCert, err := ca.MakeServerCert(sets.New("localhost"), 30)
			if err != nil {
				return nil, nil, err
			}
			if err := servingCert.WriteCertConfigFile(config.ServingInfo.CertFile, config.ServingInfo.KeyFile); err != nil {
				return nil, nil, err
			}
		}
	}
	return startingFileContent, observedFiles, nil
}

// StartController runs the controller. This is the recommend entrypoint when you don't need
// to customize the builder.
func (c *ControllerCommandConfig) StartController(ctx context.Context) error {
	unstructuredConfig, config, configContent, err := c.Config()
	if err != nil {
		return err
	}

	startingFileContent, observedFiles, err := c.AddDefaultRotationToConfig(config, configContent)
	if err != nil {
		return err
	}

	if len(c.basicFlags.BindAddress) != 0 {
		config.ServingInfo.BindAddress = c.basicFlags.BindAddress
	}

	exitOnChangeReactorCh := make(chan struct{})
	controllerCtx, cancel := context.WithCancel(ctx)
	go func() {
		select {
		case <-exitOnChangeReactorCh:
			cancel()
		case <-ctx.Done():
			cancel()
		}
	}()

	config.LeaderElection.Disable = c.DisableLeaderElection
	config.LeaderElection.LeaseDuration = c.LeaseDuration
	config.LeaderElection.RenewDeadline = c.RenewDeadline
	config.LeaderElection.RetryPeriod = c.RetryPeriod

	builder := NewController(c.componentName, c.startFunc, c.clock).
		WithKubeConfigFile(c.basicFlags.KubeConfigFile, nil).
		WithComponentNamespace(c.basicFlags.Namespace).
		WithLeaderElection(config.LeaderElection, c.basicFlags.Namespace, c.componentName+"-lock").
		WithVersion(c.version).
		WithHealthChecks(c.healthChecks...).
		WithEventRecorderOptions(c.eventRecorderOptions).
		WithRestartOnChange(exitOnChangeReactorCh, startingFileContent, observedFiles...).
		WithComponentOwnerReference(c.ComponentOwnerReference)

	if !c.DisableServing {
		builder = builder.WithServer(config.ServingInfo, config.Authentication, config.Authorization)
		if c.EnableHTTP2 {
			builder = builder.WithHTTP2()
		}
	}

	if c.TopologyDetector != nil {
		builder = builder.WithTopologyDetector(c.TopologyDetector)
	}

	return builder.Run(controllerCtx, unstructuredConfig)
}
