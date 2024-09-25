package auth

import (
	"encoding/json"
	"fmt"

	configv1 "github.com/openshift/api/config/v1"
	"github.com/openshift/api/features"
	"github.com/openshift/cluster-kube-apiserver-operator/pkg/operator/configobservation"
	"github.com/openshift/cluster-kube-apiserver-operator/pkg/operator/operatorclient"
	"github.com/openshift/library-go/pkg/operator/configobserver"
	"github.com/openshift/library-go/pkg/operator/configobserver/featuregates"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/resourcesynccontroller"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apiserver/pkg/apis/apiserver"
	"k8s.io/klog/v2"
)

const (
	eventComponentName = "ObserveExternalOIDC"

	apiServerArgumentsPath = "apiServerArguments"
	argAuthConfig          = "authentication-config"

	SourceAuthConfigCMNamespace = "openshift-config-managed"
	AuthConfigCMName            = "auth-config"
	staticAuthConfigPath        = "/etc/kubernetes/static-pod-resources/configmaps/" + AuthConfigCMName + "/auth-config.json"
)

func NewObserveExternalOIDC(featureGateAccessor featuregates.FeatureGateAccess) configobserver.ObserveConfigFunc {
	return (&externalOIDC{
		featureGateAccessor: featureGateAccessor,
	}).ObserveExternalOIDC
}

type externalOIDC struct {
	featureGateAccessor featuregates.FeatureGateAccess
}

// ObserveExternalOIDC observes the authentication.config/cluster resource
// and if the type field is set to OIDC, it configures an external OIDC provider
// to the KAS pods by setting the --authentication-config apiserver argument. It also
// takes care of synchronizing the structured auth config file into the apiserver's namespace
// so that it gets mounted as a static file on each node.
func (o *externalOIDC) ObserveExternalOIDC(genericListers configobserver.Listers, recorder events.Recorder, existingConfig map[string]interface{}) (map[string]interface{}, []error) {
	if o.featureGateAccessor == nil || !o.featureGateAccessor.AreInitialFeatureGatesObserved() {
		// if we haven't observed featuregates yet, return the existing
		return existingConfig, nil
	}

	featureGates, err := o.featureGateAccessor.CurrentFeatureGates()
	if err != nil {
		return existingConfig, []error{err}
	}

	if !featureGates.Enabled(features.FeatureGateExternalOIDC) {
		return existingConfig, nil
	}

	listers := genericListers.(configobservation.Listers)
	auth, err := listers.AuthConfigLister.Get("cluster")
	if errors.IsNotFound(err) {
		klog.Warningf("authentications.config.openshift.io/cluster: not found")
		return existingConfig, nil
	} else if err != nil {
		return existingConfig, []error{err}
	}

	if auth.Spec.Type != configv1.AuthenticationTypeOIDC {
		if _, err := listers.ConfigMapLister().ConfigMaps(operatorclient.TargetNamespace).Get(AuthConfigCMName); errors.IsNotFound(err) {
			return nil, nil

		} else if err != nil {
			return existingConfig, []error{fmt.Errorf("failed to get configmap %s/%s: %v", operatorclient.TargetNamespace, AuthConfigCMName, err)}
		}

		// empty source name/namespace effectively deletes target configmap
		if err := syncConfigMap(genericListers.ResourceSyncer(), "", "", recorder); err != nil {
			return existingConfig, []error{err}
		}

		return nil, nil
	}

	sourceAuthConfig, err := listers.ConfigMapLister().ConfigMaps(SourceAuthConfigCMNamespace).Get(AuthConfigCMName)
	if err != nil {
		return existingConfig, []error{fmt.Errorf("failed to get configmap %s/%s: %v", SourceAuthConfigCMNamespace, AuthConfigCMName, err)}
	}

	if validationErr := validateAuthConfigMap(sourceAuthConfig); validationErr != nil {
		return existingConfig, []error{fmt.Errorf("configmap %s/%s is invalid: %v", SourceAuthConfigCMNamespace, AuthConfigCMName, validationErr)}
	}

	observedConfig := make(map[string]interface{})
	if err := unstructured.SetNestedField(observedConfig, []interface{}{staticAuthConfigPath}, apiServerArgumentsPath, argAuthConfig); err != nil {
		return existingConfig, []error{err}
	}

	targetAuthConfig, err := listers.ConfigMapLister().ConfigMaps(operatorclient.TargetNamespace).Get(AuthConfigCMName)
	if err != nil && !errors.IsNotFound(err) {
		return existingConfig, []error{err}
	}

	if targetAuthConfig == nil || !equality.Semantic.DeepEqual(targetAuthConfig.Data, sourceAuthConfig.Data) {
		if err := syncConfigMap(genericListers.ResourceSyncer(), sourceAuthConfig.Name, sourceAuthConfig.Namespace, recorder); err != nil {
			return existingConfig, []error{err}
		}
	}

	return observedConfig, nil

}

func syncConfigMap(syncer resourcesynccontroller.ResourceSyncer, sourceName, sourceNamespace string, recorder events.Recorder) error {
	if err := syncer.SyncConfigMap(
		resourcesynccontroller.ResourceLocation{Namespace: operatorclient.TargetNamespace, Name: AuthConfigCMName},
		resourcesynccontroller.ResourceLocation{Namespace: sourceNamespace, Name: sourceName},
	); err != nil {
		return err
	}

	if len(sourceName) == 0 {
		recorder.Eventf(eventComponentName, "deleted configmap %s/%s", operatorclient.TargetNamespace, AuthConfigCMName)
	} else {
		recorder.Eventf(eventComponentName, "synced configmap %s/%s to %s/%s", sourceNamespace, sourceName, operatorclient.TargetNamespace, AuthConfigCMName)
	}

	return nil
}

func validateAuthConfigMap(cm *corev1.ConfigMap) error {
	if cm == nil {
		return fmt.Errorf("configmap is nil")
	}

	authConfigRaw, ok := cm.Data["auth-config.json"]
	if !ok {
		return fmt.Errorf("missing required 'auth-config.json' key")
	}

	if len(authConfigRaw) == 0 {
		return fmt.Errorf("value of key 'auth-config.json' is empty")
	}

	var authConfig apiserver.AuthenticationConfiguration
	if err := json.Unmarshal([]byte(authConfigRaw), &authConfig); err != nil {
		return fmt.Errorf("cannot unmarshal auth config JSON into apiserver.config.k8s.io/AuthenticationConfiguration: %v", err)
	}

	return nil
}
