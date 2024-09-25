package auth

import (
	"fmt"
	"net/url"

	configv1 "github.com/openshift/api/config/v1"
	"github.com/openshift/api/features"
	"github.com/openshift/cluster-kube-apiserver-operator/pkg/operator/configobservation"
	"github.com/openshift/cluster-kube-apiserver-operator/pkg/operator/operatorclient"
	"github.com/openshift/library-go/pkg/operator/configobserver"
	"github.com/openshift/library-go/pkg/operator/configobserver/featuregates"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/resourcesynccontroller"
	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/klog/v2"
)

const (
	eventComponentName        = "ObserveExternalOIDC"
	componentName             = "kube-apiserver"
	caBundleSourceNamespace   = "openshift-config"
	TargetOIDCCAConfigMapName = "oidc-serving-ca-bundle"
	staticCABundleFilePath    = "/etc/kubernetes/static-pod-resources/configmaps/oidc-serving-ca-bundle/ca-bundle.crt"
	apiServerArgumentsPath    = "apiServerArguments"

	oidcIssuerURLPath      = "oidc-issuer-url"
	oidcClientIDPath       = "oidc-client-id"
	oidcUsernameClaimPath  = "oidc-username-claim"
	oidcUsernamePrefixPath = "oidc-username-prefix"
	oidcGroupsClaimPath    = "oidc-groups-claim"
	oidcGroupsPrefixPath   = "oidc-groups-prefix"
	oidcRequiredClaimPath  = "oidc-required-claim"
	oidcCAFilePath         = "oidc-ca-file"
	// oidcSigningAlgsPath    = "oidc-signing-algs" // not part of auth CR; default is RS256
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
// to the KAS pods by setting the corresponding --oidc-* apiserver arguments. It also
// takes care of synchronizing the CA bundle configmap to the openshift-kube-apiserver NS
// so that it gets mounted as a static file on each node.
func (o *externalOIDC) ObserveExternalOIDC(genericListers configobserver.Listers, recorder events.Recorder, existingConfig map[string]interface{}) (map[string]interface{}, []error) {
	if !o.featureGateAccessor.AreInitialFeatureGatesObserved() {
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

	errs := []error{}
	listers := genericListers.(configobservation.Listers)
	resourceSyncer := genericListers.ResourceSyncer()

	auth, err := listers.AuthConfigLister.Get("cluster")
	if errors.IsNotFound(err) {
		klog.Warningf("authentications.config.openshift.io/cluster: not found")
		return existingConfig, nil
	} else if err != nil {
		return existingConfig, append(errs, err)
	}

	switch auth.Spec.Type {
	case configv1.AuthenticationTypeIntegratedOAuth, configv1.AuthenticationTypeNone, "":
		// sync an empty configmap to effectively remove the OIDC CA bundle if it exists
		err := resourceSyncer.SyncConfigMap(
			resourcesynccontroller.ResourceLocation{Namespace: operatorclient.TargetNamespace, Name: TargetOIDCCAConfigMapName},
			resourcesynccontroller.ResourceLocation{Namespace: "", Name: ""},
		)
		if err != nil {
			return existingConfig, append(errs, err)
		}

		if oidcAlreadyExists, err := oidcConfigExists(existingConfig); err != nil {
			return existingConfig, append(errs, err)
		} else if oidcAlreadyExists {
			recorder.Eventf(eventComponentName, "Removed ExternalOIDC configuration")
		}

		return nil, nil

	case configv1.AuthenticationTypeOIDC:
		return observeExternalOIDC(auth, listers, resourceSyncer, recorder, existingConfig)
	}

	// this should never happen; resource is CEL-validated
	return existingConfig, append(errs, fmt.Errorf("invalid auth type: %s", auth.Spec.Type))
}

func observeExternalOIDC(auth *configv1.Authentication, listers configobservation.Listers, resourceSyncer resourcesynccontroller.ResourceSyncer, recorder events.Recorder, existingConfig map[string]interface{}) (map[string]interface{}, []error) {
	errs := []error{}
	oidcConfigValues := map[string][]interface{}{}

	if len(auth.Spec.OIDCProviders) != 1 {
		// this should never happen; resource is CEL-validated
		return existingConfig, append(errs, fmt.Errorf("exactly one OIDC provider must be configured in authentication.config/cluster resource"))
	}

	provider := auth.Spec.OIDCProviders[0]
	clientConfig := getOIDCClientForComponent(auth, componentName, operatorclient.TargetNamespace)
	if clientConfig == nil {
		return existingConfig, append(errs, fmt.Errorf("no OIDC client config found for component %s/%s", componentName, operatorclient.TargetNamespace))
	}

	// issuer URL is required (https)
	if issuerURL, err := url.Parse(provider.Issuer.URL); err != nil {
		errs = append(errs, err)
	} else if issuerURL.Scheme != "https" {
		errs = append(errs, fmt.Errorf("https is required for provider URL"))
	} else {
		oidcConfigValues[oidcIssuerURLPath] = []interface{}{provider.Issuer.URL}
	}

	// OIDC client ID is required
	if len(clientConfig.ClientID) > 0 {
		oidcConfigValues[oidcClientIDPath] = []interface{}{clientConfig.ClientID}
	} else {
		errs = append(errs, fmt.Errorf("OIDC client ID not set"))
	}

	if len(provider.ClaimMappings.Username.Claim) > 0 {
		oidcConfigValues[oidcUsernameClaimPath] = []interface{}{provider.ClaimMappings.Username.Claim}
	}
	if len(provider.ClaimMappings.Groups.Claim) > 0 {
		oidcConfigValues[oidcGroupsClaimPath] = []interface{}{provider.ClaimMappings.Groups.Claim}
	}
	if len(provider.ClaimMappings.Groups.Prefix) > 0 {
		oidcConfigValues[oidcGroupsPrefixPath] = []interface{}{provider.ClaimMappings.Groups.Prefix}
	}

	switch provider.ClaimMappings.Username.PrefixPolicy {
	case configv1.NoOpinion:
		// do not pass --oidc-username-prefix for the default behaviour

	case configv1.NoPrefix:
		// "-" disables any prefix
		oidcConfigValues[oidcUsernamePrefixPath] = []interface{}{"-"}

	case configv1.Prefix:
		// prefix value must be specified
		if provider.ClaimMappings.Username.Prefix == nil {
			errs = append(errs, fmt.Errorf("nil username prefix while policy expects one"))
		} else {
			oidcConfigValues[oidcUsernamePrefixPath] = []interface{}{provider.ClaimMappings.Username.Prefix.PrefixString}
		}
	}

	if len(provider.ClaimValidationRules) > 0 {
		oidcConfigValues[oidcRequiredClaimPath] = make([]interface{}, len(provider.ClaimValidationRules))
		for i, rule := range provider.ClaimValidationRules {
			hasErrors := false
			if rule.Type != configv1.TokenValidationRuleTypeRequiredClaim {
				hasErrors = true
				errs = append(errs, fmt.Errorf("invalid claim validation rule type: %s", rule.Type))
			}

			if rule.RequiredClaim == nil {
				hasErrors = true
				errs = append(errs, fmt.Errorf("empty validation rule at index %d", i))
			}

			if !hasErrors {
				oidcConfigValues[oidcRequiredClaimPath][i] = fmt.Sprintf("%s=%s", rule.RequiredClaim.Claim, rule.RequiredClaim.RequiredValue)
			}
		}
	}

	if len(provider.Issuer.CertificateAuthority.Name) > 0 {
		oidcConfigValues[oidcCAFilePath] = []interface{}{staticCABundleFilePath}
	}

	// TODO: client secret? extra scopes?

	if len(errs) > 0 {
		// do not continue to sync if any errors were encountered
		return existingConfig, errs
	}

	caBundleSynced, err := syncCABundleIfNeeded(listers, resourceSyncer, provider)
	if err != nil {
		return existingConfig, append(errs, err)
	}

	configChanged := false
	observedConfig := map[string]interface{}{}
	for _, path := range []string{
		oidcIssuerURLPath,
		oidcClientIDPath,
		oidcUsernameClaimPath,
		oidcUsernamePrefixPath,
		oidcGroupsClaimPath,
		oidcGroupsPrefixPath,
		oidcRequiredClaimPath,
		oidcCAFilePath,
	} {
		newVal, newValConfigured := oidcConfigValues[path]

		// check if we have made any changes to the OIDC config, and record an event if we did
		if !configChanged {
			existingValue, _, err := unstructured.NestedSlice(existingConfig, apiServerArgumentsPath, path)
			if err != nil {
				errs = append(errs, err)
			} else if !equality.Semantic.DeepEqual(existingValue, newVal) {
				configChanged = true
			}
		}

		if !newValConfigured {
			// skip oidc config paths that haven't been set
			continue
		}

		if err := unstructured.SetNestedSlice(observedConfig, newVal, apiServerArgumentsPath, path); err != nil {
			recorder.Eventf(eventComponentName, "Failed setting '%s': %v", path, err)
			errs = append(errs, err)
		}
	}

	if caBundleSynced {
		recorder.Eventf(eventComponentName, "ExternalOIDC CA bundle configmap synced")
	}

	if configChanged {
		recorder.Eventf(eventComponentName, "ExternalOIDC configuration changed")
	}

	return observedConfig, errs
}

func syncCABundleIfNeeded(listers configobservation.Listers, resourceSyncer resourcesynccontroller.ResourceSyncer, provider configv1.OIDCProvider) (bool, error) {
	caBundleSyncNeeded, err := cmNeedsSync(listers, TargetOIDCCAConfigMapName, operatorclient.TargetNamespace, provider.Issuer.CertificateAuthority.Name, caBundleSourceNamespace, "ca-bundle.crt")
	if err != nil {
		klog.Warningf("error while checking whether %s configmap needs syncing, will sync anyway: %v", targetNamespaceName, err)
		caBundleSyncNeeded = true
	}

	if !caBundleSyncNeeded {
		return false, nil
	}

	sourceName := provider.Issuer.CertificateAuthority.Name
	sourceNamespace := caBundleSourceNamespace
	if len(sourceName) == 0 {
		sourceNamespace = ""
	}

	if err := resourceSyncer.SyncConfigMap(
		resourcesynccontroller.ResourceLocation{Namespace: operatorclient.TargetNamespace, Name: TargetOIDCCAConfigMapName},
		resourcesynccontroller.ResourceLocation{Namespace: sourceNamespace, Name: sourceName},
	); err != nil {
		return false, err
	}

	return true, nil
}

func getOIDCClientForComponent(auth *configv1.Authentication, name, namespace string) *configv1.OIDCClientConfig {
	for _, clientConfig := range auth.Spec.OIDCProviders[0].OIDCClients {
		if clientConfig.ComponentName == name && clientConfig.ComponentNamespace == namespace {
			return &clientConfig
		}
	}

	return nil
}

func cmNeedsSync(listers configobservation.Listers, destinationCMName, destinationCMNamespace, sourceCMName, sourceCMNamespace, key string) (bool, error) {
	existingCM, err := listers.ConfigMapLister().ConfigMaps(destinationCMNamespace).Get(destinationCMName)
	if errors.IsNotFound(err) {
		// destination doesn't exist; must sync
		return true, nil
	} else if err != nil {
		return false, err
	}

	if len(sourceCMName) == 0 {
		// source has been deleted; must sync
		return true, nil
	}

	sourceCM, err := listers.ConfigMapLister().ConfigMaps(sourceCMNamespace).Get(sourceCMName)
	if err != nil {
		return false, err
	}

	if len(key) == 0 {
		return !equality.Semantic.DeepEqual(existingCM.Data, sourceCM.Data), nil
	}

	val1, found1 := existingCM.Data[key]
	val2, found2 := sourceCM.Data[key]

	if found1 && found2 {
		// contents have changed; must sync
		return val1 != val2, nil
	}

	if !found2 {
		if !found1 {
			// neither cm contains key; do not sync
			return false, fmt.Errorf("key '%s' not found in either configmap", key)
		}
		return false, fmt.Errorf("key '%s' not found in source configmap", key)
	}

	// key mismatch; sync source
	return true, nil
}

func oidcConfigExists(config map[string]interface{}) (bool, error) {
	for _, path := range []string{
		oidcIssuerURLPath,
		oidcClientIDPath,
		oidcUsernameClaimPath,
		oidcUsernamePrefixPath,
		oidcGroupsClaimPath,
		oidcGroupsPrefixPath,
		oidcRequiredClaimPath,
		oidcCAFilePath,
	} {
		_, found, err := unstructured.NestedSlice(config, apiServerArgumentsPath, path)
		if err != nil {
			return false, err
		}

		if found {
			return true, nil
		}
	}

	return false, nil
}
