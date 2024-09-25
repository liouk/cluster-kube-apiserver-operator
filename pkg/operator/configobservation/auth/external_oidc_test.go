package auth

import (
	"fmt"
	"testing"

	configv1 "github.com/openshift/api/config/v1"
	"github.com/openshift/api/features"
	configlistersv1 "github.com/openshift/client-go/config/listers/config/v1"
	"github.com/openshift/cluster-kube-apiserver-operator/pkg/operator/configobservation"
	"github.com/openshift/library-go/pkg/operator/configobserver/featuregates"
	"github.com/openshift/library-go/pkg/operator/events"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/diff"
	corelistersv1 "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
)

var (
	featureGatesWithOIDC = featuregates.NewHardcodedFeatureGateAccessForTesting(
		[]configv1.FeatureGateName{features.FeatureGateExternalOIDC},
		[]configv1.FeatureGateName{},
		makeClosedChannel(),
		nil,
	)

	authResourceWithOAuth = configv1.Authentication{
		ObjectMeta: metav1.ObjectMeta{
			Name: "cluster",
		},
		Spec: configv1.AuthenticationSpec{
			Type: configv1.AuthenticationTypeIntegratedOAuth,
		},
	}

	authResourceWithOIDC = configv1.Authentication{
		ObjectMeta: metav1.ObjectMeta{
			Name: "cluster",
		},
		Spec: configv1.AuthenticationSpec{
			Type: configv1.AuthenticationTypeOIDC,
		},
	}

	baseConfig = map[string]interface{}{
		apiServerArgumentsPath: map[string]interface{}{
			argAuthConfig: staticAuthConfigPath,
		},
	}

	baseConfigMap = corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "auth-config",
			Namespace: "openshift-config",
		},
		Data: map[string]string{
			"auth-config.json": `{}`,
		},
	}

	invalidConfigMap = corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "auth-config",
			Namespace: "openshift-config",
		},
		Data: map[string]string{
			"invalid-auth-config.json": `{}`,
		},
	}
)

func TestObserveExternalOIDC(t *testing.T) {
	for _, tt := range []struct {
		name string

		featureGates      featuregates.FeatureGateAccess
		existingConfig    map[string]interface{}
		existingConfigMap *corev1.ConfigMap

		auth        *configv1.Authentication
		authIndexer cache.Indexer
		cmIndexer   cache.Indexer

		expectedConfig map[string]interface{}
		expectedSynced map[string]string
		expectErrors   bool
		expectEvents   bool
	}{
		{
			name:           "nil feature gates accessor",
			featureGates:   nil,
			existingConfig: baseConfig,
			expectedConfig: baseConfig,
			expectErrors:   false,
		},
		{
			name: "initial feature gates not observed",
			featureGates: featuregates.NewHardcodedFeatureGateAccessForTesting(
				[]configv1.FeatureGateName{},
				[]configv1.FeatureGateName{},
				make(chan struct{}),
				nil,
			),
			existingConfig: baseConfig,
			expectedConfig: baseConfig,
			expectErrors:   false,
		},
		{
			name: "feature gates access error",
			featureGates: featuregates.NewHardcodedFeatureGateAccessForTesting(
				[]configv1.FeatureGateName{},
				[]configv1.FeatureGateName{},
				makeClosedChannel(),
				fmt.Errorf("error"),
			),
			existingConfig: baseConfig,
			expectedConfig: baseConfig,
			expectErrors:   true,
		},
		{
			name: "ExternalOIDC feature gate disabled",
			featureGates: featuregates.NewHardcodedFeatureGateAccessForTesting(
				[]configv1.FeatureGateName{},
				[]configv1.FeatureGateName{features.FeatureGateExternalOIDC},
				makeClosedChannel(),
				nil,
			),
			existingConfig: baseConfig,
			expectedConfig: baseConfig,
			expectErrors:   false,
		},
		{
			name:           "auth resource not found",
			featureGates:   featureGatesWithOIDC,
			existingConfig: baseConfig,
			expectedConfig: baseConfig,
			expectErrors:   false,
		},
		{
			name:           "auth resource retrieval error",
			featureGates:   featureGatesWithOIDC,
			authIndexer:    &everFailingIndexer{},
			existingConfig: baseConfig,
			expectedConfig: baseConfig,
			expectErrors:   true,
		},
		{
			name:           "auth type not OIDC without existing config",
			featureGates:   featureGatesWithOIDC,
			existingConfig: nil,
			auth:           &authResourceWithOAuth,
			expectedConfig: nil,
			expectedSynced: nil,
			expectEvents:   false,
			expectErrors:   false,
		},
		{
			name:              "auth type changed from OIDC to IntegratedOAuth",
			featureGates:      featureGatesWithOIDC,
			existingConfig:    baseConfig,
			existingConfigMap: &baseConfigMap,
			auth:              &authResourceWithOAuth,
			expectedConfig:    nil,
			expectedSynced: map[string]string{
				"configmap/auth-config.openshift-kube-apiserver": "DELETE",
			},
			expectEvents: true,
			expectErrors: false,
		},
		{
			name:              "source configmap does not exist",
			featureGates:      featureGatesWithOIDC,
			existingConfig:    nil,
			existingConfigMap: nil,
			auth:              &authResourceWithOIDC,
			expectEvents:      false,
			expectErrors:      true,
		},
		{
			name:              "source configmap lister error",
			featureGates:      featureGatesWithOIDC,
			cmIndexer:         &everFailingIndexer{},
			existingConfig:    nil,
			existingConfigMap: &baseConfigMap,
			auth:              &authResourceWithOIDC,
			expectEvents:      false,
			expectErrors:      true,
		},
		{
			name:              "new invalid OIDC config",
			featureGates:      featureGatesWithOIDC,
			existingConfig:    nil,
			existingConfigMap: &invalidConfigMap,
			auth:              &authResourceWithOIDC,
			expectEvents:      false,
			expectErrors:      true,
		},
		{
			name:              "updated invalid OIDC config",
			featureGates:      featureGatesWithOIDC,
			existingConfig:    baseConfig,
			existingConfigMap: &invalidConfigMap,
			auth:              &authResourceWithOIDC,
			expectedConfig:    baseConfig,
			expectEvents:      false,
			expectErrors:      true,
		},
		{
			name:              "new valid OIDC config",
			featureGates:      featureGatesWithOIDC,
			existingConfig:    nil,
			existingConfigMap: &baseConfigMap,
			auth:              &authResourceWithOIDC,
			expectedConfig:    baseConfig,
			expectedSynced: map[string]string{
				"configmap/auth-config.openshift-kube-apiserver": "configmap/auth-config.openshift-config",
			},
			expectEvents: true,
			expectErrors: false,
		},
		{
			name:              "updated valid OIDC config",
			featureGates:      featureGatesWithOIDC,
			existingConfig:    baseConfig,
			existingConfigMap: &baseConfigMap,
			auth:              &authResourceWithOIDC,
			expectedConfig:    baseConfig,
			expectedSynced: map[string]string{
				"configmap/auth-config.openshift-kube-apiserver": "configmap/auth-config.openshift-config",
			},
			expectEvents: true,
			expectErrors: false,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			synced := map[string]string{}
			eventRecorder := events.NewInMemoryRecorder("externaloidctest")

			if tt.authIndexer == nil {
				tt.authIndexer = cache.NewIndexer(func(obj interface{}) (string, error) {
					return "cluster", nil
				}, cache.Indexers{})
			}

			if tt.auth != nil {
				tt.authIndexer.Add(tt.auth)
			}

			if tt.cmIndexer == nil {
				tt.cmIndexer = cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
			}

			if tt.existingConfigMap != nil {
				tt.cmIndexer.Add(tt.existingConfigMap)
			}

			listers := configobservation.Listers{
				AuthConfigLister: configlistersv1.NewAuthenticationLister(tt.authIndexer),
				ConfigmapLister_: corelistersv1.NewConfigMapLister(tt.cmIndexer),
				ResourceSync:     &mockResourceSyncer{t: t, synced: synced},
			}

			c := externalOIDC{featureGateAccessor: tt.featureGates}
			actualConfig, errs := c.ObserveExternalOIDC(listers, eventRecorder, tt.existingConfig)

			if tt.expectErrors != (len(errs) > 0) {
				t.Errorf("expected errors: %v; got %v", tt.expectErrors, errs)
			}

			if recordedEvents := eventRecorder.Events(); tt.expectEvents != (len(recordedEvents) > 0) {
				t.Errorf("expected events: %v; got %v", tt.expectEvents, recordedEvents)
			}

			if !equality.Semantic.DeepEqual(tt.expectedConfig, actualConfig) {
				t.Errorf("unexpected config diff: %s", diff.ObjectReflectDiff(tt.expectedConfig, actualConfig))
			}

			if !equality.Semantic.DeepEqual(tt.expectedSynced, synced) {
				t.Errorf("expected resources not synced: %s", diff.ObjectReflectDiff(tt.expectedSynced, synced))
			}
		})
	}
}

func Test_validateAuthConfigMap(t *testing.T) {
	for _, tt := range []struct {
		name string

		configMap *corev1.ConfigMap

		expectError bool
	}{
		{
			name:        "nil configmap",
			configMap:   nil,
			expectError: true,
		},
		{
			name:        "configmap with empty data",
			configMap:   &corev1.ConfigMap{},
			expectError: true,
		},
		{
			name: "configmap does not contain key auth-config.json",
			configMap: &corev1.ConfigMap{Data: map[string]string{
				"some-key": "some-val",
			}},
			expectError: true,
		},
		{
			name: "configmap has empty value for key",
			configMap: &corev1.ConfigMap{Data: map[string]string{
				"auth-config.json": "",
			}},
			expectError: true,
		},
		{
			name: "configmap has invalid JSON",
			configMap: &corev1.ConfigMap{Data: map[string]string{
				"auth-config.json": "not-a-json-string",
			}},
			expectError: true,
		},
		{
			name: "configmap is valid",
			configMap: &corev1.ConfigMap{Data: map[string]string{
				"auth-config.json": `{"JWT":[{"Issuer":{"URL":"","DiscoveryURL":"","CertificateAuthority":"","Audiences":null,"AudienceMatchPolicy":""},"ClaimValidationRules":null,"ClaimMappings":{"Username":{"Claim":"","Prefix":null,"Expression":""},"Groups":{"Claim":"","Prefix":null,"Expression":""},"UID":{"Claim":"","Expression":""},"Extra":null},"UserValidationRules":null}]}`,
			}},
			expectError: false,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			err := validateAuthConfigMap(tt.configMap)

			if tt.expectError && err == nil {
				t.Errorf("expected error but didn't get any")
			}

			if !tt.expectError && err != nil {
				t.Errorf("did not expect any error but got: %v", err)
			}

		})
	}
}

func makeClosedChannel() chan struct{} {
	ch := make(chan struct{})
	close(ch)
	return ch
}

type everFailingIndexer struct{}

// Index always returns an error
func (i *everFailingIndexer) Index(indexName string, obj interface{}) ([]interface{}, error) {
	return nil, fmt.Errorf("Index method not implemented")
}

// IndexKeys always returns an error
func (i *everFailingIndexer) IndexKeys(indexName, indexedValue string) ([]string, error) {
	return nil, fmt.Errorf("IndexKeys method not implemented")
}

// ListIndexFuncValues always returns an error
func (i *everFailingIndexer) ListIndexFuncValues(indexName string) []string {
	return nil
}

// ByIndex always returns an error
func (i *everFailingIndexer) ByIndex(indexName, indexedValue string) ([]interface{}, error) {
	return nil, fmt.Errorf("ByIndex method not implemented")
}

// GetIndexers always returns an error
func (i *everFailingIndexer) GetIndexers() cache.Indexers {
	return nil
}

// AddIndexers always returns an error
func (i *everFailingIndexer) AddIndexers(newIndexers cache.Indexers) error {
	return fmt.Errorf("AddIndexers method not implemented")
}

// Add always returns an error
func (s *everFailingIndexer) Add(obj interface{}) error {
	return fmt.Errorf("Add method not implemented")
}

// Update always returns an error
func (s *everFailingIndexer) Update(obj interface{}) error {
	return fmt.Errorf("Update method not implemented")
}

// Delete always returns an error
func (s *everFailingIndexer) Delete(obj interface{}) error {
	return fmt.Errorf("Delete method not implemented")
}

// List always returns nil
func (s *everFailingIndexer) List() []interface{} {
	return nil
}

// ListKeys always returns nil
func (s *everFailingIndexer) ListKeys() []string {
	return nil
}

// Get always returns an error
func (s *everFailingIndexer) Get(obj interface{}) (item interface{}, exists bool, err error) {
	return nil, false, fmt.Errorf("Get method not implemented")
}

// GetByKey always returns an error
func (s *everFailingIndexer) GetByKey(key string) (item interface{}, exists bool, err error) {
	return nil, false, fmt.Errorf("GetByKey method not implemented")
}

// Replace always returns an error
func (s *everFailingIndexer) Replace(objects []interface{}, sKey string) error {
	return fmt.Errorf("Replace method not implemented")
}

// Resync always returns an error
func (s *everFailingIndexer) Resync() error {
	return fmt.Errorf("Resync method not implemented")
}
