package auth

import (
	"fmt"
	"testing"

	configv1 "github.com/openshift/api/config/v1"
	"github.com/openshift/api/features"
	configlistersv1 "github.com/openshift/client-go/config/listers/config/v1"
	"github.com/openshift/cluster-kube-apiserver-operator/pkg/operator/configobservation"
	"github.com/openshift/cluster-kube-apiserver-operator/pkg/operator/operatorclient"
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
	baseAuthResource = configv1.AuthenticationSpec{
		Type: configv1.AuthenticationTypeOIDC,
		OIDCProviders: []configv1.OIDCProvider{
			{
				Name: "test-oidc-provider",
				Issuer: configv1.TokenIssuer{
					URL:                  "https://test-oidc-provider.com",
					CertificateAuthority: configv1.ConfigMapNameReference{Name: "oidc-ca-bundle"},
				},
				OIDCClients: []configv1.OIDCClientConfig{
					{
						ComponentName:      "console",
						ComponentNamespace: "openshift-console",
						ClientID:           "console-oidc-client",
					},
					{
						ComponentName:      "kube-apiserver",
						ComponentNamespace: "openshift-kube-apiserver",
						ClientID:           "test-oidc-client",
					},
				},
				ClaimMappings: configv1.TokenClaimMappings{
					Username: configv1.UsernameClaimMapping{
						TokenClaimMapping: configv1.TokenClaimMapping{
							Claim: "username",
						},
						PrefixPolicy: configv1.Prefix,
						Prefix: &configv1.UsernamePrefix{
							PrefixString: "oidc-user:",
						},
					},
					Groups: configv1.PrefixedClaimMapping{
						TokenClaimMapping: configv1.TokenClaimMapping{
							Claim: "groups",
						},
						Prefix: "oidc-group:",
					},
				},
				ClaimValidationRules: []configv1.TokenClaimValidationRule{
					{
						Type: configv1.TokenValidationRuleTypeRequiredClaim,
						RequiredClaim: &configv1.TokenRequiredClaim{
							Claim:         "username",
							RequiredValue: "test",
						},
					},
					{
						Type: configv1.TokenValidationRuleTypeRequiredClaim,
						RequiredClaim: &configv1.TokenRequiredClaim{
							Claim:         "email",
							RequiredValue: "test",
						},
					},
				},
			},
		},
	}

	baseConfig = map[string]interface{}{
		"apiServerArguments": map[string]interface{}{
			"oidc-issuer-url":      []interface{}{"https://test-oidc-provider.com"},
			"oidc-client-id":       []interface{}{"test-oidc-client"},
			"oidc-username-claim":  []interface{}{"username"},
			"oidc-username-prefix": []interface{}{"oidc-user:"},
			"oidc-groups-claim":    []interface{}{"groups"},
			"oidc-groups-prefix":   []interface{}{"oidc-group:"},
			"oidc-ca-file":         []interface{}{staticCABundleFilePath},
			"oidc-required-claim":  []interface{}{"username=test", "email=test"},
		},
	}
)

func TestObserveExternalOIDC(t *testing.T) {
	observeExternalOIDCFunc := NewObserveExternalOIDC(featuregates.NewHardcodedFeatureGateAccess([]configv1.FeatureGateName{features.FeatureGateExternalOIDC}, []configv1.FeatureGateName{}))

	tests := []struct {
		name              string
		existingConfig    map[string]interface{}
		existingCAContent string
		syncError         error
		authSpec          *configv1.AuthenticationSpec
		newCAContent      string
		expectErrs        bool
		expectEvents      bool
		expectedConfig    map[string]interface{}
		expectedSynced    map[string]string
	}{
		{
			name: "auth resource not found",
		},
		{
			name: "auth type is IntegratedOAuth",
			authSpec: &configv1.AuthenticationSpec{
				Type: configv1.AuthenticationTypeIntegratedOAuth,
			},
			expectedConfig: map[string]interface{}{},
			expectedSynced: map[string]string{
				"configmap/oidc-serving-ca-bundle.openshift-kube-apiserver": "DELETE",
			},
		},
		{
			name: "auth type is empty",
			authSpec: &configv1.AuthenticationSpec{
				Type: configv1.AuthenticationTypeIntegratedOAuth,
			},
			expectedConfig: map[string]interface{}{},
			expectedSynced: map[string]string{
				"configmap/oidc-serving-ca-bundle.openshift-kube-apiserver": "DELETE",
			},
		},
		{
			name: "auth type is None",
			authSpec: &configv1.AuthenticationSpec{
				Type: configv1.AuthenticationTypeNone,
			},
			expectedConfig: map[string]interface{}{},
			expectedSynced: map[string]string{
				"configmap/oidc-serving-ca-bundle.openshift-kube-apiserver": "DELETE",
			},
		},
		{
			name:           "auth type changed to IntegratedOAuth",
			existingConfig: baseConfig,
			authSpec: &configv1.AuthenticationSpec{
				Type: configv1.AuthenticationTypeIntegratedOAuth,
			},
			expectEvents:   true,
			expectedConfig: map[string]interface{}{},
			expectedSynced: map[string]string{
				"configmap/oidc-serving-ca-bundle.openshift-kube-apiserver": "DELETE",
			},
		},
		{
			name:           "auth type changed to empty",
			existingConfig: baseConfig,
			authSpec: &configv1.AuthenticationSpec{
				Type: configv1.AuthenticationTypeIntegratedOAuth,
			},
			expectEvents:   true,
			expectedConfig: map[string]interface{}{},
			expectedSynced: map[string]string{
				"configmap/oidc-serving-ca-bundle.openshift-kube-apiserver": "DELETE",
			},
		},
		{
			name:           "auth type changed to None",
			existingConfig: baseConfig,
			authSpec: &configv1.AuthenticationSpec{
				Type: configv1.AuthenticationTypeNone,
			},
			expectEvents:   true,
			expectedConfig: map[string]interface{}{},
			expectedSynced: map[string]string{
				"configmap/oidc-serving-ca-bundle.openshift-kube-apiserver": "DELETE",
			},
		},
		{
			name:      "sync error when auth type is IntegratedOAuth",
			syncError: fmt.Errorf("sync failed"),
			authSpec: &configv1.AuthenticationSpec{
				Type: configv1.AuthenticationTypeIntegratedOAuth,
			},
		},
		{
			name:      "sync error when auth type is empty",
			syncError: fmt.Errorf("sync failed"),
			authSpec: &configv1.AuthenticationSpec{
				Type: configv1.AuthenticationTypeIntegratedOAuth,
			},
		},
		{
			name: "no OIDC provider configured",
			authSpec: &configv1.AuthenticationSpec{
				Type: configv1.AuthenticationTypeOIDC,
			},
			expectErrs: true,
		},
		{
			name: "multiple OIDC providers configured",
			authSpec: &configv1.AuthenticationSpec{
				Type: configv1.AuthenticationTypeOIDC,
				OIDCProviders: []configv1.OIDCProvider{
					{Name: "oidc1"}, {Name: "oidc2"},
				},
			},
			expectErrs: true,
		},
		{
			name: "no OIDC client config found",
			authSpec: &configv1.AuthenticationSpec{
				Type: configv1.AuthenticationTypeOIDC,
				OIDCProviders: []configv1.OIDCProvider{
					{
						Name: "test-oidc-provider",
						OIDCClients: []configv1.OIDCClientConfig{
							{
								ComponentName:      "not-kube-apiserver",
								ComponentNamespace: "not-openshift-kube-apiserver",
								ClientID:           "test-oidc-client",
							},
						},
					},
				},
			},
			expectErrs: true,
		},
		{
			name: "invalid OIDC provider URL",
			authSpec: &configv1.AuthenticationSpec{
				Type: configv1.AuthenticationTypeOIDC,
				OIDCProviders: []configv1.OIDCProvider{
					{
						Name: "test-oidc-provider",
						Issuer: configv1.TokenIssuer{
							URL: "https:invalid-url",
						},
					},
				},
			},
			expectErrs: true,
		},
		{
			name: "invalid (http) OIDC provider URL",
			authSpec: &configv1.AuthenticationSpec{
				Type: configv1.AuthenticationTypeOIDC,
				OIDCProviders: []configv1.OIDCProvider{
					{
						Name: "test-oidc-provider",
						Issuer: configv1.TokenIssuer{
							URL: "http://new-test-oidc-provider.com",
						},
					},
				},
			},
			expectErrs: true,
		},
		{
			name:       "empty OIDC client ID",
			authSpec:   withClientID(baseAuthResource, ""),
			expectErrs: true,
		},
		{
			name:       "invalid required claim type",
			authSpec:   withClaimValidationRulesInvalidType(),
			expectErrs: true,
		},
		{
			name:       "nil required claim",
			authSpec:   withClaimValidationRulesNilRequiredClaim(),
			expectErrs: true,
		},
		{
			name:              "no change in OIDC config",
			existingConfig:    baseConfig,
			existingCAContent: "some-cert",
			authSpec:          &baseAuthResource,
			newCAContent:      "some-cert",
			expectedConfig:    baseConfig,
		},
		{
			name:           "new valid OIDC config",
			authSpec:       &baseAuthResource,
			expectedConfig: baseConfig,
			expectEvents:   true,
			expectedSynced: map[string]string{
				"configmap/oidc-serving-ca-bundle.openshift-kube-apiserver": "configmap/oidc-ca-bundle.openshift-config",
			},
		},
		{
			name:      "sync error when auth type is OIDC and config is valid",
			authSpec:  &baseAuthResource,
			syncError: fmt.Errorf("sync failed"),
		},
		{
			name:              "update OIDC url",
			existingConfig:    baseConfig,
			existingCAContent: "some-cert",
			authSpec:          withProviderURL(baseAuthResource, "https://new-test-oidc-provider.com"),
			newCAContent:      "some-cert",
			expectEvents:      true,
			expectedConfig: map[string]interface{}{
				"apiServerArguments": map[string]interface{}{
					"oidc-issuer-url":      []interface{}{"https://new-test-oidc-provider.com"},
					"oidc-client-id":       []interface{}{"test-oidc-client"},
					"oidc-username-claim":  []interface{}{"username"},
					"oidc-username-prefix": []interface{}{"oidc-user:"},
					"oidc-groups-claim":    []interface{}{"groups"},
					"oidc-groups-prefix":   []interface{}{"oidc-group:"},
					"oidc-ca-file":         []interface{}{staticCABundleFilePath},
					"oidc-required-claim":  []interface{}{"username=test", "email=test"},
				},
			},
		},
		{
			name:              "update OIDC client ID",
			existingConfig:    baseConfig,
			existingCAContent: "some-cert",
			authSpec:          withClientID(baseAuthResource, "new-test-oidc-client"),
			newCAContent:      "some-cert",
			expectEvents:      true,
			expectedConfig: map[string]interface{}{
				"apiServerArguments": map[string]interface{}{
					"oidc-issuer-url":      []interface{}{"https://test-oidc-provider.com"},
					"oidc-client-id":       []interface{}{"new-test-oidc-client"},
					"oidc-username-claim":  []interface{}{"username"},
					"oidc-username-prefix": []interface{}{"oidc-user:"},
					"oidc-groups-claim":    []interface{}{"groups"},
					"oidc-groups-prefix":   []interface{}{"oidc-group:"},
					"oidc-ca-file":         []interface{}{staticCABundleFilePath},
					"oidc-required-claim":  []interface{}{"username=test", "email=test"},
				},
			},
		},
		{
			name:              "update OIDC username claim",
			existingConfig:    baseConfig,
			existingCAContent: "some-cert",
			authSpec:          withUsernameClaim(baseAuthResource, "username2"),
			newCAContent:      "some-cert",
			expectEvents:      true,
			expectedConfig: map[string]interface{}{
				"apiServerArguments": map[string]interface{}{
					"oidc-issuer-url":      []interface{}{"https://test-oidc-provider.com"},
					"oidc-client-id":       []interface{}{"test-oidc-client"},
					"oidc-username-claim":  []interface{}{"username2"},
					"oidc-username-prefix": []interface{}{"oidc-user:"},
					"oidc-groups-claim":    []interface{}{"groups"},
					"oidc-groups-prefix":   []interface{}{"oidc-group:"},
					"oidc-ca-file":         []interface{}{staticCABundleFilePath},
					"oidc-required-claim":  []interface{}{"username=test", "email=test"},
				},
			},
		},
		{
			name:              "delete OIDC username claim",
			existingConfig:    baseConfig,
			existingCAContent: "some-cert",
			authSpec:          withUsernameClaim(baseAuthResource, ""),
			newCAContent:      "some-cert",
			expectEvents:      true,
			expectedConfig: map[string]interface{}{
				"apiServerArguments": map[string]interface{}{
					"oidc-issuer-url":      []interface{}{"https://test-oidc-provider.com"},
					"oidc-client-id":       []interface{}{"test-oidc-client"},
					"oidc-username-prefix": []interface{}{"oidc-user:"},
					"oidc-groups-claim":    []interface{}{"groups"},
					"oidc-groups-prefix":   []interface{}{"oidc-group:"},
					"oidc-ca-file":         []interface{}{staticCABundleFilePath},
					"oidc-required-claim":  []interface{}{"username=test", "email=test"},
				},
			},
		},
		{
			name:              "update OIDC username prefix",
			existingConfig:    baseConfig,
			existingCAContent: "some-cert",
			authSpec:          withUsernamePrefix(baseAuthResource, configv1.Prefix, "new-oidc-user:"),
			newCAContent:      "some-cert",
			expectEvents:      true,
			expectedConfig: map[string]interface{}{
				"apiServerArguments": map[string]interface{}{
					"oidc-issuer-url":      []interface{}{"https://test-oidc-provider.com"},
					"oidc-client-id":       []interface{}{"test-oidc-client"},
					"oidc-username-claim":  []interface{}{"username"},
					"oidc-username-prefix": []interface{}{"new-oidc-user:"},
					"oidc-groups-claim":    []interface{}{"groups"},
					"oidc-groups-prefix":   []interface{}{"oidc-group:"},
					"oidc-ca-file":         []interface{}{staticCABundleFilePath},
					"oidc-required-claim":  []interface{}{"username=test", "email=test"},
				},
			},
		},
		{
			name:              "change OIDC username policy to NoOpinion",
			existingConfig:    baseConfig,
			existingCAContent: "some-cert",
			authSpec:          withUsernamePrefix(baseAuthResource, configv1.NoOpinion, ""),
			newCAContent:      "some-cert",
			expectEvents:      true,
			expectedConfig: map[string]interface{}{
				"apiServerArguments": map[string]interface{}{
					"oidc-issuer-url":     []interface{}{"https://test-oidc-provider.com"},
					"oidc-client-id":      []interface{}{"test-oidc-client"},
					"oidc-username-claim": []interface{}{"username"},
					"oidc-groups-claim":   []interface{}{"groups"},
					"oidc-groups-prefix":  []interface{}{"oidc-group:"},
					"oidc-ca-file":        []interface{}{staticCABundleFilePath},
					"oidc-required-claim": []interface{}{"username=test", "email=test"},
				},
			},
		},
		{
			name:              "delete OIDC username prefix",
			existingConfig:    baseConfig,
			existingCAContent: "some-cert",
			authSpec:          withUsernamePrefix(baseAuthResource, configv1.NoPrefix, ""),
			newCAContent:      "some-cert",
			expectEvents:      true,
			expectedConfig: map[string]interface{}{
				"apiServerArguments": map[string]interface{}{
					"oidc-issuer-url":      []interface{}{"https://test-oidc-provider.com"},
					"oidc-client-id":       []interface{}{"test-oidc-client"},
					"oidc-username-claim":  []interface{}{"username"},
					"oidc-username-prefix": []interface{}{"-"},
					"oidc-groups-claim":    []interface{}{"groups"},
					"oidc-groups-prefix":   []interface{}{"oidc-group:"},
					"oidc-ca-file":         []interface{}{staticCABundleFilePath},
					"oidc-required-claim":  []interface{}{"username=test", "email=test"},
				},
			},
		},
		{
			name:              "update OIDC groups claim",
			existingConfig:    baseConfig,
			existingCAContent: "some-cert",
			authSpec:          withGroupsClaim(baseAuthResource, "new-groups"),
			newCAContent:      "some-cert",
			expectEvents:      true,
			expectedConfig: map[string]interface{}{
				"apiServerArguments": map[string]interface{}{
					"oidc-issuer-url":      []interface{}{"https://test-oidc-provider.com"},
					"oidc-client-id":       []interface{}{"test-oidc-client"},
					"oidc-username-claim":  []interface{}{"username"},
					"oidc-username-prefix": []interface{}{"oidc-user:"},
					"oidc-groups-claim":    []interface{}{"new-groups"},
					"oidc-groups-prefix":   []interface{}{"oidc-group:"},
					"oidc-ca-file":         []interface{}{staticCABundleFilePath},
					"oidc-required-claim":  []interface{}{"username=test", "email=test"},
				},
			},
		},
		{
			name:              "delete OIDC groups claim",
			existingConfig:    baseConfig,
			existingCAContent: "some-cert",
			authSpec:          withGroupsClaim(baseAuthResource, ""),
			newCAContent:      "some-cert",
			expectEvents:      true,
			expectedConfig: map[string]interface{}{
				"apiServerArguments": map[string]interface{}{
					"oidc-issuer-url":      []interface{}{"https://test-oidc-provider.com"},
					"oidc-client-id":       []interface{}{"test-oidc-client"},
					"oidc-username-claim":  []interface{}{"username"},
					"oidc-username-prefix": []interface{}{"oidc-user:"},
					"oidc-groups-prefix":   []interface{}{"oidc-group:"},
					"oidc-ca-file":         []interface{}{staticCABundleFilePath},
					"oidc-required-claim":  []interface{}{"username=test", "email=test"},
				},
			},
		},
		{
			name:              "update OIDC groups prefix",
			existingConfig:    baseConfig,
			existingCAContent: "some-cert",
			authSpec:          withGroupsPrefix(baseAuthResource, "new-oidc-group:"),
			newCAContent:      "some-cert",
			expectEvents:      true,
			expectedConfig: map[string]interface{}{
				"apiServerArguments": map[string]interface{}{
					"oidc-issuer-url":      []interface{}{"https://test-oidc-provider.com"},
					"oidc-client-id":       []interface{}{"test-oidc-client"},
					"oidc-username-claim":  []interface{}{"username"},
					"oidc-username-prefix": []interface{}{"oidc-user:"},
					"oidc-groups-claim":    []interface{}{"groups"},
					"oidc-groups-prefix":   []interface{}{"new-oidc-group:"},
					"oidc-ca-file":         []interface{}{staticCABundleFilePath},
					"oidc-required-claim":  []interface{}{"username=test", "email=test"},
				},
			},
		},
		{
			name:              "delete OIDC groups prefix",
			existingConfig:    baseConfig,
			existingCAContent: "some-cert",
			authSpec:          withGroupsPrefix(baseAuthResource, ""),
			newCAContent:      "some-cert",
			expectEvents:      true,
			expectedConfig: map[string]interface{}{
				"apiServerArguments": map[string]interface{}{
					"oidc-issuer-url":      []interface{}{"https://test-oidc-provider.com"},
					"oidc-client-id":       []interface{}{"test-oidc-client"},
					"oidc-username-claim":  []interface{}{"username"},
					"oidc-username-prefix": []interface{}{"oidc-user:"},
					"oidc-groups-claim":    []interface{}{"groups"},
					"oidc-ca-file":         []interface{}{staticCABundleFilePath},
					"oidc-required-claim":  []interface{}{"username=test", "email=test"},
				},
			},
		},
		{
			name:              "update OIDC ca name but same content",
			existingConfig:    baseConfig,
			existingCAContent: "some-cert",
			authSpec:          withCAName(baseAuthResource, "new-oidc-ca-bundle"),
			newCAContent:      "some-cert",
			expectedConfig:    baseConfig,
		},
		{
			name:              "update OIDC ca content",
			existingConfig:    baseConfig,
			existingCAContent: "some-cert",
			authSpec:          &baseAuthResource,
			newCAContent:      "some-new-cert",
			expectEvents:      true,
			expectedConfig:    baseConfig,
			expectedSynced: map[string]string{
				"configmap/oidc-serving-ca-bundle.openshift-kube-apiserver": "configmap/oidc-ca-bundle.openshift-config",
			},
		},
		{
			name:              "update OIDC ca name and content",
			existingConfig:    baseConfig,
			existingCAContent: "some-cert",
			authSpec:          withCAName(baseAuthResource, "new-oidc-ca-bundle"),
			newCAContent:      "some-new-cert",
			expectEvents:      true,
			expectedConfig:    baseConfig,
			expectedSynced: map[string]string{
				"configmap/oidc-serving-ca-bundle.openshift-kube-apiserver": "configmap/new-oidc-ca-bundle.openshift-config",
			},
		},
		{
			name:              "delete OIDC ca",
			existingConfig:    baseConfig,
			existingCAContent: "some-cert",
			authSpec:          withCAName(baseAuthResource, ""),
			expectEvents:      true,
			expectedConfig: map[string]interface{}{
				"apiServerArguments": map[string]interface{}{
					"oidc-issuer-url":      []interface{}{"https://test-oidc-provider.com"},
					"oidc-client-id":       []interface{}{"test-oidc-client"},
					"oidc-username-claim":  []interface{}{"username"},
					"oidc-username-prefix": []interface{}{"oidc-user:"},
					"oidc-groups-claim":    []interface{}{"groups"},
					"oidc-groups-prefix":   []interface{}{"oidc-group:"},
					"oidc-required-claim":  []interface{}{"username=test", "email=test"},
				},
			},
			expectedSynced: map[string]string{
				"configmap/oidc-serving-ca-bundle.openshift-kube-apiserver": "DELETE",
			},
		},
		{
			name:              "add required claim",
			existingConfig:    baseConfig,
			existingCAContent: "some-cert",
			authSpec:          withClaimValidationRules(baseAuthResource, "username", "test", "email", "test", "new-claim", "test"),
			newCAContent:      "some-cert",
			expectEvents:      true,
			expectedConfig: map[string]interface{}{
				"apiServerArguments": map[string]interface{}{
					"oidc-issuer-url":      []interface{}{"https://test-oidc-provider.com"},
					"oidc-client-id":       []interface{}{"test-oidc-client"},
					"oidc-username-claim":  []interface{}{"username"},
					"oidc-username-prefix": []interface{}{"oidc-user:"},
					"oidc-groups-claim":    []interface{}{"groups"},
					"oidc-groups-prefix":   []interface{}{"oidc-group:"},
					"oidc-ca-file":         []interface{}{staticCABundleFilePath},
					"oidc-required-claim":  []interface{}{"username=test", "email=test", "new-claim=test"},
				},
			},
		},
		{
			name:              "change required claim",
			existingConfig:    baseConfig,
			existingCAContent: "some-cert",
			authSpec:          withClaimValidationRules(baseAuthResource, "username", "test", "email", "test2"),
			newCAContent:      "some-cert",
			expectEvents:      true,
			expectedConfig: map[string]interface{}{
				"apiServerArguments": map[string]interface{}{
					"oidc-issuer-url":      []interface{}{"https://test-oidc-provider.com"},
					"oidc-client-id":       []interface{}{"test-oidc-client"},
					"oidc-username-claim":  []interface{}{"username"},
					"oidc-username-prefix": []interface{}{"oidc-user:"},
					"oidc-groups-claim":    []interface{}{"groups"},
					"oidc-groups-prefix":   []interface{}{"oidc-group:"},
					"oidc-ca-file":         []interface{}{staticCABundleFilePath},
					"oidc-required-claim":  []interface{}{"username=test", "email=test2"},
				},
			},
		},
		{
			name:              "delete all required claims",
			existingConfig:    baseConfig,
			existingCAContent: "some-cert",
			authSpec:          withClaimValidationRules(baseAuthResource),
			newCAContent:      "some-cert",
			expectEvents:      true,
			expectedConfig: map[string]interface{}{
				"apiServerArguments": map[string]interface{}{
					"oidc-issuer-url":      []interface{}{"https://test-oidc-provider.com"},
					"oidc-client-id":       []interface{}{"test-oidc-client"},
					"oidc-username-claim":  []interface{}{"username"},
					"oidc-username-prefix": []interface{}{"oidc-user:"},
					"oidc-groups-claim":    []interface{}{"groups"},
					"oidc-groups-prefix":   []interface{}{"oidc-group:"},
					"oidc-ca-file":         []interface{}{staticCABundleFilePath},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})

			if tt.authSpec != nil {
				auth := &configv1.Authentication{
					ObjectMeta: metav1.ObjectMeta{
						Name: "cluster",
					},
					Spec: *tt.authSpec,
				}
				if err := indexer.Add(auth); err != nil {
					t.Fatal(err)
				}

				if cmName := getCAName(auth); len(cmName) > 0 {
					cm := &corev1.ConfigMap{
						ObjectMeta: metav1.ObjectMeta{
							Name:      cmName,
							Namespace: caBundleSourceNamespace,
						},
						Data: map[string]string{
							"ca-bundle.crt": tt.newCAContent,
						},
					}
					if err := indexer.Add(cm); err != nil {
						t.Fatal(err)
					}
				}

				if len(tt.existingCAContent) > 0 {
					cm := &corev1.ConfigMap{
						ObjectMeta: metav1.ObjectMeta{
							Name:      TargetOIDCCAConfigMapName,
							Namespace: operatorclient.TargetNamespace,
						},
						Data: map[string]string{
							"ca-bundle.crt": tt.existingCAContent,
						},
					}
					if err := indexer.Add(cm); err != nil {
						t.Fatal(err)
					}
				}
			}

			synced := map[string]string{}
			eventRecorder := events.NewInMemoryRecorder("externaloidctest")
			listers := configobservation.Listers{
				AuthConfigLister: configlistersv1.NewAuthenticationLister(indexer),
				ConfigmapLister_: corelistersv1.NewConfigMapLister(indexer),
				ResourceSync:     &mockResourceSyncer{t: t, synced: synced, syncError: tt.syncError},
			}

			gotConfig, errs := observeExternalOIDCFunc(listers, eventRecorder, tt.existingConfig)

			if recordedEvents := eventRecorder.Events(); tt.expectEvents != (len(recordedEvents) > 0) {
				t.Errorf("expected events: %v, but got %v", tt.expectEvents, len(recordedEvents))
			}

			if (tt.expectErrs || tt.syncError != nil) && len(errs) == 0 {
				t.Error("expected errors, didn't get any")
			}

			if !tt.expectErrs && tt.syncError == nil && len(errs) > 0 {
				t.Errorf("expected 0 errors, got %v", len(errs))
				for _, err := range errs {
					t.Log(err.Error())
				}
			}

			if !equality.Semantic.DeepEqual(tt.expectedConfig, gotConfig) {
				t.Errorf("unexpected config diff: %s", diff.ObjectReflectDiff(tt.expectedConfig, gotConfig))
			}

			if !equality.Semantic.DeepEqual(tt.expectedSynced, synced) {
				t.Errorf("expected resources not synced: %s", diff.ObjectReflectDiff(tt.expectedSynced, synced))
			}

		})
	}
}

func TestCMNeedsSync(t *testing.T) {
	indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
	for _, cm := range []*corev1.ConfigMap{
		{
			ObjectMeta: metav1.ObjectMeta{Name: "cm1", Namespace: "ns1"},
			Data:       map[string]string{"keyA": "aaa", "keyB": "bbb", "key1": "val1"},
		},
		{
			ObjectMeta: metav1.ObjectMeta{Name: "cm2", Namespace: "ns2"},
			Data:       map[string]string{"keyA": "aaa", "keyB": "bbbbbb", "key2": "val2"},
		},
		{
			ObjectMeta: metav1.ObjectMeta{Name: "cm3", Namespace: "ns3"},
			Data:       map[string]string{"keyA": "aaaaaa", "keyB": "bbb"},
		},
		{
			ObjectMeta: metav1.ObjectMeta{Name: "cm4", Namespace: "ns4"},
			Data:       map[string]string{"keyA": "aaaaaa", "keyB": "bbb"},
		},
	} {
		if err := indexer.Add(cm); err != nil {
			t.Fatalf("could not add cm to indexer: %v", err)
		}
	}

	lister := configobservation.Listers{
		ConfigmapLister_: corelistersv1.NewConfigMapLister(indexer),
	}

	for _, tt := range []struct {
		name     string
		cm1, ns1 string
		cm2, ns2 string
		key      string

		expectNeedsSync bool
		expectError     bool
	}{
		{
			name: "configmap1 not found",
			cm1:  "not found", ns1: "ns1",
			cm2: "cm2", ns2: "ns2",
			expectNeedsSync: true,
		},
		{
			name: "configmap2 not found",
			cm1:  "cm1", ns1: "ns1",
			cm2: "not found", ns2: "ns2",
			expectError: true,
		},
		{
			name: "configmap key values equal",
			cm1:  "cm1", ns1: "ns1",
			cm2: "cm2", ns2: "ns2",
			key: "keyA", expectNeedsSync: false,
		},
		{
			name: "configmap key values different",
			cm1:  "cm1", ns1: "ns1",
			cm2: "cm2", ns2: "ns2",
			key: "keyB", expectNeedsSync: true,
		},
		{
			name: "configmap key not found in first cm",
			cm1:  "cm1", ns1: "ns1",
			cm2: "cm2", ns2: "ns2",
			key: "key2", expectNeedsSync: true,
		},
		{
			name: "configmap key not found in second cm",
			cm1:  "cm1", ns1: "ns1",
			cm2: "cm2", ns2: "ns2",
			key: "key1", expectNeedsSync: false, expectError: true,
		},
		{
			name: "configmap key not found in either cms",
			cm1:  "cm1", ns1: "ns1",
			cm2: "cm2", ns2: "ns2",
			key: "key3", expectNeedsSync: false, expectError: true,
		},
		{
			name: "configmap data values different",
			cm1:  "cm1", ns1: "ns1",
			cm2: "cm2", ns2: "ns2",
			key: "", expectNeedsSync: true,
		},
		{
			name: "configmap data values equal",
			cm1:  "cm3", ns1: "ns3",
			cm2: "cm3", ns2: "ns3",
			key: "", expectNeedsSync: false,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			equal, err := cmNeedsSync(lister, tt.cm1, tt.ns1, tt.cm2, tt.ns2, tt.key)

			if tt.expectError != (err != nil) {
				t.Errorf("expected error: %v; got error: %v", tt.expectError, err)
			}

			if tt.expectNeedsSync != equal {
				t.Errorf("expected equal: %v; got: %v", tt.expectNeedsSync, equal)
			}
		})
	}
}

func getCAName(auth *configv1.Authentication) string {
	if len(auth.Spec.OIDCProviders) != 1 {
		return ""
	}

	return auth.Spec.OIDCProviders[0].Issuer.CertificateAuthority.Name
}

func withProviderURL(authSpec configv1.AuthenticationSpec, url string) *configv1.AuthenticationSpec {
	authSpecCopy := authSpec.DeepCopy()
	authSpecCopy.OIDCProviders[0].Issuer.URL = url
	return authSpecCopy
}

func withClientID(authSpec configv1.AuthenticationSpec, id string) *configv1.AuthenticationSpec {
	idx := -1
	for i, cfg := range authSpec.OIDCProviders[0].OIDCClients {
		if cfg.ComponentName == componentName && cfg.ComponentNamespace == operatorclient.TargetNamespace {
			idx = i
		}
	}

	if idx == -1 {
		return &authSpec
	}

	authSpecCopy := authSpec.DeepCopy()
	authSpecCopy.OIDCProviders[0].OIDCClients[idx].ClientID = id
	return authSpecCopy
}

func withUsernameClaim(authSpec configv1.AuthenticationSpec, claim string) *configv1.AuthenticationSpec {
	authSpecCopy := authSpec.DeepCopy()
	authSpecCopy.OIDCProviders[0].ClaimMappings.Username.Claim = claim
	return authSpecCopy
}

func withUsernamePrefix(authSpec configv1.AuthenticationSpec, policy configv1.UsernamePrefixPolicy, prefix string) *configv1.AuthenticationSpec {
	authSpecCopy := authSpec.DeepCopy()
	authSpecCopy.OIDCProviders[0].ClaimMappings.Username.PrefixPolicy = policy

	switch policy {
	case configv1.Prefix:
		authSpecCopy.OIDCProviders[0].ClaimMappings.Username.Prefix = &configv1.UsernamePrefix{
			PrefixString: prefix,
		}
	case configv1.NoPrefix, configv1.NoOpinion:
		authSpecCopy.OIDCProviders[0].ClaimMappings.Username.Prefix = nil
	}

	return authSpecCopy
}

func withGroupsClaim(authSpec configv1.AuthenticationSpec, claim string) *configv1.AuthenticationSpec {
	authSpecCopy := authSpec.DeepCopy()
	authSpecCopy.OIDCProviders[0].ClaimMappings.Groups.Claim = claim
	return authSpecCopy
}

func withGroupsPrefix(authSpec configv1.AuthenticationSpec, prefix string) *configv1.AuthenticationSpec {
	authSpecCopy := authSpec.DeepCopy()
	authSpecCopy.OIDCProviders[0].ClaimMappings.Groups.Prefix = prefix
	return authSpecCopy
}

func withCAName(authSpec configv1.AuthenticationSpec, caName string) *configv1.AuthenticationSpec {
	authSpecCopy := authSpec.DeepCopy()
	authSpecCopy.OIDCProviders[0].Issuer.CertificateAuthority.Name = caName
	return authSpecCopy
}

// empty claims deletes all
func withClaimValidationRules(authSpec configv1.AuthenticationSpec, claims ...string) *configv1.AuthenticationSpec {
	authSpecCopy := authSpec.DeepCopy()
	authSpecCopy.OIDCProviders[0].ClaimValidationRules = nil

	if len(claims) == 0 {
		return authSpecCopy
	}

	authSpecCopy.OIDCProviders[0].ClaimValidationRules = make([]configv1.TokenClaimValidationRule, len(claims)/2)
	for i := 0; i < len(claims); i += 2 {
		authSpecCopy.OIDCProviders[0].ClaimValidationRules[i/2] = configv1.TokenClaimValidationRule{
			Type: configv1.TokenValidationRuleTypeRequiredClaim,
			RequiredClaim: &configv1.TokenRequiredClaim{
				Claim:         claims[i],
				RequiredValue: claims[i+1],
			},
		}
	}

	return authSpecCopy
}

func withClaimValidationRulesInvalidType() *configv1.AuthenticationSpec {
	spec := withClaimValidationRules(baseAuthResource, "username", "test")
	spec.OIDCProviders[0].ClaimValidationRules[0].Type = "invalid"
	return spec
}

func withClaimValidationRulesNilRequiredClaim() *configv1.AuthenticationSpec {
	spec := withClaimValidationRules(baseAuthResource, "username", "test")
	spec.OIDCProviders[0].ClaimValidationRules[0].RequiredClaim = nil
	return spec
}
