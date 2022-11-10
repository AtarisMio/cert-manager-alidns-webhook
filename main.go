package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sync"

	extapi "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	//"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	"github.com/cert-manager/cert-manager/pkg/acme/webhook/cmd"
	cmmetav1 "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/cert-manager/cert-manager/pkg/issuer/acme/dns/util"

	"github.com/ataris-mio/cert-manager-alidns-webhook/alidns"
)

var GroupName = os.Getenv("GROUP_NAME")

func main() {
	if GroupName == "" {
		panic("GROUP_NAME must be specified")
	}

	// This will register our custom DNS provider with the webhook serving
	// library, making it available as an API under the provided GroupName.
	// You can register multiple DNS provider implementations with a single
	// webhook, where the Name() method will be used to disambiguate between
	// the different implementations.
	cmd.RunWebhookServer(GroupName,
		&aliDNSProviderSolver{},
	)
}

// aliDNSProviderSolver implements the provider-specific logic needed to
// 'present' an ACME challenge TXT record for your own DNS provider.
// To do so, it must implement the `github.com/jetstack/cert-manager/pkg/acme/webhook.Solver`
// interface.
type aliDNSProviderSolver struct {
	client     *kubernetes.Clientset
	dnsClients sync.Map
}

// customDNSProviderConfig is a structure that is used to decode into when
// solving a DNS01 challenge.
// This information is provided by cert-manager, and may be a reference to
// additional configuration that's needed to solve the challenge for this
// particular certificate or issuer.
// This typically includes references to Secret resources containing DNS
// provider credentials, in cases where a 'multi-tenant' DNS solver is being
// created.
// If you do *not* require per-issuer or per-certificate configuration to be
// provided to your webhook, you can skip decoding altogether in favour of
// using CLI flags or similar to provide configuration.
// You should not include sensitive information here. If credentials need to
// be used by your provider here, you should reference a Kubernetes Secret
// resource and fetch these credentials using a Kubernetes clientset.
type aliDNSProviderConfig struct {
	Region             string                     `json:"region"`
	AccessKeySecretRef cmmetav1.SecretKeySelector `json:"accessKeySecretRef"`
	SecretKeySecretRef cmmetav1.SecretKeySelector `json:"secretKeySecretRef"`
}

// Name is used as the name for this DNS solver when referencing it on the ACME
// Issuer resource.
// This should be unique **within the group name**, i.e. you can have two
// solvers configured with the same Name() **so long as they do not co-exist
// within a single webhook deployment**.
// For example, `cloudflare` may be used as the name of a solver.
func (c *aliDNSProviderSolver) Name() string {
	return "alidns-solver"
}

// Present is responsible for actually presenting the DNS record with the
// DNS provider.
// This method should tolerate being called multiple times with the same value.
// cert-manager itself will later perform a self check to ensure that the
// solver has correctly configured the DNS provider.
func (c *aliDNSProviderSolver) Present(ch *v1alpha1.ChallengeRequest) error {
	cfg, err := loadConfig(ch.Config)
	if err != nil {
		return err
	}

	zoneName, err := util.FindZoneByFqdn(ch.ResolvedFQDN, util.RecursiveNameservers)
	if err != nil {
		return err
	}
	domainName := util.UnFqdn(zoneName)

	dnsClient, err := c.dnsClient(domainName, cfg, ch)
	if err != nil {
		return err
	}

	return dnsClient.Present(ch.ResolvedZone, ch.ResolvedFQDN, ch.Key)
}

func (c *aliDNSProviderSolver) dnsClient(domain string, cfg aliDNSProviderConfig, ch *v1alpha1.ChallengeRequest) (*alidns.AliDNSClient, error) {
	v, ok := c.dnsClients.Load(domain)
	if ok {
		return v.(*alidns.AliDNSClient), nil
	}

	accessKey, err := c.getSecretData(cfg.AccessKeySecretRef, ch.ResourceNamespace)
	if err != nil {
		return nil, err
	}

	secretKey, err := c.getSecretData(cfg.SecretKeySecretRef, ch.ResourceNamespace)
	if err != nil {
		return nil, err
	}

	client, err := alidns.NewClient(cfg.Region, accessKey, secretKey)
	if err != nil {
		return nil, err
	}
	c.dnsClients.Store(domain, client)
	return client, nil
}

// CleanUp should delete the relevant TXT record from the DNS provider console.
// If multiple TXT records exist with the same record name (e.g.
// _acme-challenge.example.com) then **only** the record with the same `key`
// value provided on the ChallengeRequest should be cleaned up.
// This is in order to facilitate multiple DNS validations for the same domain
// concurrently.
func (c *aliDNSProviderSolver) CleanUp(ch *v1alpha1.ChallengeRequest) error {
	cfg, err := loadConfig(ch.Config)
	if err != nil {
		return err
	}

	client, err := c.dnsClient(ch.ResolvedZone, cfg, ch)
	if err != nil {
		return err
	}

	return client.CleanUp(ch.ResolvedZone, ch.ResolvedFQDN, ch.Key)
}

// Initialize will be called when the webhook first starts.
// This method can be used to instantiate the webhook, i.e. initialising
// connections or warming up caches.
// Typically, the kubeClientConfig parameter is used to build a Kubernetes
// client that can be used to fetch resources from the Kubernetes API, e.g.
// Secret resources containing credentials used to authenticate with DNS
// provider accounts.
// The stopCh can be used to handle early termination of the webhook, in cases
// where a SIGTERM or similar signal is sent to the webhook process.
func (c *aliDNSProviderSolver) Initialize(kubeClientConfig *rest.Config, stopCh <-chan struct{}) error {
	cl, err := kubernetes.NewForConfig(kubeClientConfig)
	if err != nil {
		return err
	}

	c.client = cl

	///// END OF CODE TO MAKE KUBERNETES CLIENTSET AVAILABLE
	return nil
}

// loadConfig is a small helper function that decodes JSON configuration into
// the typed config struct.
func loadConfig(cfgJSON *extapi.JSON) (aliDNSProviderConfig, error) {
	cfg := aliDNSProviderConfig{}
	// handle the 'base case' where no configuration has been provided
	if cfgJSON == nil {
		return cfg, nil
	}
	if err := json.Unmarshal(cfgJSON.Raw, &cfg); err != nil {
		return cfg, fmt.Errorf("error decoding solver config: %v", err)
	}

	return cfg, nil
}

func (c *aliDNSProviderSolver) getSecretData(selector cmmetav1.SecretKeySelector, ns string) (string, error) {
	secret, err := c.client.CoreV1().Secrets(ns).Get(context.TODO(), selector.Name, metav1.GetOptions{})
	if err != nil {
		return "", fmt.Errorf("failed to get secret %q: %v", ns+"/"+selector.Name, err)
	}
	if data, ok := secret.Data[selector.Key]; ok {
		return string(data), nil
	}
	return "", fmt.Errorf("key not found in secret %q: %v", ns+"/"+selector.Name, err)
}
