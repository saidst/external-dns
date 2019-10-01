/*
Copyright 2017 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package provider

import (
	"context"
	"fmt"
	"io/ioutil"
	"strings"

	log "github.com/sirupsen/logrus"

	"gopkg.in/yaml.v2"

	"github.com/Azure/azure-sdk-for-go/services/dns/mgmt/2018-05-01/dns"
	"github.com/Azure/go-autorest/autorest"
	"github.com/Azure/go-autorest/autorest/adal"
	"github.com/Azure/go-autorest/autorest/azure"
	"github.com/Azure/go-autorest/autorest/to"

	"github.com/kubernetes-incubator/external-dns/endpoint"
	"github.com/kubernetes-incubator/external-dns/plan"
)

const (
	azureRecordTTL = 300
)

type config struct {
	Cloud                       string `json:"cloud" yaml:"cloud"`
	TenantID                    string `json:"tenantId" yaml:"tenantId"`
	SubscriptionID              string `json:"subscriptionId" yaml:"subscriptionId"`
	ResourceGroup               string `json:"resourceGroup" yaml:"resourceGroup"`
	Location                    string `json:"location" yaml:"location"`
	ClientID                    string `json:"aadClientId" yaml:"aadClientId"`
	ClientSecret                string `json:"aadClientSecret" yaml:"aadClientSecret"`
	UseManagedIdentityExtension bool   `json:"useManagedIdentityExtension" yaml:"useManagedIdentityExtension"`
}

// create general structs and interfaces to decouple from particular types of Azure DNS and Azure Private DNS
type Zone struct {
	Name string
	Id   string
	Type string
}

type ZonesClient interface {
	ListByResourceGroupComplete(ctx context.Context, resourceGroupName string) ([]Zone, error)
}

type PublicZonesClient struct {
	*dns.ZonesClient
}

// PublicRecordSetsClient is an interface of dns.PublicRecordSetsClient that can be stubbed for testing.
type PublicRecordSetsClient interface {
	ListAllByDNSZoneComplete(ctx context.Context, resourceGroupName string, zoneName string, top *int32, recordSetNameSuffix string) (result dns.RecordSetListResultIterator, err error)
	Delete(ctx context.Context, resourceGroupName string, zoneName string, relativeRecordSetName string, recordType dns.RecordType, ifMatch string) (result autorest.Response, err error)
	CreateOrUpdate(ctx context.Context, resourceGroupName string, zoneName string, relativeRecordSetName string, recordType dns.RecordType, parameters dns.RecordSet, ifMatch string, ifNoneMatch string) (result dns.RecordSet, err error)
}

// AzureProvider implements the DNS provider for Microsoft's Azure cloud platform.
type AzureProvider struct {
	domainFilter           DomainFilter
	zoneIDFilter           ZoneIDFilter
	dryRun                 bool
	resourceGroup          string
	publicZonesClient      ZonesClient
	publicRecordSetsClient PublicRecordSetsClient
}

// NewAzureProvider creates a new Azure provider.
//
// Returns the provider or an error if a provider could not be created.
func NewAzureProvider(configFile string, domainFilter DomainFilter, zoneIDFilter ZoneIDFilter, resourceGroup string, dryRun bool) (*AzureProvider, error) {
	contents, err := ioutil.ReadFile(configFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read Azure config file '%s': %v", configFile, err)
	}
	cfg := config{}
	err = yaml.Unmarshal(contents, &cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to read Azure config file '%s': %v", configFile, err)
	}

	// If a resource group was given, override what was present in the config file
	if resourceGroup != "" {
		cfg.ResourceGroup = resourceGroup
	}

	var environment azure.Environment
	if cfg.Cloud == "" {
		environment = azure.PublicCloud
	} else {
		environment, err = azure.EnvironmentFromName(cfg.Cloud)
		if err != nil {
			return nil, fmt.Errorf("invalid cloud value '%s': %v", cfg.Cloud, err)
		}
	}

	token, err := getAccessToken(cfg, environment)
	if err != nil {
		return nil, fmt.Errorf("failed to get token: %v", err)
	}

	// Public DNS
	zonesClient := dns.NewZonesClientWithBaseURI(environment.ResourceManagerEndpoint, cfg.SubscriptionID)
	zonesClient.Authorizer = autorest.NewBearerAuthorizer(token)
	publicZonesClient := PublicZonesClient{&zonesClient}

	recordSetsClient := dns.NewRecordSetsClientWithBaseURI(environment.ResourceManagerEndpoint, cfg.SubscriptionID)
	recordSetsClient.Authorizer = autorest.NewBearerAuthorizer(token)

	// Private DNS
	//privateZonesClient := privatedns.NewPrivateZonesClientWithBaseURI(environment.ResourceManagerEndpoint, cfg.SubscriptionID)

	provider := &AzureProvider{
		domainFilter:           domainFilter,
		zoneIDFilter:           zoneIDFilter,
		dryRun:                 dryRun,
		resourceGroup:          cfg.ResourceGroup,
		publicZonesClient:      publicZonesClient,
		publicRecordSetsClient: recordSetsClient,
	}
	return provider, nil
}

// getAccessToken retrieves Azure API access token.
func getAccessToken(cfg config, environment azure.Environment) (*adal.ServicePrincipalToken, error) {
	// Try to retrive token with MSI.
	if cfg.UseManagedIdentityExtension {
		log.Info("Using managed identity extension to retrieve access token for Azure API.")
		msiEndpoint, err := adal.GetMSIVMEndpoint()
		if err != nil {
			return nil, fmt.Errorf("failed to get the managed service identity endpoint: %v", err)
		}

		token, err := adal.NewServicePrincipalTokenFromMSI(msiEndpoint, environment.ServiceManagementEndpoint)
		if err != nil {
			return nil, fmt.Errorf("failed to create the managed service identity token: %v", err)
		}
		return token, nil
	}

	// Try to retrieve token with service principal credentials.
	if len(cfg.ClientID) > 0 && len(cfg.ClientSecret) > 0 {
		log.Info("Using client_id+client_secret to retrieve access token for Azure API.")
		oauthConfig, err := adal.NewOAuthConfig(environment.ActiveDirectoryEndpoint, cfg.TenantID)
		if err != nil {
			return nil, fmt.Errorf("failed to retrieve OAuth config: %v", err)
		}

		token, err := adal.NewServicePrincipalToken(*oauthConfig, cfg.ClientID, cfg.ClientSecret, environment.ResourceManagerEndpoint)
		if err != nil {
			return nil, fmt.Errorf("failed to create service principal token: %v", err)
		}
		return token, nil
	}

	return nil, fmt.Errorf("no credentials provided for Azure API")
}

// Records gets the current records.
//
// Returns the current records or an error if the operation failed.
func (p *AzureProvider) Records() (endpoints []*endpoint.Endpoint, _ error) {
	ctx := context.Background()
	zones, err := p.readZones(ctx)
	if err != nil {
		return nil, err
	}

	discoveredEndpoints := []*endpoint.Endpoint{}
	for _, zone := range zones {
		zoneEndpoints, err := p.getRecordsByZoneName(ctx, zone.Name)
		discoveredEndpoints = append(discoveredEndpoints, zoneEndpoints...)
		if err != nil {
			return nil, err
		}
	}
	return discoveredEndpoints, nil
}

// ApplyChanges applies the given changes.
//
// Returns nil if the operation was successful or an error if the operation failed.
func (p *AzureProvider) ApplyChanges(ctx context.Context, changes *plan.Changes) error {
	zones, err := p.readZones(ctx)
	if err != nil {
		return err
	}

	deleted, updated := p.mapChanges(zones, changes)
	p.deleteRecords(ctx, deleted)
	p.updateRecords(ctx, updated)
	return nil
}

func (p PublicZonesClient) ListByResourceGroupComplete(ctx context.Context, resourceGroupName string) ([]Zone, error) {
	log.Debugf("Retrieving Azure DNS Zones for rg: %s.", resourceGroupName)

	var zones []Zone

	// public zones
	i, err := p.ZonesClient.ListByResourceGroupComplete(ctx, resourceGroupName, nil)
	if err != nil {
		return nil, err
	}

	err = i.NextWithContext(ctx)

	if err != nil {
		return nil, err
	}

	for i.NotDone() {
		zones = append(zones, Zone{
			Id:   *i.Value().ID,
			Name: *i.Value().Name,
			Type: "public",
		})

		err := i.NextWithContext(ctx)
		if err != nil {
			return nil, err
		}
	}

	return zones, nil
}

func (p *AzureProvider) readZones(ctx context.Context) ([]Zone, error) {
	log.Debugf("Retrieving public and private DNS Zones for RG: %s.", p.resourceGroup)

	var validatedZones []Zone

	// public zones
	unvalidatedPublicZones, err := p.publicZonesClient.ListByResourceGroupComplete(ctx, p.resourceGroup)
	if err != nil {
		return nil, err
	}

	for _, unvalidatedZone := range unvalidatedPublicZones {
		log.Debugf("Validating Zone: %v", unvalidatedZone.Name)

		if unvalidatedZone.Name == "" {
			continue
		}

		if !p.domainFilter.Match(unvalidatedZone.Name) {
			continue
		}

		if !p.zoneIDFilter.Match(unvalidatedZone.Id) {
			continue
		}

		validatedZones = append(validatedZones, unvalidatedZone)
	}

	log.Debugf("Found %d Azure DNS zone(s).", len(validatedZones))
	return validatedZones, nil
}

// getRecordsByZoneName returns all records for the specified zoneName.
func (p *AzureProvider) getRecordsByZoneName(ctx context.Context, zoneName string) ([]*endpoint.Endpoint, error) {
	log.Debugf("Retrieving Azure DNS records for zone '%s'.", zoneName)

	i, err := p.publicRecordSetsClient.ListAllByDNSZoneComplete(ctx, p.resourceGroup, zoneName, nil, "")

	if err != nil {
		return nil, err
	}

	err = i.NextWithContext(ctx)
	if err != nil {
		return nil, err
	}

	endpoints := []*endpoint.Endpoint{}

	for i.NotDone() {
		// validation of a record has been moved to a separate function
		ep, err := p.validateRecordSet(zoneName, i.Value())
		if err != nil {
			return nil, err
		}
		if ep != nil {
			endpoints = append(endpoints, ep)
		}

		err = i.NextWithContext(ctx)
		if err != nil {
			return nil, err
		}
	}

	return endpoints, nil
}

// validateRecordSet is a callback-function used to filter out records according to defined criteria.
func (p *AzureProvider) validateRecordSet(zoneName string, recordSet dns.RecordSet) (*endpoint.Endpoint, error) {
	if recordSet.Name == nil || recordSet.Type == nil {
		err := fmt.Errorf("Skipping invalid record set with nil name or type.")
		return nil, err
	}
	recordType := strings.TrimLeft(*recordSet.Type, "Microsoft.Network/dnszones/")
	if !supportedRecordType(recordType) {
		return nil, nil
	}
	name := formatAzureDNSName(*recordSet.Name, zoneName)
	targets := extractAzureTargets(&recordSet)
	if len(targets) == 0 {
		err := fmt.Errorf("Failed to extract targets for '%s' with type '%s'.", name, recordType)
		return nil, err
	}

	// all criteria has been passed
	var ttl endpoint.TTL
	if recordSet.TTL != nil {
		ttl = endpoint.TTL(*recordSet.TTL)
	}
	ep := endpoint.NewEndpointWithTTL(name, recordType, endpoint.TTL(ttl), targets...)
	log.Debugf(
		"Found %s record for '%s' with target '%s'.",
		ep.RecordType,
		ep.DNSName,
		ep.Targets,
	)

	return ep, nil
}

type azureChangeMap map[string][]*endpoint.Endpoint

func (p *AzureProvider) mapChanges(zones []Zone, changes *plan.Changes) (azureChangeMap, azureChangeMap) {
	ignored := map[string]bool{}
	deleted := azureChangeMap{}
	updated := azureChangeMap{}
	zoneNameIDMapper := zoneIDName{}
	for _, z := range zones {
		if z.Name != "" {
			zoneNameIDMapper.Add(z.Name, z.Name)
		}
	}
	mapChange := func(changeMap azureChangeMap, change *endpoint.Endpoint) {
		zone, _ := zoneNameIDMapper.FindZone(change.DNSName)
		if zone == "" {
			if _, ok := ignored[change.DNSName]; !ok {
				ignored[change.DNSName] = true
				log.Infof("Ignoring changes to '%s' because a suitable Azure DNS zone was not found.", change.DNSName)
			}
			return
		}
		// Ensure the record type is suitable
		changeMap[zone] = append(changeMap[zone], change)
	}

	for _, change := range changes.Delete {
		mapChange(deleted, change)
	}

	for _, change := range changes.UpdateOld {
		mapChange(deleted, change)
	}

	for _, change := range changes.Create {
		mapChange(updated, change)
	}

	for _, change := range changes.UpdateNew {
		mapChange(updated, change)
	}
	return deleted, updated
}

func (p *AzureProvider) deleteRecords(ctx context.Context, deleted azureChangeMap) {
	// Delete records first
	for zone, endpoints := range deleted {
		for _, endpoint := range endpoints {
			name := p.recordSetNameForZone(zone, endpoint)
			if p.dryRun {
				log.Infof("Would delete %s record named '%s' for Azure DNS zone '%s'.", endpoint.RecordType, name, zone)
			} else {
				log.Infof("Deleting %s record named '%s' for Azure DNS zone '%s'.", endpoint.RecordType, name, zone)
				if _, err := p.publicRecordSetsClient.Delete(ctx, p.resourceGroup, zone, name, dns.RecordType(endpoint.RecordType), ""); err != nil {
					log.Errorf(
						"Failed to delete %s record named '%s' for Azure DNS zone '%s': %v",
						endpoint.RecordType,
						name,
						zone,
						err,
					)
				}
			}
		}
	}
}

func (p *AzureProvider) updateRecords(ctx context.Context, updated azureChangeMap) {
	for zone, endpoints := range updated {
		for _, endpoint := range endpoints {
			name := p.recordSetNameForZone(zone, endpoint)
			if p.dryRun {
				log.Infof(
					"Would update %s record named '%s' to '%s' for Azure DNS zone '%s'.",
					endpoint.RecordType,
					name,
					endpoint.Targets,
					zone,
				)
				continue
			}

			log.Infof(
				"Updating %s record named '%s' to '%s' for Azure DNS zone '%s'.",
				endpoint.RecordType,
				name,
				endpoint.Targets,
				zone,
			)

			recordSet, err := p.newRecordSet(endpoint)
			if err == nil {
				_, err = p.publicRecordSetsClient.CreateOrUpdate(
					ctx,
					p.resourceGroup,
					zone,
					name,
					dns.RecordType(endpoint.RecordType),
					recordSet,
					"",
					"",
				)
			}
			if err != nil {
				log.Errorf(
					"Failed to update %s record named '%s' to '%s' for DNS zone '%s': %v",
					endpoint.RecordType,
					name,
					endpoint.Targets,
					zone,
					err,
				)
			}
		}
	}
}

func (p *AzureProvider) recordSetNameForZone(zone string, endpoint *endpoint.Endpoint) string {
	// Remove the zone from the record set
	name := endpoint.DNSName
	name = name[:len(name)-len(zone)]
	name = strings.TrimSuffix(name, ".")

	// For root, use @
	if name == "" {
		return "@"
	}
	return name
}

func (p *AzureProvider) newRecordSet(endpoint *endpoint.Endpoint) (dns.RecordSet, error) {
	var ttl int64 = azureRecordTTL
	if endpoint.RecordTTL.IsConfigured() {
		ttl = int64(endpoint.RecordTTL)
	}
	switch dns.RecordType(endpoint.RecordType) {
	case dns.A:
		aRecords := make([]dns.ARecord, len(endpoint.Targets))
		for i, target := range endpoint.Targets {
			aRecords[i] = dns.ARecord{
				Ipv4Address: to.StringPtr(target),
			}
		}
		return dns.RecordSet{
			RecordSetProperties: &dns.RecordSetProperties{
				TTL:      to.Int64Ptr(ttl),
				ARecords: &aRecords,
			},
		}, nil
	case dns.CNAME:
		return dns.RecordSet{
			RecordSetProperties: &dns.RecordSetProperties{
				TTL: to.Int64Ptr(ttl),
				CnameRecord: &dns.CnameRecord{
					Cname: to.StringPtr(endpoint.Targets[0]),
				},
			},
		}, nil
	case dns.TXT:
		return dns.RecordSet{
			RecordSetProperties: &dns.RecordSetProperties{
				TTL: to.Int64Ptr(ttl),
				TxtRecords: &[]dns.TxtRecord{
					{
						Value: &[]string{
							endpoint.Targets[0],
						},
					},
				},
			},
		}, nil
	}
	return dns.RecordSet{}, fmt.Errorf("unsupported record type '%s'", endpoint.RecordType)
}

// Helper function (shared with test code)
func formatAzureDNSName(recordName, zoneName string) string {
	if recordName == "@" {
		return zoneName
	}
	return fmt.Sprintf("%s.%s", recordName, zoneName)
}

// Helper function (shared with text code)
func extractAzureTargets(recordSet *dns.RecordSet) []string {
	properties := recordSet.RecordSetProperties
	if properties == nil {
		return []string{}
	}

	// Check for A records
	aRecords := properties.ARecords
	if aRecords != nil && len(*aRecords) > 0 && (*aRecords)[0].Ipv4Address != nil {
		targets := make([]string, len(*aRecords))
		for i, aRecord := range *aRecords {
			targets[i] = *aRecord.Ipv4Address
		}
		return targets
	}

	// Check for CNAME records
	cnameRecord := properties.CnameRecord
	if cnameRecord != nil && cnameRecord.Cname != nil {
		return []string{*cnameRecord.Cname}
	}

	// Check for TXT records
	txtRecords := properties.TxtRecords
	if txtRecords != nil && len(*txtRecords) > 0 && (*txtRecords)[0].Value != nil {
		values := (*txtRecords)[0].Value
		if values != nil && len(*values) > 0 {
			return []string{(*values)[0]}
		}
	}
	return []string{}
}
