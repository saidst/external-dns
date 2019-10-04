package provider

import (
	"context"
	"github.com/Azure/azure-sdk-for-go/services/dns/mgmt/2018-05-01/dns"
	"github.com/Azure/go-autorest/autorest"
	"github.com/kubernetes-incubator/external-dns/endpoint"
)

// interlayer which generalizes similar type system of Azure DNS and Azure Private DNS

type Zone struct {
	Name string
	Id   string
	Type string
}

type RecordSet struct {
	Name *string
	Type *string
	*RecordSetProperties
}

type RecordSetProperties struct {
	TTL         *int64
	ARecords    *[]ARecord
	CnameRecord *CnameRecord
	TxtRecords  *[]TxtRecord
}

type ARecord struct {
	Ipv4Address *string
}

type CnameRecord struct {
	Cname *string
}

type TxtRecord struct {
	Value *[]string
}

// interfaces used for mocking clients in tests
// they are not specific for Azure DNS and Azure Private

type ZonesClient interface {
	ListByResourceGroupComplete(ctx context.Context, resourceGroupName string) ([]Zone, error)
}

type RecordSetsClient interface {
	GetRecordsByZoneName(ctx context.Context, resourceGroupName string, zoneName string) ([]RecordSet, error)
	Delete(ctx context.Context, resourceGroupName string, zoneName string, relativeRecordSetName string, recordType dns.RecordType, ifMatch string) (result autorest.Response, err error)
	CreateOrUpdate(ctx context.Context, resourceGroupName string, zoneName string, relativeRecordSetName string, recordType dns.RecordType, parameters dns.RecordSet, ifMatch string, ifNoneMatch string) (result dns.RecordSet, err error)
}

// clients which extend the types of the Azure SDK through a general interface

type PublicZonesClient struct {
	*dns.ZonesClient
}

type PublicRecordSetsClient struct {
	*dns.RecordSetsClient
}

// AzureProvider implements the DNS provider for Microsoft's Azure cloud platform.
type AzureProvider struct {
	domainFilter           DomainFilter
	zoneIDFilter           ZoneIDFilter
	dryRun                 bool
	resourceGroup          string
	publicZonesClient      ZonesClient
	publicRecordSetsClient RecordSetsClient
}

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

type azureChangeMap map[string][]*endpoint.Endpoint
