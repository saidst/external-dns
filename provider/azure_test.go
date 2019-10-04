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
	"encoding/json"
	"fmt"
	"testing"

	"github.com/Azure/azure-sdk-for-go/services/dns/mgmt/2018-05-01/dns"
	"github.com/Azure/go-autorest/autorest"
	"github.com/Azure/go-autorest/autorest/azure"
	"github.com/Azure/go-autorest/autorest/to"

	"github.com/kubernetes-incubator/external-dns/endpoint"
	"github.com/kubernetes-incubator/external-dns/internal/testutils"
	"github.com/kubernetes-incubator/external-dns/plan"
	"github.com/stretchr/testify/assert"
)

type mockZonesClient struct {
	zones []Zone
}

type mockRecordSetsClient struct {
	recordSets       []RecordSet
	deletedEndpoints []*endpoint.Endpoint
	updatedEndpoints []*endpoint.Endpoint
}

func createMockZone(zone string, id string) dns.Zone {
	return dns.Zone{
		ID:   to.StringPtr(id),
		Name: to.StringPtr(zone),
	}
}

func (client *mockZonesClient) ListByResourceGroupComplete(ctx context.Context, resourceGroupName string) ([]Zone, error) {
	return client.zones, nil
}

func aRecordSetPropertiesGetter(values []string, ttl int64) *RecordSetProperties {
	aRecords := make([]ARecord, len(values))
	for i, value := range values {
		aRecords[i] = ARecord{
			Ipv4Address: to.StringPtr(value),
		}
	}
	return &RecordSetProperties{
		TTL:      to.Int64Ptr(ttl),
		ARecords: &aRecords,
	}
}

func cNameRecordSetPropertiesGetter(values []string, ttl int64) *RecordSetProperties {
	return &RecordSetProperties{
		TTL: to.Int64Ptr(ttl),
		CnameRecord: &CnameRecord{
			Cname: to.StringPtr(values[0]),
		},
	}
}

func txtRecordSetPropertiesGetter(values []string, ttl int64) *RecordSetProperties {
	return &RecordSetProperties{
		TTL: to.Int64Ptr(ttl),
		TxtRecords: &[]TxtRecord{
			{
				Value: &[]string{values[0]},
			},
		},
	}
}

func othersRecordSetPropertiesGetter(values []string, ttl int64) *RecordSetProperties {
	return &RecordSetProperties{
		TTL: to.Int64Ptr(ttl),
	}
}

func createMockRecordSet(name, recordType string, values ...string) RecordSet {
	return createMockRecordSetMultiWithTTL(name, recordType, 0, values...)
}
func createMockRecordSetWithTTL(name, recordType, value string, ttl int64) RecordSet {
	return createMockRecordSetMultiWithTTL(name, recordType, ttl, value)
}
func createMockRecordSetMultiWithTTL(name, recordType string, ttl int64, values ...string) RecordSet {
	var getterFunc func(values []string, ttl int64) *RecordSetProperties

	switch recordType {
	case endpoint.RecordTypeA:
		getterFunc = aRecordSetPropertiesGetter
	case endpoint.RecordTypeCNAME:
		getterFunc = cNameRecordSetPropertiesGetter
	case endpoint.RecordTypeTXT:
		getterFunc = txtRecordSetPropertiesGetter
	default:
		getterFunc = othersRecordSetPropertiesGetter
	}
	return RecordSet{
		Name:                to.StringPtr(name),
		Type:                to.StringPtr("Microsoft.Network/dnszones/" + recordType),
		RecordSetProperties: getterFunc(values, ttl),
	}

}

func azureARecordSetPropertiesGetter(values []string, ttl int64) *dns.RecordSetProperties {
	aRecords := make([]dns.ARecord, len(values))
	for i, value := range values {
		aRecords[i] = dns.ARecord{
			Ipv4Address: to.StringPtr(value),
		}
	}
	return &dns.RecordSetProperties{
		TTL:      to.Int64Ptr(ttl),
		ARecords: &aRecords,
	}
}

func azureCNameRecordSetPropertiesGetter(values []string, ttl int64) *dns.RecordSetProperties {
	return &dns.RecordSetProperties{
		TTL: to.Int64Ptr(ttl),
		CnameRecord: &dns.CnameRecord{
			Cname: to.StringPtr(values[0]),
		},
	}
}

func azureTxtRecordSetPropertiesGetter(values []string, ttl int64) *dns.RecordSetProperties {
	return &dns.RecordSetProperties{
		TTL: to.Int64Ptr(ttl),
		TxtRecords: &[]dns.TxtRecord{
			{
				Value: &[]string{values[0]},
			},
		},
	}
}

func azureOthersRecordSetPropertiesGetter(values []string, ttl int64) *dns.RecordSetProperties {
	return &dns.RecordSetProperties{
		TTL: to.Int64Ptr(ttl),
	}
}

func createMockAzureRecordSet(name, recordType string, values ...string) dns.RecordSet {
	return createMockAzureRecordSetMultiWithTTL(name, recordType, 0, values...)
}
func createMockAzureRecordSetWithTTL(name, recordType, value string, ttl int64) dns.RecordSet {
	return createMockAzureRecordSetMultiWithTTL(name, recordType, ttl, value)
}
func createMockAzureRecordSetMultiWithTTL(name, recordType string, ttl int64, values ...string) dns.RecordSet {
	var getterFunc func(values []string, ttl int64) *dns.RecordSetProperties

	switch recordType {
	case endpoint.RecordTypeA:
		getterFunc = azureARecordSetPropertiesGetter
	case endpoint.RecordTypeCNAME:
		getterFunc = azureCNameRecordSetPropertiesGetter
	case endpoint.RecordTypeTXT:
		getterFunc = azureTxtRecordSetPropertiesGetter
	default:
		getterFunc = azureOthersRecordSetPropertiesGetter
	}
	return dns.RecordSet{
		Name:                to.StringPtr(name),
		Type:                to.StringPtr("Microsoft.Network/dnszones/" + recordType),
		RecordSetProperties: getterFunc(values, ttl),
	}

}

func (client *mockRecordSetsClient) GetRecordsByZoneName(ctx context.Context, resourceGroupName string, zoneName string) ([]RecordSet, error) {
	return client.recordSets, nil
}

func (client *mockRecordSetsClient) Delete(ctx context.Context, resourceGroupName string, zoneName string, relativeRecordSetName string, recordType dns.RecordType, ifMatch string) (result autorest.Response, err error) {
	client.deletedEndpoints = append(
		client.deletedEndpoints,
		endpoint.NewEndpoint(
			formatAzureDNSName(relativeRecordSetName, zoneName),
			string(recordType),
			"",
		),
	)
	return autorest.Response{}, nil
}

func (client *mockRecordSetsClient) CreateOrUpdate(ctx context.Context, resourceGroupName string, zoneName string, relativeRecordSetName string, recordType dns.RecordType, parameters dns.RecordSet, ifMatch string, ifNoneMatch string) (result dns.RecordSet, err error) {
	var ttl endpoint.TTL
	if parameters.TTL != nil {
		ttl = endpoint.TTL(*parameters.TTL)
	}
	client.updatedEndpoints = append(
		client.updatedEndpoints,
		endpoint.NewEndpointWithTTL(
			formatAzureDNSName(relativeRecordSetName, zoneName),
			string(recordType),
			ttl,
			extractAzureTargetsFromAzureRecordSet(&parameters)...,
		),
	)
	return parameters, nil
}

func newAzureProvider(domainFilter DomainFilter, zoneIDFilter ZoneIDFilter, dryRun bool, resourceGroup string, zonesClient ZonesClient, recordSetsClient RecordSetsClient) *AzureProvider {
	return &AzureProvider{
		domainFilter:           domainFilter,
		zoneIDFilter:           zoneIDFilter,
		dryRun:                 dryRun,
		resourceGroup:          resourceGroup,
		publicZonesClient:      zonesClient,
		publicRecordSetsClient: recordSetsClient,
	}
}

func validateAzureEndpoints(t *testing.T, endpoints []*endpoint.Endpoint, expected []*endpoint.Endpoint) {
	assert.True(t, testutils.SameEndpoints(endpoints, expected), "expected and actual endpoints don't match. %s:%s", endpoints, expected)
}

func TestAzureRecord(t *testing.T) {
	zonesClient := mockZonesClient{
		zones: []Zone{
			{
				Name: "example.com",
				Id:   "/dnszones/example.com",
				Type: "public",
			},
		},
	}

	recordSetsClient := mockRecordSetsClient{
		recordSets: []RecordSet{
			createMockRecordSet("@", "NS", "ns1-03.azure-dns.com."),
			createMockRecordSet("@", "SOA", "Email: azuredns-hostmaster.microsoft.com"),
			createMockRecordSet("@", endpoint.RecordTypeA, "123.123.123.122"),
			createMockRecordSet("@", endpoint.RecordTypeTXT, "heritage=external-dns,external-dns/owner=default"),
			createMockRecordSetWithTTL("nginx", endpoint.RecordTypeA, "123.123.123.123", 3600),
			createMockRecordSetWithTTL("nginx", endpoint.RecordTypeTXT, "heritage=external-dns,external-dns/owner=default", recordTTL),
			createMockRecordSetWithTTL("hack", endpoint.RecordTypeCNAME, "hack.azurewebsites.net", 10),
		},
	}

	provider := newAzureProvider(NewDomainFilter([]string{"example.com"}), NewZoneIDFilter([]string{""}), true, "k8s", &zonesClient, &recordSetsClient)

	actual, err := provider.Records()

	if err != nil {
		t.Fatal(err)
	}
	expected := []*endpoint.Endpoint{
		endpoint.NewEndpoint("example.com", endpoint.RecordTypeA, "123.123.123.122"),
		endpoint.NewEndpoint("example.com", endpoint.RecordTypeTXT, "heritage=external-dns,external-dns/owner=default"),
		endpoint.NewEndpointWithTTL("nginx.example.com", endpoint.RecordTypeA, 3600, "123.123.123.123"),
		endpoint.NewEndpointWithTTL("nginx.example.com", endpoint.RecordTypeTXT, recordTTL, "heritage=external-dns,external-dns/owner=default"),
		endpoint.NewEndpointWithTTL("hack.example.com", endpoint.RecordTypeCNAME, 10, "hack.azurewebsites.net"),
	}

	debug, _ := json.Marshal(actual)
	fmt.Printf("Debugging azure test: %v", debug)

	validateAzureEndpoints(t, actual, expected)
}

func TestAzureMultiRecord(t *testing.T) {
	zonesClient := mockZonesClient{
		zones: []Zone{
			{
				Name: "example.com",
				Id:   "/dnszones/example.com",
				Type: "public",
			},
		},
	}

	recordSetsClient := mockRecordSetsClient{
		recordSets: []RecordSet{
			createMockRecordSet("@", "NS", "ns1-03.azure-dns.com."),
			createMockRecordSet("@", "SOA", "Email: azuredns-hostmaster.microsoft.com"),
			createMockRecordSet("@", endpoint.RecordTypeA, "123.123.123.122", "234.234.234.233"),
			createMockRecordSet("@", endpoint.RecordTypeTXT, "heritage=external-dns,external-dns/owner=default"),
			createMockRecordSetMultiWithTTL("nginx", endpoint.RecordTypeA, 3600, "123.123.123.123", "234.234.234.234"),
			createMockRecordSetWithTTL("nginx", endpoint.RecordTypeTXT, "heritage=external-dns,external-dns/owner=default", recordTTL),
			createMockRecordSetWithTTL("hack", endpoint.RecordTypeCNAME, "hack.azurewebsites.net", 10),
		},
	}

	provider := newAzureProvider(NewDomainFilter([]string{"example.com"}), NewZoneIDFilter([]string{""}), true, "k8s", &zonesClient, &recordSetsClient)

	actual, err := provider.Records()

	if err != nil {
		t.Fatal(err)
	}
	expected := []*endpoint.Endpoint{
		endpoint.NewEndpoint("example.com", endpoint.RecordTypeA, "123.123.123.122", "234.234.234.233"),
		endpoint.NewEndpoint("example.com", endpoint.RecordTypeTXT, "heritage=external-dns,external-dns/owner=default"),
		endpoint.NewEndpointWithTTL("nginx.example.com", endpoint.RecordTypeA, 3600, "123.123.123.123", "234.234.234.234"),
		endpoint.NewEndpointWithTTL("nginx.example.com", endpoint.RecordTypeTXT, recordTTL, "heritage=external-dns,external-dns/owner=default"),
		endpoint.NewEndpointWithTTL("hack.example.com", endpoint.RecordTypeCNAME, 10, "hack.azurewebsites.net"),
	}

	validateAzureEndpoints(t, actual, expected)

}

func TestAzureApplyChanges(t *testing.T) {
	recordsClient := mockRecordSetsClient{}

	testAzureApplyChangesInternal(t, false, &recordsClient)

	validateAzureEndpoints(t, recordsClient.deletedEndpoints, []*endpoint.Endpoint{
		endpoint.NewEndpoint("old.example.com", endpoint.RecordTypeA, ""),
		endpoint.NewEndpoint("oldcname.example.com", endpoint.RecordTypeCNAME, ""),
		endpoint.NewEndpoint("deleted.example.com", endpoint.RecordTypeA, ""),
		endpoint.NewEndpoint("deletedcname.example.com", endpoint.RecordTypeCNAME, ""),
	})

	validateAzureEndpoints(t, recordsClient.updatedEndpoints, []*endpoint.Endpoint{
		endpoint.NewEndpointWithTTL("example.com", endpoint.RecordTypeA, endpoint.TTL(recordTTL), "1.2.3.4"),
		endpoint.NewEndpointWithTTL("example.com", endpoint.RecordTypeTXT, endpoint.TTL(recordTTL), "tag"),
		endpoint.NewEndpointWithTTL("foo.example.com", endpoint.RecordTypeA, endpoint.TTL(recordTTL), "1.2.3.4", "1.2.3.5"),
		endpoint.NewEndpointWithTTL("foo.example.com", endpoint.RecordTypeTXT, endpoint.TTL(recordTTL), "tag"),
		endpoint.NewEndpointWithTTL("bar.example.com", endpoint.RecordTypeCNAME, endpoint.TTL(recordTTL), "other.com"),
		endpoint.NewEndpointWithTTL("bar.example.com", endpoint.RecordTypeTXT, endpoint.TTL(recordTTL), "tag"),
		endpoint.NewEndpointWithTTL("other.com", endpoint.RecordTypeA, endpoint.TTL(recordTTL), "5.6.7.8"),
		endpoint.NewEndpointWithTTL("other.com", endpoint.RecordTypeTXT, endpoint.TTL(recordTTL), "tag"),
		endpoint.NewEndpointWithTTL("new.example.com", endpoint.RecordTypeA, 3600, "111.222.111.222"),
		endpoint.NewEndpointWithTTL("newcname.example.com", endpoint.RecordTypeCNAME, 10, "other.com"),
	})
}

func TestAzureApplyChangesDryRun(t *testing.T) {
	recordsClient := mockRecordSetsClient{}

	testAzureApplyChangesInternal(t, true, &recordsClient)

	validateAzureEndpoints(t, recordsClient.deletedEndpoints, []*endpoint.Endpoint{})

	validateAzureEndpoints(t, recordsClient.updatedEndpoints, []*endpoint.Endpoint{})
}

func testAzureApplyChangesInternal(t *testing.T, dryRun bool, client RecordSetsClient) {
	zonesClient := mockZonesClient{
		zones: []Zone{
			{
				Name: "example.com",
				Id:   "/dnszones/example.com",
				Type: "public",
			},
			{
				Name: "other.com",
				Id:   "/dnszones/other.com",
				Type: "public",
			},
		},
	}

	provider := newAzureProvider(
		NewDomainFilter([]string{""}),
		NewZoneIDFilter([]string{""}),
		dryRun,
		"group",
		&zonesClient,
		client,
	)

	createRecords := []*endpoint.Endpoint{
		endpoint.NewEndpoint("example.com", endpoint.RecordTypeA, "1.2.3.4"),
		endpoint.NewEndpoint("example.com", endpoint.RecordTypeTXT, "tag"),
		endpoint.NewEndpoint("foo.example.com", endpoint.RecordTypeA, "1.2.3.5", "1.2.3.4"),
		endpoint.NewEndpoint("foo.example.com", endpoint.RecordTypeTXT, "tag"),
		endpoint.NewEndpoint("bar.example.com", endpoint.RecordTypeCNAME, "other.com"),
		endpoint.NewEndpoint("bar.example.com", endpoint.RecordTypeTXT, "tag"),
		endpoint.NewEndpoint("other.com", endpoint.RecordTypeA, "5.6.7.8"),
		endpoint.NewEndpoint("other.com", endpoint.RecordTypeTXT, "tag"),
		endpoint.NewEndpoint("nope.com", endpoint.RecordTypeA, "4.4.4.4"),
		endpoint.NewEndpoint("nope.com", endpoint.RecordTypeTXT, "tag"),
	}

	currentRecords := []*endpoint.Endpoint{
		endpoint.NewEndpoint("old.example.com", endpoint.RecordTypeA, "121.212.121.212"),
		endpoint.NewEndpoint("oldcname.example.com", endpoint.RecordTypeCNAME, "other.com"),
		endpoint.NewEndpoint("old.nope.com", endpoint.RecordTypeA, "121.212.121.212"),
	}
	updatedRecords := []*endpoint.Endpoint{
		endpoint.NewEndpointWithTTL("new.example.com", endpoint.RecordTypeA, 3600, "111.222.111.222"),
		endpoint.NewEndpointWithTTL("newcname.example.com", endpoint.RecordTypeCNAME, 10, "other.com"),
		endpoint.NewEndpoint("new.nope.com", endpoint.RecordTypeA, "222.111.222.111"),
	}

	deleteRecords := []*endpoint.Endpoint{
		endpoint.NewEndpoint("deleted.example.com", endpoint.RecordTypeA, "111.222.111.222"),
		endpoint.NewEndpoint("deletedcname.example.com", endpoint.RecordTypeCNAME, "other.com"),
		endpoint.NewEndpoint("deleted.nope.com", endpoint.RecordTypeA, "222.111.222.111"),
	}

	changes := &plan.Changes{
		Create:    createRecords,
		UpdateNew: updatedRecords,
		UpdateOld: currentRecords,
		Delete:    deleteRecords,
	}

	if err := provider.ApplyChanges(context.Background(), changes); err != nil {
		t.Fatal(err)
	}
}

func TestAzureGetAccessToken(t *testing.T) {
	env := azure.PublicCloud
	cfg := config{
		ClientID:                    "",
		ClientSecret:                "",
		TenantID:                    "",
		UseManagedIdentityExtension: false,
	}

	_, err := getAccessToken(cfg, env)
	if err == nil {
		t.Fatalf("expected to fail, but got no error")
	}
}

func TestAzureConvertRecordSetToEndpoint(t *testing.T) {
	recordSet := createMockRecordSet("bar", endpoint.RecordTypeA, "111.222.333.444")
	actualEndpoint, err := convertRecordSetToEndpoint("example.com", recordSet)
	if err != nil {
		t.Fatalf("error validating recordSet: %s", err.Error())
	}

	expectedEndpoint := endpoint.NewEndpoint("bar.example.com", endpoint.RecordTypeA, "111.222.333.444")

	validateAzureEndpoints(t, []*endpoint.Endpoint{actualEndpoint}, []*endpoint.Endpoint{expectedEndpoint})
}

func TestAzureConvertAzureARecordSetToRecordSet(t *testing.T) {
	recordSet := createMockAzureRecordSet("bar", endpoint.RecordTypeA, "111.222.333.444")
	actualRecordSet := convertAzureRecordSetToRecordSet(recordSet)

	expectedRecordSet := RecordSet{
		Name: to.StringPtr("bar"),
		Type: to.StringPtr(endpoint.RecordTypeA),
		RecordSetProperties: &RecordSetProperties{
			ARecords: &[]ARecord{
				{
					Ipv4Address: to.StringPtr("111.222.333.444"),
				},
			},
		},
	}

	assert.True(t, compareRecordSets(actualRecordSet, &expectedRecordSet), "Records mismatch: %s vs. %s", (*actualRecordSet).toString(), (expectedRecordSet).toString())
}

func TestAzureConvertAzureAMultiRecordSetToRecordSet(t *testing.T) {
	recordSet := createMockAzureRecordSet("bar", endpoint.RecordTypeA, "111.222.333.444", "222.333.444.555")
	actualRecordSet := convertAzureRecordSetToRecordSet(recordSet)

	expectedRecordSet := RecordSet{
		Name: to.StringPtr("bar"),
		Type: to.StringPtr(endpoint.RecordTypeA),
		RecordSetProperties: &RecordSetProperties{
			ARecords: &[]ARecord{
				{
					Ipv4Address: to.StringPtr("111.222.333.444"),
				},
				{
					Ipv4Address: to.StringPtr("222.333.444.555"),
				},
			},
		},
	}

	assert.True(t, compareRecordSets(actualRecordSet, &expectedRecordSet), "Records mismatch: %s vs. %s", (*actualRecordSet).toString(), (expectedRecordSet).toString())
}

func TestAzureConvertAzureCNameRecordSetToRecordSet(t *testing.T) {
	recordSet := createMockAzureRecordSet("bar", endpoint.RecordTypeCNAME, "foo.example.com")
	actualRecordSet := convertAzureRecordSetToRecordSet(recordSet)

	expectedRecordSet := RecordSet{
		Name: to.StringPtr("bar"),
		Type: to.StringPtr(endpoint.RecordTypeA),
		RecordSetProperties: &RecordSetProperties{
			CnameRecord: &CnameRecord{
				Cname: to.StringPtr("foo.example.com"),
			},
		},
	}

	assert.True(t, compareRecordSets(actualRecordSet, &expectedRecordSet), "Records mismatch: %s vs. %s", (*actualRecordSet).toString(), (expectedRecordSet).toString())
}

func TestAzureConvertAzureTxtRecordSetToRecordSet(t *testing.T) {
	recordSet := createMockAzureRecordSet("bar", endpoint.RecordTypeTXT, "tag")
	actualRecordSet := convertAzureRecordSetToRecordSet(recordSet)

	expectedRecordSet := RecordSet{
		Name: to.StringPtr("bar"),
		Type: to.StringPtr(endpoint.RecordTypeTXT),
		RecordSetProperties: &RecordSetProperties{
			TxtRecords: &[]TxtRecord{
				{
					Value: to.StringSlicePtr([]string{"tag"}),
				},
			},
		},
	}

	assert.True(t, compareRecordSets(actualRecordSet, &expectedRecordSet), "Records mismatch: %s vs. %s", (*actualRecordSet).toString(), (expectedRecordSet).toString())
}

func compareRecordSets(actual *RecordSet, expected *RecordSet) bool {
	return (*actual).toString() == (*expected).toString()
}
