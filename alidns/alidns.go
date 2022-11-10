package alidns

import (
	"fmt"
	"strings"

	"github.com/aliyun/alibaba-cloud-sdk-go/sdk"
	"github.com/aliyun/alibaba-cloud-sdk-go/sdk/auth/credentials"
	"github.com/aliyun/alibaba-cloud-sdk-go/sdk/requests"
	dns "github.com/aliyun/alibaba-cloud-sdk-go/services/alidns"

	"github.com/cert-manager/cert-manager/pkg/issuer/acme/dns/util"
)

type AliDNSClient struct {
	dnsClient *dns.Client
}

func NewClient(regionId string, accessToken string, secretKey string) (*AliDNSClient, error) {
	conf := sdk.NewConfig()

	credential := credentials.NewAccessKeyCredential(accessToken, secretKey)

	dnsClient, err := dns.NewClientWithOptions(regionId, conf, credential)

	if err != nil {
		return nil, err
	}

	return &AliDNSClient{dnsClient}, nil
}

func (c *AliDNSClient) CleanUp(resolvedZone string, resolvedFQDN string, delKey string) error {
	records, err := c.findTxtRecords(resolvedZone, resolvedFQDN)
	if err != nil {
		return fmt.Errorf("alicloud: error finding txt records: %v", err)
	}

	_, _, err = c.getHostedZone(resolvedZone)
	if err != nil {
		return fmt.Errorf("alicloud: %v", err)
	}
	for _, rec := range records {
		if delKey == rec.Value {
			request := dns.CreateDeleteDomainRecordRequest()
			request.RecordId = rec.RecordId
			_, err := c.dnsClient.DeleteDomainRecord(request)
			if err != nil {
				return fmt.Errorf("alicloud: error deleting domain record: %v", err)
			}
		}
	}
	return nil
}

func (c *AliDNSClient) getHostedZone(resolvedZone string) (string, string, error) {
	request := dns.CreateDescribeDomainsRequest()

	var domains []dns.DomainInDescribeDomains
	startPage := 1

	for {
		request.PageNumber = requests.NewInteger(startPage)

		response, err := c.dnsClient.DescribeDomains(request)
		if err != nil {
			return "", "", fmt.Errorf("alicloud: error describing domains: %v", err)
		}

		domains = append(domains, response.Domains.Domain...)

		if response.PageNumber*response.PageSize >= response.TotalCount {
			break
		}

		startPage++
	}

	var hostedZone dns.DomainInDescribeDomains
	for _, zone := range domains {
		if zone.DomainName == util.UnFqdn(resolvedZone) {
			hostedZone = zone
		}
	}

	if hostedZone.DomainId == "" {
		return "", "", fmt.Errorf("zone %s not found in AliDNS", resolvedZone)
	}
	return fmt.Sprintf("%v", hostedZone.DomainId), hostedZone.DomainName, nil
}

func (c *AliDNSClient) newTxtRecord(zone, fqdn, value string) *dns.AddDomainRecordRequest {
	request := dns.CreateAddDomainRecordRequest()
	request.Type = "TXT"
	request.DomainName = zone
	request.RR = c.extractRecordName(fqdn, zone)
	request.Value = value
	return request
}

func (c *AliDNSClient) findTxtRecords(domain string, fqdn string) ([]dns.Record, error) {
	_, zoneName, err := c.getHostedZone(domain)
	if err != nil {
		return nil, err
	}

	request := dns.CreateDescribeDomainRecordsRequest()
	request.DomainName = zoneName
	request.PageSize = requests.NewInteger(500)

	var records []dns.Record

	result, err := c.dnsClient.DescribeDomainRecords(request)
	if err != nil {
		return records, fmt.Errorf("alicloud: error describing domain records: %v", err)
	}

	recordName := c.extractRecordName(fqdn, zoneName)
	for _, record := range result.DomainRecords.Record {
		if record.RR == recordName {
			records = append(records, record)
		}
	}
	return records, nil
}

func (c *AliDNSClient) extractRecordName(fqdn, domain string) string {
	name := util.UnFqdn(fqdn)
	if idx := strings.Index(name, "."+domain); idx != -1 {
		return name[:idx]
	}
	return name
}

func (c *AliDNSClient) Present(ResolvedZone string, ResolvedFQDN string, Key string) error {
	_, zoneName, err := c.getHostedZone(ResolvedZone)
	if err != nil {
		return fmt.Errorf("alicloud: error getting hosted zones: %v", err)
	}

	recordAttributes := c.newTxtRecord(zoneName, ResolvedFQDN, Key)

	_, err = c.dnsClient.AddDomainRecord(recordAttributes)
	if err != nil {
		return fmt.Errorf("alicloud: error adding domain record: %v", err)
	}
	return nil
}
