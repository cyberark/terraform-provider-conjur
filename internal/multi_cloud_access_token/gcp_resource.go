package multi_cloud_access_token

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
)

var baseURL = "http://metadata/computeMetadata/v1/instance/service-accounts/default/identity"

type GCPTokenProvider struct {
	Account string
	HostID  string
}

func GetIdentityToken(account, hostId string) (string, error) {

	// Build query parameters
	params := url.Values{}
	audience := "conjur/" + account + "/" + hostId
	params.Add("audience", audience)
	params.Add("format", "full")

	// Build final URL with encoded parameters
	fullURL := fmt.Sprintf("%s?%s", baseURL, params.Encode())

	// Create a new request
	req, err := http.NewRequest("GET", fullURL, nil)
	if err != nil {
		log.Fatalf("Failed to create request for GCP metadata token: %v", err)
		return "", err
	}

	// Set required header
	req.Header.Add("Metadata-Flavor", "Google")

	// Perform the request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Fatalf("Request failed for GCP Metadata token: %v", err)
		return "", err
	}
	defer resp.Body.Close()

	// Check if response status is not 200 (OK)
    if resp.StatusCode != http.StatusOK {
        return "", fmt.Errorf("received non-200 response: %v", resp.Status)
    } 
	
	// Read the response
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("Failed to read response for GCP metadata token: %v", err)
		return "", err
	}
	
	return string(body), nil
}

func (g *GCPTokenProvider) Token(_ string) (string, error) {
	return GetIdentityToken(g.Account, g.HostID)
}
