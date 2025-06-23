package multi_cloud_access_token

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

var AzureBaseURL = "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01"

type AzureTokenProvider struct{}

type responseJson struct {
	AccessToken  string `json:"access_token"`
}

func (a *AzureTokenProvider) Token(client_id string) (string, error) {
	// Create HTTP request for a managed services for Azure resources token to access Azure Resource Manager
	var msi_endpoint *url.URL
	msi_endpoint, err := url.Parse(AzureBaseURL)
	if err != nil {
		fmt.Println("Error creating URL for Azure Metadata Token: ", err)
		return "", err
	}
	msi_parameters := msi_endpoint.Query()
	if client_id != "" {
		msi_parameters.Add("client_id", client_id)
	}
	msi_parameters.Add("resource", "https://management.azure.com/")
	msi_endpoint.RawQuery = msi_parameters.Encode()
	req, err := http.NewRequest("GET", msi_endpoint.String(), nil)
	if err != nil {
		fmt.Println("Error creating HTTP request for Azure Metadata Token: ", err)
		return "", err
	}
	req.Header.Add("Metadata", "true")

	// Call managed services for Azure resources token endpoint
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error calling Azure token endpoint: ", err)
		return "", err
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected status code from Azure metadata service: %d", resp.StatusCode)
	}
	
	// Pull out response body
	responseBytes, err := io.ReadAll(resp.Body)

	if err != nil {
		fmt.Println("Error retrieving Azure token: ", err)
		return "", err
	}

	// Unmarshall response body into struct
	var r responseJson
	err = json.Unmarshal(responseBytes, &r)
	if err != nil {
		fmt.Println("Error unmarshalling the response for Azure token:", err)
		return "", err
	}

	return r.AccessToken, nil
}
