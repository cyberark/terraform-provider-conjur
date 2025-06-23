package multi_cloud_access_token

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"
)

var (
	AWSMetadataURL      = "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
	AWSAvailabilityZone = "http://169.254.169.254/latest/meta-data/placement/availability-zone"
	AWSTokenURL         = "http://169.254.169.254/latest/api/token"
	Method              = "GET"
	Service             = "sts"
	Host                = "sts.amazonaws.com"
	Endpoint            = "https://sts.amazonaws.com"
	RequestParameters   = "Action=GetCallerIdentity&Version=2011-06-15"
)

type IAMTokenProvider struct {}

type ConjurIAMAuthnException struct{}
func (e *ConjurIAMAuthnException) Error() string {
	return "Conjur IAM authentication failed with 401 - Unauthorized. Check Conjur logs for more information"
}

type IAMRoleNotAvailableException struct{}
func (e *IAMRoleNotAvailableException) Error() string {
	return "IAM role is not available or incorrectly configured"
}

type InvalidAwsAccountIdException struct{}
func (e *InvalidAwsAccountIdException) Error() string {
	return "The AWS Account ID specified is invalid and must be a 12-digit number"
}

func validAWSAccountNumber(hostID string) bool {
	parts := strings.Split(hostID, "/")
	accountID := parts[len(parts)-2]
	return len(accountID) == 12
}

func sign(key []byte, msg string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(msg))
	return h.Sum(nil)
}

func getSignatureKey(secretKey, dateStamp, regionName, serviceName string) []byte {
	kDate := sign([]byte("AWS4"+secretKey), dateStamp)
	kRegion := sign(kDate, regionName)
	kService := sign(kRegion, serviceName)
	kSigning := sign(kService, "aws4_request")
	return kSigning
}

func getAWSRegion() string {
	return "us-east-1"
}

func getMetadataToken(url string) (string, error) {
	req, err := http.NewRequest("PUT", url, nil)
	if err != nil {
		return "", nil
	}
	req.Header.Set("X-aws-ec2-metadata-token-ttl-seconds", "900")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", nil
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", nil
	}
	return string(body), nil
}

func getIAMRoleName() (string, error) {
	token, err := getMetadataToken(AWSTokenURL)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequest("GET", AWSMetadataURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("X-aws-ec2-metadata-token", token)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("Failed to retrieve IAM role name: %v. Please verify if IAM role is mapped with AWS resource.", resp.Status)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return string(body), nil
}

func getIAMRoleMetadata(roleName, token string) (string, string, string, error) {
	headers := map[string]string{}
	if token != "" {
		headers["X-aws-ec2-metadata-token"] = token
	}
	client := &http.Client{}
	req, err := http.NewRequest("GET", AWSMetadataURL+roleName, nil)
	if err != nil {
		return "", "", "", err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", "", "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return "", "", "", &IAMRoleNotAvailableException{}
	}
	if resp.StatusCode != http.StatusOK {
		return "", "", "", fmt.Errorf("Error retrieving IAM role metadata: %d", resp.StatusCode)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", "", "", err
	}

	var result map[string]string
	if err := json.Unmarshal(body, &result); err != nil {
		return "", "", "", err
	}

	return result["AccessKeyId"], result["SecretAccessKey"], result["Token"], nil
}

func createCanonicalRequest(amzDate, token, signedHeaders, payloadHash string) string {
	canonicalURI := "/"
	canonicalQueryString := RequestParameters
	canonicalHeaders := fmt.Sprintf("host:%s\nx-amz-content-sha256:%s\nx-amz-date:%s\nx-amz-security-token:%s\n", Host, payloadHash, amzDate, token)
	signedHeaders = "host;x-amz-content-sha256;x-amz-date;x-amz-security-token"
	return fmt.Sprintf("%s\n%s\n%s\n%s\n%s\n%s", Method, canonicalURI, canonicalQueryString, canonicalHeaders, signedHeaders, payloadHash)
}

func getCanonicalRequestHash(canonicalRequest string) string {
	hash := sha256.New()
	hash.Write([]byte(canonicalRequest))
	return hex.EncodeToString(hash.Sum(nil))
}

func createConjurIAMAPIKey() (string, error) {
	iamRoleName, err := getIAMRoleName()
	if err != nil {
		return "", err
	}

	// Get metadata token
	metadataToken, err := getMetadataToken(AWSTokenURL)
	if err != nil {
		return "", err
	}

	// Retrieve IAM credentials using role name and metadata token
	accessKey, secretKey, token, err := getIAMRoleMetadata(iamRoleName, metadataToken)
	if err != nil {
		return "", err
	}

	// Generate signature and canonical request
	region := getAWSRegion()
	date := time.Now().UTC()
	amzDate := date.Format("20060102T150405Z")
	dateStamp := date.Format("20060102")

	signedHeaders := "host;x-amz-content-sha256;x-amz-date;x-amz-security-token"
	payloadHash := hex.EncodeToString(sha256.New().Sum([]byte("")))
	canonicalRequest := createCanonicalRequest(amzDate, token, signedHeaders, payloadHash)
	canonicalRequestHash := getCanonicalRequestHash(canonicalRequest)

	credentialScope := fmt.Sprintf("%s/%s/%s/aws4_request", dateStamp, region, Service)
	stringToSign := fmt.Sprintf("AWS4-HMAC-SHA256\n%s\n%s\n%s", amzDate, credentialScope, canonicalRequestHash)

	signingKey := getSignatureKey(secretKey, dateStamp, region, Service)
	signature := hex.EncodeToString(sign(signingKey, stringToSign))

	authorizationHeader := fmt.Sprintf("AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s", accessKey, credentialScope, signedHeaders, signature)

	headers := map[string]string{
		"host":                 Host,
		"x-amz-date":           amzDate,
		"x-amz-security-token": token,
		"x-amz-content-sha256": payloadHash,
		"authorization":        authorizationHeader,
	}

	headersJSON, err := json.Marshal(headers)
	if err != nil {
		return "", err
	}

	return string(headersJSON), nil
}

func (p *IAMTokenProvider) Token(_ string) (string, error) {

	iamAPIKey, err := createConjurIAMAPIKey()
	if err != nil {
		return "", err
	}

	return iamAPIKey, nil
}
