package main

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/valyala/fasthttp"
	"time"
)

// OutlineVPN represents connection source to manage Outline VPN server
type OutlineVPN struct {
	apiURL  string
	session *fasthttp.Client
}

// OutlineKey represents access key parameters for Outline server
type OutlineKey struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Password  string `json:"password"`
	Port      int64  `json:"port"`
	Method    string `json:"method"`
	AccessURL string `json:"accessUrl"`
}

// OutlineConnectionSource represents connection data given by Outline server
// https://www.reddit.com/r/outlinevpn/wiki/index/dynamic_access_keys/
type OutlineConnectionSource struct {
	Server     string `json:"server"`
	ServerPort uint   `json:"server_port"`
	Password   string `json:"password"`
	Method     string `json:"method"`
}

// ServerInfo represents Outline server info
type ServerInfo struct {
	Name               string `json:"name"`
	ServerID           string `json:"serverId"`
	MetricsEnabled     bool   `json:"metricsEnabled"`
	CreatedTimestampMs int64  `json:"createdTimestampMs"`
	Version            string `json:"version"`
	AccessKeyDataLimit struct {
		Bytes int64 `json:"bytes"`
	} `json:"accessKeyDataLimit"`
	PortForNewAccessKeys  int    `json:"portForNewAccessKeys"`
	HostnameForAccessKeys string `json:"hostnameForAccessKeys"`
}

// BytesTransferred represents transferred bytes by client when using Outline VPN
type BytesTransferred struct {
	BytesTransferredByUserId map[string]int64 `json:"bytesTransferredByUserId"`
}

// Set default timeout to 5 seconds
var defaultTimeout = time.Second * 5

func main() {
}

// NewOutlineVPN creates a new Outline VPN management connection source.
func NewOutlineVPN(apiURL string, certSha256 string) (*OutlineVPN, error) {
	// todo
	/*if certSha256 == "" {
		return nil, fmt.Errorf("no certificate SHA256 provided. Running without certificate is no longer supported")
	}*/

	// Creating a client
	client := &fasthttp.Client{
		TLSConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}

	// Create OutlineVPN instance with configured TLS client
	return &OutlineVPN{
		apiURL:  apiURL,
		session: client,
	}, nil
}

// NewOutlineConnection creates a new Outline client connection source.
func NewOutlineConnection(server string, port uint, password string, method string) *OutlineConnectionSource {
	return &OutlineConnectionSource{
		Server:     server,
		ServerPort: port,
		Password:   password,
		Method:     method,
	}
}

func (vpn *OutlineVPN) GetKeys() ([]OutlineKey, error) {
	request := fasthttp.AcquireRequest()
	response := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(request)
	defer fasthttp.ReleaseResponse(response)

	// Set request URI to apiURL/access-keys/
	request.SetRequestURI(fmt.Sprintf("%s/access-keys/", vpn.apiURL))

	if err := vpn.session.DoTimeout(request, response, defaultTimeout); err != nil {
		return nil, err
	}

	// If keys is gathered, status code always must be 200
	if response.StatusCode() != fasthttp.StatusOK {
		return nil, errors.New("unable to retrieve keys")
	}

	var keys struct {
		AccessKeys []OutlineKey `json:"accessKeys"`
	}

	// Trying unmarshal response body as AccessKeys array
	if err := json.Unmarshal(response.Body(), &keys); err != nil {
		return nil, err
	}

	return keys.AccessKeys, nil
}

func (vpn *OutlineVPN) GetKey(id string) (OutlineKey, error) {
	request := fasthttp.AcquireRequest()
	response := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(request)
	defer fasthttp.ReleaseResponse(response)

	var result OutlineKey

	// Set request URI to apiURL/access-keys/id
	request.SetRequestURI(fmt.Sprintf("%s/access-keys/%s", vpn.apiURL, id))
	// Executing request
	if err := vpn.session.DoTimeout(request, response, defaultTimeout); err != nil {
		return result, err
	}

	// If key is added, status code always must be 200
	if response.StatusCode() != fasthttp.StatusOK {
		return result, errors.New("unable to retrieve keys")
	}

	// Trying unmarshal response body as `OutlineKey`
	if err := json.Unmarshal(response.Body(), &result); err != nil {
		return result, err
	}

	return result, nil
}

func (vpn *OutlineVPN) AddKey(key *OutlineKey) (*OutlineKey, error) {
	request := fasthttp.AcquireRequest()
	response := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(request)
	defer fasthttp.ReleaseResponse(response)

	if key.ID == "" {
		// Set request URI to apiURL/access-keys/id
		request.SetRequestURI(fmt.Sprintf("%s/access-keys", vpn.apiURL))
		request.Header.SetMethod(fasthttp.MethodPost)
	} else {
		// Set request URI to apiURL/access-keys/
		request.SetRequestURI(fmt.Sprintf("%s/access-keys/%s", vpn.apiURL, key.ID))
		request.Header.SetMethod(fasthttp.MethodPut)
	}

	// Trying to marshal key as a json
	requestBody, err := json.Marshal(*key)
	if err != nil {
		return key, err
	}

	// Set body json
	request.SetBody(requestBody)
	// Executing request
	if err := vpn.session.DoTimeout(request, response, defaultTimeout); err != nil {
		return key, err
	}

	// If key is created, status code always must be 201
	if response.StatusCode() != fasthttp.StatusCreated {
		return key, errors.New("response error while adding new key")
	}

	// Trying to unmarshal response body as `OutlineKey`
	if err := json.Unmarshal(response.Body(), &key); err != nil {
		return key, err
	}

	return key, nil
}

func (vpn *OutlineVPN) DeleteKey(key *OutlineKey) error {
	return vpn.DeleteKeyByID(key.ID)
}

func (vpn *OutlineVPN) DeleteKeyByID(id string) error {
	request := fasthttp.AcquireRequest()
	response := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(request)
	defer fasthttp.ReleaseResponse(response)

	// Set request URI to apiURL/access-keys/id
	request.SetRequestURI(fmt.Sprintf("%s/access-keys/%s", vpn.apiURL, id))
	request.Header.SetMethod(fasthttp.MethodDelete)
	// Executing request
	if err := vpn.session.DoTimeout(request, response, defaultTimeout); err != nil {
		return err
	}

	// If key is deleted, status code always must be 204
	if response.StatusCode() != fasthttp.StatusNoContent {
		return errors.New("response error while adding new key")
	}

	return nil
}

func (vpn *OutlineVPN) RenameKey(key *OutlineKey, name string) error {
	err := vpn.RenameKeyByID(key.ID, name)
	if err != nil {
		return err
	}
	key.Name = name
	return nil
}

func (vpn *OutlineVPN) RenameKeyByID(id string, name string) error {
	request := fasthttp.AcquireRequest()
	response := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(request)
	defer fasthttp.ReleaseResponse(response)

	// Set request URI to apiURL/access-keys/id/name
	request.SetRequestURI(fmt.Sprintf("%s/access-keys/%s/name", vpn.apiURL, id))
	request.Header.SetMethod(fasthttp.MethodPut)
	request.Header.SetContentType("application/x-www-form-urlencoded")
	request.SetBodyString(fmt.Sprintf("name=%s", name))
	// Executing request
	if err := vpn.session.DoTimeout(request, response, defaultTimeout); err != nil {
		return err
	}

	// If key is renamed, status code always must be 204
	if response.StatusCode() != fasthttp.StatusNoContent {
		return errors.New("response error while renaming key")
	}

	return nil
}

func (vpn *OutlineVPN) GetTransferMetrics() (BytesTransferred, error) {
	request := fasthttp.AcquireRequest()
	response := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(request)
	defer fasthttp.ReleaseResponse(response)

	var result BytesTransferred

	// Set request URI to apiURL/metrics/transfer
	request.SetRequestURI(fmt.Sprintf("%s/metrics/transfer", vpn.apiURL))
	// Executing request
	if err := vpn.session.DoTimeout(request, response, defaultTimeout); err != nil {
		return result, err
	}

	// If data is gathered, status code always must be lower than 400
	if response.StatusCode() >= fasthttp.StatusBadRequest {
		return result, errors.New("unable to get metrics for keys")
	}

	// Trying to unmarshal response body as `BytesTransferred`
	if err := json.Unmarshal(response.Body(), &result); err != nil {
		return result, err
	}

	return result, nil
}

func (vpn *OutlineVPN) GetServerInfo() (ServerInfo, error) {
	request := fasthttp.AcquireRequest()
	response := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(request)
	defer fasthttp.ReleaseResponse(response)

	var result ServerInfo

	// Set request URI to apiURL/server
	request.SetRequestURI(fmt.Sprintf("%s/server", vpn.apiURL))
	// Executing request
	if err := vpn.session.DoTimeout(request, response, defaultTimeout); err != nil {
		return result, err
	}

	// If data is gathered, status code always must be lower than 400
	if response.StatusCode() >= fasthttp.StatusBadRequest {
		return result, errors.New("unable to get metrics for keys")
	}

	// Trying to unmarshal response body as `ServerInfo`
	if err := json.Unmarshal(response.Body(), &result); err != nil {
		return result, err
	}

	return result, nil
}
