package main

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/valyala/fasthttp"
	"time"
)

type OutlineVPN struct {
	apiURL  string
	session *fasthttp.Client
}

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

func NewOutlineVPN(apiURL, certSha256 string) (*OutlineVPN, error) {
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

func (vpn *OutlineVPN) GetKeys() ([]OutlineKey, error) {
	request := fasthttp.AcquireRequest()
	response := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(request)
	defer fasthttp.ReleaseResponse(response)

	request.SetRequestURI(fmt.Sprintf("%s/access-keys/", vpn.apiURL))

	if err := vpn.session.DoTimeout(request, response, time.Second*5); err != nil {
		return nil, err
	}

	if response.StatusCode() != fasthttp.StatusOK {
		return nil, errors.New("unable to retrieve keys")
	}

	var keys struct {
		AccessKeys []OutlineKey `json:"accessKeys"`
	}
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

	// GET method is used by default
	request.SetRequestURI(fmt.Sprintf("%s/access-keys/%s", vpn.apiURL, id))
	request.SetTimeout(time.Second * 5)

	var result OutlineKey
	if err := vpn.session.Do(request, response); err != nil {
		return result, err
	}

	if response.StatusCode() != fasthttp.StatusOK {
		return result, errors.New("unable to retrieve keys")
	}

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
		request.SetRequestURI(fmt.Sprintf("%s/access-keys", vpn.apiURL))
		request.Header.SetMethod(fasthttp.MethodPost)
		request.Header.IsPost()
	} else {
		request.SetRequestURI(fmt.Sprintf("%s/access-keys/%s", vpn.apiURL, key.ID))
		request.Header.SetMethod(fasthttp.MethodPut)
	}

	requestBody, err := json.Marshal(*key)
	if err != nil {
		return key, err
	}

	request.SetBody(requestBody)
	request.SetTimeout(time.Second * 5)

	if err := vpn.session.Do(request, response); err != nil {
		return key, err
	}

	if response.StatusCode() != fasthttp.StatusCreated {
		return key, errors.New("response error while adding new key")
	}

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

	request.SetRequestURI(fmt.Sprintf("%s/access-keys/%s", vpn.apiURL, id))
	request.Header.SetMethod(fasthttp.MethodDelete)
	request.SetTimeout(time.Second * 5)

	if err := vpn.session.Do(request, response); err != nil {
		return err
	}

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

	request.SetRequestURI(fmt.Sprintf("%s/access-keys/%s/name", vpn.apiURL, id))
	request.Header.SetMethod(fasthttp.MethodPut)
	request.SetTimeout(time.Second * 5)
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.SetBodyString(fmt.Sprintf("name=%s", name))

	if err := vpn.session.Do(request, response); err != nil {
		return err
	}

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

	request.SetRequestURI(fmt.Sprintf("%s/metrics/transfer", vpn.apiURL))
	if err := vpn.session.DoTimeout(request, response, time.Second*5); err != nil {
		return result, err
	}

	if response.StatusCode() >= fasthttp.StatusBadRequest {
		return result, errors.New("unable to get metrics for keys")
	}

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

	request.SetRequestURI(fmt.Sprintf("%s/server", vpn.apiURL))
	if err := vpn.session.DoTimeout(request, response, time.Second*5); err != nil {
		return result, err
	}

	if response.StatusCode() >= fasthttp.StatusBadRequest {
		return result, errors.New("unable to get metrics for keys")
	}

	if err := json.Unmarshal(response.Body(), &result); err != nil {
		return result, err
	}

	return result, nil
}
