// Copyright 2017 The OPA Authors. All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

// Package engine enables interaction between PAM modules and policy engine OPA.
package engine

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"time"

	"github.com/pkg/errors"
)

func TimeoutDialer(cTimeout time.Duration, rwTimeout time.Duration) func(net, addr string) (c net.Conn, err error) {
	return func(netw, addr string) (net.Conn, error) {
		conn, err := net.DialTimeout(netw, addr, cTimeout)
		if err != nil {
			return nil, err
		}
		conn.SetDeadline(time.Now().Add(rwTimeout))
		return conn, nil
	}
}

func NewTimeoutClient(connectTimeout time.Duration, readWriteTimeout time.Duration) *http.Client {

	return &http.Client{
		Transport: &http.Transport{
			Dial: TimeoutDialer(connectTimeout, readWriteTimeout),
		},
	}
}

// Engine provides methods to interact with OPA.
type Engine struct {
	URL string

	DisplayEndpoint string
	PullEndpoint    string
	AuthzEndpoint   string

	client *http.Client
}

func New(url, displayEndpoint, pullEndpoint, authzEndpoint string) Engine {
	return Engine{
		URL:             url,
		DisplayEndpoint: displayEndpoint,
		PullEndpoint:    pullEndpoint,
		AuthzEndpoint:   authzEndpoint,
		client:          NewTimeoutClient(5*time.Second, 5*time.Second),
	}
}

// call makes an HTTP call to the given policy engine endpoint using the method, params, headers and body given.
// If respBody is non-nil, it looks for and unmarshals the response body into respBody, which must be a pointer.
// It returns the response status and error encountered, if any.
func (e Engine) call(method, endpoint string, params, headers map[string]string, body, respBody interface{}) (int, error) {
	url, err := joinURL(e.URL, endpoint)
	if err != nil {
		return 0, err
	}

	log(logLevelError, "PARAMS %s %s %s %s %s %s", method, endpoint, params, headers, body, respBody)

	log(logLevelError, "URL %s", url)

	j, err := json.Marshal(body)
	if err != nil {
		return 0, errors.Wrapf(err, "unable to marshal JSON.")
	}

	log(logLevelError, "Unmarshaling %s", url)

	req, err := http.NewRequest(method, url, bytes.NewReader(j))
	if err != nil {
		return 0, errors.Wrapf(err, "could not create request using parameters: %s, %s, %v.", method, url, body)
	}

	// Add params to the request query.
	q := req.URL.Query()
	for key, val := range params {
		q.Add(key, val)
	}
	req.URL.RawQuery = q.Encode()

	// Add headers to to request.
	for key, val := range headers {
		req.Header.Add(key, val)
	}

	trace := &httptrace.ClientTrace{
		DNSDone: func(dnsInfo httptrace.DNSDoneInfo) {
			log(logLevelError, "DNS Info: %+v", dnsInfo)
		},
		GotConn: func(connInfo httptrace.GotConnInfo) {
			log(logLevelError, "Got Conn: %+v", connInfo)
		},
		ConnectStart: func(network, addr string) {
			log(logLevelError, "Connect start %s %s", network, addr)
		},
		DNSStart: func(info httptrace.DNSStartInfo) {
			log(logLevelError, "DNS start %+v", info)
		},
		GetConn: func(hostPort string) {
			log(logLevelError, "Get conn %s", hostPort)
		},
	}
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))

	log(logLevelError, "CALLING %s", url)

	resp, err := e.client.Do(req)
	log(logLevelError, "DONE CALL")

	if err != nil {
		return 0, errors.Wrapf(err, "unable to perform HTTP request.")
	}

	defer resp.Body.Close()
	j, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		return 0, errors.Wrapf(err, "unable to read response body: %v", resp.Body)
	}

	log(logLevelError, "got %s", string(j))

	if len(j) > 0 && respBody != nil {
		err = json.Unmarshal(j, respBody)
		if err != nil {
			return 0, errors.Wrapf(err, "unable to unmarshal json: %v", string(j))
		}
	}

	log(logLevelError, "done")

	return resp.StatusCode, nil
}

// joinURL combines resource addresses. Everything after the last / in a will be removed.
func joinURL(a, b string) (string, error) {
	x, err := url.Parse(a)
	if err != nil {
		return "", err
	}

	y, err := url.Parse(b)
	if err != nil {
		return "", err
	}

	return x.ResolveReference(y).String(), nil
}
