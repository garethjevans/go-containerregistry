// Copyright 2018 Google LLC All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package transport

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
)

type bearerTransport struct {
	// Wrapped by bearerTransport.
	inner http.RoundTripper
	// Basic credentials that we exchange for bearer tokens.
	basic authn.Authenticator
	// Holds the bearer response from the token service.
	bearer *authn.Bearer
	// Registry to which we send bearer tokens.
	registry name.Registry
	// See https://tools.ietf.org/html/rfc6750#section-3
	realm string
	// See https://docs.docker.com/registry/spec/auth/token/
	service string
	scopes  []string
}

var _ http.RoundTripper = (*bearerTransport)(nil)

// RoundTrip implements http.RoundTripper
func (bt *bearerTransport) RoundTrip(in *http.Request) (*http.Response, error) {
	logrus.Debugf("entering RoundTrip()")
	sendRequest := func() (*http.Response, error) {
		hdr, err := bt.bearer.Authorization()
		if err != nil {
			logrus.Debugf("FAILED - bt.bearer.Authorization()")
			return nil, err
		}

		// http.Client handles redirects at a layer above the http.RoundTripper
		// abstraction, so to avoid forwarding Authorization headers to places
		// we are redirected, only set it when the authorization header matches
		// the registry with which we are interacting.
		// In case of redirect http.Client can use an empty Host, check URL too.
		logrus.Debugf("in.Host - %s", in.Host)
		logrus.Debugf("in.URL.Host - %s", in.URL.Host)
		logrus.Debugf("bt.registry.RegistryStr - %s", bt.registry.RegistryStr())
		if in.Host == bt.registry.RegistryStr() || in.URL.Host == bt.registry.RegistryStr() {
			logrus.Debugf("Setting authorisation header")
			in.Header.Set("Authorization", hdr)
		} else {
			logrus.Debugf("NOT Setting authorisation header")
		}
		in.Header.Set("User-Agent", transportName)
		return bt.inner.RoundTrip(in)
	}

	res, err := sendRequest()
	if err != nil {
		logrus.Debugf("FAILED - sending request...")
		return nil, err
	}

	// Perform a token refresh() and retry the request in case the token has expired
	if res.StatusCode == http.StatusUnauthorized {
		if err = bt.refresh(); err != nil {
			logrus.Debugf("FAILED - refresh()")
			return nil, err
		}
		logrus.Debugf("retrying request...")
		return sendRequest()
	}

	return res, err
}

func (bt *bearerTransport) refresh() error {
	logrus.Debugf("entering refresh()")
	u, err := url.Parse(bt.realm)
	if err != nil {
		logrus.Debugf("FAILED - url.Parse(%s)", bt.realm)
		return err
	}
	b := &basicTransport{
		inner:  bt.inner,
		auth:   bt.basic,
		target: u.Host,
	}
	client := http.Client{Transport: b}

	u.RawQuery = url.Values{
		"scope":   bt.scopes,
		"service": []string{bt.service},
	}.Encode()

	resp, err := client.Get(u.String())
	if err != nil {
		logrus.Debugf("FAILED - client.Get")
		return err
	}
	defer resp.Body.Close()

	if err := CheckError(resp, http.StatusOK); err != nil {
		logrus.Debugf("FAILED - CheckError")
		return err
	}

	logrus.Debugf("reading body")
	content, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		logrus.Debugf("FAILED - reading body")
		return err
	}

	// Some registries don't have "token" in the response. See #54.
	type tokenResponse struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
	}

	var response tokenResponse
	if err := json.Unmarshal(content, &response); err != nil {
		logrus.Debugf("FAILED - json.Unmarshal")
		return err
	}

	// Find a token to turn into a Bearer authenticator
	var bearer authn.Bearer
	if response.Token != "" {
		logrus.Debugf("setting new token")
		bearer = authn.Bearer{Token: response.Token}
	} else if response.AccessToken != "" {
		logrus.Debugf("setting new access_token")
		bearer = authn.Bearer{Token: response.AccessToken}
	} else {
		return fmt.Errorf("no token in bearer response:\n%s", content)
	}

	// DEBUG
	claims := strings.Split(bearer.Token,".")[1]
	data, err := base64.StdEncoding.DecodeString(claims)
	if err != nil {
		fmt.Println("error:", err)
	}
	fmt.Printf("%q\n", data)
	
	// Replace our old bearer authenticator (if we had one) with our newly refreshed authenticator.
	bt.bearer = &bearer
	return nil
}
