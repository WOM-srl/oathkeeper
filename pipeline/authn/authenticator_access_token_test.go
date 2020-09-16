/*
 * Copyright © 2020 Alessandro Chitolina <alekitto@gmail.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * @author       Alessandro Chitolina <alekitto@gmail.com>
 * @copyright    2020 Alessandro Chitolina <alekitto@gmail.com>
 * @license  	 Apache-2.0
 */

package authn_test

import (
	"encoding/json"

	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/julienschmidt/httprouter"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tidwall/sjson"

	"github.com/ory/oathkeeper/driver/configuration"
	"github.com/ory/oathkeeper/internal"
	. "github.com/ory/oathkeeper/pipeline/authn"
	"github.com/ory/viper"
)

func TestAuthenticatorAccessToken(t *testing.T) {
	conf := internal.NewConfigurationWithDefaults()
	reg := internal.NewRegistry(conf)

	a, err := reg.PipelineAuthenticator("access_token")
	require.NoError(t, err)
	assert.Equal(t, "access_token", a.GetID())

	t.Run("method=authenticate", func(t *testing.T) {

		for k, tc := range []struct {
			d              string
			setup          func(*testing.T, *httprouter.Router)
			r              *http.Request
			config         json.RawMessage
			expectErr      bool
			expectExactErr error
			expectSess     *AuthenticationSession
		}{
			{
				d:         "should fail because no payloads",
				r:         &http.Request{Header: http.Header{}},
				expectErr: true,
			},
			{
				d: "should fail because wrong response",
				r: &http.Request{
					Form: map[string][]string{
						"token": {"token"},
					},
				},
				config: []byte(`{}`),
				setup: func(t *testing.T, m *httprouter.Router) {
					m.POST("/oauth2/introspect", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
						require.NoError(t, r.ParseForm())
						require.Equal(t, "token", r.Form.Get("token"))
						w.WriteHeader(http.StatusNotFound)
					})
				},
				expectErr: true,
			},
			{
				d:              "should return error saying that authenticator is not responsible for validating the request, as the token was not provided in a proper location (default)",
				r:              &http.Request{Header: http.Header{"Foobar": {"bearer token"}}},
				expectErr:      true,
				expectExactErr: ErrAuthenticatorNotResponsible,
			},
			{
				d: "should pass because the valid token was provided in a proper location",
				r: &http.Request{
					Form: map[string][]string{
						"token": {"token"},
					},
				},
				expectErr: false,
				setup: func(t *testing.T, m *httprouter.Router) {
					m.POST("/oauth2/introspect", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
						require.NoError(t, r.ParseForm())
						require.Equal(t, "token", r.Form.Get("token"))
						require.NoError(t, json.NewEncoder(w).Encode(&AuthenticatorAccessTokenResult{
							Active: true,
						}))
					})
				},
			},
			{
				d: "should fail because not active",
				r: &http.Request{
					Form: map[string][]string{
						"token": {"token"},
					},
				},
				setup: func(t *testing.T, m *httprouter.Router) {
					m.POST("/oauth2/introspect", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
						require.NoError(t, r.ParseForm())
						require.Equal(t, "token", r.Form.Get("token"))
						require.NoError(t, json.NewEncoder(w).Encode(&AuthenticatorAccessTokenResult{
							Active:  false,
							Subject: "subject",
							Extra:   map[string]interface{}{"extra": "foo"},
						}))
					})
				},
				expectErr: true,
			},
			{
				d: "should pass",
				r: &http.Request{
					Form: map[string][]string{
						"token": {"token"},
					},
				},
				config: []byte(`{}`),
				setup: func(t *testing.T, m *httprouter.Router) {
					m.POST("/oauth2/introspect", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
						require.NoError(t, r.ParseForm())
						require.NoError(t, json.NewEncoder(w).Encode(&AuthenticatorAccessTokenResult{
							Active:  true,
							Subject: "subject",
							Extra:   map[string]interface{}{"extra": "foo"},
						}))
					})
				},
				expectErr: false,
			},
		} {
			t.Run(fmt.Sprintf("case=%d/description=%s", k, tc.d), func(t *testing.T) {
				router := httprouter.New()
				if tc.setup != nil {
					tc.setup(t, router)
				}
				ts := httptest.NewServer(router)
				defer ts.Close()

				tc.config, _ = sjson.SetBytes(tc.config, "introspection_url", ts.URL+"/oauth2/introspect")
				sess := new(AuthenticationSession)
				err := a.Authenticate(tc.r, sess, tc.config, nil)
				if tc.expectErr {
					require.Error(t, err)
					if tc.expectExactErr != nil {
						assert.EqualError(t, err, tc.expectExactErr.Error(), "%+v", err)
					}
				} else {
					require.NoError(t, err)
				}

				if tc.expectSess != nil {
					assert.Equal(t, tc.expectSess, sess)
				}
			})
		}
	})

	t.Run("method=validate", func(t *testing.T) {
		viper.Set(configuration.ViperKeyAuthenticatorOAuth2TokenIntrospectionIsEnabled, false)
		require.Error(t, a.Validate(json.RawMessage(`{"introspection_url":""}`)))

		viper.Reset()
		viper.Set(configuration.ViperKeyAuthenticatorOAuth2TokenIntrospectionIsEnabled, true)
		require.Error(t, a.Validate(json.RawMessage(`{"introspection_url":""}`)))

		viper.Reset()
		viper.Set(configuration.ViperKeyAuthenticatorOAuth2TokenIntrospectionIsEnabled, false)
		require.Error(t, a.Validate(json.RawMessage(`{"introspection_url":"/oauth2/token"}`)))

		viper.Reset()
		viper.Set(configuration.ViperKeyAuthenticatorOAuth2TokenIntrospectionIsEnabled, true)
		require.Error(t, a.Validate(json.RawMessage(`{"introspection_url":"/oauth2/token"}`)))
	})
}
