package authn

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/dgraph-io/ristretto"

	"github.com/pkg/errors"
	"golang.org/x/oauth2/clientcredentials"

	"github.com/ory/oathkeeper/driver/configuration"
	"github.com/ory/oathkeeper/helper"
	"github.com/ory/oathkeeper/pipeline"
	"github.com/ory/x/httpx"
)

type AuthenticatorAccessTokenConfiguration struct {
	PreAuth                     *AuthenticatorOAuth2IntrospectionPreAuthConfiguration `json:"pre_authorization"`
	IntrospectionURL            string                                                `json:"introspection_url"`
	IntrospectionRequestHeaders map[string]string                                     `json:"introspection_request_headers"`
	Retry                       *AuthenticatorOAuth2IntrospectionRetryConfiguration   `json:"retry"`
	Cache                       cacheConfig                                           `json:"cache"`
}

type AuthenticatorAccessToken struct {
	c configuration.Provider

	client *http.Client

	tokenCache *ristretto.Cache
	cacheTTL   *time.Duration
}

func NewAuthenticatorAccessToken(c configuration.Provider) *AuthenticatorAccessToken {
	var rt http.RoundTripper
	cache, _ := ristretto.NewCache(&ristretto.Config{
		// This will hold about 1000 unique mutation responses.
		NumCounters: 10000,
		// Allocate a max of 32MB
		MaxCost: 1 << 25,
		// This is a best-practice value.
		BufferItems: 64,
	})
	return &AuthenticatorAccessToken{c: c, client: httpx.NewResilientClientLatencyToleranceSmall(rt), tokenCache: cache}
}

func (a *AuthenticatorAccessToken) GetID() string {
	return "access_token"
}

type AuthenticatorAccessTokenResult struct {
	Active  bool                   `json:"active"`
	Extra   map[string]interface{} `json:"ext"`
	Subject string                 `json:"sub,omitempty"`
	Expires int64                  `json:"exp"`
}

func (a *AuthenticatorAccessToken) tokenFromCache(config *AuthenticatorAccessTokenConfiguration, token string) (*AuthenticatorAccessTokenResult, bool) {
	if !config.Cache.Enabled {
		return nil, false
	}

	item, found := a.tokenCache.Get(token)
	if !found {
		return nil, false
	}

	i := item.(*AuthenticatorAccessTokenResult)
	expires := time.Unix(i.Expires, 0)
	if expires.Before(time.Now()) {
		a.tokenCache.Del(token)
		return nil, false
	}

	return i, true
}

func (a *AuthenticatorAccessToken) tokenToCache(config *AuthenticatorAccessTokenConfiguration, i *AuthenticatorAccessTokenResult, token string) {
	if !config.Cache.Enabled {
		return
	}

	if a.cacheTTL != nil {
		a.tokenCache.SetWithTTL(token, i, 0, *a.cacheTTL)
	} else {
		a.tokenCache.Set(token, i, 0)
	}
}

func (a *AuthenticatorAccessToken) Authenticate(r *http.Request, session *AuthenticationSession, config json.RawMessage, _ pipeline.Rule) error {
	cf, err := a.Config(config)
	if err != nil {
		return err
	}

	token := r.FormValue("token")
	if token == "" {
		return errors.WithStack(ErrAuthenticatorNotResponsible)
	}

	i, ok := a.tokenFromCache(cf, token)
	if !ok {
		body := url.Values{"token": {token}}

		introspectReq, err := http.NewRequest(http.MethodPost, cf.IntrospectionURL, strings.NewReader(body.Encode()))
		if err != nil {
			return errors.WithStack(err)
		}
		for key, value := range cf.IntrospectionRequestHeaders {
			introspectReq.Header.Set(key, value)
		}
		// set/override the content-type header
		introspectReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		resp, err := a.client.Do(introspectReq)
		if err != nil {
			return errors.WithStack(err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return errors.Errorf("Introspection returned status code %d but expected %d", resp.StatusCode, http.StatusOK)
		}

		if err := json.NewDecoder(resp.Body).Decode(&i); err != nil {
			return errors.WithStack(err)
		}
		if !i.Active {
			return errors.WithStack(helper.ErrUnauthorized.WithReason("Access token i says token is not active"))
		}

		if len(i.Extra) == 0 {
			i.Extra = map[string]interface{}{}
		}

		a.tokenToCache(cf, i, token)
	}

	session.Subject = i.Subject
	session.Extra = i.Extra

	return nil
}

func (a *AuthenticatorAccessToken) Validate(config json.RawMessage) error {
	if !a.c.AuthenticatorIsEnabled(a.GetID()) {
		return NewErrAuthenticatorNotEnabled(a)
	}

	_, err := a.Config(config)
	return err
}

func (a *AuthenticatorAccessToken) Config(config json.RawMessage) (*AuthenticatorAccessTokenConfiguration, error) {
	var c AuthenticatorAccessTokenConfiguration
	if err := a.c.AuthenticatorConfig(a.GetID(), config, &c); err != nil {
		return nil, NewErrAuthenticatorMisconfigured(a, err)
	}

	var rt http.RoundTripper

	if c.PreAuth != nil && c.PreAuth.Enabled {
		rt = (&clientcredentials.Config{
			ClientID:     c.PreAuth.ClientID,
			ClientSecret: c.PreAuth.ClientSecret,
			Scopes:       c.PreAuth.Scope,
			TokenURL:     c.PreAuth.TokenURL,
		}).Client(context.Background()).Transport
	}

	if c.Retry == nil {
		c.Retry = &AuthenticatorOAuth2IntrospectionRetryConfiguration{Timeout: "500ms", MaxWait: "1s"}
	} else {
		if c.Retry.Timeout == "" {
			c.Retry.Timeout = "500ms"
		}
		if c.Retry.MaxWait == "" {
			c.Retry.MaxWait = "1s"
		}
	}
	duration, err := time.ParseDuration(c.Retry.Timeout)
	if err != nil {
		return nil, err
	}
	timeout := time.Millisecond * duration

	maxWait, err := time.ParseDuration(c.Retry.MaxWait)
	if err != nil {
		return nil, err
	}

	a.client = httpx.NewResilientClientLatencyToleranceConfigurable(rt, timeout, maxWait)

	if c.Cache.TTL != "" {
		cacheTTL, err := time.ParseDuration(c.Cache.TTL)
		if err != nil {
			return nil, err
		}
		a.cacheTTL = &cacheTTL
	}

	return &c, nil
}
