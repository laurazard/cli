package manager

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/docker/cli/cli/config/credentials"
	"github.com/docker/cli/cli/config/types"
	"github.com/docker/cli/cli/internal/oauth/api"
	"github.com/docker/cli/cli/internal/oauth/util"
)

// OAuthManager is the manager
type OAuthManager struct {
	api       api.API
	audience  string
	tenant    string
	credStore credentials.Store
}

// OAuthManagerOptions is the options used for New to create a new auth manager.
type OAuthManagerOptions struct {
	Audience    string
	ClientID    string
	Scopes      []string
	ServiceName string
	Tenant      string
	DeviceName  string
	Store       credentials.Store
}

// TokenResult is a result from the auth manager.
type TokenResult struct {
	AccessToken  string
	RefreshToken string
	RequireAuth  bool
	Tenant       string
	Claims       util.Claims
}

func New(options OAuthManagerOptions) (*OAuthManager, error) {
	manager := OAuthManager{
		audience: options.Audience,
		api: api.API{
			BaseURL:  "https://" + options.Tenant,
			ClientID: options.ClientID,
			Scopes:   []string{"openid", "offline_access"},
			Client: util.Client{
				UserAgent: options.ServiceName,
			},
		},
		tenant:    options.Tenant,
		credStore: options.Store,
	}

	if len(options.Scopes) > 0 {
		manager.api.Scopes = options.Scopes
	}

	if options.DeviceName != "" {
		manager.api.Client.UserAgent = options.DeviceName
	}

	return &manager, nil
}

// LoginDevice launches the device authentication flow with the tenant. Once
// complete, It stores the returned tokens and returns them. You can override
// the printing of information by passing step functions. The order of these
// functions are the following:
//
// 1. Confirmation code for display
// 2. Opened browser & waiting for completion
// 3. Browser open failure
func (m OAuthManager) LoginDevice() (res TokenResult, err error) {
	state, err := m.api.GetDeviceCode(m.audience)
	if err != nil {
		return
	}

	if state.UserCode == "" {
		return res, errors.New("failed to get code for client")
	}

	_, _ = fmt.Fprintf(os.Stderr, "Attempting to automatically open the login authorization page in your default browser.\nIf the browser does not open or you wish to use a different device to authorize this request, open the following URL:\n\n%s\n", strings.Split(state.VerificationURI, "?")[0])
	err = util.OpenBrowser(state.VerificationURI)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, `%v
Couldn't open the URL, please do it manually: %s`, err, state.VerificationURI)
	}

	_, err = fmt.Fprintf(os.Stderr, "\nAnd enter the device confirmation code: %s\n", state.UserCode)
	if err != nil {
		return
	}

	_, err = fmt.Fprint(os.Stderr, "\nWaiting for authentication in the browser...\n")
	if err != nil {
		return
	}

	tokenRes, err := m.api.WaitForDeviceToken(state)
	if err != nil {
		return
	}

	claims, err := util.GetClaims(tokenRes.AccessToken)
	if err != nil {
		return
	}

	res.Tenant = m.tenant
	res.AccessToken = tokenRes.AccessToken
	res.RefreshToken = tokenRes.RefreshToken
	res.Claims = claims

	err = m.storeTokensInStore(tokenRes.AccessToken, tokenRes.RefreshToken)
	return
}

func (m OAuthManager) RefreshToken() (res TokenResult, err error) {
	access, refresh, err := m.fetchTokensFromStore()
	if err != nil {
		return
	}
	if access == "" {
		return res, ErrNoCreds
	}

	refreshRes, err := m.api.Refresh(refresh)
	if err != nil {
		return
	}

	err = m.storeTokensInStore(refreshRes.AccessToken, refreshRes.RefreshToken)
	if err != nil {
		return
	}

	claims, err := util.GetClaims(refreshRes.AccessToken)
	if err != nil {
		return
	}

	res.Tenant = m.tenant
	res.AccessToken = refreshRes.AccessToken
	res.RefreshToken = refreshRes.RefreshToken
	res.Claims = claims
	return
}

func (m OAuthManager) fetchTokensFromStore() (access, refresh string, err error) {
	accessAuth, err := m.credStore.Get("https://index.docker.io/v1/access-token")
	if err != nil {
		return
	}
	access = accessAuth.Password

	refreshAuth, err := m.credStore.Get("https://index.docker.io/v1/refresh-token")
	if err != nil {
		return
	}
	refresh = refreshAuth.Password

	return
}

func (m OAuthManager) storeTokensInStore(accessToken, refreshToken string) error {
	claims, err := util.GetClaims(accessToken)
	if err != nil {
		return err
	}
	return errors.Join(
		m.credStore.Store(types.AuthConfig{
			ServerAddress: "https://index.docker.io/v1/access-token",
			Username:      claims.Domain.Username,
			Password:      accessToken,
		}), m.credStore.Store(types.AuthConfig{
			ServerAddress: "https://index.docker.io/v1/refresh-token",
			Username:      claims.Domain.Username,
			Password:      refreshToken,
		}))
}

// Logout logs out of the session for the client and removes tokens from the storage provider.
func (m OAuthManager) Logout() error {
	url := fmt.Sprintf("https://%s/v2/logout?client_id=%s", m.tenant, m.api.ClientID)
	return util.OpenBrowser(url)
}

var ErrNoCreds = errors.New("no credentials found")

var ErrTokenStillValid = errors.New("token is still valid")
