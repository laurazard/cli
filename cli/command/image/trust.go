package image

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/distribution/reference"
	"github.com/docker/cli/cli/command"
	"github.com/docker/cli/cli/streams"
	"github.com/docker/cli/cli/trust"
	"github.com/docker/cli/cli/version"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/image"
	registrytypes "github.com/docker/docker/api/types/registry"
	"github.com/docker/docker/pkg/jsonmessage"
	"github.com/docker/docker/registry"
	"github.com/gorilla/websocket"
	"github.com/opencontainers/go-digest"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/theupdateframework/notary/client"
	"github.com/theupdateframework/notary/tuf/data"
)

type target struct {
	name   string
	digest digest.Digest
	size   int64
}

// TrustedPush handles content trust pushing of an image
func TrustedPush(ctx context.Context, cli command.Cli, repoInfo *registry.RepositoryInfo, ref reference.Named, authConfig registrytypes.AuthConfig, options image.PushOptions) error {
	responseBody, err := cli.Client().ImagePush(ctx, reference.FamiliarString(ref), options)
	if err != nil {
		return err
	}

	defer responseBody.Close()

	return PushTrustedReference(cli, repoInfo, ref, authConfig, responseBody)
}

// PushTrustedReference pushes a canonical reference to the trust server.
//
//nolint:gocyclo
func PushTrustedReference(ioStreams command.Streams, repoInfo *registry.RepositoryInfo, ref reference.Named, authConfig registrytypes.AuthConfig, in io.Reader) error {
	// If it is a trusted push we would like to find the target entry which match the
	// tag provided in the function and then do an AddTarget later.
	target := &client.Target{}
	// Count the times of calling for handleTarget,
	// if it is called more that once, that should be considered an error in a trusted push.
	cnt := 0
	handleTarget := func(msg jsonmessage.JSONMessage) {
		cnt++
		if cnt > 1 {
			// handleTarget should only be called once. This will be treated as an error.
			return
		}

		var pushResult types.PushResult
		err := json.Unmarshal(*msg.Aux, &pushResult)
		if err == nil && pushResult.Tag != "" {
			if dgst, err := digest.Parse(pushResult.Digest); err == nil {
				h, err := hex.DecodeString(dgst.Hex())
				if err != nil {
					target = nil
					return
				}
				target.Name = pushResult.Tag
				target.Hashes = data.Hashes{string(dgst.Algorithm()): h}
				target.Length = int64(pushResult.Size)
			}
		}
	}

	var tag string
	switch x := ref.(type) {
	case reference.Canonical:
		return errors.New("cannot push a digest reference")
	case reference.NamedTagged:
		tag = x.Tag()
	default:
		// We want trust signatures to always take an explicit tag,
		// otherwise it will act as an untrusted push.
		if err := jsonmessage.DisplayJSONMessagesToStream(in, ioStreams.Out(), nil); err != nil {
			return err
		}
		fmt.Fprintln(ioStreams.Err(), "No tag specified, skipping trust metadata push")
		return nil
	}

	if err := jsonmessage.DisplayJSONMessagesToStream(in, ioStreams.Out(), handleTarget); err != nil {
		return err
	}

	if cnt > 1 {
		return errors.Errorf("internal error: only one call to handleTarget expected")
	}

	if target == nil {
		return errors.Errorf("no targets found, provide a specific tag in order to sign it")
	}

	fmt.Fprintln(ioStreams.Out(), "Signing and pushing trust metadata")

	repo, err := trust.GetNotaryRepository(ioStreams.In(), ioStreams.Out(), command.UserAgent(), repoInfo, &authConfig, "push", "pull")
	if err != nil {
		return errors.Wrap(err, "error establishing connection to trust repository")
	}

	// get the latest repository metadata so we can figure out which roles to sign
	_, err = repo.ListTargets()

	switch err.(type) {
	case client.ErrRepoNotInitialized, client.ErrRepositoryNotExist:
		keys := repo.GetCryptoService().ListKeys(data.CanonicalRootRole)
		var rootKeyID string
		// always select the first root key
		if len(keys) > 0 {
			sort.Strings(keys)
			rootKeyID = keys[0]
		} else {
			rootPublicKey, err := repo.GetCryptoService().Create(data.CanonicalRootRole, "", data.ECDSAKey)
			if err != nil {
				return err
			}
			rootKeyID = rootPublicKey.ID()
		}

		// Initialize the notary repository with a remotely managed snapshot key
		if err := repo.Initialize([]string{rootKeyID}, data.CanonicalSnapshotRole); err != nil {
			return trust.NotaryError(repoInfo.Name.Name(), err)
		}
		fmt.Fprintf(ioStreams.Out(), "Finished initializing %q\n", repoInfo.Name.Name())
		err = repo.AddTarget(target, data.CanonicalTargetsRole)
	case nil:
		// already initialized and we have successfully downloaded the latest metadata
		err = AddTargetToAllSignableRoles(repo, target)
	default:
		return trust.NotaryError(repoInfo.Name.Name(), err)
	}

	if err == nil {
		err = repo.Publish()
	}

	if err != nil {
		err = errors.Wrapf(err, "failed to sign %s:%s", repoInfo.Name.Name(), tag)
		return trust.NotaryError(repoInfo.Name.Name(), err)
	}

	fmt.Fprintf(ioStreams.Out(), "Successfully signed %s:%s\n", repoInfo.Name.Name(), tag)
	return nil
}

// AddTargetToAllSignableRoles attempts to add the image target to all the top level delegation roles we can
// (based on whether we have the signing key and whether the role's path allows
// us to).
// If there are no delegation roles, we add to the targets role.
func AddTargetToAllSignableRoles(repo client.Repository, target *client.Target) error {
	signableRoles, err := trust.GetSignableRoles(repo, target)
	if err != nil {
		return err
	}

	return repo.AddTarget(target, signableRoles...)
}

// trustedPull handles content trust pulling of an image
func trustedPull(ctx context.Context, cli command.Cli, imgRefAndAuth trust.ImageRefAndAuth, opts PullOptions) error {
	refs, err := getTrustedPullTargets(cli, imgRefAndAuth)
	if err != nil {
		return err
	}

	ref := imgRefAndAuth.Reference()
	for i, r := range refs {
		displayTag := r.name
		if displayTag != "" {
			displayTag = ":" + displayTag
		}
		fmt.Fprintf(cli.Out(), "Pull (%d of %d): %s%s@%s\n", i+1, len(refs), reference.FamiliarName(ref), displayTag, r.digest)

		trustedRef, err := reference.WithDigest(reference.TrimNamed(ref), r.digest)
		if err != nil {
			return err
		}
		updatedImgRefAndAuth, err := trust.GetImageReferencesAndAuth(ctx, AuthResolver(cli), trustedRef.String())
		if err != nil {
			return err
		}
		if err := imagePullPrivileged(ctx, cli, updatedImgRefAndAuth, PullOptions{
			all:      false,
			platform: opts.platform,
			quiet:    opts.quiet,
			remote:   opts.remote,
		}); err != nil {
			return err
		}

		tagged, err := reference.WithTag(reference.TrimNamed(ref), r.name)
		if err != nil {
			return err
		}

		if err := TagTrusted(ctx, cli, trustedRef, tagged); err != nil {
			return err
		}
	}
	return nil
}

func getTrustedPullTargets(cli command.Cli, imgRefAndAuth trust.ImageRefAndAuth) ([]target, error) {
	notaryRepo, err := cli.NotaryClient(imgRefAndAuth, trust.ActionsPullOnly)
	if err != nil {
		return nil, errors.Wrap(err, "error establishing connection to trust repository")
	}

	ref := imgRefAndAuth.Reference()
	tagged, isTagged := ref.(reference.NamedTagged)
	if !isTagged {
		// List all targets
		targets, err := notaryRepo.ListTargets(trust.ReleasesRole, data.CanonicalTargetsRole)
		if err != nil {
			return nil, trust.NotaryError(ref.Name(), err)
		}
		var refs []target
		for _, tgt := range targets {
			t, err := convertTarget(tgt.Target)
			if err != nil {
				fmt.Fprintf(cli.Err(), "Skipping target for %q\n", reference.FamiliarName(ref))
				continue
			}
			// Only list tags in the top level targets role or the releases delegation role - ignore
			// all other delegation roles
			if tgt.Role != trust.ReleasesRole && tgt.Role != data.CanonicalTargetsRole {
				continue
			}
			refs = append(refs, t)
		}
		if len(refs) == 0 {
			return nil, trust.NotaryError(ref.Name(), errors.Errorf("No trusted tags for %s", ref.Name()))
		}
		return refs, nil
	}

	t, err := notaryRepo.GetTargetByName(tagged.Tag(), trust.ReleasesRole, data.CanonicalTargetsRole)
	if err != nil {
		return nil, trust.NotaryError(ref.Name(), err)
	}
	// Only get the tag if it's in the top level targets role or the releases delegation role
	// ignore it if it's in any other delegation roles
	if t.Role != trust.ReleasesRole && t.Role != data.CanonicalTargetsRole {
		return nil, trust.NotaryError(ref.Name(), errors.Errorf("No trust data for %s", tagged.Tag()))
	}

	logrus.Debugf("retrieving target for %s role", t.Role)
	r, err := convertTarget(t.Target)
	return []target{r}, err
}

// FetchTokenResponse is response from fetching token with GET request
type FetchTokenResponse struct {
	Token        string    `json:"token"`
	AccessToken  string    `json:"access_token"`
	ExpiresIn    int       `json:"expires_in"`
	IssuedAt     time.Time `json:"issued_at"`
	RefreshToken string    `json:"refresh_token"`
}

type TokenOptions struct {
	Realm    string
	Service  string
	Scopes   []string
	Username string
	Secret   string

	// FetchRefreshToken enables fetching a refresh token (aka "identity token", "offline token") along with the bearer token.
	//
	// For HTTP GET mode (FetchToken), FetchRefreshToken sets `offline_token=true` in the request.
	// https://docs.docker.com/registry/spec/auth/token/#requesting-a-token
	//
	// For HTTP POST mode (FetchTokenWithOAuth), FetchRefreshToken sets `access_type=offline` in the request.
	// https://docs.docker.com/registry/spec/auth/oauth/#getting-a-token
	FetchRefreshToken bool
}

func FetchToken(ctx context.Context, client *http.Client, headers http.Header, to TokenOptions) (*FetchTokenResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, to.Realm, nil)
	if err != nil {
		return nil, err
	}

	for k, v := range headers {
		req.Header[k] = append(req.Header[k], v...)
	}
	if len(req.Header.Get("User-Agent")) == 0 {
		req.Header.Set("User-Agent", "containerd/"+version.Version)
	}

	reqParams := req.URL.Query()

	if to.Service != "" {
		reqParams.Add("service", to.Service)
	}

	for _, scope := range to.Scopes {
		reqParams.Add("scope", scope)
	}

	if to.Secret != "" {
		req.SetBasicAuth(to.Username, to.Secret)
	}

	if to.FetchRefreshToken {
		reqParams.Add("offline_token", "true")
	}

	req.URL.RawQuery = reqParams.Encode()

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		return nil, nil
	}

	decoder := json.NewDecoder(resp.Body)

	var tr FetchTokenResponse
	if err = decoder.Decode(&tr); err != nil {
		return nil, fmt.Errorf("unable to decode token response: %w", err)
	}

	// `access_token` is equivalent to `token` and if both are specified
	// the choice is undefined.  Canonicalize `access_token` by sticking
	// things in `token`.
	if tr.AccessToken != "" {
		tr.Token = tr.AccessToken
	}

	if tr.Token == "" {
		return nil, nil
	}

	return &tr, nil
}

// imagePullPrivileged pulls the image and displays it to the output
func imagePullPrivileged(ctx context.Context, cli command.Cli, imgRefAndAuth trust.ImageRefAndAuth, opts PullOptions) error {
	encodedAuth, err := registrytypes.EncodeAuthConfig(*imgRefAndAuth.AuthConfig())
	if err != nil {
		return err
	}

	u := url.URL{Scheme: "ws", Host: "localhost", Path: "/ws-bork"}

	println("DIALER")

	wsDialer := websocket.DefaultDialer
	wsDialer.NetDial = func(_, _ string) (net.Conn, error) {
		return cli.Client().Dialer()(context.Background())
	}

	getToken := func(realm, scope, service string) string {
		to := TokenOptions{
			Realm:             realm,
			Service:           service,
			Scopes:            []string{scope},
			Username:          imgRefAndAuth.AuthConfig().Username,
			Secret:            imgRefAndAuth.AuthConfig().Password,
			FetchRefreshToken: false,
		}
		response, err := FetchToken(ctx, http.DefaultClient, nil, to)
		if err != nil {
			panic(err.Error())
		}

		return response.AccessToken
	}

	c, _, err := wsDialer.Dial(u.String(), nil)
	go func() {
		for {
			_, message, err := c.ReadMessage()
			if err != nil {
				panic(err.Error())
			}
			var authRequest AuthRequest
			err = json.Unmarshal(message, &authRequest)
			if err != nil {
				panic(err.Error())
			}

			_, params := parseValueAndParams(authRequest.Wwwauthenticate)

			authToken := getToken(params["realm"], params["scope"], params["service"])
			println("WEBSOCKET REQUEST")
			println("WEBSOCKET realm", params["realm"])
			println("WEBSOCKET scope", params["scope"])
			println("WEBSOCKET service", params["service"])
			c.WriteJSON(AuthResponse{
				Header: "Bearer " + authToken,
			})
		}
	}()
	if err != nil {
		panic(err.Error())
	}

	requestPrivilege := command.RegistryAuthenticationPrivilegedFunc(cli, imgRefAndAuth.RepoInfo().Index, "pull")
	responseBody, err := cli.Client().ImagePull(ctx, reference.FamiliarString(imgRefAndAuth.Reference()), image.PullOptions{
		RegistryAuth:  encodedAuth,
		PrivilegeFunc: requestPrivilege,
		All:           opts.all,
		Platform:      opts.platform,
	})
	if err != nil {
		return err
	}
	defer responseBody.Close()

	out := cli.Out()
	if opts.quiet {
		out = streams.NewOut(io.Discard)
	}
	return jsonmessage.DisplayJSONMessagesToStream(responseBody, out, nil)
}

// AuthRequest is sent as a callback on a stream
type AuthRequest struct {
	// Host is the registry host
	Host string `json:"host"`

	// Reference is the namespace and repository name requested from the registry
	Reference string `json:"reference"`

	// Wwwauthenticate is the HTTP WWW-Authenticate header values returned from the registry
	Wwwauthenticate string `json:"www-authenticate"`
}

type AuthResponse struct {
	Header string `json:"header"`
}

// AuthenticationScheme defines scheme of the authentication method
type AuthenticationScheme byte

const (
	// BasicAuth is scheme for Basic HTTP Authentication RFC 7617
	BasicAuth AuthenticationScheme = 1 << iota
	// DigestAuth is scheme for HTTP Digest Access Authentication RFC 7616
	DigestAuth
	// BearerAuth is scheme for OAuth 2.0 Bearer Tokens RFC 6750
	BearerAuth
)

// Challenge carries information from a WWW-Authenticate response header.
// See RFC 2617.
type Challenge struct {
	// scheme is the auth-scheme according to RFC 2617
	Scheme AuthenticationScheme

	// parameters are the auth-params according to RFC 2617
	Parameters map[string]string
}

func parseValueAndParams(header string) (value string, params map[string]string) {
	params = make(map[string]string)
	value, s := expectToken(header)
	if value == "" {
		return
	}
	value = strings.ToLower(value)
	for {
		var pkey string
		pkey, s = expectToken(skipSpace(s))
		if pkey == "" {
			return
		}
		if !strings.HasPrefix(s, "=") {
			return
		}
		var pvalue string
		pvalue, s = expectTokenOrQuoted(s[1:])
		pkey = strings.ToLower(pkey)
		params[pkey] = pvalue
		s = skipSpace(s)
		if !strings.HasPrefix(s, ",") {
			return
		}
		s = s[1:]
	}
}

// Octet types from RFC 2616.
type octetType byte

var octetTypes [256]octetType

const (
	isToken octetType = 1 << iota
	isSpace
)

func init() {
	// OCTET      = <any 8-bit sequence of data>
	// CHAR       = <any US-ASCII character (octets 0 - 127)>
	// CTL        = <any US-ASCII control character (octets 0 - 31) and DEL (127)>
	// CR         = <US-ASCII CR, carriage return (13)>
	// LF         = <US-ASCII LF, linefeed (10)>
	// SP         = <US-ASCII SP, space (32)>
	// HT         = <US-ASCII HT, horizontal-tab (9)>
	// <">        = <US-ASCII double-quote mark (34)>
	// CRLF       = CR LF
	// LWS        = [CRLF] 1*( SP | HT )
	// TEXT       = <any OCTET except CTLs, but including LWS>
	// separators = "(" | ")" | "<" | ">" | "@" | "," | ";" | ":" | "\" | <">
	//              | "/" | "[" | "]" | "?" | "=" | "{" | "}" | SP | HT
	// token      = 1*<any CHAR except CTLs or separators>
	// qdtext     = <any TEXT except <">>

	for c := 0; c < 256; c++ {
		var t octetType
		isCtl := c <= 31 || c == 127
		isChar := 0 <= c && c <= 127
		isSeparator := strings.ContainsRune(" \t\"(),/:;<=>?@[]\\{}", rune(c))
		if strings.ContainsRune(" \t\r\n", rune(c)) {
			t |= isSpace
		}
		if isChar && !isCtl && !isSeparator {
			t |= isToken
		}
		octetTypes[c] = t
	}
}

func skipSpace(s string) (rest string) {
	i := 0
	for ; i < len(s); i++ {
		if octetTypes[s[i]]&isSpace == 0 {
			break
		}
	}
	return s[i:]
}

func expectToken(s string) (token, rest string) {
	i := 0
	for ; i < len(s); i++ {
		if octetTypes[s[i]]&isToken == 0 {
			break
		}
	}
	return s[:i], s[i:]
}

func expectTokenOrQuoted(s string) (value string, rest string) {
	if !strings.HasPrefix(s, "\"") {
		return expectToken(s)
	}
	s = s[1:]
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '"':
			return s[:i], s[i+1:]
		case '\\':
			p := make([]byte, len(s)-1)
			j := copy(p, s[:i])
			escape := true
			for i = i + 1; i < len(s); i++ {
				b := s[i]
				switch {
				case escape:
					escape = false
					p[j] = b
					j++
				case b == '\\':
					escape = true
				case b == '"':
					return string(p[:j]), s[i+1:]
				default:
					p[j] = b
					j++
				}
			}
			return "", ""
		}
	}
	return "", ""
}

// TrustedReference returns the canonical trusted reference for an image reference
func TrustedReference(ctx context.Context, cli command.Cli, ref reference.NamedTagged) (reference.Canonical, error) {
	imgRefAndAuth, err := trust.GetImageReferencesAndAuth(ctx, AuthResolver(cli), ref.String())
	if err != nil {
		return nil, err
	}

	notaryRepo, err := cli.NotaryClient(imgRefAndAuth, []string{"pull"})
	if err != nil {
		return nil, errors.Wrap(err, "error establishing connection to trust repository")
	}

	t, err := notaryRepo.GetTargetByName(ref.Tag(), trust.ReleasesRole, data.CanonicalTargetsRole)
	if err != nil {
		return nil, trust.NotaryError(imgRefAndAuth.RepoInfo().Name.Name(), err)
	}
	// Only list tags in the top level targets role or the releases delegation role - ignore
	// all other delegation roles
	if t.Role != trust.ReleasesRole && t.Role != data.CanonicalTargetsRole {
		return nil, trust.NotaryError(imgRefAndAuth.RepoInfo().Name.Name(), client.ErrNoSuchTarget(ref.Tag()))
	}
	r, err := convertTarget(t.Target)
	if err != nil {
		return nil, err
	}
	return reference.WithDigest(reference.TrimNamed(ref), r.digest)
}

func convertTarget(t client.Target) (target, error) {
	h, ok := t.Hashes["sha256"]
	if !ok {
		return target{}, errors.New("no valid hash, expecting sha256")
	}
	return target{
		name:   t.Name,
		digest: digest.NewDigestFromHex("sha256", hex.EncodeToString(h)),
		size:   t.Length,
	}, nil
}

// TagTrusted tags a trusted ref
func TagTrusted(ctx context.Context, cli command.Cli, trustedRef reference.Canonical, ref reference.NamedTagged) error {
	// Use familiar references when interacting with client and output
	familiarRef := reference.FamiliarString(ref)
	trustedFamiliarRef := reference.FamiliarString(trustedRef)

	fmt.Fprintf(cli.Err(), "Tagging %s as %s\n", trustedFamiliarRef, familiarRef)

	return cli.Client().ImageTag(ctx, trustedFamiliarRef, familiarRef)
}

// AuthResolver returns an auth resolver function from a command.Cli
func AuthResolver(cli command.Cli) func(ctx context.Context, index *registrytypes.IndexInfo) registrytypes.AuthConfig {
	return func(ctx context.Context, index *registrytypes.IndexInfo) registrytypes.AuthConfig {
		return command.ResolveAuthConfig(cli.ConfigFile(), index)
	}
}
