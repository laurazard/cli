package manager

import (
	"fmt"
	"strings"

	"github.com/docker/cli/cli/config/credentials"
	"github.com/docker/cli/cli/version"
	"github.com/shirou/gopsutil/v3/host"
)

const (
	audience = "https://hub.docker.com"
	tenant   = "login.docker.com"
)

// todo(laurazard): is this necessary? any user can look
// through the binary to find find the client ID
var clientID string // baked in at build time

func NewManager(store credentials.Store) (*OAuthManager, error) {
	hostinfo, err := host.Info()
	if err != nil {
		return nil, err
	}

	version := strings.ReplaceAll(version.Version, ".", "_")

	options := OAuthManagerOptions{
		Audience:    audience,
		ClientID:    clientID,
		Scopes:      []string{"openid", "offline_access"},
		ServiceName: "docker-cli",
		Tenant:      tenant,
		DeviceName:  "docker-cli:" + version,
		Store:       store,
	}

	if hostinfo != nil {
		hostVersion := strings.ReplaceAll(hostinfo.PlatformVersion, ".", "_")
		options.DeviceName = fmt.Sprintf("docker-cli:%s:%s-%s-%s", version, hostinfo.OS, hostVersion, hostinfo.KernelArch)
	}

	authManager, err := New(options)
	if err != nil {
		return nil, err
	}

	return authManager, nil
}
