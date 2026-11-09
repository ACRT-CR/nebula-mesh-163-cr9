package configgen

import (
	"bytes"
	"fmt"

	"gopkg.in/yaml.v3"
)

// LighthouseInfo describes a lighthouse node for config generation.
type LighthouseInfo struct {
	NebulaIP   string
	PublicAddr string // "1.2.3.4:4242"
}

// FirewallRule represents a single firewall rule.
type FirewallRule struct {
	Port  string // "any", "22", "443"
	Proto string // "any", "tcp", "udp", "icmp"
	Group string // "any", "admin", etc.
}

// AdvancedUnsafeRoute mirrors models.UnsafeRoute for the generator input.
type AdvancedUnsafeRoute struct {
	Route string
	Via   string
}

// GeneratorInput contains all parameters needed to generate a Nebula config.
type GeneratorInput struct {
	HostName         string
	NebulaIP         string
	IsLighthouse     bool
	IsRelay          bool
	CACertPath       string
	CertPath         string
	KeyPath          string
	ListenPort       int
	Lighthouses      []LighthouseInfo
	Relays           []string
	FirewallInbound  []FirewallRule
	FirewallOutbound []FirewallRule

	// Optional per-host overrides. Zero values mean "use the default".
	PunchyOverride   *bool
	ListenHost       string
	MTU              int
	TunDevice        string
	UnsafeRoutes     []AdvancedUnsafeRoute
}

// Generate produces a Nebula config.yml from the given input.
func Generate(input GeneratorInput) ([]byte, error) {
	listenHost := input.ListenHost
	if listenHost == "" {
		listenHost = "0.0.0.0"
	}
	listenPort := input.ListenPort
	if listenPort <= 0 {
		listenPort = 0
		if input.IsLighthouse {
			listenPort = 4242
		}
	}
	punch := true
	if input.PunchyOverride != nil {
		punch = *input.PunchyOverride
	}

	staticHostMap := make(map[string][]string)
	lighthouse := map[string]any{"am_lighthouse": input.IsLighthouse}
	if !input.IsLighthouse {
		hosts := make([]string, 0, len(input.Lighthouses))
		for _, lh := range input.Lighthouses {
			staticHostMap[lh.NebulaIP] = []string{lh.PublicAddr}
			hosts = append(hosts, lh.NebulaIP)
		}
		lighthouse["hosts"] = hosts
	}

	firewallRules := func(rules []FirewallRule) []map[string]string {
		result := make([]map[string]string, 0, len(rules))
		for _, rule := range rules {
			r := map[string]string{"port": rule.Port, "proto": rule.Proto}
			if rule.Group == "any" {
				r["host"] = "any"
			} else {
				r["group"] = rule.Group
			}
			result = append(result, r)
		}
		return result
	}
	config := map[string]any{
		"pki": map[string]string{
			"ca":   input.CACertPath,
			"cert": input.CertPath,
			"key":  input.KeyPath,
		},
		"static_host_map": staticHostMap,
		"lighthouse":      lighthouse,
		"listen":         map[string]any{"host": listenHost, "port": listenPort},
		"punchy":         map[string]bool{"punch": punch},
		"logging":        map[string]string{"level": "info", "format": "text"},
		"firewall": map[string]any{
			"outbound": firewallRules(input.FirewallOutbound),
			"inbound":  firewallRules(input.FirewallInbound),
		},
	}
	if input.MTU != 0 || input.TunDevice != "" || len(input.UnsafeRoutes) > 0 {
		tun := make(map[string]any)
		if input.TunDevice != "" {
			tun["dev"] = input.TunDevice
		}
		if input.MTU != 0 {
			tun["mtu"] = input.MTU
		}
		if len(input.UnsafeRoutes) > 0 {
			tun["unsafe_routes"] = input.UnsafeRoutes
		}
		config["tun"] = tun
	}
	if input.IsRelay {
		config["relay"] = map[string]bool{"am_relay": true}
	} else if len(input.Relays) > 0 {
		config["relay"] = map[string][]string{"relays": input.Relays}
	}

	var buf bytes.Buffer
	encoder := yaml.NewEncoder(&buf)
	encoder.SetIndent(2)
	if err := encoder.Encode(config); err != nil {
		return nil, fmt.Errorf("encode config: %w", err)
	}

	return buf.Bytes(), nil
}
