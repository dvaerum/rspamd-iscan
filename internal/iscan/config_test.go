package iscan

import (
	"math"
	"strings"
	"testing"

	"github.com/fho/rspamd-iscan/internal/testutils/mock"
)

func validWaitCfg(t *testing.T) *Config {
	return &Config{
		ScanMailbox:           "Scan",
		InboxMailbox:          "Inbox",
		BackupMailbox:         "Backup",
		HamMailbox:            "Ham",
		SpamMailboxName:       "Spam",
		UndetectedMailboxName: "Undetected",
		Rspamc:                mock.NewRspamc(),
		SpamTreshold:          10,
		TempDir:               t.TempDir(),
	}
}

func TestConfigValidate_Wait(t *testing.T) {
	tests := []struct {
		name    string
		modify  func(c *Config)
		wantErr string // substring, empty means valid
	}{
		{"feature off", func(*Config) {}, ""},
		{
			"valid, default duration",
			func(c *Config) { c.WaitMailbox = "Wait"; c.UnsureThreshold = 5 },
			"",
		},
		{
			"valid, explicit duration",
			func(c *Config) { c.WaitMailbox = "Wait"; c.UnsureThreshold = 5; c.WaitDuration = "90m" },
			"",
		},
		{
			"unsure threshold missing",
			func(c *Config) { c.WaitMailbox = "Wait" },
			"UnsureThreshold",
		},
		{
			"unsure threshold negative",
			func(c *Config) { c.WaitMailbox = "Wait"; c.UnsureThreshold = -1 },
			"UnsureThreshold",
		},
		{
			"unsure threshold equals spam threshold",
			func(c *Config) { c.WaitMailbox = "Wait"; c.UnsureThreshold = 10 },
			"UnsureThreshold",
		},
		{
			"unsure threshold above spam threshold",
			func(c *Config) { c.WaitMailbox = "Wait"; c.UnsureThreshold = 11 },
			"UnsureThreshold",
		},
		{
			"unsure threshold NaN",
			func(c *Config) { c.WaitMailbox = "Wait"; c.UnsureThreshold = float32(math.NaN()) },
			"UnsureThreshold",
		},
		{
			"spam threshold NaN",
			func(c *Config) {
				c.WaitMailbox = "Wait"
				c.UnsureThreshold = 5
				c.SpamTreshold = float32(math.NaN())
			},
			"SpamThreshold",
		},
		{
			"same as inbox mailbox, INBOX in other case",
			func(c *Config) { c.InboxMailbox = "INBOX"; c.WaitMailbox = "Inbox"; c.UnsureThreshold = 5 },
			"InboxMailbox",
		},
		{
			"same as inbox mailbox, configured in other case",
			func(c *Config) { c.InboxMailbox = "inbox"; c.WaitMailbox = "INBOX"; c.UnsureThreshold = 5 },
			"InboxMailbox",
		},
		{
			"other mailbox names stay case-sensitive",
			func(c *Config) { c.WaitMailbox = "backup"; c.UnsureThreshold = 5 },
			"",
		},
		{
			"duration unparsable",
			func(c *Config) { c.WaitMailbox = "Wait"; c.UnsureThreshold = 5; c.WaitDuration = "soon" },
			"WaitDuration",
		},
		{
			"duration zero",
			func(c *Config) { c.WaitMailbox = "Wait"; c.UnsureThreshold = 5; c.WaitDuration = "0s" },
			"WaitDuration",
		},
		{
			"duration negative",
			func(c *Config) { c.WaitMailbox = "Wait"; c.UnsureThreshold = 5; c.WaitDuration = "-1h" },
			"WaitDuration",
		},
		{
			"same as scan mailbox",
			func(c *Config) { c.WaitMailbox = "Scan"; c.UnsureThreshold = 5 },
			"ScanMailbox",
		},
		{
			"same as inbox mailbox",
			func(c *Config) { c.WaitMailbox = "Inbox"; c.UnsureThreshold = 5 },
			"InboxMailbox",
		},
		{
			"same as spam mailbox",
			func(c *Config) { c.WaitMailbox = "Spam"; c.UnsureThreshold = 5 },
			"SpamMailbox",
		},
		{
			"same as backup mailbox",
			func(c *Config) { c.WaitMailbox = "Backup"; c.UnsureThreshold = 5 },
			"BackupMailbox",
		},
		{
			"same as ham mailbox",
			func(c *Config) { c.WaitMailbox = "Ham"; c.UnsureThreshold = 5 },
			"HamMailbox",
		},
		{
			"same as undetected mailbox",
			func(c *Config) { c.WaitMailbox = "Undetected"; c.UnsureThreshold = 5 },
			"UndetectedMailbox",
		},
		{
			"unsure threshold without wait mailbox",
			func(c *Config) { c.UnsureThreshold = 5 },
			"WaitMailbox",
		},
		{
			"duration without wait mailbox",
			func(c *Config) { c.WaitDuration = "6h" },
			"WaitMailbox",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validWaitCfg(t)
			tt.modify(cfg)

			err := cfg.validate()
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("validate() = %v, want nil", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("validate() = nil, want error containing %q", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("validate() = %q, want error containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestConfigWaitDuration(t *testing.T) {
	cfg := validWaitCfg(t)
	cfg.WaitMailbox = "Wait"
	cfg.UnsureThreshold = 5

	d, err := cfg.waitDuration()
	if err != nil || d != 6*60*60*1e9 {
		t.Fatalf("waitDuration() = %v, %v, want 6h default", d, err)
	}

	cfg.WaitDuration = "90m"
	d, err = cfg.waitDuration()
	if err != nil || d != 90*60*1e9 {
		t.Fatalf("waitDuration() = %v, %v, want 90m", d, err)
	}
}
