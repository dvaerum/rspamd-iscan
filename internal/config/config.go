package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pelletier/go-toml/v2"
)

// DefaultWaitDuration is the wait duration used when WaitDuration is empty.
// It is the single source for the iscan package and the startup banner.
const DefaultWaitDuration = 6 * time.Hour

type Config struct {
	RspamdURL               string
	RspamdPassword          string
	ImapAddr                string
	ImapUser                string
	ImapPassword            string
	InboxMailbox            string
	SpamMailbox             string
	ScanMailbox             string
	HamMailbox              string
	BackupMailbox           string
	UndetectedMailbox       string
	SpamThreshold           float32
	TempDir                 string
	KeepTempFiles           bool
	LogIMAPData             bool
	MarkLearnedAsSpamAsRead bool
	LogLevel                string
	// WaitMailbox enables the unsure/wait band when set: mails with a score
	// in [UnsureThreshold, SpamThreshold) are held there for WaitDuration
	// and scanned again afterwards.
	WaitMailbox     string
	UnsureThreshold float32
	// WaitDuration is parsed with time.ParseDuration, go-toml has no
	// duration type.
	WaitDuration string
}

// New returns an new config initialized with default values
func New() *Config {
	return &Config{
		LogLevel:                "info",
		MarkLearnedAsSpamAsRead: true,
		TempDir:                 os.TempDir(),
	}
}

func (c *Config) String() string {
	const unset = "UNSET"
	const hiddenPasswd = "***"
	var sb strings.Builder

	printKv := func(k string, v any) {
		fmt.Fprintf(&sb, "%-30v%-50v\n", k+":", v)
	}

	sb.WriteString("Configuration:\n")
	printKv("Rspamd URL", c.RspamdURL)

	if c.RspamdPassword == "" {
		printKv("Rspamd Password", unset)
	} else {
		printKv("Rspamd Password", hiddenPasswd)
	}

	printKv("IMAP Server Address", c.ImapAddr)
	printKv("IMAP User", c.ImapUser)

	if c.ImapPassword == "" {
		printKv("IMAP Password", unset)
	} else {
		printKv("IMAP Password", hiddenPasswd)
	}

	printKv("Spam Treshold", c.SpamThreshold)
	printKv("Scan Mailbox", c.ScanMailbox)
	printKv("Inbox Mailbox", c.InboxMailbox)
	printKv("Spam Mailbox", c.SpamMailbox)
	printKv("Undetected Mailbox", c.UndetectedMailbox)
	printKv("Backup Mailbox", c.BackupMailbox)
	printKv("Mark Learned Spam as Read", c.MarkLearnedAsSpamAsRead)
	if c.WaitMailbox != "" {
		printKv("Wait Mailbox", c.WaitMailbox)
		printKv("Unsure Threshold", c.UnsureThreshold)
		if c.WaitDuration == "" {
			printKv("Wait Duration", DefaultWaitDuration.String()+" (default)")
		} else {
			printKv("Wait Duration", c.WaitDuration)
		}
	}

	printKv("Temporary Directory", c.TempDir)
	printKv("Keep Temporary Files", c.KeepTempFiles)
	printKv("Log IMAP Data", c.LogIMAPData)
	printKv("Log Level", c.LogLevel)

	sb.WriteRune('\n')
	fmt.Fprintf(&sb, "Mails in %q are scanned and backuped to %q.\n", c.ScanMailbox, c.BackupMailbox)
	fmt.Fprintf(&sb, "Mails with a spam score of >=%f are moved to %q,\n", c.SpamThreshold, c.SpamMailbox)
	fmt.Fprintf(&sb, "others are moved to %q.\n", c.InboxMailbox)
	if c.UndetectedMailbox != "" {
		fmt.Fprintf(&sb, "Mails in %q are learned as Spam and moved to %q.\n", c.UndetectedMailbox, c.SpamMailbox)
	}
	if c.WaitMailbox != "" {
		waitDuration := c.WaitDuration
		if waitDuration == "" {
			waitDuration = DefaultWaitDuration.String()
		}
		fmt.Fprintf(&sb, "Mails with a spam score of >=%f and <%f are moved to %q and scanned again after %s.\n",
			c.UnsureThreshold, c.SpamThreshold, c.WaitMailbox, waitDuration)
	}
	fmt.Fprintf(&sb, "Mails in %q are learned as Ham and moved to %q.\n", c.HamMailbox, c.InboxMailbox)

	return sb.String()
}

func FromFile(path string) (*Config, error) {
	result := New()

	buf, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	err = toml.Unmarshal(buf, result)
	if err != nil {
		return nil, err
	}

	return result, nil
}

// LoadCredentialsFromDirectory reads credentials from files in the specified
// directory. If a file exists, its content overwrite the corresponding config
// value.
func (c *Config) LoadCredentialsFromDirectory(dir string) error {
	if _, err := os.Stat(dir); err != nil {
		return fmt.Errorf("credentials directory: %w", err)
	}

	credentials := []struct {
		name   string
		target *string
	}{
		{"RspamdURL", &c.RspamdURL},
		{"RspamdPassword", &c.RspamdPassword},
		{"ImapUser", &c.ImapUser},
		{"ImapPassword", &c.ImapPassword},
	}

	for _, cred := range credentials {
		path := filepath.Join(dir, cred.name)
		value, err := readCredentialFile(path)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return fmt.Errorf("reading credential %s: %w", cred.name, err)
		}
		*cred.target = value
	}

	return nil
}

func readCredentialFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}

	// Trim trailing newlines because editors often add
	// an empty newline at the end of the file
	value := strings.TrimRight(string(data), "\r\n")

	if value == "" {
		return "", fmt.Errorf("file is empty")
	}
	return value, nil
}
