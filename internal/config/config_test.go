package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fho/rspamd-iscan/internal/testutils/assert"
)

func TestLoadCredentialsFromDirectory(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "RspamdPassword"), []byte("secret123"), 0o600)
	_ = os.WriteFile(filepath.Join(dir, "ImapUser"), []byte("testuser"), 0o600)

	cfg := &Config{
		RspamdURL:      "http://original.url",
		RspamdPassword: "original",
	}

	err := cfg.LoadCredentialsFromDirectory(dir)
	assert.NoError(t, err)
	assert.Equal(t, "secret123", cfg.RspamdPassword)
	assert.Equal(t, "testuser", cfg.ImapUser)
	assert.Equal(t, "http://original.url", cfg.RspamdURL)
}

func TestLoadCredentialsFromDirectory_MissingFilesSkipped(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "RspamdPassword"), []byte("secret"), 0o600)

	cfg := &Config{ImapPassword: "original"}

	err := cfg.LoadCredentialsFromDirectory(dir)
	assert.NoError(t, err)
	assert.Equal(t, "secret", cfg.RspamdPassword)
	assert.Equal(t, "original", cfg.ImapPassword)
}

func TestLoadCredentialsFromDirectory_DirNotExistsError(t *testing.T) {
	cfg := &Config{}
	err := cfg.LoadCredentialsFromDirectory("/nonexistent/path")
	assert.Error(t, err)
	assert.Equal(t, "credentials directory: stat /nonexistent/path: no such file or directory", err.Error())
}

func TestLoadCredentialsFromDirectory_EmptyFileError(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "RspamdPassword"), []byte(""), 0o600)

	cfg := &Config{}
	err := cfg.LoadCredentialsFromDirectory(dir)
	assert.Error(t, err)
	assert.Equal(t, "reading credential RspamdPassword: file is empty", err.Error())
}

func TestLoadCredentialsFromDirectory_PreservesSpaces(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "RspamdPassword"), []byte(" spaces \nnewline\n"), 0o600)
	_ = os.WriteFile(filepath.Join(dir, "ImapPassword"), []byte(" spaces \r\nnewline\n\r"), 0o600)

	cfg := &Config{}
	err := cfg.LoadCredentialsFromDirectory(dir)
	assert.NoError(t, err)
	assert.Equal(t, " spaces \nnewline", cfg.RspamdPassword)
	assert.Equal(t, " spaces \r\nnewline", cfg.ImapPassword)
}

func TestDefaults(t *testing.T) {
	dir := t.TempDir()

	f := filepath.Join(dir, "cfg.toml")
	assert.NoError(t, os.WriteFile(f, []byte{}, 0o600))

	cfg, err := FromFile(f)
	assert.NoError(t, err)

	assert.Equal(t, cfg.TempDir, os.TempDir())
	assert.Equal(t, cfg.MarkLearnedAsSpamAsRead, true)
	assert.Equal(t, cfg.LogLevel, "info")

	// The wait band is off by default. WaitDuration stays empty, so a
	// WaitDuration without WaitMailbox can be detected, iscan applies the
	// 6h default when the feature is enabled.
	assert.Equal(t, cfg.WaitMailbox, "")
	assert.Equal(t, cfg.UnsureThreshold, float32(0))
	assert.Equal(t, cfg.WaitDuration, "")
}

func TestFromFile_WaitOptions(t *testing.T) {
	f := filepath.Join(t.TempDir(), "cfg.toml")
	assert.NoError(t, os.WriteFile(f, []byte(`
WaitMailbox     = "Wait"
UnsureThreshold = 4.5
WaitDuration    = "90m"
`), 0o600))

	cfg, err := FromFile(f)
	assert.NoError(t, err)

	assert.Equal(t, "Wait", cfg.WaitMailbox)
	assert.Equal(t, float32(4.5), cfg.UnsureThreshold)
	assert.Equal(t, "90m", cfg.WaitDuration)
}

func TestString_WaitOptions(t *testing.T) {
	cfg := New()
	// output is unchanged while the feature is off
	if strings.Contains(cfg.String(), "Wait") {
		t.Errorf("String() mentions the wait band while it is disabled:\n%s", cfg.String())
	}

	cfg.WaitMailbox = "Wait"
	cfg.UnsureThreshold = 4.5
	cfg.WaitDuration = "90m"
	out := cfg.String()

	for _, want := range []string{"Wait Mailbox", "Wait", "Unsure Threshold", "4.5", "Wait Duration", "90m"} {
		if !strings.Contains(out, want) {
			t.Errorf("String() output does not contain %q:\n%s", want, out)
		}
	}
}
