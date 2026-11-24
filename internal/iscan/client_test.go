package iscan

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"iter"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/fho/rspamd-iscan/internal/imapclt"
	"github.com/fho/rspamd-iscan/internal/log"
	"github.com/fho/rspamd-iscan/internal/rspamc"
	"github.com/fho/rspamd-iscan/internal/testutils/assert"
	"github.com/fho/rspamd-iscan/internal/testutils/imapserver"
	"github.com/fho/rspamd-iscan/internal/testutils/mail"
	"github.com/fho/rspamd-iscan/internal/testutils/mock"
)

func startServerClient(t *testing.T) (*imapserver.Server, *Client) {
	srv := imapserver.StartServer(t)
	return srv, newTestClient(t, srv)
}

func testClientCfg(t *testing.T, clt IMAPClient, srv *imapserver.Server) *Config {
	return &Config{
		ScanMailbox:           srv.ScanMailbox,
		InboxMailbox:          srv.InboxMailBox,
		BackupMailbox:         srv.BackupMailbox,
		HamMailbox:            srv.HamMailbox,
		SpamMailboxName:       srv.SpamMailbox,
		UndetectedMailboxName: srv.UndetectedMailbox,
		Logger:                log.SlogTestLogger(t),
		Rspamc:                mock.NewRspamc(),
		IMAPClient:            clt,
		SpamTreshold:          10,
		TempDir:               t.TempDir(),
	}
}

func newTestClient(t *testing.T, srv *imapserver.Server) *Client {
	imapClt := connectTestIMAPClient(t, srv)

	clt, err := NewClient(testClientCfg(t, imapClt, srv))
	assert.NoError(t, err)

	t.Cleanup(func() { _ = clt.Stop() })
	return clt
}

func connectTestIMAPClient(t *testing.T, srv *imapserver.Server) *imapclt.Client {
	var err error

	imapClt := imapclt.NewClient(&imapclt.Config{
		Address:       srv.ListenAddr,
		User:          srv.UserName,
		Password:      srv.UserPasswd,
		AllowInsecure: true,
	})

	// we retry connecting because the server might not have finished
	// startup
	for range 9 {
		err = imapClt.Connect()
		if err != nil {
			t.Logf("establishing connection to imap server failed (server still starting?): %s", err)
			time.Sleep(500 * time.Millisecond)
			continue
		}
		break
	}
	assert.NoError(t, err)

	t.Logf("connection to imap server established successfully")

	// A connection left open blocks the shutdown of the in-memory server and
	// with it the start of the next test's server on the same port.
	t.Cleanup(func() { _ = imapClt.Close() })

	return imapClt
}

func TestProcessScanBox_DownloadAndScanFails(t *testing.T) {
	srv, clt := startServerClient(t)
	clt.rspamc = &mock.Rspamc{
		CheckFn: func(context.Context, io.Reader) (*rspamc.CheckResult, error) {
			return nil, errors.New("mock err")
		},
	}

	err := clt.clt.Upload(mail.TestHamMailPath(t), srv.ScanMailbox, time.Now())
	assert.NoError(t, err)

	err = clt.clt.Upload(mail.TestHamMailPath(t), srv.ScanMailbox, time.Now())
	assert.NoError(t, err)

	err = clt.ProcessScanBox()
	assert.Error(t, err)

	clt.rspamc = mock.NewRspamc()

	// Ensure client is still usable
	err = clt.ProcessScanBox()
	assert.NoError(t, err)
}

func TestRun(t *testing.T) {
	srv, clt := startServerClient(t)
	clt.learnInterval = 100 * time.Millisecond

	runErrChan := make(chan error, 1)
	go func() {
		runErrChan <- clt.Monitor()
	}()

	clt2 := newTestClient(t, srv)

	err := clt2.clt.Upload(mail.TestHamMailPath(t), srv.ScanMailbox, time.Now())
	assert.NoError(t, err)

	err = clt2.clt.Upload(mail.TestSpamMailPath(t), srv.ScanMailbox, time.Now())
	assert.NoError(t, err)

	err = clt2.clt.Upload(mail.TestSuspiciousMailPath(t), srv.ScanMailbox, time.Now())
	assert.NoError(t, err)

	err = clt2.clt.Upload(mail.TestHamMailPath(t), srv.HamMailbox, time.Now())
	assert.NoError(t, err)

	err = clt2.clt.Upload(mail.TestSpamMailPath(t), srv.UndetectedMailbox, time.Now())
	assert.NoError(t, err)

	for clt.cntProcessedMails.Load() < 5 {
		time.Sleep(50 * time.Millisecond)
	}

	assert.Equal(t, true, mailboxIsEmpty(t, clt2.clt, srv.ScanMailbox))
	assert.Equal(t, true, mailboxIsEmpty(t, clt2.clt, srv.UndetectedMailbox))

	assert.Equal(
		t, 1,
		mailboxContainsMailCnt(t, clt2.clt, clt.backupMailbox, mail.HamMailSubject),
	)

	assert.Equal(
		t, 1,
		mailboxContainsMailCnt(t, clt2.clt, clt.backupMailbox, mail.SpamMailSubject),
	)

	assert.Equal(
		t, 1,
		mailboxContainsMailCnt(t, clt2.clt, clt.backupMailbox, mail.SuspiciousMailSubject),
	)

	assert.Equal(
		t, 2,
		mailboxContainsMailCnt(t, clt2.clt, clt.inboxMailbox, mail.HamMailSubject),
	)

	assert.Equal(
		t, 2,
		mailboxContainsMailCnt(t, clt2.clt, clt.spamMailbox, mail.SpamMailSubject),
	)

	assert.Equal(
		t, 1,
		mailboxContainsMailCnt(t, clt2.clt, clt.inboxMailbox, mail.SuspiciousMailRewrittenSubject),
	)

	assert.NoError(t, clt.Stop())
	err = <-runErrChan
	assert.NoError(t, err)
}

func mailboxIsEmpty(t *testing.T, clt IMAPClient, mailbox string) bool {
	for _, err := range clt.Messages(mailbox) {
		assert.NoError(t, err)
		return false
	}
	return true
}

func mailboxContainsMailCnt(
	t *testing.T,
	clt IMAPClient,
	mailbox string,
	mailSubject string,
) int {
	cnt := 0
	for msg, err := range clt.Messages(mailbox) {
		assert.NoError(t, err)
		if msg.Envelope.Subject == mailSubject {
			cnt++
		}
	}

	return cnt
}

// TestLearn_MalformedMessage verifies that when a mailbox contains a malformed
// message (e.g. envelope parsing fails), it is skipped and moved to the
// destination mailbox.
func TestLearn_MalformedMessage(t *testing.T) {
	srv, clt := startServerClient(t)

	hamMail := mail.TestHamMailPath(t)
	spamMail := mail.TestSpamMailPath(t)
	malformedMail := mail.TestMalformedMailPath(t)

	assert.NoError(t, clt.clt.Upload(hamMail, srv.ScanMailbox, time.Now()))
	assert.NoError(t, clt.clt.Upload(malformedMail, srv.ScanMailbox, time.Now()))
	assert.NoError(t, clt.clt.Upload(spamMail, srv.ScanMailbox, time.Now()))
	assert.NoError(t, clt.clt.Upload(malformedMail, srv.HamMailbox, time.Now()))
	assert.NoError(t, clt.clt.Upload(malformedMail, srv.UndetectedMailbox, time.Now()))

	assert.NoError(t, clt.ProcessScanBox())
	assert.NoError(t, clt.ProcessHam())
	assert.NoError(t, clt.ProcessSpam())

	assert.Equal(t, true, mailboxIsEmpty(t, clt.clt, srv.ScanMailbox))
	assert.Equal(t, true, mailboxIsEmpty(t, clt.clt, srv.HamMailbox))
	assert.Equal(t, true, mailboxIsEmpty(t, clt.clt, srv.UndetectedMailbox))
	assert.Equal(t, 3, countMessagesInMailbox(t, clt.clt, srv.InboxMailBox))
	assert.Equal(t, 2, countMessagesInMailbox(t, clt.clt, srv.SpamMailbox))
}

func countMessagesInMailbox(t *testing.T, clt IMAPClient, mailbox string) int {
	cnt := 0
	for _, err := range clt.Messages(mailbox) {
		var errMalformed *imapclt.ErrMalformedMsg
		if err != nil && !errors.As(err, &errMalformed) {
			assert.NoError(t, err)
		}
		cnt++
	}
	return cnt
}

// verifyCountingClient counts VerifyMailbox calls. Calling any other method
// panics because the embedded interface is nil.
type verifyCountingClient struct {
	IMAPClient
	verified []string
}

func (c *verifyCountingClient) VerifyMailbox(mailbox string) error {
	c.verified = append(c.verified, mailbox)
	return nil
}

func TestNewClient_WaitMailboxMissing(t *testing.T) {
	srv := imapserver.StartServer(t)
	imapClt := connectTestIMAPClient(t, srv)

	cfg := testClientCfg(t, imapClt, srv)
	cfg.WaitMailbox = "no-such-wait-mailbox"
	cfg.UnsureThreshold = 5

	_, err := NewClient(cfg)
	assert.Error(t, err)
	if !strings.Contains(err.Error(), "no-such-wait-mailbox") {
		t.Errorf("error %q does not name the wait mailbox", err)
	}
}

func TestNewClient_WaitMailboxExists(t *testing.T) {
	srv := imapserver.StartServer(t)
	imapClt := connectTestIMAPClient(t, srv)

	cfg := testClientCfg(t, imapClt, srv)
	cfg.WaitMailbox = srv.WaitMailbox
	cfg.UnsureThreshold = 5

	_, err := NewClient(cfg)
	assert.NoError(t, err)
}

func TestNewClient_WaitMailboxChecked(t *testing.T) {
	srv := imapserver.StartServer(t)
	clt := &verifyCountingClient{}

	cfg := testClientCfg(t, clt, srv)
	cfg.WaitMailbox = srv.WaitMailbox
	cfg.UnsureThreshold = 5

	_, err := NewClient(cfg)
	assert.NoError(t, err)
	assert.Equal(t, 2, len(clt.verified))
	assert.Equal(t, srv.WaitMailbox, clt.verified[0])
	assert.Equal(t, srv.BackupMailbox, clt.verified[1])
}

// Held mails are moved to the backup mailbox, a missing one would make every
// hold a duplicate, see TestProcessScanBox_WaitBackupMoveFails.
func TestNewClient_WaitEnabledBackupMailboxMissing(t *testing.T) {
	srv := imapserver.StartServer(t)
	imapClt := connectTestIMAPClient(t, srv)

	cfg := testClientCfg(t, imapClt, srv)
	cfg.WaitMailbox = srv.WaitMailbox
	cfg.UnsureThreshold = 5
	cfg.BackupMailbox = "no-such-backup-mailbox"

	_, err := NewClient(cfg)
	assert.Error(t, err)
	if !strings.Contains(err.Error(), "no-such-backup-mailbox") {
		t.Errorf("error %q does not name the backup mailbox", err)
	}
}

// With the wait band off the startup checks stay as upstream: a missing
// backup mailbox is not detected by NewClient.
func TestNewClient_WaitDisabledBackupMailboxNotChecked(t *testing.T) {
	srv := imapserver.StartServer(t)
	imapClt := connectTestIMAPClient(t, srv)

	cfg := testClientCfg(t, imapClt, srv)
	cfg.BackupMailbox = "no-such-backup-mailbox"

	_, err := NewClient(cfg)
	assert.NoError(t, err)
}

func TestNewClient_NoWaitMailboxNoCheck(t *testing.T) {
	srv := imapserver.StartServer(t)
	clt := &verifyCountingClient{}

	_, err := NewClient(testClientCfg(t, clt, srv))
	assert.NoError(t, err)
	assert.Equal(t, 0, len(clt.verified))
}

// fakeClock is an adjustable clock for [Client.now].
type fakeClock struct{ t time.Time }

func (f *fakeClock) Now() time.Time          { return f.t }
func (f *fakeClock) Advance(d time.Duration) { f.t = f.t.Add(d) }

const (
	testUnsureThreshold = 5
	testWaitDuration    = 6 * time.Hour
)

// newWaitTestClient returns a client with the wait band enabled
// (UnsureThreshold 5, SpamThreshold 10, WaitDuration 6h) and a fake clock.
func newWaitTestClient(t *testing.T) (*imapserver.Server, *Client, *fakeClock) {
	srv := imapserver.StartServer(t)
	imapClt := connectTestIMAPClient(t, srv)

	cfg := testClientCfg(t, imapClt, srv)
	cfg.WaitMailbox = srv.WaitMailbox
	cfg.UnsureThreshold = testUnsureThreshold
	cfg.WaitDuration = testWaitDuration.String()

	clt, err := NewClient(cfg)
	assert.NoError(t, err)
	t.Cleanup(func() { _ = clt.Stop() })

	clock := &fakeClock{t: time.Now().Truncate(time.Second)}
	clt.now = clock.Now

	return srv, clt, clock
}

func TestNewClient_DefaultClockIsTimeNow(t *testing.T) {
	_, clt := startServerClient(t)

	before := time.Now()
	got := clt.now()
	if got.Before(before) || time.Since(got) > time.Minute {
		t.Errorf("default clock returned %s, expected approx. now", got)
	}
}

func TestNewClient_WaitConfigApplied(t *testing.T) {
	srv, clt, _ := newWaitTestClient(t)

	assert.Equal(t, srv.WaitMailbox, clt.waitMailbox)
	assert.Equal(t, float32(testUnsureThreshold), clt.unsureThreshold)
	assert.Equal(t, testWaitDuration, clt.waitDuration)
}

func TestNewClient_WaitDurationDefault(t *testing.T) {
	srv := imapserver.StartServer(t)
	imapClt := connectTestIMAPClient(t, srv)

	cfg := testClientCfg(t, imapClt, srv)
	cfg.WaitMailbox = srv.WaitMailbox
	cfg.UnsureThreshold = testUnsureThreshold

	clt, err := NewClient(cfg)
	assert.NoError(t, err)
	assert.Equal(t, defaultWaitDuration, clt.waitDuration)
}

func TestClassify(t *testing.T) {
	tests := []struct {
		name        string
		waitMailbox string
		score       float32
		want        scoreBand
	}{
		{"ham below unsure", "wait", 4.99, bandHam},
		{"zero", "wait", 0, bandHam},
		{"negative", "wait", -3, bandHam},
		{"unsure boundary goes to wait", "wait", 5, bandUnsure},
		{"inside unsure band", "wait", 7.5, bandUnsure},
		{"just below spam", "wait", 9.99, bandUnsure},
		{"spam boundary goes to spam", "wait", 10, bandSpam},
		{"above spam", "wait", 100, bandSpam},
		{"feature off, in would-be band", "", 7.5, bandHam},
		{"feature off, unsure boundary", "", 5, bandHam},
		{"feature off, below spam", "", 9.99, bandHam},
		{"feature off, spam boundary", "", 10, bandSpam},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Client{
				waitMailbox:     tt.waitMailbox,
				unsureThreshold: 5,
				spamTreshold:    10,
			}
			assert.Equal(t, tt.want, c.classify(tt.score))
		})
	}
}

// storedMail is a mail read back from a mailbox.
type storedMail struct {
	Subject      string
	Raw          string
	InternalDate time.Time
}

func readMailbox(t *testing.T, clt IMAPClient, mailbox string) []storedMail {
	t.Helper()

	var result []storedMail
	for msg, err := range clt.Messages(mailbox) {
		assert.NoError(t, err)
		raw, err := io.ReadAll(msg.Message)
		assert.NoError(t, err)
		result = append(result, storedMail{
			Subject:      msg.Envelope.Subject,
			Raw:          string(raw),
			InternalDate: msg.InternalDate,
		})
	}

	return result
}

// headerCount counts the header lines whose name starts with prefix
// (case-insensitive) in the header section of raw.
func headerCount(raw, prefix string) int {
	hdrs, _, _ := strings.Cut(raw, "\r\n\r\n")

	cnt := 0
	for line := range strings.SplitSeq(hdrs, "\r\n") {
		if strings.HasPrefix(strings.ToLower(line), strings.ToLower(prefix)) {
			cnt++
		}
	}

	return cnt
}

func uploadTo(t *testing.T, clt IMAPClient, path, mailbox string) {
	t.Helper()
	assert.NoError(t, clt.Upload(path, mailbox, time.Now()))
}

func TestProcessScanBox_UnsureGoesToWait(t *testing.T) {
	srv, clt, clock := newWaitTestClient(t)
	uploadTo(t, clt.clt, mail.TestSuspiciousMailPath(t), srv.ScanMailbox)

	assert.NoError(t, clt.ProcessScanBox())

	held := readMailbox(t, clt.clt, srv.WaitMailbox)
	assert.Equal(t, 1, len(held))
	// original subject: no rewrite
	assert.Equal(t, mail.SuspiciousMailSubject, held[0].Subject)
	// exactly one extra header, no scan result headers
	assert.Equal(t, 1, headerCount(held[0].Raw, hdrPrefix))
	assert.Equal(t, 1, headerCount(held[0].Raw, hdrFirstScore+": 6"))
	assert.Equal(t, 0, headerCount(held[0].Raw, hdrRspamdScore))
	assert.Equal(t, true, held[0].InternalDate.Equal(clock.Now()))

	assert.Equal(t, true, mailboxIsEmpty(t, clt.clt, srv.ScanMailbox))
	assert.Equal(t, true, mailboxIsEmpty(t, clt.clt, srv.InboxMailBox))
	assert.Equal(t, true, mailboxIsEmpty(t, clt.clt, srv.SpamMailbox))

	backup := readMailbox(t, clt.clt, srv.BackupMailbox)
	assert.Equal(t, 1, len(backup))
	assert.Equal(t, 0, headerCount(backup[0].Raw, hdrPrefix))
}

func TestProcessScanBox_BelowUnsureGoesToInbox(t *testing.T) {
	srv, clt, _ := newWaitTestClient(t)
	uploadTo(t, clt.clt, mail.TestHamMailPath(t), srv.ScanMailbox)

	assert.NoError(t, clt.ProcessScanBox())

	inbox := readMailbox(t, clt.clt, srv.InboxMailBox)
	assert.Equal(t, 1, len(inbox))
	assert.Equal(t, 1, headerCount(inbox[0].Raw, hdrRspamdScore))
	assert.Equal(t, 0, headerCount(inbox[0].Raw, hdrFirstScore))
	assert.Equal(t, true, mailboxIsEmpty(t, clt.clt, srv.WaitMailbox))
}

func TestProcessScanBox_SpamUnaffected(t *testing.T) {
	srv, clt, _ := newWaitTestClient(t)
	uploadTo(t, clt.clt, mail.TestSpamMailPath(t), srv.ScanMailbox)

	assert.NoError(t, clt.ProcessScanBox())

	spam := readMailbox(t, clt.clt, srv.SpamMailbox)
	assert.Equal(t, 1, len(spam))
	assert.Equal(t, 1, headerCount(spam[0].Raw, hdrRspamdScore))
	assert.Equal(t, 0, headerCount(spam[0].Raw, hdrFirstScore))
	assert.Equal(t, true, mailboxIsEmpty(t, clt.clt, srv.WaitMailbox))
}

// With WaitMailbox unset a mid-score mail takes today's path: subject
// rewritten, scan headers added, delivered to the inbox.
func TestProcessScanBox_WaitDisabledIsUnchanged(t *testing.T) {
	srv, clt := startServerClient(t)
	uploadTo(t, clt.clt, mail.TestSuspiciousMailPath(t), srv.ScanMailbox)

	assert.NoError(t, clt.ProcessScanBox())

	inbox := readMailbox(t, clt.clt, srv.InboxMailBox)
	assert.Equal(t, 1, len(inbox))
	assert.Equal(t, mail.SuspiciousMailRewrittenSubject, inbox[0].Subject)
	assert.Equal(t, 1, headerCount(inbox[0].Raw, hdrRspamdScore))
	assert.Equal(t, 0, headerCount(inbox[0].Raw, hdrFirstScore))
	assert.Equal(t, true, mailboxIsEmpty(t, clt.clt, srv.WaitMailbox))
	assert.Equal(t, true, mailboxIsEmpty(t, clt.clt, srv.ScanMailbox))
	assert.Equal(t, 1, countMessagesInMailbox(t, clt.clt, srv.BackupMailbox))
}

// failingUploadClient fails uploads to failMailbox while failing is set.
type failingUploadClient struct {
	IMAPClient
	failMailbox string
	failing     bool
}

func (c *failingUploadClient) Upload(path, mailbox string, ts time.Time) error {
	if c.failing && mailbox == c.failMailbox {
		return errors.New("mock upload error")
	}

	return c.IMAPClient.Upload(path, mailbox, ts)
}

func TestProcessScanBox_WaitUploadFailsKeepsOriginal(t *testing.T) {
	srv, clt, _ := newWaitTestClient(t)
	failing := &failingUploadClient{
		IMAPClient: clt.clt, failMailbox: srv.WaitMailbox, failing: true,
	}
	clt.clt = failing
	uploadTo(t, failing.IMAPClient, mail.TestSuspiciousMailPath(t), srv.ScanMailbox)

	assert.Error(t, clt.ProcessScanBox())

	assert.Equal(t, 1, countMessagesInMailbox(t, clt.clt, srv.ScanMailbox))
	assert.Equal(t, true, mailboxIsEmpty(t, clt.clt, srv.WaitMailbox))
	assert.Equal(t, true, mailboxIsEmpty(t, clt.clt, srv.BackupMailbox))

	// the next round retries
	failing.failing = false
	assert.NoError(t, clt.ProcessScanBox())

	assert.Equal(t, true, mailboxIsEmpty(t, clt.clt, srv.ScanMailbox))
	assert.Equal(t, 1, countMessagesInMailbox(t, clt.clt, srv.WaitMailbox))
	assert.Equal(t, 1, countMessagesInMailbox(t, clt.clt, srv.BackupMailbox))
}

// failingMoveClient fails moves to failMailbox while failing is set.
type failingMoveClient struct {
	IMAPClient
	failMailbox string
	failing     bool
}

func (c *failingMoveClient) Move(uids []uint32, mailbox string) error {
	if c.failing && mailbox == c.failMailbox {
		return errors.New("mock move error")
	}

	return c.IMAPClient.Move(uids, mailbox)
}

// Documents the at-least-once behaviour: the wait copy is uploaded before the
// original is moved to the backup mailbox, so a failing move leaves the
// original in the scan mailbox and the next round holds it again.
func TestProcessScanBox_WaitBackupMoveFails(t *testing.T) {
	srv, clt, _ := newWaitTestClient(t)
	failing := &failingMoveClient{
		IMAPClient: clt.clt, failMailbox: srv.BackupMailbox, failing: true,
	}
	clt.clt = failing
	uploadTo(t, failing.IMAPClient, mail.TestSuspiciousMailPath(t), srv.ScanMailbox)

	assert.Error(t, clt.ProcessScanBox())

	assert.Equal(t, 1, countMessagesInMailbox(t, clt.clt, srv.ScanMailbox))
	assert.Equal(t, 1, countMessagesInMailbox(t, clt.clt, srv.WaitMailbox))
	assert.Equal(t, true, mailboxIsEmpty(t, clt.clt, srv.BackupMailbox))

	// next round: the original is held a second time
	failing.failing = false
	assert.NoError(t, clt.ProcessScanBox())

	assert.Equal(t, true, mailboxIsEmpty(t, clt.clt, srv.ScanMailbox))
	assert.Equal(t, 2, countMessagesInMailbox(t, clt.clt, srv.WaitMailbox))
	assert.Equal(t, 1, countMessagesInMailbox(t, clt.clt, srv.BackupMailbox))
}

// sequenceRspamc returns the given results one per Check call, then the
// last one again.
func sequenceRspamc(results ...rspamc.CheckResult) *mock.Rspamc {
	calls := 0

	return &mock.Rspamc{
		CheckFn: func(_ context.Context, r io.Reader) (*rspamc.CheckResult, error) {
			if _, err := io.Copy(io.Discard, r); err != nil {
				return nil, err
			}

			res := results[min(calls, len(results)-1)]
			calls++

			return &res, nil
		},
	}
}

// holdMailInWaitBox puts the suspicious mail through a first scan with score 6
// so that it lands in the wait mailbox, then lets the next scans return
// secondRes.
func holdMailInWaitBox(
	t *testing.T, srv *imapserver.Server, clt *Client, secondRes rspamc.CheckResult,
) {
	t.Helper()

	clt.rspamc = sequenceRspamc(rspamc.CheckResult{Score: 6}, secondRes)
	uploadTo(t, clt.clt, mail.TestSuspiciousMailPath(t), srv.ScanMailbox)
	assert.NoError(t, clt.ProcessScanBox())
	assert.Equal(t, 1, countMessagesInMailbox(t, clt.clt, srv.WaitMailbox))
}

func TestProcessWaitBox_YoungMailStays(t *testing.T) {
	srv, clt, clock := newWaitTestClient(t)
	holdMailInWaitBox(t, srv, clt, rspamc.CheckResult{Score: 1})

	clock.Advance(testWaitDuration - time.Second)
	assert.NoError(t, clt.ProcessWaitBox())

	assert.Equal(t, 1, countMessagesInMailbox(t, clt.clt, srv.WaitMailbox))
	assert.Equal(t, true, mailboxIsEmpty(t, clt.clt, srv.InboxMailBox))
	assert.Equal(t, true, mailboxIsEmpty(t, clt.clt, srv.SpamMailbox))
	assert.Equal(t, 1, countMessagesInMailbox(t, clt.clt, srv.BackupMailbox))
}

func TestProcessWaitBox_OldMailToInbox(t *testing.T) {
	srv, clt, clock := newWaitTestClient(t)
	holdMailInWaitBox(t, srv, clt, rspamc.CheckResult{Score: 1})

	clock.Advance(testWaitDuration)
	assert.NoError(t, clt.ProcessWaitBox())

	inbox := readMailbox(t, clt.clt, srv.InboxMailBox)
	assert.Equal(t, 1, len(inbox))
	assert.Equal(t, 1, headerCount(inbox[0].Raw, hdrRspamdScore+": 1"))
	assert.Equal(t, 1, headerCount(inbox[0].Raw, hdrFirstScore+": 6"))
	assert.Equal(t, true, mailboxIsEmpty(t, clt.clt, srv.WaitMailbox))
	assert.Equal(t, true, mailboxIsEmpty(t, clt.clt, srv.SpamMailbox))
	// original from the hold and the held copy
	assert.Equal(t, 2, countMessagesInMailbox(t, clt.clt, srv.BackupMailbox))
}

func TestProcessWaitBox_OldMailToSpam(t *testing.T) {
	srv, clt, clock := newWaitTestClient(t)
	holdMailInWaitBox(t, srv, clt, rspamc.CheckResult{Score: 10})

	clock.Advance(testWaitDuration)
	assert.NoError(t, clt.ProcessWaitBox())

	spam := readMailbox(t, clt.clt, srv.SpamMailbox)
	assert.Equal(t, 1, len(spam))
	assert.Equal(t, 1, headerCount(spam[0].Raw, hdrFirstScore+": 6"))
	assert.Equal(t, true, mailboxIsEmpty(t, clt.clt, srv.WaitMailbox))
	assert.Equal(t, true, mailboxIsEmpty(t, clt.clt, srv.InboxMailBox))
	// original from the hold and the held copy
	assert.Equal(t, 2, countMessagesInMailbox(t, clt.clt, srv.BackupMailbox))
}

// A failed upload on release leaves the held copy in the wait mailbox and
// delivers nothing, the next round retries.
func TestProcessWaitBox_ReleaseUploadFailsKeepsHeldMail(t *testing.T) {
	srv, clt, clock := newWaitTestClient(t)
	holdMailInWaitBox(t, srv, clt, rspamc.CheckResult{Score: 1})
	failing := &failingUploadClient{
		IMAPClient: clt.clt, failMailbox: srv.InboxMailBox, failing: true,
	}
	clt.clt = failing

	clock.Advance(testWaitDuration)
	assert.Error(t, clt.ProcessWaitBox())

	assert.Equal(t, 1, countMessagesInMailbox(t, clt.clt, srv.WaitMailbox))
	assert.Equal(t, true, mailboxIsEmpty(t, clt.clt, srv.InboxMailBox))
	assert.Equal(t, true, mailboxIsEmpty(t, clt.clt, srv.SpamMailbox))
	assert.Equal(t, 1, countMessagesInMailbox(t, clt.clt, srv.BackupMailbox))

	failing.failing = false
	assert.NoError(t, clt.ProcessWaitBox())

	assert.Equal(t, true, mailboxIsEmpty(t, clt.clt, srv.WaitMailbox))
	assert.Equal(t, 1, countMessagesInMailbox(t, clt.clt, srv.InboxMailBox))
	assert.Equal(t, 2, countMessagesInMailbox(t, clt.clt, srv.BackupMailbox))
}

// Documents the at-least-once behaviour: the mail is delivered before the held
// copy is moved to the backup mailbox, so a failing move leaves the held copy
// in place and the next round delivers the mail a second time.
func TestProcessWaitBox_ReleaseBackupMoveFails(t *testing.T) {
	srv, clt, clock := newWaitTestClient(t)
	holdMailInWaitBox(t, srv, clt, rspamc.CheckResult{Score: 1})
	failing := &failingMoveClient{
		IMAPClient: clt.clt, failMailbox: srv.BackupMailbox, failing: true,
	}
	clt.clt = failing

	clock.Advance(testWaitDuration)
	assert.Error(t, clt.ProcessWaitBox())

	assert.Equal(t, 1, countMessagesInMailbox(t, clt.clt, srv.WaitMailbox))
	assert.Equal(t, 1, countMessagesInMailbox(t, clt.clt, srv.InboxMailBox))
	assert.Equal(t, 1, countMessagesInMailbox(t, clt.clt, srv.BackupMailbox))

	// next round: delivered a second time
	failing.failing = false
	assert.NoError(t, clt.ProcessWaitBox())

	assert.Equal(t, true, mailboxIsEmpty(t, clt.clt, srv.WaitMailbox))
	assert.Equal(t, 2, countMessagesInMailbox(t, clt.clt, srv.InboxMailBox))
	assert.Equal(t, 2, countMessagesInMailbox(t, clt.clt, srv.BackupMailbox))
}

func TestProcessWaitBox_NeverWaitsTwice(t *testing.T) {
	srv, clt, clock := newWaitTestClient(t)
	holdMailInWaitBox(t, srv, clt, rspamc.CheckResult{Score: 7})

	clock.Advance(testWaitDuration)
	assert.NoError(t, clt.ProcessWaitBox())

	assert.Equal(t, 1, countMessagesInMailbox(t, clt.clt, srv.InboxMailBox))
	assert.Equal(t, true, mailboxIsEmpty(t, clt.clt, srv.WaitMailbox))
}

func TestProcessWaitBox_NoDuplicateHeaders(t *testing.T) {
	srv, clt, clock := newWaitTestClient(t)
	holdMailInWaitBox(t, srv, clt, rspamc.CheckResult{
		Score:   2,
		Symbols: map[string]*rspamc.Symbol{"TEST_SYM": {Name: "TEST_SYM", Score: 1.5}},
	})

	clock.Advance(testWaitDuration)
	assert.NoError(t, clt.ProcessWaitBox())

	inbox := readMailbox(t, clt.clt, srv.InboxMailBox)
	assert.Equal(t, 1, len(inbox))
	assert.Equal(t, 1, headerCount(inbox[0].Raw, hdrFirstScore))
	assert.Equal(t, 1, headerCount(inbox[0].Raw, hdrRspamdScore))
	assert.Equal(t, 1, headerCount(inbox[0].Raw, hdrPrefix+"Symbol-"))
	assert.Equal(t, 3, headerCount(inbox[0].Raw, hdrPrefix))
}

func TestProcessWaitBox_SubjectRewrittenOnce(t *testing.T) {
	srv, clt, clock := newWaitTestClient(t)
	holdMailInWaitBox(t, srv, clt, rspamc.CheckResult{
		Score:   1,
		Subject: mail.SuspiciousMailRewrittenSubject,
	})

	held := readMailbox(t, clt.clt, srv.WaitMailbox)
	assert.Equal(t, mail.SuspiciousMailSubject, held[0].Subject)

	clock.Advance(testWaitDuration)
	assert.NoError(t, clt.ProcessWaitBox())

	inbox := readMailbox(t, clt.clt, srv.InboxMailBox)
	assert.Equal(t, 1, len(inbox))
	assert.Equal(t, mail.SuspiciousMailRewrittenSubject, inbox[0].Subject)
	assert.Equal(t, 1, headerCount(inbox[0].Raw, "Subject:"))
}

// A future INTERNALDATE (clock skew, hand-set date) must not hold a mail
// longer than the wait duration, counted from when the mail was first seen.
func TestProcessWaitBox_FutureInternalDateReleasedAfterWaitDuration(t *testing.T) {
	srv, clt, clock := newWaitTestClient(t)
	err := clt.clt.Upload(
		mail.TestHamMailPath(t), srv.WaitMailbox, clock.Now().Add(24*time.Hour),
	)
	assert.NoError(t, err)

	assert.NoError(t, clt.ProcessWaitBox())
	assert.Equal(t, 1, countMessagesInMailbox(t, clt.clt, srv.WaitMailbox))

	clock.Advance(testWaitDuration - time.Second)
	assert.NoError(t, clt.ProcessWaitBox())
	assert.Equal(t, 1, countMessagesInMailbox(t, clt.clt, srv.WaitMailbox))

	clock.Advance(time.Second)
	assert.NoError(t, clt.ProcessWaitBox())

	assert.Equal(t, true, mailboxIsEmpty(t, clt.clt, srv.WaitMailbox))
	assert.Equal(t, 1, countMessagesInMailbox(t, clt.clt, srv.InboxMailBox))
}

// A mail dragged into the wait mailbox by hand has no first-score header. It is
// released once and routed by the second score.
func TestProcessWaitBox_NoFirstScoreHeader(t *testing.T) {
	tests := []struct {
		name  string
		score float32
	}{
		{"low score to inbox", 1},
		{"unsure score to inbox", 7},
		{"spam score to spam", 10},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv, clt, clock := newWaitTestClient(t)
			uploadDueToWaitBox(t, clt.clt, srv, clock)
			clt.rspamc = sequenceRspamc(rspamc.CheckResult{Score: tt.score})

			assert.NoError(t, clt.ProcessWaitBox())

			dest, other := srv.InboxMailBox, srv.SpamMailbox
			if tt.score >= 10 {
				dest, other = other, dest
			}

			released := readMailbox(t, clt.clt, dest)
			assert.Equal(t, 1, len(released))
			assert.Equal(t, 0, headerCount(released[0].Raw, hdrFirstScore))
			assert.Equal(t, 1, headerCount(released[0].Raw, hdrRspamdScore))
			assert.Equal(t, true, mailboxIsEmpty(t, clt.clt, other))
			assert.Equal(t, true, mailboxIsEmpty(t, clt.clt, srv.WaitMailbox))
			assert.Equal(t, 1, countMessagesInMailbox(t, clt.clt, srv.BackupMailbox))
		})
	}
}

// Documents the v1 behaviour: when the Check call of the second scan fails the
// error is returned and the held mail stays in the wait mailbox, to be retried
// in the next round. (The production rspamc client reports an unreachable
// rspamd as a result with score 0 instead, so those mails are released like
// any other failed scan.)
func TestProcessWaitBox_CheckErrorKeepsHeldMail(t *testing.T) {
	srv, clt, clock := newWaitTestClient(t)
	holdMailInWaitBox(t, srv, clt, rspamc.CheckResult{Score: 1})
	clt.rspamc = &mock.Rspamc{
		CheckFn: func(context.Context, io.Reader) (*rspamc.CheckResult, error) {
			return nil, errors.New("mock check error")
		},
	}

	clock.Advance(testWaitDuration)
	assert.Error(t, clt.ProcessWaitBox())

	assert.Equal(t, 1, countMessagesInMailbox(t, clt.clt, srv.WaitMailbox))
	assert.Equal(t, true, mailboxIsEmpty(t, clt.clt, srv.InboxMailBox))
	assert.Equal(t, true, mailboxIsEmpty(t, clt.clt, srv.SpamMailbox))
}

func TestProcessWaitBox_MalformedMail(t *testing.T) {
	srv, clt, _ := newWaitTestClient(t)
	uploadTo(t, clt.clt, mail.TestMalformedMailPath(t), srv.WaitMailbox)

	assert.NoError(t, clt.ProcessWaitBox())

	assert.Equal(t, 1, countMessagesInMailbox(t, clt.clt, srv.InboxMailBox))
	assert.Equal(t, true, mailboxIsEmpty(t, clt.clt, srv.WaitMailbox))
}

func TestProcessWaitBox_EmptyWaitBox(t *testing.T) {
	srv, clt, clock := newWaitTestClient(t)
	clock.Advance(24 * time.Hour)

	assert.NoError(t, clt.ProcessWaitBox())

	assert.Equal(t, true, mailboxIsEmpty(t, clt.clt, srv.InboxMailBox))
	assert.Equal(t, true, mailboxIsEmpty(t, clt.clt, srv.SpamMailbox))
}

func TestProcessWaitBox_DisabledIsNoop(t *testing.T) {
	srv, clt := startServerClient(t)
	uploadTo(t, clt.clt, mail.TestHamMailPath(t), srv.WaitMailbox)

	assert.NoError(t, clt.ProcessWaitBox())

	assert.Equal(t, 1, countMessagesInMailbox(t, clt.clt, srv.WaitMailbox))
	assert.Equal(t, true, mailboxIsEmpty(t, clt.clt, srv.InboxMailBox))
}

func TestProcessWaitBox_DryRunMovesNothing(t *testing.T) {
	srv, clt, clock := newWaitTestClient(t)
	holdMailInWaitBox(t, srv, clt, rspamc.CheckResult{Score: 1})

	dry := imapclt.NewDryClient(&imapclt.Config{
		Address:       srv.ListenAddr,
		User:          srv.UserName,
		Password:      srv.UserPasswd,
		AllowInsecure: true,
	})
	assert.NoError(t, dry.Connect())
	t.Cleanup(func() { _ = dry.Close() })
	clt.clt = dry

	clock.Advance(testWaitDuration)
	assert.NoError(t, clt.ProcessWaitBox())

	assert.Equal(t, 1, countMessagesInMailbox(t, clt.clt, srv.WaitMailbox))
	assert.Equal(t, true, mailboxIsEmpty(t, clt.clt, srv.InboxMailBox))
	assert.Equal(t, true, mailboxIsEmpty(t, clt.clt, srv.SpamMailbox))
	assert.Equal(t, 1, countMessagesInMailbox(t, clt.clt, srv.BackupMailbox))
}

// uploadDueToWaitBox puts a mail into the wait mailbox that is already older
// than the wait duration.
func uploadDueToWaitBox(t *testing.T, clt IMAPClient, srv *imapserver.Server, clock *fakeClock) {
	t.Helper()

	err := clt.Upload(
		mail.TestHamMailPath(t), srv.WaitMailbox,
		clock.Now().Add(-testWaitDuration-time.Hour),
	)
	assert.NoError(t, err)
}

func TestRunOnce_ProcessesWaitBox(t *testing.T) {
	srv, clt, clock := newWaitTestClient(t)
	uploadDueToWaitBox(t, clt.clt, srv, clock)

	assert.NoError(t, clt.RunOnce())

	assert.Equal(t, 1, countMessagesInMailbox(t, clt.clt, srv.InboxMailBox))
	assert.Equal(t, true, mailboxIsEmpty(t, clt.clt, srv.WaitMailbox))
}

func TestMonitor_TimerProcessesWaitBox(t *testing.T) {
	srv, clt, clock := newWaitTestClient(t)
	clt.learnInterval = 100 * time.Millisecond

	runErrChan := make(chan error, 1)
	go func() {
		runErrChan <- clt.Monitor()
	}()

	// the wait mailbox does not generate scan mailbox events, only the
	// periodic timer can pick the mail up
	clt2 := newTestClient(t, srv)
	uploadDueToWaitBox(t, clt2.clt, srv, clock)

	deadline := time.Now().Add(10 * time.Second)
	for clt.cntProcessedMails.Load() < 1 {
		if time.Now().After(deadline) {
			_ = clt.Stop()
			t.Fatal("wait mailbox was not processed by the periodic timer")
		}
		time.Sleep(50 * time.Millisecond)
	}

	assert.Equal(t, 1, countMessagesInMailbox(t, clt2.clt, srv.InboxMailBox))
	assert.Equal(t, true, mailboxIsEmpty(t, clt2.clt, srv.WaitMailbox))

	assert.NoError(t, clt.Stop())
	assert.NoError(t, <-runErrChan)
}

// badHeaderClient serves every message of waitMailbox with a header line
// without a colon. The in-memory server refuses to store such a mail, real
// servers do not.
type badHeaderClient struct {
	IMAPClient
	waitMailbox string
}

func (c *badHeaderClient) Messages(mailbox string) iter.Seq2[*imapclt.Message, error] {
	return func(yield func(*imapclt.Message, error) bool) {
		for msg, err := range c.IMAPClient.Messages(mailbox) {
			if err == nil && mailbox == c.waitMailbox {
				msg.Message = strings.NewReader(
					"Subject: bad header mail\r\nthis line has no colon\r\n\r\nbody\r\n",
				)
			}
			if !yield(msg, err) {
				return
			}
		}
	}
}

func TestProcessWaitBox_MalformedHeaderLineIsReleased(t *testing.T) {
	srv, clt, clock := newWaitTestClient(t)
	holdMailInWaitBox(t, srv, clt, rspamc.CheckResult{Score: 1})
	clt.clt = &badHeaderClient{IMAPClient: clt.clt, waitMailbox: srv.WaitMailbox}

	clock.Advance(testWaitDuration)
	assert.NoError(t, clt.ProcessWaitBox())

	assert.Equal(t, 1, countMessagesInMailbox(t, clt.clt, srv.InboxMailBox))
	assert.Equal(t, true, mailboxIsEmpty(t, clt.clt, srv.WaitMailbox))
}

// A mail that fails the second scan must not keep the other held mails from
// being released in the same round.
func TestProcessWaitBox_BadMailDoesNotBlockOthers(t *testing.T) {
	srv, clt, clock := newWaitTestClient(t)
	uploadDueToWaitBox(t, clt.clt, srv, clock)
	// uploaded first, so it is processed before the good mail
	err := clt.clt.Upload(
		mail.TestSpamMailPath(t), srv.WaitMailbox,
		clock.Now().Add(-testWaitDuration-time.Hour),
	)
	assert.NoError(t, err)
	uploadDueToWaitBox(t, clt.clt, srv, clock)

	clt.rspamc = &mock.Rspamc{
		CheckFn: func(_ context.Context, r io.Reader) (*rspamc.CheckResult, error) {
			buf, err := io.ReadAll(r)
			if err != nil {
				return nil, err
			}
			if strings.Contains(string(buf), mail.SpamMailSubject) {
				return nil, errors.New("mock check error")
			}

			return &rspamc.CheckResult{Score: 1}, nil
		},
	}

	assert.Error(t, clt.ProcessWaitBox())

	assert.Equal(t, 2, mailboxContainsMailCnt(t, clt.clt, srv.InboxMailBox, mail.HamMailSubject))
	assert.Equal(t, 1, mailboxContainsMailCnt(t, clt.clt, srv.WaitMailbox, mail.SpamMailSubject))
	assert.Equal(t, 1, countMessagesInMailbox(t, clt.clt, srv.WaitMailbox))
}

// captureLogs replaces the logger of clt with one that records its output as
// JSON lines and returns the buffer.
func captureLogs(clt *Client) *bytes.Buffer {
	buf := &bytes.Buffer{}
	clt.logger = slog.New(slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	return buf
}

// logRecordsWithMsg returns the JSON log records whose message is msg.
func logRecordsWithMsg(t *testing.T, logs *bytes.Buffer, msg string) []map[string]any {
	t.Helper()

	var result []map[string]any
	for line := range strings.SplitSeq(strings.TrimSpace(logs.String()), "\n") {
		if line == "" {
			continue
		}
		rec := map[string]any{}
		assert.NoError(t, json.Unmarshal([]byte(line), &rec))
		if rec["msg"] == msg {
			result = append(result, rec)
		}
	}

	return result
}

const msgMovedAndUploaded = "moved message to backup mailbox and uploaded modified message with scan results to inbox"

func TestProcessScanBox_MovedLogNamesDestinationMailbox(t *testing.T) {
	tests := []struct {
		name     string
		mailPath func(*testing.T) string
		dest     func(*imapserver.Server) string
	}{
		{"spam", mail.TestSpamMailPath, func(s *imapserver.Server) string { return s.SpamMailbox }},
		{"ham", mail.TestHamMailPath, func(s *imapserver.Server) string { return s.InboxMailBox }},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv, clt := startServerClient(t)
			logs := captureLogs(clt)
			uploadTo(t, clt.clt, tc.mailPath(t), srv.ScanMailbox)

			assert.NoError(t, clt.ProcessScanBox())

			recs := logRecordsWithMsg(t, logs, msgMovedAndUploaded)
			assert.Equal(t, 1, len(recs))
			assert.Equal[any](t, tc.dest(srv), recs[0]["mailbox.destination"])
		})
	}
}

// spoofedFirstScoreMail writes the suspicious test mail with an incoming
// First-Score header on top and returns its path.
func spoofedFirstScoreMail(t *testing.T, value string) string {
	t.Helper()

	orig, err := os.ReadFile(mail.TestSuspiciousMailPath(t))
	assert.NoError(t, err)

	path := filepath.Join(t.TempDir(), "spoofed.eml")
	data := append([]byte(hdrFirstScore+": "+value+"\r\n"), orig...)
	assert.NoError(t, os.WriteFile(path, data, 0o600))

	return path
}

// A First-Score header that comes with the mail is replaced by the one of our
// first scan, it neither stays next to it nor reaches the log or the routing.
func TestProcessScanBox_HeldMailReplacesIncomingFirstScoreHeader(t *testing.T) {
	srv, clt, _ := newWaitTestClient(t)
	clt.rspamc = sequenceRspamc(rspamc.CheckResult{Score: 6})
	uploadTo(t, clt.clt, spoofedFirstScoreMail(t, "99"), srv.ScanMailbox)

	assert.NoError(t, clt.ProcessScanBox())

	held := readMailbox(t, clt.clt, srv.WaitMailbox)
	assert.Equal(t, 1, len(held))
	assert.Equal(t, 1, headerCount(held[0].Raw, hdrFirstScore))
	assert.Equal(t, 1, headerCount(held[0].Raw, hdrFirstScore+": 6"))
}

func TestProcessWaitBox_IncomingFirstScoreHeaderIsNotUsed(t *testing.T) {
	srv, clt, clock := newWaitTestClient(t)
	logs := captureLogs(clt)
	clt.rspamc = sequenceRspamc(rspamc.CheckResult{Score: 6}, rspamc.CheckResult{Score: 1})
	uploadTo(t, clt.clt, spoofedFirstScoreMail(t, "99"), srv.ScanMailbox)
	assert.NoError(t, clt.ProcessScanBox())

	clock.Advance(testWaitDuration)
	assert.NoError(t, clt.ProcessWaitBox())

	// routing follows the second scan (1), not the spoofed 99
	inbox := readMailbox(t, clt.clt, srv.InboxMailBox)
	assert.Equal(t, 1, len(inbox))
	assert.Equal(t, 1, headerCount(inbox[0].Raw, hdrFirstScore))
	assert.Equal(t, 1, headerCount(inbox[0].Raw, hdrFirstScore+": 6"))
	assert.Equal(t, true, mailboxIsEmpty(t, clt.clt, srv.SpamMailbox))

	recs := logRecordsWithMsg(t, logs, "released held message")
	assert.Equal(t, 1, len(recs))
	assert.Equal[any](t, "6", recs[0]["scan.first_score"])
}
