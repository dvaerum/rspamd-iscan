package iscan

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	netmail "net/mail"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fho/rspamd-iscan/internal/imapclt"
	"github.com/fho/rspamd-iscan/internal/log"
	"github.com/fho/rspamd-iscan/internal/mail"
	"github.com/fho/rspamd-iscan/internal/rspamc"
)

const (
	hdrPrefix      = "X-rspamd-iscan-"
	hdrRspamdScore = hdrPrefix + "Score"
	// hdrFirstScore carries the score of the first scan on mails held in the
	// wait mailbox, so the second scan knows it.
	hdrFirstScore = hdrPrefix + "First-Score"
)

type RspamdClient interface {
	Check(context.Context, io.Reader) (*rspamc.CheckResult, error)
	Spam(context.Context, io.Reader) error
	Ham(context.Context, io.Reader) error
}

type Client struct {
	clt    IMAPClient
	rspamc RspamdClient
	logger *slog.Logger

	stopCh   chan struct{}
	stopOnce sync.Once
	wgRun    sync.WaitGroup

	scanMailbox       string
	inboxMailbox      string
	spamMailbox       string
	hamMailbox        string
	backupMailbox     string
	undetectedMailbox string
	spamTreshold      float32

	// waitMailbox enables the unsure/wait band when non-empty.
	waitMailbox     string
	unsureThreshold float32
	waitDuration    time.Duration

	// now is the clock used for the wait-band INTERNALDATE and age checks;
	// tests replace it.
	now func() time.Time

	tempDir       string
	keepTempFiles bool

	markLearnedAsSpamAsRead bool

	learnInterval time.Duration

	// cntProcessedMails counts the number of emails that have been processed
	// in the [Client.scanMailbox], [Client.hamMailbox] and [Client.
	// spamMailbox].
	// It is only used in tests.
	cntProcessedMails atomic.Uint64
}

type scannedMail struct {
	Path        string
	UID         uint32
	Envelope    *imapclt.Envelope
	CheckResult *rspamc.CheckResult
	// Band is the destination class; bandUnsure mails are unmodified apart
	// from the first-score header.
	Band scoreBand
	// FirstScore is the value of the first-score header, empty if absent.
	// Only set by the second scan.
	FirstScore string
	// HeldFor is how long the mail was in the wait mailbox.
	HeldFor time.Duration
}

type learnFn func(context.Context, io.Reader) error

func NewClient(cfg *Config) (*Client, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}

	// Fail early with a clear error, instead of when the first mail should
	// be moved to a mailbox that does not exist.
	if cfg.WaitMailbox != "" {
		if err := cfg.IMAPClient.VerifyMailbox(cfg.WaitMailbox); err != nil {
			return nil, fmt.Errorf("WaitMailbox %q: %w", cfg.WaitMailbox, err)
		}

		// A failing backup move after the upload to the wait mailbox
		// leaves the original in the scan mailbox, so it would be held
		// again every round.
		if err := cfg.IMAPClient.VerifyMailbox(cfg.BackupMailbox); err != nil {
			return nil, fmt.Errorf(
				"BackupMailbox %q (required when WaitMailbox is set): %w",
				cfg.BackupMailbox, err,
			)
		}
	}

	waitDuration, err := cfg.waitDuration()
	if err != nil {
		return nil, err
	}

	c := &Client{
		clt:                     cfg.IMAPClient,
		logger:                  log.EnsureLoggerInstance(cfg.Logger),
		inboxMailbox:            cfg.InboxMailbox,
		scanMailbox:             cfg.ScanMailbox,
		spamMailbox:             cfg.SpamMailboxName,
		hamMailbox:              cfg.HamMailbox,
		undetectedMailbox:       cfg.UndetectedMailboxName,
		rspamc:                  cfg.Rspamc,
		spamTreshold:            cfg.SpamTreshold,
		waitMailbox:             cfg.WaitMailbox,
		unsureThreshold:         cfg.UnsureThreshold,
		waitDuration:            waitDuration,
		now:                     time.Now,
		learnInterval:           30 * time.Minute,
		backupMailbox:           cfg.BackupMailbox,
		tempDir:                 cfg.TempDir,
		keepTempFiles:           cfg.KeepTempFiles,
		markLearnedAsSpamAsRead: cfg.MarkLearnedAsSpamAsRead,
		stopCh:                  make(chan struct{}),
	}

	return c, nil
}

func (c *Client) ProcessHam() error {
	if c.hamMailbox == "" {
		return nil
	}

	return c.learn(c.hamMailbox, c.inboxMailbox, false, c.rspamc.Ham)
}

func (c *Client) ProcessSpam() error {
	if c.undetectedMailbox == "" {
		return nil
	}

	return c.learn(c.undetectedMailbox, c.spamMailbox, c.markLearnedAsSpamAsRead, c.rspamc.Spam)
}

func (c *Client) learn(srcMailbox, destMailbox string, markAsSeen bool, learnFn learnFn) error {
	var processedMsgUIDs []uint32

	logger := c.logger.With("mailbox.source", srcMailbox)

	logger.Info("checking mailbox for new messages to learn")

	for msg, err := range c.clt.Messages(srcMailbox) {
		if err != nil {
			if errMalformed, ok := errors.AsType[*imapclt.ErrMalformedMsg](err); ok {
				logger.Warn(
					"skipping malformed message",
					"mail.uid", errMalformed.UID,
					"error", err,
					"event", "imap.msg_malformed",
				)
				processedMsgUIDs = append(processedMsgUIDs, errMalformed.UID)
				continue
			}

			return fmt.Errorf("fetching messages from imap mailbox failed: %w", err)
		}

		logger := c.logger.With("mail.subject", msg.Envelope.Subject, "mail.uid", msg.UID)
		logger.Debug("fetched message")

		// TODO: retry Check if it failed with a temporary error
		err = learnFn(
			context.TODO(),
			msg.Message,
		)
		if err != nil {
			logger.Warn("learning message failed", "error", err,
				"event", "rspamd.msg_learn_failed")
			return nil
		}

		logger.Info("learned message", "event", "rspamd.msg_learned")
		processedMsgUIDs = append(processedMsgUIDs, msg.UID)
	}

	if len(processedMsgUIDs) == 0 {
		return nil
	}

	if markAsSeen {
		if err := c.clt.MarkSeen(processedMsgUIDs); err != nil {
			logger.Warn("marking learned message as seen failed",
				"error", err)
		}
	}

	err := c.clt.Move(processedMsgUIDs, destMailbox)
	if err != nil {
		return fmt.Errorf("moving messages after learning failed: %w", err)
	}

	c.cntProcessedMails.Add(uint64(len(processedMsgUIDs)))

	return nil
}

func asHdrMap(prefix string, scores map[string]*rspamc.Symbol, skipZeroScores bool) []*mail.Header {
	result := make([]*mail.Header, 0, len(scores))

	for _, v := range scores {
		if skipZeroScores && v.Score == 0 {
			continue
		}

		result = append(result, &mail.Header{
			Name: prefix + v.Name,
			Body: fmt.Sprint(v.Score),
		})
	}

	return result
}

func addScanResultHeaders(mailFilepath string, result *rspamc.CheckResult) error {
	var hdrsData []byte

	hdrs := asHdrMap(hdrPrefix+"Symbol-", result.Symbols, true)
	hdrs = append(hdrs, &mail.Header{
		Name: hdrRspamdScore,
		Body: fmt.Sprint(result.Score),
	})

	sortHeaders(hdrs)

	// TODO: instead of adding a header line per symbol, add a multiline
	// header with all symbols
	hdrsData, err := mail.AsHeaders(hdrs)
	if err != nil {
		return err
	}

	return mail.AddHeaders(mailFilepath, hdrsData)
}

// readHeader returns the value of the named header of the mail read from r,
// or "" if it is absent. r is read from its current position.
func readHeader(r io.Reader, name string) (string, error) {
	if f, ok := r.(io.Seeker); ok {
		if _, err := f.Seek(0, io.SeekStart); err != nil {
			return "", err
		}
	}

	m, err := netmail.ReadMessage(r)
	if err != nil {
		return "", err
	}

	return m.Header.Get(name), nil
}

func addFirstScoreHeader(mailFilepath string, score float32) error {
	hdr, err := mail.AsHeaders([]*mail.Header{
		{Name: hdrFirstScore, Body: fmt.Sprint(score)},
	})
	if err != nil {
		return err
	}

	return mail.AddHeaders(mailFilepath, hdr)
}

func sortHeaders(hdrs []*mail.Header) {
	slices.SortFunc(hdrs, func(a, b *mail.Header) int {
		if a.Name == hdrRspamdScore {
			return 1
		}

		if b.Name == hdrRspamdScore {
			return -1
		}

		score := strings.Compare(a.Name, b.Name)
		if score == 0 {
			return strings.Compare(a.Body, b.Body)
		}

		return score
	})
}

func (c *Client) isSpam(r *rspamc.CheckResult) bool {
	return r.Score >= c.spamTreshold
}

// scoreBand is the destination class of a scanned mail.
type scoreBand int

const (
	bandHam scoreBand = iota
	bandUnsure
	bandSpam
)

// classify maps a score to its band. Without a wait mailbox no mail is ever
// unsure.
func (c *Client) classify(score float32) scoreBand {
	switch {
	case score >= c.spamTreshold:
		return bandSpam
	case c.waitMailbox != "" && score >= c.unsureThreshold:
		return bandUnsure
	default:
		return bandHam
	}
}

// replaceWithModifiedMails uploads mails to the spam or inbox mailbox, depending on their
// spam score.
// The original email is moved to the backup mailbox.
// It returns an UIDSet of all successfully uploaded mails.
// When errors happen, an error **and** a non-empty UIDSet can be returned.
func (c *Client) replaceWithModifiedMails(mails []*scannedMail) error {
	var errs []error

	for _, mail := range mails {
		var mbox string

		logger := c.logger.With(
			"mail.subject", mail.Envelope.Subject,
			"mail.uid", mail.UID,
		)

		if mail.Band == bandUnsure {
			if err := c.holdMail(mail, logger); err != nil {
				errs = append(errs, err)
			}

			continue
		}

		// TODO: support deleting emails from the mailbox, when backupMailbox is
		// empty instead of keeping a copy of the original, deleting
		// must happen after appendMail!
		err := c.clt.Move([]uint32{mail.UID}, c.backupMailbox)
		if err != nil {
			errs = append(errs, fmt.Errorf(
				"moving mail (%d) (%s) to backup mailbox %s failed: %w",
				mail.UID, mail.Envelope.Subject, c.backupMailbox, err,
			))

			continue
		}

		if c.isSpam(mail.CheckResult) {
			mbox = c.spamMailbox
		} else {
			mbox = c.inboxMailbox
		}

		err = c.clt.Upload(mail.Path, mbox, mail.Envelope.Date)
		if err != nil {
			errs = append(errs, fmt.Errorf(
				"uploading email %d (%s) (%s) to %s failed: %w",
				mail.UID, mail.Envelope.Subject, mail.Path, mbox, err,
			))
			logger.Warn(
				"uploading scanned email to inbox failed, please find the original email in the backup mailbox!",
				"event", "imap.msg_append_failed",
				"filepath", mail.Path,
				"mailbox.backup", c.backupMailbox,
				"mailbox.inbox", c.inboxMailbox,
			)

			continue
		}

		if c.keepTempFiles {
			continue
		}

		if err := os.Remove(mail.Path); err != nil {
			logger.Warn(
				"deleting email file failed",
				"error", err,
				"event", "imap.msg_delete_failed",
				"filepath", mail.Path,
			)
		}

		logger.Info("moved message to backup mailbox and uploaded modified message with scan results to inbox")
	}

	return errors.Join(errs...)
}

// holdMail uploads the unmodified copy of an unsure mail to the wait mailbox
// and moves the original to the backup mailbox. The upload comes first so that
// a failed upload leaves the original in the scan mailbox, to be retried in the
// next round.
func (c *Client) holdMail(mail *scannedMail, logger *slog.Logger) error {
	// INTERNALDATE is the time the mail was put on hold, the age check of
	// the second scan relies on it.
	err := c.clt.Upload(mail.Path, c.waitMailbox, c.now())
	if err != nil {
		c.removeTempFile(mail.Path, logger)

		return fmt.Errorf(
			"uploading email %d (%s) to wait mailbox %s failed: %w",
			mail.UID, mail.Envelope.Subject, c.waitMailbox, err,
		)
	}

	c.removeTempFile(mail.Path, logger)

	err = c.clt.Move([]uint32{mail.UID}, c.backupMailbox)
	if err != nil {
		return fmt.Errorf(
			"moving mail (%d) (%s) to backup mailbox %s failed after it was uploaded to the wait mailbox: %w",
			mail.UID, mail.Envelope.Subject, c.backupMailbox, err,
		)
	}

	logger.Info(
		"held message in wait mailbox, moved original to backup mailbox",
		"scan.score", mail.CheckResult.Score,
		"mailbox.wait", c.waitMailbox,
		"event", "iscan.msg_held",
	)

	return nil
}

func (c *Client) removeTempFile(path string, logger *slog.Logger) {
	if c.keepTempFiles {
		return
	}

	if err := os.Remove(path); err != nil {
		logger.Warn(
			"deleting email file failed",
			"error", err,
			"event", "imap.msg_delete_failed",
			"filepath", path,
		)
	}
}

// downloadAndScan downloads and scans msg and prepares the local copy for its
// destination.
// With final set (second scan of a held mail) the mail is never held again.
func (c *Client) downloadAndScan(msg *imapclt.Message, final bool) (*scannedMail, error) {
	tmpFile, err := os.CreateTemp(
		c.tempDir,
		"rspamd-iscan-mail-"+strconv.Itoa(int(msg.UID)),
	)
	if err != nil {
		return nil, fmt.Errorf("creating temporary file failed: %w", err)
	}

	errCleanupfn := func() {
		_ = tmpFile.Close()

		if c.keepTempFiles {
			return
		}

		if err := os.Remove(tmpFile.Name()); err != nil {
			c.logger.Error("deleting temporary file failed",
				"error", err, "filepath", tmpFile.Name(),
				"event", "file.deletion_failed")
		}
	}

	_, err = io.Copy(tmpFile, msg.Message)
	if err != nil {
		errCleanupfn()
		return nil, fmt.Errorf("downloading imap message to disk failed: %w", err)
	}

	env := &msg.Envelope
	logger := c.logger.With("mail.subject", env.Subject, "mail.uid", msg.UID)
	logger.Debug(
		"downloaded imap message",
		"filepath", tmpFile.Name(),
		"mail.envelope.message_id", env.MessageID,
		"mail.envelope.from", env.From,
		"mail.envelope.recipients", env.Recipients,
	)

	var firstScore string
	if final {
		// The first score is only logged. A mail whose headers net/mail
		// rejects must still be released, so a failure is not fatal.
		firstScore, err = readHeader(tmpFile, hdrFirstScore)
		if err != nil {
			logger.Warn(
				"reading first-score header failed, continuing without it",
				"error", err, "header", hdrFirstScore,
			)
			firstScore = ""
		}
	}

	_, err = tmpFile.Seek(0, 0)
	if err != nil {
		errCleanupfn()
		return nil, fmt.Errorf("setting %q file position to beginning failed: %w", tmpFile.Name(), err)
	}
	// TODO: retry Check if it failed with a temporary error
	scanResult, err := c.rspamc.Check(context.Background(), tmpFile)
	if err != nil {
		errCleanupfn()
		return nil, err
	}

	if err := tmpFile.Close(); err != nil {
		errCleanupfn()
		return nil, fmt.Errorf("closing file of downloaded mail failed: %w", err)
	}

	band := c.classify(scanResult.Score)
	if final && band == bandUnsure {
		band = bandHam
	}

	if band == bandUnsure {
		// Held mails stay unmodified: the scan headers and the subject
		// rewrite are added once, after the second scan.
		if err := addFirstScoreHeader(tmpFile.Name(), scanResult.Score); err != nil {
			return nil, fmt.Errorf("adding first-score header to local mail copy failed: %w", err)
		}

		logger.Info(
			"message scanned, score is in the unsure band",
			"scan.score", scanResult.Score, "scan.is_spam", false,
			"scan.band", "unsure",
		)

		return &scannedMail{
			Path:        tmpFile.Name(),
			UID:         msg.UID,
			Envelope:    env,
			CheckResult: scanResult,
			Band:        bandUnsure,
		}, nil
	}

	if scanResult.Subject != "" && scanResult.Subject != env.Subject {
		err := mail.ReplaceHeader(
			tmpFile.Name(),
			mail.Header{Name: "Subject", Body: scanResult.Subject},
		)
		if err != nil {
			return nil, fmt.Errorf("rewriting subject failed: %w", err)
		}

		logger.Debug(
			"rewrote mail subject",
			"mail.subject.old", env.Subject,
			"mail.subject.new", scanResult.Subject,
		)
	}

	err = addScanResultHeaders(tmpFile.Name(), scanResult)
	if err != nil {
		return nil, fmt.Errorf("adding scan result headers to local mail copy failed: %w", err)
	}

	logger.Info(
		"message scanned",
		"scan.score", scanResult.Score, "scan.is_spam", c.isSpam(scanResult),
	)

	return &scannedMail{
		Path:        tmpFile.Name(),
		UID:         msg.UID,
		Envelope:    env,
		CheckResult: scanResult,
		Band:        band,
		FirstScore:  firstScore,
	}, nil
}

func (c *Client) ProcessScanBox() error {
	var scannedMails []*scannedMail
	var malformedMailsUIDs []uint32
	var errs []error

	logger := c.logger.With("mailbox.source", c.scanMailbox)
	logger.Info("processing scan box")

	for msg, err := range c.clt.Messages(c.scanMailbox) {
		if err != nil {
			if errMalformed, ok := errors.AsType[*imapclt.ErrMalformedMsg](err); ok {
				logger.Warn(
					"email is malformed, skipping scan",
					"mail.uid", errMalformed.UID,
					"error", err,
					"event", "imap.msg_malformed",
				)
				malformedMailsUIDs = append(malformedMailsUIDs, errMalformed.UID)
				continue
			}

			return fmt.Errorf("fetching messages from scanbox failed: %w", err)
		}

		sm, err := c.downloadAndScan(msg, false)
		if err != nil {
			// TODO: abort on local tmpfile errors immediately,
			// unlikely that the following mail won't encounter the
			// same issue
			errs = append(errs, err)
			break
		}

		scannedMails = append(scannedMails, sm)
	}

	err := c.replaceWithModifiedMails(scannedMails)
	if err != nil {
		errs = append(errs, err)
	}

	if len(malformedMailsUIDs) > 0 {
		err = c.clt.Move(malformedMailsUIDs, c.inboxMailbox)
		if err != nil {
			errs = append(errs, fmt.Errorf("moving malformed mails failed: %w", err))
		}

		logger.Info("skipped scanning of malformed emails, moved mails to inbox",
			"count", len(malformedMailsUIDs))
	}

	c.cntProcessedMails.Add(uint64(len(scannedMails)))

	return errors.Join(errs...)
}

// ProcessWaitBox scans the mails that have been held in the wait mailbox for
// at least the wait duration and delivers them to the spam or inbox mailbox.
// This is the final decision, mails are never held again.
// It does nothing when no wait mailbox is configured.
func (c *Client) ProcessWaitBox() error {
	if c.waitMailbox == "" {
		return nil
	}

	var scannedMails []*scannedMail
	var malformedMailsUIDs []uint32
	var errs []error

	logger := c.logger.With("mailbox.source", c.waitMailbox)
	logger.Info("processing wait box")

	now := c.now()

	for msg, err := range c.clt.Messages(c.waitMailbox) {
		if err != nil {
			if errMalformed, ok := errors.AsType[*imapclt.ErrMalformedMsg](err); ok {
				logger.Warn(
					"email is malformed, skipping scan",
					"mail.uid", errMalformed.UID,
					"error", err,
					"event", "imap.msg_malformed",
				)
				malformedMailsUIDs = append(malformedMailsUIDs, errMalformed.UID)
				continue
			}

			return fmt.Errorf("fetching messages from waitbox failed: %w", err)
		}

		heldFor := now.Sub(msg.InternalDate)
		if heldFor < c.waitDuration {
			continue
		}

		sm, err := c.downloadAndScan(msg, true)
		if err != nil {
			// Unlike in the scan box, continue: a mail that keeps failing
			// must not block the other held mails.
			errs = append(errs, err)
			continue
		}

		sm.HeldFor = heldFor
		scannedMails = append(scannedMails, sm)
	}

	for _, sm := range scannedMails {
		if err := c.releaseHeldMail(sm); err != nil {
			errs = append(errs, err)
		}
	}

	if len(malformedMailsUIDs) > 0 {
		err := c.clt.Move(malformedMailsUIDs, c.inboxMailbox)
		if err != nil {
			errs = append(errs, fmt.Errorf("moving malformed mails failed: %w", err))
		}

		logger.Info("skipped scanning of malformed emails, moved mails to inbox",
			"count", len(malformedMailsUIDs))
	}

	return errors.Join(errs...)
}

// releaseHeldMail uploads the finally scanned mail to its destination and then
// moves the held copy out of the wait mailbox to the backup mailbox. The upload
// comes first so a failed upload leaves the held mail for the next round.
func (c *Client) releaseHeldMail(mail *scannedMail) error {
	logger := c.logger.With(
		"mail.subject", mail.Envelope.Subject,
		"mail.uid", mail.UID,
	)

	mbox := c.inboxMailbox
	if mail.Band == bandSpam {
		mbox = c.spamMailbox
	}

	err := c.clt.Upload(mail.Path, mbox, mail.Envelope.Date)
	c.removeTempFile(mail.Path, logger)
	if err != nil {
		return fmt.Errorf(
			"uploading held email %d (%s) to %s failed: %w",
			mail.UID, mail.Envelope.Subject, mbox, err,
		)
	}

	err = c.clt.Move([]uint32{mail.UID}, c.backupMailbox)
	if err != nil {
		return fmt.Errorf(
			"moving held mail (%d) (%s) to backup mailbox %s failed after it was uploaded to %s: %w",
			mail.UID, mail.Envelope.Subject, c.backupMailbox, mbox, err,
		)
	}

	c.cntProcessedMails.Add(1)

	logger.Info(
		"released held message",
		"scan.first_score", mail.FirstScore,
		"scan.final_score", mail.CheckResult.Score,
		"mailbox.destination", mbox,
		"wait.held_for", mail.HeldFor.String(),
		"event", "iscan.wait_decision",
	)

	return nil
}

// Monitor monitors the Unscanned mailbox for new messages and processes them
// continuously,
// It also checks periodically the Ham and Undetected Mailbox for new messages.
// sents them to rspamd for leanring and moves them to their target inbox.
//
// The method blocks until an error occurred or [*Client.Stop] is called.
// When an error happens [*Client.Stop] should still be called to ensure that
// the IMAP connection is closed.
func (c *Client) Monitor() error {
	c.wgRun.Add(1)
	defer c.wgRun.Done()

	if err := c.RunOnce(); err != nil {
		return err
	}

	lastLearnAt := time.Now()

	for {
		eventCh, monitorCancelFn, err := c.clt.Monitor(c.scanMailbox)
		if err != nil {
			return err
		}

		c.logger.Debug("waiting for mailbox update events")
		select {
		case <-time.After(c.learnInterval - time.Since(lastLearnAt)):
			c.logger.Debug("periodic timer expired, learning ham, spam and checking the scan mailbox")

			if err := monitorCancelFn(); err != nil {
				return err
			}

			// sometimes monitoring stopped working and no updates
			// were send anymore, despite new imap messages, as
			// workaround we additionally check the Scanbox. //
			// TODO: verify if that really is still an issue or
			// could be removed
			if err := c.ProcessScanBox(); err != nil {
				return err
			}

			if err := c.ProcessHam(); err != nil {
				return err
			}

			if err := c.ProcessSpam(); err != nil {
				return err
			}

			if err := c.ProcessWaitBox(); err != nil {
				return err
			}

			lastLearnAt = time.Now()

		case evA, ok := <-eventCh:
			if !ok {
				c.logger.Debug("event channel was closed")
				_ = monitorCancelFn()
				return nil
			}

			if err := monitorCancelFn(); err != nil {
				return err
			}

			if evA.NewMsgCount == 0 {
				c.logger.Debug("ignoring MailboxUpdate, no new messages")
				continue
			}

			err = c.ProcessScanBox()
			if err != nil {
				return err
			}

		case <-c.stopCh:
			if err := monitorCancelFn(); err != nil {
				return err
			}

			return nil
		}
	}
}

// RunOnce processes all mails in the ham, spam, scan and, if configured, wait
// mailbox once.
func (c *Client) RunOnce() error {
	err := c.ProcessHam()
	if err != nil {
		return fmt.Errorf("learning ham failed: %w", err)
	}

	err = c.ProcessSpam()
	if err != nil {
		return fmt.Errorf("learning spam failed: %w", err)
	}

	err = c.ProcessScanBox()
	if err != nil {
		return err
	}

	return c.ProcessWaitBox()
}

// Stop closes the connection the IMAP-Server.
// If [Client.Monitor] is being executed concurrently, it first terminates it
// gracefully.
func (c *Client) Stop() error {
	var err error

	c.stopOnce.Do(func() {
		close(c.stopCh)
		c.wgRun.Wait()
		err = c.clt.Close()
	})

	return err
}
