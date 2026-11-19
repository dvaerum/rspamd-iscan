package imapclt

import (
	"strings"
	"testing"
	"time"

	"github.com/fho/rspamd-iscan/internal/testutils/assert"
	"github.com/fho/rspamd-iscan/internal/testutils/mail"
)

func TestMonitor(t *testing.T) {
	srv, clt := startServerClient(t)
	testMailPath := mail.TestHamMailPath(t)

	ch, stopFn, err := clt.Monitor(srv.InboxMailBox)
	assert.NoError(t, err)

	clt2 := newTestClient(t, srv)
	assert.NoError(t, clt2.Upload(testMailPath, srv.InboxMailBox, time.Now()))
	_ = clt2.Close()

	ev := <-ch
	assert.Equal(t, 1, ev.NewMsgCount)

	assert.NoError(t, stopFn())

	_, ok := <-ch
	assert.Equal(t, false, ok)
}

func TestMonitorChanIsNonBlocking(t *testing.T) {
	testMailPath := mail.TestHamMailPath(t)
	srv, clt := startServerClient(t)

	_, stopFn, err := clt.Monitor(srv.InboxMailBox)
	assert.NoError(t, err)

	clt2 := newTestClient(t, srv)
	assert.NoError(t, clt2.Upload(testMailPath, srv.InboxMailBox, time.Now()))

	assert.NoError(t, clt2.Upload(testMailPath, srv.InboxMailBox, time.Now()))
	clt2.Close()

	assert.NoError(t, stopFn())
}

func TestVerifyMailbox(t *testing.T) {
	srv, clt := startServerClient(t)

	assert.NoError(t, clt.VerifyMailbox(srv.InboxMailBox))
	assert.NoError(t, clt.VerifyMailbox(srv.WaitMailbox))

	err := clt.VerifyMailbox("does-not-exist")
	assert.Error(t, err)
	if !strings.Contains(err.Error(), "does-not-exist") {
		t.Errorf("error %q does not name the mailbox", err)
	}
}
