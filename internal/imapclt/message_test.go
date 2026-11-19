package imapclt

import (
	"io"
	"os"
	"testing"
	"time"

	"github.com/fho/rspamd-iscan/internal/testutils/assert"
	"github.com/fho/rspamd-iscan/internal/testutils/mail"
)

func testMailData(t *testing.T) []byte {
	data, err := os.ReadFile(mail.TestHamMailPath(t))
	assert.NoError(t, err)
	return data
}

func TestMessages(t *testing.T) {
	testMailPath := mail.TestHamMailPath(t)
	srv, clt := startServerClient(t)

	assert.NoError(t, clt.Upload(testMailPath, srv.InboxMailBox, time.Now()))
	assert.NoError(t, clt.Upload(testMailPath, srv.InboxMailBox, time.Now()))
	assert.NoError(t, clt.Upload(testMailPath, srv.InboxMailBox, time.Now()))

	cnt := 0
	for msg, err := range clt.Messages(srv.InboxMailBox) {
		assert.NoError(t, err)
		if msg.UID == 0 {
			t.Error("msg.uid is 0")
		}
		body, err := io.ReadAll(msg.Message)
		assert.NoError(t, err)

		assert.NotEqual(t, msg.UID, 0)
		assert.NotEqual(t, len(body), 0)
		expectedMail := testMailData(t)
		assert.Equal(t, string(expectedMail), string(body))
		assert.Equal(t, testMailSubject, msg.Envelope.Subject)
		assert.Equal(t, 1, len(msg.Envelope.Recipients))
		assert.Equal(t, testMailRecipient, msg.Envelope.Recipients[0])
		assert.Equal(t, 1, len(msg.Envelope.From))
		assert.Equal(t, testMailSender, msg.Envelope.From[0])
		cnt++
	}
	assert.Equal(t, 3, cnt)
}

func TestMessages_InternalDate(t *testing.T) {
	srv, clt := startServerClient(t)

	// A date far in the past, so it can't be confused with the time of the
	// upload. IMAP INTERNALDATE has a resolution of one second.
	want := time.Date(2020, time.March, 4, 5, 6, 7, 0, time.FixedZone("x", 2*3600))
	assert.NoError(t, clt.Upload(mail.TestHamMailPath(t), srv.InboxMailBox, want))

	cnt := 0
	for msg, err := range clt.Messages(srv.InboxMailBox) {
		assert.NoError(t, err)
		if !msg.InternalDate.Equal(want) {
			t.Errorf("InternalDate = %s, want %s", msg.InternalDate, want)
		}
		cnt++
	}
	assert.Equal(t, 1, cnt)
}
