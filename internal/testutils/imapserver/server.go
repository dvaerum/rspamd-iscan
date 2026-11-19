package imapserver

import (
	"errors"
	"net"
	"testing"

	"github.com/emersion/go-imap/v2/imapserver"
	"github.com/emersion/go-imap/v2/imapserver/imapmemserver"
)

type Server struct {
	UserName   string
	UserPasswd string
	ListenAddr string

	BackupMailbox     string
	HamMailbox        string
	InboxMailBox      string
	ScanMailbox       string
	SpamMailbox       string
	UndetectedMailbox string
	WaitMailbox       string

	srv *imapserver.Server
	ch  chan error
}

func StartServer(t *testing.T) *Server {
	srv := Server{
		UserName:          "user",
		UserPasswd:        "none",
		ListenAddr:        "127.0.0.1:0",
		ch:                make(chan error, 2),
		InboxMailBox:      "INBOX",
		ScanMailbox:       "unscanned",
		BackupMailbox:     "backup",
		HamMailbox:        "ham",
		SpamMailbox:       "spam",
		UndetectedMailbox: "undetected",
		WaitMailbox:       "wait",
	}

	user := imapmemserver.NewUser(srv.UserName, srv.UserPasswd)
	createMailbox(t, user, srv.BackupMailbox)
	createMailbox(t, user, srv.HamMailbox)
	createMailbox(t, user, srv.InboxMailBox)
	createMailbox(t, user, srv.ScanMailbox)
	createMailbox(t, user, srv.SpamMailbox)
	createMailbox(t, user, srv.UndetectedMailbox)
	createMailbox(t, user, srv.WaitMailbox)

	msrv := imapmemserver.New()
	msrv.AddUser(user)

	isrv := imapserver.New(&imapserver.Options{
		NewSession: func(*imapserver.Conn) (imapserver.Session, *imapserver.GreetingData, error) {
			return msrv.NewSession(), nil, nil
		},
		Logger:       testLoggerAsImapServerLogger(t),
		InsecureAuth: true,
	})

	// Port 0 gives every test its own free port, so tests in parallel
	// packages cannot collide; ListenAddr is rewritten to the chosen address.
	ln, err := net.Listen("tcp", srv.ListenAddr)
	if err != nil {
		t.Fatalf("listening on %s failed: %s", srv.ListenAddr, err)
	}
	srv.ListenAddr = ln.Addr().String()
	srv.srv = isrv

	// Close the listener ourselves: if Close runs before Serve starts,
	// go-imap's Serve returns without closing it and the listener leaks.
	t.Cleanup(func() {
		_ = isrv.Close()
		_ = ln.Close()
	})
	go func() {
		err := isrv.Serve(ln)
		srv.ch <- err
		close(srv.ch)
	}()

	return &srv
}

func createMailbox(t *testing.T, user *imapmemserver.User, mailboxName string) {
	if err := user.Create(mailboxName, nil); err != nil {
		t.Fatalf("creating %s mailbox failed: %s", mailboxName, err)
	}
}

func (s *Server) Close() error {
	err := s.srv.Close()

	for chErr := range s.ch {
		err = errors.Join(err, chErr)
	}
	return err
}
