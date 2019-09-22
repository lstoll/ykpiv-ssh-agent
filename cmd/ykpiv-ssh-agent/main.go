package main

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"

	"github.com/lstoll/ykpiv-ssh-agent/internal/yubikey"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"pault.ag/go/ykpiv"
)

func main() {
	ag := &ykagent{}

	sigC := make(chan os.Signal, 1)
	signal.Notify(sigC, syscall.SIGINT, syscall.SIGTERM)

	agentDir, err := ioutil.TempDir("", "ssh-agent-test")
	if err != nil {
		log.Fatal(err)
	}
	defer os.RemoveAll(agentDir)

	home, err := os.UserHomeDir()
	if err != nil {
		log.Fatal(err)
	}

	agentSock := filepath.Join(home, ".ssh", "ykpiv-agent.sock")
	agentLis, err := net.Listen("unix", agentSock)
	if err != nil {
		log.Fatalf("failed to create agent socket listener")
	}

	log.Printf("Listening at: %s", agentSock)

	newConns := make(chan net.Conn, 1)
	go func() {
		for {
			c, err := agentLis.Accept()
			if err != nil {
				log.Printf("failed to accept incoming agent connection: %v", err)
				return
			}
			newConns <- c
		}
	}()

	for {
		select {
		case c := <-newConns:
			log.Print("agent received connection")
			go func() {
				if err := agent.ServeAgent(ag, c); err != nil && err != io.EOF {
					log.Fatalf("error serving agent: %v", err)
				}
			}()
		case <-sigC:
			agentLis.Close()
			log.Fatal("Signal received, interrupting")
		}
	}

}

var _ agent.Agent = (*ykagent)(nil)

type ykagent struct {
	ykl sync.Mutex
}

// List returns the identities known to the agent.
func (s *ykagent) List() ([]*agent.Key, error) {
	sl, ykcl, err := s.getSlot()
	if err != nil {
		return nil, err
	}
	defer ykcl()

	pk, err := ssh.NewPublicKey(sl.Public())
	if err != nil {
		return nil, fmt.Errorf("failed to create SSH key from slot public key: %w", err)
	}

	return []*agent.Key{
		// Offer up the public key, in case the remote isn't using CA
		{
			Format:  "rsa",
			Blob:    pk.Marshal(),
			Comment: "yubikey-backed key",
		},
	}, nil
}

// Sign has the agent sign the data using a protocol 2 key as defined
// in [PROTOCOL.agent] section 2.6.2.
func (s *ykagent) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	sl, ykcl, err := s.getSlot()
	if err != nil {
		return nil, err
	}
	defer ykcl()

	pk, err := ssh.NewPublicKey(sl.Public())
	if err != nil {
		return nil, fmt.Errorf("failed to create SSH key from slot public key: %w", err)
	}

	if !bytes.Equal(pk.Marshal(), key.Marshal()) {
		return nil, fmt.Errorf("can't sign for this key")
	}

	ykSigner, err := ssh.NewSignerFromSigner(sl)
	if err != nil {
		return nil, fmt.Errorf("couldn't create signer: %w", err)
	}

	sig, err := ykSigner.Sign(rand.Reader, data)
	if err != nil {
		return nil, fmt.Errorf("failed to sign data: %w", err)
	}

	return sig, nil
}

// Add adds a private key to the agent.
func (s *ykagent) Add(key agent.AddedKey) error {
	return errors.New("this agent does not support adding keys")
}

// Remove removes all identities with the given public key.
func (s *ykagent) Remove(key ssh.PublicKey) error {
	return errors.New("this agent does not support removing keys")
}

// RemoveAll removes all identities.
func (s *ykagent) RemoveAll() error {
	return errors.New("this agent does not support removing keys")
}

// Lock locks the agent. Sign and Remove will fail, and List will empty an empty list.
func (s *ykagent) Lock(passphrase []byte) error {
	return errors.New("this agent is not lockable")
}

// Unlock undoes the effect of Lock
func (s *ykagent) Unlock(passphrase []byte) error {
	return nil // always unlocked
}

// Signers returns signers for all the known keys.
func (s *ykagent) Signers() ([]ssh.Signer, error) {
	panic("This should not be called - for client implementations only?")
}

func (s *ykagent) getSlot() (slot *ykpiv.Slot, closer func() error, err error) {
	// I'm not 100% sure that we need to open/close on each usage, need to
	// investigate how the underlying library manages locking and concurrent
	// consumers of the key. In the mean time, err on the side of caution
	s.ykl.Lock()
	yk, err := yubikey.GetForUsage("", "123456")
	if err != nil {
		return nil, nil, err
	}
	sl, err := yk.Slot(ykpiv.Authentication)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get slot: %w", err)
	}
	closer = func() error {
		err := yk.Close()
		s.ykl.Unlock()
		return err
	}
	return sl, closer, nil
}
