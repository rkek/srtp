package srtp

import (
	"errors"
	"fmt"
	"net"

	"github.com/pion/logging"
	"github.com/pion/rtcp"
)

// SessionSRTCP implements io.ReadWriteCloser and provides a bi-directional SRTCP session
// SRTCP itself does not have a design like this, but it is common in most applications
// for local/remote to each have their own keying material. This provides those patterns
// instead of making everyone re-implement
type SessionSRTCP struct {
	session
	writeStream *WriteStreamSRTCP
}

// NewSessionSRTCP creates a SRTCP session using conn as the underlying transport.
func NewSessionSRTCP(conn net.Conn, config *Config) (*SessionSRTCP, error) {
	if config == nil {
		return nil, errors.New("no config provided")
	}

	loggerFactory := config.LoggerFactory
	if loggerFactory == nil {
		loggerFactory = logging.NewDefaultLoggerFactory()
	}

	s := &SessionSRTCP{
		session: session{
			nextConn:    conn,
			readStreams: map[uint32]readStream{},
			newStream:   make(chan readStream),
			started:     make(chan interface{}),
			closed:      make(chan interface{}),
			log:         loggerFactory.NewLogger("srtp"),
		},
	}
	s.writeStream = &WriteStreamSRTCP{s}

	err := s.session.start(
		config.Keys.LocalMasterKey, config.Keys.LocalMasterSalt,
		config.Keys.RemoteMasterKey, config.Keys.RemoteMasterSalt,
		config.Profile,
		s,
	)
	if err != nil {
		return nil, err
	}
	return s, nil
}

// OpenWriteStream returns the global write stream for the Session
func (s *SessionSRTCP) OpenWriteStream() (*WriteStreamSRTCP, error) {
	return s.writeStream, nil
}

// OpenReadStream opens a read stream for the given SSRC, it can be used
// if you want a certain SSRC, but don't want to wait for AcceptStream
func (s *SessionSRTCP) OpenReadStream(SSRC uint32) (*ReadStreamSRTCP, error) {
	r, _ := s.session.getOrCreateReadStream(SSRC, s, newReadStreamSRTCP)

	if readStream, ok := r.(*ReadStreamSRTCP); ok {
		return readStream, nil
	}
	return nil, fmt.Errorf("failed to open ReadStreamSRCTP, type assertion failed")
}

// AcceptStream returns a stream to handle RTCP for a single SSRC
func (s *SessionSRTCP) AcceptStream() (*ReadStreamSRTCP, uint32, error) {
	stream, ok := <-s.newStream
	if !ok {
		return nil, 0, fmt.Errorf("SessionSRTCP has been closed")
	}

	readStream, ok := stream.(*ReadStreamSRTCP)
	if !ok {
		return nil, 0, fmt.Errorf("newStream was found, but failed type assertion")
	}

	return readStream, stream.GetSSRC(), nil
}

// Close ends the session
func (s *SessionSRTCP) Close() error {
	return s.session.close()
}

// Private

func (s *SessionSRTCP) write(buf []byte) (int, error) {
	if _, ok := <-s.session.started; ok {
		return 0, fmt.Errorf("started channel used incorrectly, should only be closed")
	}

	s.session.localContextMutex.Lock()
	defer s.session.localContextMutex.Unlock()

	encrypted, err := s.localContext.EncryptRTCP(nil, buf, nil)
	if err != nil {
		return 0, err
	}
	return s.session.nextConn.Write(encrypted)
}

func (s *SessionSRTCP) decrypt(buf []byte) error {
	decrypted, err := s.remoteContext.DecryptRTCP(buf, buf, nil)
	if err != nil {
		return err
	}

	forward := func(ssrc uint32) (closed bool, err error) {
		r, isNew := s.session.getOrCreateReadStream(ssrc, s, newReadStreamSRTCP)
		if r == nil {
			return true, nil // Session has been closed
		} else if isNew {
			s.session.newStream <- r // Notify AcceptStream
		}

		readStream, ok := r.(*ReadStreamSRTCP)
		if !ok {
			return false, fmt.Errorf("failed to get/create ReadStreamSRTP")
		}

		_, err = readStream.write(decrypted)
		if err != nil {
			return false, err
		}
		return false, nil
	}

	pkt, err := rtcp.Unmarshal(decrypted)
	if err != nil {
		return err
	}

	cpkt := rtcp.CompoundPacket(pkt)
	ssrc_set := make(map[uint32]bool)
	if cpkt.Validate() == nil {
		for _, ssrc := range cpkt.DestinationSSRC() {
			ssrc_set[ssrc] = true
		}
	} else {
		for _, p := range pkt {
			for _, ssrc := range p.DestinationSSRC() {
				ssrc_set[ssrc] = true
			}
		}
	}

	for ssrc, _ := range ssrc_set {
		_, err = forward(ssrc)
		if err != nil {
			return err
		}
	}

	return nil
}
