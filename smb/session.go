package smb

import (
	"bufio"
	"bytes"
	"encoding/asn1"
	"encoding/binary"
	"fmt"
	"io"
	"net"

	"github.com/hy05190134/smb/gss"
	"github.com/hy05190134/smb/ntlmssp"
	"github.com/hy05190134/smb/smb/encoder"
	"github.com/pkg/errors"
)

// Session wraps the current connection session settings
type Session struct {
	IsSigningRequired bool
	IsAuthenticated   bool
	debug             bool
	securityMode      uint16
	messageID         uint64
	sessionID         uint64
	conn              net.Conn
	dialect           uint16
	options           *Options
	trees             map[string]uint32
}

// Options store current options
type Options struct {
	Host        string
	Port        int
	Workstation string
	Domain      string
	User        string
	Password    string
	Hash        string
	Debug       bool
}

func validateOptions(opt *Options) (err error) {
	if opt.Host == "" {
		err = fmt.Errorf("missing required option: Host")
		return
	}
	if opt.Port < 1 || opt.Port > 65535 {
		err = fmt.Errorf("invalid or missing value: Port")
		return
	}
	return
}

// New creates a new connection
func New(opt *Options) (s *Session, err error) {
	err = validateOptions(opt)
	if err != nil {
		err = errors.Wrap(err, "options are invalid")
		return
	}

	conn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", opt.Host, opt.Port))
	if err != nil {
		return
	}

	s = &Session{
		IsSigningRequired: false,
		IsAuthenticated:   false,
		debug:             opt.Debug,
		securityMode:      0,
		messageID:         0,
		sessionID:         0,
		dialect:           0,
		conn:              conn,
		options:           opt,
		trees:             make(map[string]uint32),
	}

	err = s.negotiateProtocol()
	if err != nil {
		err = errors.Wrap(err, "failed to negotiate protocol")
		return
	}

	return s, nil
}

// NegotiateProtocol attempts to negotiate the protocol
func (s *Session) negotiateProtocol() (err error) {
	negReq := s.NewNegotiateReq()
	buf, err := s.send(negReq)
	if err != nil {
		err = errors.Wrap(err, "failed to send negotiate request")
		return
	}

	negRes := newNegotiateRes()
	if err := encoder.Unmarshal(buf, negRes); err != nil {
		err = errors.Wrap(err, "failed to unmarshal negotiation response")
		//	return err
	}

	if negRes.Header.Status != StatusOk {
		err = errors.Wrapf(err, "unexpected status header: %d", negRes.Header.Status)
		return
	}

	// Check SPNEGO security blob
	spnegoOID, err := gss.ObjectIDStrToInt(gss.SpnegoOid)
	if err != nil {
		err = errors.Wrap(err, "security blob failure")
		return
	}
	oid := negRes.SecurityBlob.OID
	if !oid.Equal(asn1.ObjectIdentifier(spnegoOID)) {
		err = fmt.Errorf("unknown security type OID [expecting %s]: %s", gss.SpnegoOid, negRes.SecurityBlob.OID)
		return
	}

	// Check for NTLMSSP support
	ntlmsspOID, err := gss.ObjectIDStrToInt(gss.NtLmSSPMechTypeOid)
	if err != nil {
		err = errors.Wrap(err, "failed to check for NTLMSSP support")
		return
	}

	hasNTLMSSP := false
	for _, mechType := range negRes.SecurityBlob.Data.MechTypes {
		if mechType.Equal(asn1.ObjectIdentifier(ntlmsspOID)) {
			hasNTLMSSP = true
			break
		}
	}
	if !hasNTLMSSP {
		err = fmt.Errorf("server does not support NTLMSSP")
		return
	}

	s.securityMode = negRes.SecurityMode
	s.dialect = negRes.DialectRevision

	// Determine whether signing is required
	mode := uint16(s.securityMode)
	if mode&SecurityModeSigningEnabled > 0 {
		if mode&SecurityModeSigningRequired > 0 {
			s.IsSigningRequired = true
		} else {
			s.IsSigningRequired = false
		}
	} else {
		s.IsSigningRequired = false
	}

	ssreq, err := s.NewSessionSetup1Req()
	if err != nil {
		err = errors.Wrap(err, "failed to establish new session setup1 request")
		return
	}
	ssres, err := newSessionSetup1Res()
	if err != nil {
		err = errors.Wrap(err, "failed to establish new session setup1 response")
		return
	}
	buf, err = encoder.Marshal(ssreq)
	if err != nil {
		err = errors.Wrap(err, "failed to marshal setup1 request")
		return
	}

	buf, err = s.send(ssreq)
	if err != nil {
		err = errors.Wrap(err, "failed to send setup1 request")
		return
	}

	err = encoder.Unmarshal(buf, &ssres)
	if err != nil {
		err = errors.Wrap(err, "failed to unmarshal setup1 response")
		return
	}

	challenge := ntlmssp.NewChallenge()
	resp := ssres.SecurityBlob
	err = encoder.Unmarshal(resp.ResponseToken, &challenge)
	if err != nil {
		err = errors.Wrap(err, "failed to unmarshal security blob")
		return
	}

	if ssres.Header.Status != StatusMoreProcessingRequired {
		status, ok := StatusMap[negRes.Header.Status]
		if !ok {
			err = errors.Wrapf(err, "unknown header type %d", negRes.Header.Status)
			return
		}
		err = fmt.Errorf("unexpected status header: %s", status)
		return
	}
	s.sessionID = ssres.Header.SessionID

	ss2req, err := s.NewSessionSetup2Req()
	if err != nil {
		err = errors.Wrap(err, "failed to create setup2 request")
		return
	}

	var auth ntlmssp.Authenticate
	if s.options.Hash != "" {
		// Hash present, use it for auth
		auth = ntlmssp.NewAuthenticateHash(s.options.Domain, s.options.User, s.options.Workstation, s.options.Hash, challenge)
	} else {
		// No hash, use password
		auth = ntlmssp.NewAuthenticatePass(s.options.Domain, s.options.User, s.options.Workstation, s.options.Password, challenge)
	}

	responseToken, err := encoder.Marshal(auth)
	if err != nil {
		err = errors.Wrap(err, "failed to marshal response token")
		return
	}
	resp2 := ss2req.SecurityBlob
	resp2.ResponseToken = responseToken
	ss2req.SecurityBlob = resp2
	ss2req.Header.Credits = 127
	buf, err = encoder.Marshal(ss2req)
	if err != nil {
		err = errors.Wrap(err, "failed to marshal setup2 request")
		return
	}

	buf, err = s.send(ss2req)
	if err != nil {
		err = errors.Wrap(err, "failed to send setup2 request")
		return
	}

	var authResp Header
	err = encoder.Unmarshal(buf, &authResp)
	if err != nil {
		err = errors.Wrap(err, "failed to unmarshal auth response")
		return
	}

	if authResp.Status != StatusOk {
		status, ok := StatusMap[authResp.Status]
		if !ok {
			err = errors.Wrapf(err, "unrecognized auth response status type: %d", authResp.Status)
			return
		}
		err = fmt.Errorf("auth response failed with status %s", status)
		return
	}
	s.IsAuthenticated = true
	return
}

// TreeConnect establishes a connection with a tree share
func (s *Session) TreeConnect(name string) (err error) {

	req, err := s.NewTreeConnectReq(name)
	if err != nil {
		err = errors.Wrap(err, "failed to create new tree connect request")
		return
	}
	buf, err := s.send(req)
	if err != nil {
		err = errors.Wrap(err, "failed to send new tree connect request")
		return
	}
	var res treeConnectRes
	err = encoder.Unmarshal(buf, &res)
	if err != nil {
		err = errors.Wrap(err, "failed to unmarshal tree connect response")
		return
	}

	if res.Header.Status != StatusOk {
		status, ok := StatusMap[res.Header.Status]
		if !ok {
			err = fmt.Errorf("failed to connect to tree (unknown status): %d", res.Header.Status)
			return
		}
		err = fmt.Errorf("failed to connect to tree: %s", status)
		return
	}
	s.trees[name] = res.Header.TreeID
	return nil
}

// TreeDisconnect stops a connection
func (s *Session) TreeDisconnect(name string) (err error) {

	var treeid uint32
	var pathFound bool

	for k, v := range s.trees {
		if k == name {
			treeid = v
			pathFound = true
			break
		}
	}

	if !pathFound {
		err = fmt.Errorf("Unable to find tree path for disconnect")
		return
	}

	req, err := s.NewTreeDisconnectReq(treeid)
	if err != nil {
		err = errors.Wrap(err, "failed to create new tree disconnect request")
		return
	}
	buf, err := s.send(req)
	if err != nil {
		err = errors.Wrap(err, "failed to send tree disconnect")
		return
	}

	var res treeDisconnectRes
	err = encoder.Unmarshal(buf, &res)
	if err != nil {
		err = errors.Wrap(err, "failed to unmarshal tree disconnect response")
		return
	}
	if res.Header.Status != StatusOk {
		status, ok := StatusMap[res.Header.Status]
		if !ok {
			err = fmt.Errorf("failed to disconnect from tree: (unknown status): %s", res.Header.Status)
			return
		}
		err = fmt.Errorf("failed to disconnect from tree: %s", status)
		return
	}
	delete(s.trees, name)

	return nil
}

// OpenFile opens a file to begin a transfer
func (s *Session) OpenFile(tree, name string) (fileHandle *FileID, err error) {
	req, err := s.NewCreateReq(tree, name)
	if err != nil {
		err = errors.Wrap(err, "failed to create new create request")
		return
	}
	buf, err := s.send(req)
	if err != nil {
		err = errors.Wrap(err, "failed to send new create request")
		return
	}
	var res createRes

	err = encoder.Unmarshal(buf, &res)
	if err != nil {
		err = errors.Wrap(err, "failed to unmarshal new create request")
		return
	}

	if res.Header.Status != StatusOk {
		status, ok := StatusMap[res.Header.Status]
		if !ok {
			err = fmt.Errorf("failed to do new create (unknown status): %d", res.Header.Status)
			return
		}
		err = fmt.Errorf("failed to do new create: %s", status)
		return
	}

	fileHandle = &res.FileID
	return
}

// ReadFile reads a new file
func (s *Session) ReadFile(tree string, fileHandle *FileID) (data []byte, err error) {
	req := s.newReadReq(tree, fileHandle)
	if err != nil {
		err = errors.Wrap(err, "failed to create new read request")
		return
	}
	buf, err := s.send(req)
	if err != nil {
		err = errors.Wrap(err, "Failed to send read request")
		return
	}
	var res readRes
	err = encoder.Unmarshal(buf, res)
	if err != nil {
		err = errors.Wrap(err, "failed to unmarshal read response")
		return nil, err
	}

	if res.Header.Status != StatusOk {
		err = fmt.Errorf("Failed to read file: %s", StatusMap[res.Header.Status])
		return
	}
	data = res.Data
	return
}

// CloseFile closes a file request
func (s *Session) CloseFile(tree string, fileHandle *FileID) (err error) {
	req, err := s.NewCloseReq(tree, fileHandle)
	if err != nil {
		err = errors.Wrap(err, "failed to create new close request")
		return
	}
	buf, err := s.send(req)
	if err != nil {
		err = errors.Wrap(err, "failed to send close request")
		return
	}

	var res closeRes
	err = encoder.Unmarshal(buf, &res)
	if err != nil {
		err = errors.Wrap(err, "failed to unmarshal close file response")
		return
	}

	if res.Header.Status != StatusOk {
		err = fmt.Errorf("Failed to close file: %s", StatusMap[res.Header.Status])
		return
	}
	return
}

// LogOff exits the session
func (s *Session) LogOff() (err error) {
	req, err := s.NewLogoffReq()
	if err != nil {
		err = errors.Wrap(err, "failed to create new logoff request")
		return
	}

	buf, err := s.send(req)
	if err != nil {
		err = errors.Wrap(err, "failed to send logoff request")
		return
	}

	var res logoffRes
	err = encoder.Unmarshal(buf, &res)
	if err != nil {
		err = errors.Wrap(err, "failed to unmarshal logoff request")
		return
	}

	if res.Header.Status != StatusOk {
		err = fmt.Errorf("failed to log off: %s", StatusMap[res.Header.Status])
		return
	}
	return
}

// Close closes the session
func (s *Session) Close() (errs []error) {
	var err error
	for k := range s.trees {
		err = s.TreeDisconnect(k)
		if err != nil {
			errs = append(errs, errors.Wrapf(err, "failed to disconnect tree %s", k))
		}
	}

	err = s.conn.Close()
	if err != nil {
		errs = append(errs, errors.Wrap(err, "failed to disconnect connection"))
	}
	return
}

func (s *Session) send(req interface{}) (res []byte, err error) {
	buf, err := encoder.Marshal(req)
	if err != nil {
		err = errors.Wrap(err, "failed during marshal")
		return
	}

	b := new(bytes.Buffer)
	err = binary.Write(b, binary.BigEndian, uint32(len(buf)))
	if err != nil {
		err = errors.Wrap(err, "failed during write")
		return
	}

	rw := bufio.NewReadWriter(bufio.NewReader(s.conn), bufio.NewWriter(s.conn))
	_, err = rw.Write(append(b.Bytes(), buf...))
	if err != nil {
		err = errors.Wrap(err, "failed during readwriter")
		return
	}
	rw.Flush()

	var size uint32
	if err = binary.Read(rw, binary.BigEndian, &size); err != nil {
		err = errors.Wrap(err, "failed during binary read")
		return
	}
	if size > 0x00FFFFFF {
		err = fmt.Errorf("invalid netbios session message")
		return
	}

	data := make([]byte, size)
	l, err := io.ReadFull(rw, data)
	if err != nil {
		err = errors.Wrap(err, "failed to read payload")
		return
	}
	if uint32(l) != size {
		err = fmt.Errorf("message size invalid")
		return
	}

	protID := data[0:4]
	switch string(protID) {
	default:
		err = fmt.Errorf("protocol %s not implemented", string(protID))
		return
	case ProtocolSmb2:
	}

	s.messageID++
	return
}
