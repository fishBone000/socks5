package s5i

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"

	"github.com/asaskevich/govalidator"
)

type closer interface {
	Close() error
}

func err(err error, a ...any) error {
	if err == nil && len(a) == 0 {
		return nil
	}
	if err == nil {
		return fmt.Errorf("%s", fmt.Sprint(a...))
	}
	if len(a) == 0 {
		return err
	}
	return fmt.Errorf("%s: %w", fmt.Sprint(a...), err)
}

func fillBuffer(b []byte, reader io.Reader) (n int, err error) {
	for n < len(b) && err == nil {
		var n1 int
		n1, err = reader.Read(b[n:])
		n += n1
	}
	return
}

func readByte(reader io.Reader) (byte, error) {
	buf := make([]byte, 1)

	if _, err := fillBuffer(buf, reader); err != nil {
		return 0, err
	}
	return buf[0], nil
}

func readUInt16BigEndian(reader io.Reader) (uint16, error) {
	buf := make([]byte, 2)

	if _, err := fillBuffer(buf, reader); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint16(buf), nil
}

func addrStr(laddr, raddr net.Addr) string {
	if laddr == nil && raddr == nil {
		return ""
	}
	s := ""
	if laddr != nil {
		s += " " + laddr.String()
	}
	s += " ->"
	if raddr != nil {
		s += " " + raddr.String()
	}
	return s
}

func parseUint16(str string) (i uint16, ok bool) {
	if d, err := strconv.Atoi(str); err == nil && d >= 0 && d < 0x100 {
		return uint16(d), true
	}
	return 0, false
}

func cmdCode2Str(cmd byte) string {
	switch cmd {
	case CmdCONNECT:
		return "CONNECT"
	case CmdBIND:
		return "BIND"
	case CmdASSOC:
		return "UDP ASSOCIATE"
	default:
		return "CMD " + fmt.Sprintf("0x%02X", cmd)
	}
}

func copyClose(s *Server, r io.ReadCloser, w io.WriteCloser) {
	io.Copy(w, r)
	s.closeCloser(r)
	s.closeCloser(w)
}
