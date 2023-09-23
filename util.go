package socksy5

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
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

// TODO Replace it with io.ReadFull
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

func conn2str(conn net.Conn) string {
	laddr := conn.LocalAddr()
	raddr := conn.RemoteAddr()
	s := ""
	if laddr == nil {
		s += "<nil>"
	} else {
		s += laddr.String()
	}
	s += " -> "
	if raddr == nil {
		s += "<nil>"
	} else {
		s += raddr.String()
	}
	return s
}

func closer2str(c closer) string {
	switch c := c.(type) {
	case net.Listener:
		return fmt.Sprintf("listener")
	case net.Conn:
		return fmt.Sprintf("connection")
	default:
		return fmt.Sprintf("%T", c)
	}
}

func parseUint16(str string) (i uint16, ok bool) {
	if d, err := strconv.Atoi(str); err == nil && d >= 0 && d < 0x10000 {
		return uint16(d), true
	}
	return 0, false
}

func cmd2str(cmd byte) string {
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

func method2Str(method byte) string {
	switch method {
	case MethodNoAuth:
		return "no auth"
	case MethodGSSAPI:
		return "GSS API"
	case MethodUsrPwd:
		return "USR/PWD"
	case MethodCHAP:
		return "CHAP"
	case byte(0x04):
		return "unassigned 0x04"
	case MethodCRAM:
		return "CRAM"
	case MethodSSL:
		return "SSL"
	case MethodNDS:
		return "NDS"
	case MethodMAF:
		return "MAF"
	case MethodJRB:
		return "JRB"

	case MethodNoAccepted:
		return "no accepted"
	}
	if method >= 0x0A && method <= 0x07F {
		return fmt.Sprintf("unassigned 0x%02X", method)
	} else {
		return fmt.Sprintf("private 0x%02X", method)
	}
}

func rep2str(rep byte) string {
	switch rep {
	case RepSucceeded:
		return "succeeded"
	case RepGeneralFailure:
		return "general failure"
	case RepConnNotAllowedByRuleset:
		return "connection not allowed by ruleset"
	case RepNetworkUnreachable:
		return "Network unreachable"
	case RepHostUnreachable:
		return "Host unreachable"
	case RepConnRefused:
		return "Connection refused"
	case RepTtlExpired:
		return "TTL expired"
	case RepCmdNotSupported:
		return "Command not supported"
	case RepAddrTypeNotSupported:
		return "Address type not supported"
	default:
		return fmt.Sprintf("unassigned 0x%02X", rep)
	}
}

func relay2str(cConn net.Conn, hConn net.Conn) string {
	return fmt.Sprintf(
		"proxy started %s<->%s<->%s<->%s",
		cConn.RemoteAddr(), cConn.LocalAddr(),
		hConn.LocalAddr(), hConn.RemoteAddr(),
	)
}

func copyClose(s *Server, r io.ReadCloser, w io.WriteCloser) {
	io.Copy(w, r)
	s.closeCloser(r)
	s.closeCloser(w)
}

func mapIp2Tcp(ip string) string {
	switch ip {
	case "ip":
		return "tcp"
	case "ip4":
		return "tcp4"
	case "ip6":
		return "tcp6"
	}
	return ip
}

func isIntOneOf(a int, ints ...int) bool {
	for _, v := range ints {
		if a == v {
			return true
		}
	}
	return false
}
