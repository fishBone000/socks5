package socksy5

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
)

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

func readByte(reader io.Reader) (byte, error) {
	buf := make([]byte, 1)

	if _, err := io.ReadFull(reader, buf); err != nil {
		return 0, err
	}
	return buf[0], nil
}

func readUInt16BigEndian(reader io.Reader) (uint16, error) {
	buf := make([]byte, 2)

	if _, err := io.ReadFull(reader, buf); err != nil {
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

func parseUint16(str string) (i uint16, err error) {
	d, err := strconv.Atoi(str)
	if err != nil {
		return
	}
	if d < 0x00 || d > 0xFFFF {
		return 0, fmt.Errorf("%d is not uint16", d)
	}
	return uint16(d), err
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
	if method >= 0x0A && method <= 0x7F {
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

func relayAddr2str(craddr, claddr, hladdr, hraddr net.Addr) string {
	return fmt.Sprintf(
		"relay [client %s]<->[%s server %s]<->[%s host]",
		craddr, claddr,
		hladdr, hraddr,
	)
}

func relay2str(cConn net.Conn, hConn net.Conn) string {
	return relayAddr2str(cConn.RemoteAddr(), cConn.LocalAddr(), hConn.LocalAddr(), hConn.RemoteAddr())
}

func isByteOneOf(a byte, bytes ...byte) bool {
	for _, v := range bytes {
		if a == v {
			return true
		}
	}
	return false
}

func cpySlice(src []byte) (result []byte) {
	result = make([]byte, len(src))
	copy(result, src)
	return
}

func listenMultipleTCP(ips []net.IP, port string) (ls []net.Listener, err error) {
	result := make([]net.Listener, 0, 4)

	for _, ip := range ips {
		var l net.Listener

		l, err := net.Listen("tcp", net.JoinHostPort(ip.String(), port))
		if err != nil {
			break
		}

		if port == "0" {
			_, port, _ = net.SplitHostPort(l.Addr().String())
		}

		result = append(result, l)
	}

	if err != nil {
		for _, l := range result {
			l.Close()
		}
		return nil, err
	}

	return result, nil
}

func parseHostToAddrPort(host string) *AddrPort {
	result := new(AddrPort)
	if ipAddr, err := netip.ParseAddr(host); err == nil {
		if ipAddr.Is4() {
			result.Type = ATYPV4
		} else {
			result.Type = ATYPV6
		}
		raw, _ := ipAddr.MarshalBinary()
		result.Addr = cpySlice(raw)
	} else {
		result.Type = ATYPDOMAIN
		result.Addr = []byte(host)
	}
	return result
}

type sliceReader struct {
	bytes []byte
	n     int
}

func newSliceReader(b []byte) *sliceReader {
	bytes := make([]byte, len(b))
	copy(bytes, b)
	return &sliceReader{
		bytes: bytes,
	}
}

func (r *sliceReader) Read(p []byte) (n int, err error) {
	if len(r.bytes[r.n:]) == 0 {
		return 0, io.EOF
	}
	n = copy(p, r.bytes[r.n:])
	r.n += n
	return n, nil
}
