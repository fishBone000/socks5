package s5i

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

type closable interface {
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

func sAddr(c net.Conn) string {
  laddr := c.LocalAddr()
  raddr := c.RemoteAddr()
  var lstr string
  var rstr string
  if laddr == nil {
    lstr = "<unknown>"
  } else {
    lstr = laddr.String()
  }
  if raddr == nil {
    rstr = "<unknown>"
  } else {
    rstr = raddr.String()
  }
  return "S|"+lstr+"<->"+rstr+"|C"
}
