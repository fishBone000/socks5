package s5i

import (
	"fmt"
	"io"
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
