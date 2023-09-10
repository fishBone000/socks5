package s5i

import (
	"errors"
	"net"
)

var (
  ErrMalformed = errors.New("malformed request/response")
  ErrCmdNotSupported = errors.New("cmd not supported")
)
