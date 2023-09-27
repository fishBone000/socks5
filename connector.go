package socksy5

import (
	"net"
)

// A Connector handles CONNECT request by utilizing [net.Dial]. 
type Connector struct {
}

// Handle handles the CONNECT request, 
// accepting or denying it accordingly. 
func (c *Connector) Handle(req *ConnectRequest) error {
	conn, err := net.Dial(req.Dst().Network(), req.Dst().String())
	if err != nil {
    req.Deny(RepGeneralFailure, "")
		return err
	}
	if ok := req.Accept(conn); !ok {
		return ErrAcceptOrDenyFailed
	}
	return nil
}
