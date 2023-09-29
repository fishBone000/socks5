package socksy5

import (
	"net"
)

// Connect handles the CONNECT request,
// accepting or denying it accordingly.
//
// Currently if req is to be denied, only [RepGeneralFailure]
// will be replied.
func Connect(req *ConnectRequest) error {
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
