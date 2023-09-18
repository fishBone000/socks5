package socksy5

import "io"

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
