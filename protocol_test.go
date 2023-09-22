package socksy5

import (
	"encoding/binary"
	"io"
	"reflect"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func FuzzReadAddr(f *testing.F) {
	f.Add(
		[]byte{ATYPV4, 0, 0, 0, 0, 0, 0},
	)

	f.Fuzz(func(t *testing.T, a []byte) {
		r := newSliceReader(a)
		addr, err := readAddrPort(r)

		inputLength := len(a)
		Convey("Read address", t, func() {
			if inputLength == 0 {
				So(addr, ShouldBeNil)
				So(err, ShouldEqual, io.EOF)
				return
			}

			if inputLength >= 1 {
				if a[0] != ATYPV4 && a[0] != ATYPDOMAIN && a[0] != ATYPV6 {
					So(addr, ShouldBeNil)
					So(err, ShouldEqual, ErrMalformed)
					return
				}
			}

			if inputLength == 1 {
				So(addr, ShouldBeNil)
				So(err, ShouldEqual, io.EOF)
				return
			}


			if a[0] == ATYPDOMAIN {
        addrLength := 2+int(a[1])+2
				if addrLength > inputLength {
					So(addr, ShouldBeNil)
					So(err, ShouldEqual, io.EOF)
					return
				} else {
					So(err, ShouldBeNil)
					So(addr.Type, ShouldEqual, ATYPDOMAIN)
					So(addr.Bytes, ShouldEqual, a[2:addrLength-2])
          So(binary.BigEndian.Uint16(a[addrLength-2:addrLength]), ShouldEqual, addr.Port)
					So(r.n, ShouldEqual, addrLength)
					return
				}
			}

			var addrLength int
			if a[0] == ATYPV4 {
				addrLength = 1+4+2
			} else {
				addrLength = 1+16+2
			}
			if inputLength < addrLength {
				So(addr, ShouldBeNil)
				So(err, ShouldEqual, io.EOF)
				return
			}

			So(err, ShouldBeNil)
			So(addr.Bytes, ShouldEqual, a[1:addrLength-2])
      So(binary.BigEndian.Uint16(a[addrLength-2:addrLength]), ShouldEqual, addr.Port)
			So(r.n, ShouldEqual, addrLength)

			return
		})
	})
}

func FuzzAddrMarshalBinary(f *testing.F) {
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, a []byte) {
		r := newSliceReader(a)
		addr, err := readAddrPort(r)
		if err != nil {
			return
		}

		raw, err := addr.MarshalBinary()
		if err != nil {
			t.Logf("err %s read %02x addr %#v", err.Error(), a[:r.n], addr)
			t.Fail()
		}
		if !reflect.DeepEqual(a[:r.n], raw) {
			t.Logf("desired %02x actual %02x", a[:r.n], raw)
			t.Fail()
		}
	})
}

func FuzzReadHandshake(f *testing.F) {
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, a []byte) {
		Convey("read handshake", t, func() {
			r := newSliceReader(a)

			hs, err := readHandshake(r)
			l := len(a)

			if l == 0 {
				So(err, ShouldEqual, io.EOF)
				return
			}

			if l >= 1 && a[0] != VerSOCKS5 {
				So(err, ShouldEqual, ErrMalformed)
				return
			}

			if l == 1 {
				So(err, ShouldEqual, io.EOF)
				return
			}

			if 2+int(a[1]) > l {
				So(err, ShouldEqual, io.EOF)
				return
			}

			So(r.n, ShouldEqual, 2+int(a[1]))
			So(err, ShouldBeNil)
			So(hs.ver, ShouldEqual, VerSOCKS5)
			So(hs.nmethods, ShouldEqual, a[1])
			So(len(hs.methods), ShouldEqual, a[1])
			So(hs.methods, ShouldEqual, a[2:2+int(a[1])])
			So(hs.wg, ShouldNotBeNil)
			So(hs.once, ShouldNotBeNil)

		})
	})
}
