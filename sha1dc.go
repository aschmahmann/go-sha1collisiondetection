package sha1dc

// #cgo CFLAGS:-I${SRCDIR}/sha1collisiondetection/lib
// #cgo LDFLAGS: -L${SRCDIR}/sha1collisiondetection/lib
// #include <sha1collisiondetection/lib/sha1.h>
// #include <sha1collisiondetection/lib/sha1.c>
// #include <sha1collisiondetection/lib/ubc_check.h>
// #include <sha1collisiondetection/lib/ubc_check.c>
// #include <stdlib.h>
import "C"
import (
	"errors"
)

// The size of a SHA-1 checksum in bytes.
const Size = 20

// The blocksize of SHA-1 in bytes.
const BlockSize = 64

func New() *digest {
	d := new(digest)
	d.Reset()
	return d
}

type digest struct {
	ctx C.SHA1_CTX
}

func (d *digest) Write(p []byte) (n int, err error) {
	cDataPtr := (*C.char)(C.CBytes(p))
	C.SHA1DCUpdate(&d.ctx, cDataPtr, (C.ulonglong)(len(p)))
	// TODO: is there any info to return from C?
	return len(p), nil
}

var ErrSHA1Collision = errors.New("detected a possible SHA1 collision")

func (d *digest) Finalize() ([]byte, error) {
	b := make([]byte, 20)
	cHashPtr := C.CBytes(b)
	x := C.SHA1DCFinal((*C.uchar)(cHashPtr),&d.ctx)
	val := C.GoBytes(cHashPtr, 20)
	if x != 0 {
		return nil, ErrSHA1Collision
	}
	return val, nil
}

func (d *digest) Reset() {
	C.SHA1DCInit(&d.ctx)
}

func (d *digest) Size() int { return Size }

func (d *digest) BlockSize() int { return BlockSize }
