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
	"fmt"
	"hash"
)

// The size of a SHA-1 checksum in bytes.
const Size = 20

// The blocksize of SHA-1 in bytes.
const BlockSize = 64

func New() hash.Hash {
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

func (d *digest) Sum(b []byte) []byte {
	// TODO: Don't modify underlying ctx
	b := make([]byte, 20)
	cHashPtr := C.CBytes(b)
	x := C.SHA1DCFinal((*C.uchar)(cHashPtr),&d.ctx)
	val := C.GoBytes(cHashPtr, 20)
}

func (d *digest) Reset() {
	C.SHA1DCInit(&d.ctx)
}

func (d *digest) Size() int { return Size }

func (d *digest) BlockSize() int { return BlockSize }

var _ hash.Hash = (*digest)(nil)

func main() {


	var ctx C.SHA1_CTX
	b := make([]byte, 20)
	C.SHA1DCInit(&ctx)

	data := []byte("abc123\r\n")
	cDataPtr := (*C.char)(C.CBytes(data))
	C.SHA1DCUpdate(&ctx, cDataPtr, (C.ulonglong)(len(data)))
	cHashPtr := C.CBytes(b)
	x := C.SHA1DCFinal((*C.uchar)(cHashPtr),&ctx)
	val := C.GoBytes(cHashPtr, 20)
	fmt.Printf("output %v\n", x)
	fmt.Printf("hash %x\n", val)
}