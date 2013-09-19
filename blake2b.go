// Package blake2 provides an optimized Go wrapper around the public domain
// implementation of BLAKE2.
// The cryptographic hash function BLAKE2 is an improved version of the SHA-3
// finalist BLAKE. Like BLAKE or SHA-3, BLAKE2 offers the highest security, yet
// is fast as MD5 on 64-bit platforms and requires at least 33% less RAM than
// SHA-2 or SHA-3 on low-end systems.
package blake2

import (
	// #cgo CFLAGS: -O3
	// #include "blake2.h"
	"C"
	"hash"
	"unsafe"
)

type digest struct {
	state *C.blake2b_state
	key   []byte
	size  int
}

// NewBlake2B returns a new 512-bit BLAKE2B hash.
func NewBlake2B() hash.Hash {
	d := new(digest)
	d.size = 64
	d.Reset()
	return d
}

// NewKeyedBlake2B returns a new 512-bit BLAKE2B hash with the given secret key.
func NewKeyedBlake2B(key []byte) hash.Hash {
	d := new(digest)
	d.size = 64
	d.key = key
	d.Reset()
	return d
}

func (*digest) BlockSize() int {
	return 128
}

func (d *digest) Size() int {
	return d.size
}

func (d *digest) Reset() {
	d.state = new(C.blake2b_state)
	if len(d.key) == 0 {
		if C.blake2b_init(d.state, C.uint8_t(d.Size())) < 0 {
			panic("blake2: unable to reset")
		}
	} else {
		if C.blake2b_init_key(d.state, C.uint8_t(d.Size()), unsafe.Pointer(&d.key[0]), C.uint8_t(len(d.key))) < 0 {
			panic("blake2: unable to reset")
		}
	}
}

func (d *digest) Sum(buf []byte) []byte {
	digest := make([]C.uint8_t, d.Size())
	C.blake2b_final(d.state, &digest[0], C.uint8_t(d.Size()))

	for _, v := range digest {
		buf = append(buf, byte(v))
	}

	return buf
}

func (d *digest) Write(buf []byte) (int, error) {
	if len(buf) > 0 {
		c := &buf[0]
		C.blake2b_update(d.state, (*C.uint8_t)(c), C.uint64_t(len(buf)))
	}
	return len(buf), nil
}
