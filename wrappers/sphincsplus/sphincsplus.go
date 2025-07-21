package sphincsplus

/*
#cgo CFLAGS: -I.
#include "api.h"
#include "params.h"
#include "address.h"
#include <stdlib.h>
// Map PQClean names to standard ones for Go cgo compatibility:
#define CRYPTO_PUBLICKEYBYTES PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES
#define CRYPTO_SECRETKEYBYTES PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES
#define CRYPTO_BYTES PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_CRYPTO_BYTES

#define crypto_sign_keypair PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_crypto_sign_keypair
#define crypto_sign PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_crypto_sign
#define crypto_sign_open PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_crypto_sign_open
*/
import "C"
import ("unsafe")

// Exported key/signature sizes
func PublicKeyBytes() int  { return int(C.CRYPTO_PUBLICKEYBYTES) }
func SecretKeyBytes() int  { return int(C.CRYPTO_SECRETKEYBYTES) }
func SignatureBytes() int  { return int(C.CRYPTO_BYTES) }

// KeyGen generates a public/private keypair
func KeyGen() (pk []byte, sk []byte) {
    pk = make([]byte, PublicKeyBytes())
    sk = make([]byte, SecretKeyBytes())
    ret := C.crypto_sign_keypair(
        (*C.uchar)(unsafe.Pointer(&pk[0])),
        (*C.uchar)(unsafe.Pointer(&sk[0])),
    )
    if ret != 0 {
        panic("SPHINCS+ KeyGen failed")
    }
    return pk, sk
}

// Sign returns a signature for msg using the secret key sk.
func Sign(sk []byte, msg []byte) []byte {
    sig := make([]byte, SignatureBytes()+len(msg)) // oversized buffer
    var siglen C.ulonglong
    ret := C.crypto_sign(
        (*C.uchar)(unsafe.Pointer(&sig[0])),
        &siglen,
        (*C.uchar)(unsafe.Pointer(&msg[0])),
        C.ulonglong(len(msg)),
        (*C.uchar)(unsafe.Pointer(&sk[0])),
    )
    if ret != 0 {
        panic("SPHINCS+ Sign failed")
    }
    return sig[:siglen]
}

// Verify checks that sig is a valid signature for msg under pk.
// Returns true if valid, false if invalid.
func Verify(pk []byte, msg []byte, sig []byte) bool {
    var mlen C.ulonglong
    out := make([]byte, len(msg)+SignatureBytes())
    ret := C.crypto_sign_open(
        (*C.uchar)(unsafe.Pointer(&out[0])),
        &mlen,
        (*C.uchar)(unsafe.Pointer(&sig[0])),
        C.ulonglong(len(sig)),
        (*C.uchar)(unsafe.Pointer(&pk[0])),
    )
    return ret == 0
}
