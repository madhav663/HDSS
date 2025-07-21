package falcon

/*
#cgo CFLAGS: -I.
#include "api.h"
#include <stdlib.h>

// PQClean macros
#define CRYPTO_PUBLICKEYBYTES PQCLEAN_FALCON512_CLEAN_CRYPTO_PUBLICKEYBYTES
#define CRYPTO_SECRETKEYBYTES PQCLEAN_FALCON512_CLEAN_CRYPTO_SECRETKEYBYTES
#define CRYPTO_BYTES PQCLEAN_FALCON512_CLEAN_CRYPTO_BYTES
#define crypto_sign_keypair PQCLEAN_FALCON512_CLEAN_crypto_sign_keypair
#define crypto_sign PQCLEAN_FALCON512_CLEAN_crypto_sign
#define crypto_sign_open PQCLEAN_FALCON512_CLEAN_crypto_sign_open
*/
import "C"
import ("unsafe")

func PublicKeyBytes() int  { return int(C.CRYPTO_PUBLICKEYBYTES) }
func SecretKeyBytes() int  { return int(C.CRYPTO_SECRETKEYBYTES) }
func SignatureBytes() int  { return int(C.CRYPTO_BYTES) }

func KeyGen() (pk, sk []byte) {
    pk = make([]byte, PublicKeyBytes())
    sk = make([]byte, SecretKeyBytes())
    ret := C.crypto_sign_keypair(
        (*C.uchar)(unsafe.Pointer(&pk[0])),
        (*C.uchar)(unsafe.Pointer(&sk[0])),
    )
    if ret != 0 {
        panic("Falcon KeyGen failed")
    }
    return pk, sk
}

func Sign(sk, msg []byte) []byte {
    sig := make([]byte, SignatureBytes()+len(msg))
    var siglen C.ulonglong
    ret := C.crypto_sign(
        (*C.uchar)(unsafe.Pointer(&sig[0])),
        &siglen,
        (*C.uchar)(unsafe.Pointer(&msg[0])),
        C.ulonglong(len(msg)),
        (*C.uchar)(unsafe.Pointer(&sk[0])),
    )
    if ret != 0 {
        panic("Falcon Sign failed")
    }
    return sig[:siglen]
}

func Verify(pk, msg, sig []byte) bool {
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
