package hybrid

import (
    "crypto"
    "crypto/rand"
    "fmt"

    "github.com/cloudflare/circl/kem"
    "github.com/cloudflare/circl/kem/kyber/kyber512"
    "github.com/cloudflare/circl/sign/dilithium/mode2"
)

////////////////////
// --- Kyber ---
////////////////////

// Kyber-512 key generation
func KyberKeyGen() (kem.PublicKey, kem.PrivateKey) {
    scheme := kyber512.Scheme()
    pk, sk, err := scheme.GenerateKeyPair()
    if err != nil {
        panic(fmt.Sprintf("KyberKeyGen error: %v", err))
    }
    return pk, sk // these are kem.PublicKey, kem.PrivateKey interfaces
}

// Kyber encapsulation (encryption)
func KyberEncaps(pk kem.PublicKey) (ct, ss []byte) {
    scheme := kyber512.Scheme()
    c, s, err := scheme.Encapsulate(pk)
    if err != nil {
        panic(fmt.Sprintf("KyberEncaps error: %v", err))
    }
    return c, s
}

// Kyber decapsulation (decryption)
func KyberDecaps(sk kem.PrivateKey, ct []byte) (ss []byte) {
    scheme := kyber512.Scheme()
    s, err := scheme.Decapsulate(sk, ct)
    if err != nil {
        panic(fmt.Sprintf("KyberDecaps error: %v", err))
    }
    return s
}

////////////////////
// --- Dilithium2 ---
////////////////////

// Dilithium2 key generation
func DilithiumKeyGen() (*mode2.PublicKey, *mode2.PrivateKey) {
    pk, sk, err := mode2.GenerateKey(rand.Reader)
    if err != nil {
        panic(fmt.Sprintf("DilithiumKeyGen error: %v", err))
    }
    return pk, sk
}

// Dilithium2 signature
func DilithiumSign(sk *mode2.PrivateKey, msg []byte) []byte {
    sig, err := sk.Sign(rand.Reader, msg, crypto.Hash(0))
    if err != nil {
        panic(fmt.Sprintf("DilithiumSign error: %v", err))
    }
    return sig
}


// Dilithium2 verification
func DilithiumVerify(pk *mode2.PublicKey, msg, sig []byte) bool {
    return mode2.Verify(pk, msg, sig)
}


////////////////////
// --- PQ-Blend+ Hybrid ---
////////////////////

// Keys for both Dilithium2 and Kyber512
type PQBlendKeys struct {
    DilithiumPK *mode2.PublicKey
    DilithiumSK *mode2.PrivateKey
    KyberPK     kem.PublicKey
    KyberSK     kem.PrivateKey
}

// Signature struct
type PQBlendSignature struct {
    DilithiumSig []byte
}

// Generate hybrid keys
func PQBlendKeyGen() PQBlendKeys {
    dpk, dsk := DilithiumKeyGen()
    kpk, ksk := KyberKeyGen()
    return PQBlendKeys{
        DilithiumPK: dpk, DilithiumSK: dsk,
        KyberPK:     kpk, KyberSK: ksk,
    }
}

// Sign with Dilithium2
func PQBlendSign(keys PQBlendKeys, msg []byte) PQBlendSignature {
    dsig := DilithiumSign(keys.DilithiumSK, msg)
    return PQBlendSignature{
        DilithiumSig: dsig,
    }
}

// Verify with Dilithium2
func PQBlendVerify(keys PQBlendKeys, msg []byte, sig PQBlendSignature) bool {
    return DilithiumVerify(keys.DilithiumPK, msg, sig.DilithiumSig)
}
