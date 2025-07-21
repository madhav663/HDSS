package aggregate

import (
	// "crypto/rand"
	"fmt"
	falcon "github.com/madhav663/pq-blend-go/wrappers/falcon"
	sphincs "github.com/madhav663/pq-blend-go/wrappers/sphincsplus"
)

type HAPQSKeys struct {
	FalconPK  []byte
	FalconSK  []byte
	SphincsPK []byte
	SphincsSK []byte
}

type HAPQSSignature struct {
	FalconSig  []byte
	SphincsSig []byte
}

// KeyGen for both schemes (generate ONCE per session, reuse keys!)
func HAPQSKeyGen() *HAPQSKeys {
	fpk, fsk := falcon.KeyGen()
	spk, ssk := sphincs.KeyGen()
	return &HAPQSKeys{
		FalconPK: fpk, FalconSK: fsk,
		SphincsPK: spk, SphincsSK: ssk,
	}
}

// Concurrency pattern for signing
func HAPQSSign(keys *HAPQSKeys, msg []byte) *HAPQSSignature {
	type sigResult struct {
		name string
		sig  []byte
	}
	ch := make(chan sigResult, 2)

	go func() {
		ch <- sigResult{"Falcon", falcon.Sign(keys.FalconSK, msg)}
	}()
	go func() {
		ch <- sigResult{"Sphincs+", sphincs.Sign(keys.SphincsSK, msg)}
	}()
	sig := &HAPQSSignature{}
	for i := 0; i < 2; i++ {
		res := <-ch
		switch res.name {
		case "Falcon":
			sig.FalconSig = res.sig
		case "Sphincs+":
			sig.SphincsSig = res.sig
		}
	}
	return sig
}

// Concurrency pattern for verify
func HAPQSVerify(keys *HAPQSKeys, msg []byte, sig *HAPQSSignature) bool {
	type verifyResult struct {
		name  string
		valid bool
	}
	ch := make(chan verifyResult, 2)
	go func() {
		valid := falcon.Verify(keys.FalconPK, msg, sig.FalconSig)
		ch <- verifyResult{"Falcon", valid}
	}()
	go func() {
		valid := sphincs.Verify(keys.SphincsPK, msg, sig.SphincsSig)
		ch <- verifyResult{"Sphincs+", valid}
	}()
	success := true
	for i := 0; i < 2; i++ {
		res := <-ch
		if !res.valid {
			success = false
		}
	}
	return success
}

// Utility for log/debug (optional) 
func PrintSignatureStatus(row int, msg []byte, keys *HAPQSKeys, sig *HAPQSSignature) {
	falconValid := falcon.Verify(keys.FalconPK, msg, sig.FalconSig)
	sphincsValid := sphincs.Verify(keys.SphincsPK, msg, sig.SphincsSig)
	hapqsValid := HAPQSVerify(keys, msg, sig)
	fmt.Printf("[HAPQS] Row %d: Falcon=%v Sphincs+=%v HAPQS=%v\n", row, falconValid, sphincsValid, hapqsValid)
}

func PrintTamperStatus(row int, msg []byte, keys *HAPQSKeys, sig *HAPQSSignature) {
	tampered := append([]byte{}, msg...)
	if len(tampered) > 0 {
		tampered[0] = tampered[0] + 1 // corrupt the message
	}
	falconValid := falcon.Verify(keys.FalconPK, tampered, sig.FalconSig)
	sphincsValid := sphincs.Verify(keys.SphincsPK, tampered, sig.SphincsSig)
	hapqsValid := HAPQSVerify(keys, tampered, sig)
	fmt.Printf("[HAPQS] Tampered Row %d: Falcon=%v Sphincs+=%v HAPQS=%v\n", row, falconValid, sphincsValid, hapqsValid)
}
