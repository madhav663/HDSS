package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/csv"
	"fmt"
	"math/big"
	"os"
	"strconv"
	"time"

	"github.com/madhav663/pq-blend-go/aggregate"
	"github.com/madhav663/pq-blend-go/hybrid"
	falcon "github.com/madhav663/pq-blend-go/wrappers/falcon"
	sphincs "github.com/madhav663/pq-blend-go/wrappers/sphincsplus"

	"github.com/cloudflare/circl/kem/kyber/kyber512"
	"github.com/cloudflare/circl/sign/dilithium/mode2"
)

type Result struct {
	Scheme    string
	Op        string
	TimeNs    int64
	SizeBytes int
	IsValid   bool
}

// PQC signature benchmark
func benchmarkSig(
	scheme string,
	keygen func() (interface{}, interface{}),
	sign func(interface{}, []byte) []byte,
	verify func(interface{}, []byte, []byte) bool,
	iterations int,
) []Result {
	results := []Result{}
	msg := []byte("PQC Benchmark test message")

	// KeyGen
	start := time.Now()
	pk, sk := keygen()
	keygenTime := time.Since(start)
	pkSize, skSize := 0, 0
	switch v := pk.(type) {
	case []byte:
		pkSize = len(v)
	case *mode2.PublicKey:
		pkBytes := v.Bytes()
		pkSize = len(pkBytes)
	case *kyber512.PublicKey:
		pkBytes, _ := v.MarshalBinary()
		pkSize = len(pkBytes)
	}
	switch v := sk.(type) {
	case []byte:
		skSize = len(v)
	case *mode2.PrivateKey:
		skBytes := v.Bytes()
		skSize = len(skBytes)
	case *kyber512.PrivateKey:
		skBytes, _ := v.MarshalBinary()
		skSize = len(skBytes)
	}
	results = append(results, Result{scheme, "KeyGen", keygenTime.Nanoseconds(), pkSize + skSize, true})

	// Sign & Verify
	var signTotal, verifyTotal int64
	var sig []byte
	for i := 0; i < iterations; i++ {
		start = time.Now()
		sig = sign(sk, msg)
		signTotal += time.Since(start).Nanoseconds()

		start = time.Now()
		valid := verify(pk, msg, sig)
		verifyTotal += time.Since(start).Nanoseconds()
		results = append(results, Result{scheme, "Verify", verifyTotal / int64(i+1), len(sig), valid})
	}
	results = append(results, Result{scheme, "Sign", signTotal / int64(iterations), len(sig), true})

	// Tampered test
	tampered := []byte("tampered")
	valid := verify(pk, tampered, sig)
	results = append(results, Result{scheme, "VerifyTampered", 0, len(sig), valid})

	return results
}

// PQC KEM (Kyber) benchmark
func benchmarkKEM(
	scheme string,
	keygen func() (interface{}, interface{}),
	encaps func(interface{}) ([]byte, []byte),
	decaps func(interface{}, []byte) []byte,
	pkSize, skSize int,
	iterations int,
) []Result {
	results := []Result{}
	start := time.Now()
	pk, sk := keygen()
	keygenTime := time.Since(start)
	results = append(results, Result{scheme, "KeyGen", keygenTime.Nanoseconds(), pkSize + skSize, true})

	var encapsTotal, decapsTotal int64
	var ct, ss1, ss2 []byte
	for i := 0; i < iterations; i++ {
		start = time.Now()
		ct, ss1 = encaps(pk)
		encapsTotal += time.Since(start).Nanoseconds()
		start = time.Now()
		ss2 = decaps(sk, ct)
		decapsTotal += time.Since(start).Nanoseconds()
		equal := string(ss1) == string(ss2)
		results = append(results, Result{scheme, "Decaps", decapsTotal / int64(i+1), len(ss2), equal})
	}
	results = append(results, Result{scheme, "Encaps", encapsTotal / int64(iterations), len(ct), true})

	return results
}

// Classical: RSA-2048
func benchmarkRSA(iterations int) []Result {
	results := []Result{}
	msg := []byte("PQC Benchmark test message")
	start := time.Now()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	pub := &priv.PublicKey
	keygenTime := time.Since(start)
	pkSize := pub.Size()
	skSize := priv.Size()
	results = append(results, Result{"RSA-2048", "KeyGen", keygenTime.Nanoseconds(), pkSize + skSize, true})

	var signTotal, verifyTotal int64
	var sig []byte
	for i := 0; i < iterations; i++ {
		start = time.Now()
		hashed := sha256.Sum256(msg)
		sig, err = rsa.SignPKCS1v15(rand.Reader, priv, 0, hashed[:])
		signTotal += time.Since(start).Nanoseconds()

		start = time.Now()
		err = rsa.VerifyPKCS1v15(pub, 0, hashed[:], sig)
		verifyTotal += time.Since(start).Nanoseconds()
		results = append(results, Result{"RSA-2048", "Verify", verifyTotal / int64(i+1), len(sig), err == nil})
	}
	results = append(results, Result{"RSA-2048", "Sign", signTotal / int64(iterations), len(sig), true})

	tampered := []byte("tampered")
	hashed := sha256.Sum256(tampered)
	err = rsa.VerifyPKCS1v15(pub, 0, hashed[:], sig)
	results = append(results, Result{"RSA-2048", "VerifyTampered", 0, len(sig), err == nil})
	return results
}

// Classical: ECDSA-P256
func benchmarkECDSA(iterations int) []Result {
	results := []Result{}
	msg := []byte("PQC Benchmark test message")
	start := time.Now()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	pub := &priv.PublicKey
	keygenTime := time.Since(start)
	pkSize := pub.Params().BitSize / 8
	skSize := priv.Params().BitSize / 8
	results = append(results, Result{"ECDSA-P256", "KeyGen", keygenTime.Nanoseconds(), pkSize + skSize, true})

	var signTotal, verifyTotal int64
	var r, s *big.Int
	for i := 0; i < iterations; i++ {
		start = time.Now()
		hashed := sha256.Sum256(msg)
		r, s, err = ecdsa.Sign(rand.Reader, priv, hashed[:])
		signTotal += time.Since(start).Nanoseconds()

		start = time.Now()
		valid := ecdsa.Verify(pub, hashed[:], r, s)
		verifyTotal += time.Since(start).Nanoseconds()
		results = append(results, Result{"ECDSA-P256", "Verify", verifyTotal / int64(i+1), r.BitLen()/8 + s.BitLen()/8, valid})
	}
	results = append(results, Result{"ECDSA-P256", "Sign", signTotal / int64(iterations), r.BitLen()/8 + s.BitLen()/8, true})

	tampered := []byte("tampered")
	hashed := sha256.Sum256(tampered)
	valid := ecdsa.Verify(pub, hashed[:], r, s)
	results = append(results, Result{"ECDSA-P256", "VerifyTampered", 0, r.BitLen()/8 + s.BitLen()/8, valid})
	return results
}

// Classical: Ed25519
func benchmarkEd25519(iterations int) []Result {
	results := []Result{}
	msg := []byte("PQC Benchmark test message")
	start := time.Now()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	keygenTime := time.Since(start)
	results = append(results, Result{"Ed25519", "KeyGen", keygenTime.Nanoseconds(), len(pub) + len(priv), true})

	var signTotal, verifyTotal int64
	var sig []byte
	for i := 0; i < iterations; i++ {
		start = time.Now()
		sig = ed25519.Sign(priv, msg)
		signTotal += time.Since(start).Nanoseconds()

		start = time.Now()
		valid := ed25519.Verify(pub, msg, sig)
		verifyTotal += time.Since(start).Nanoseconds()
		results = append(results, Result{"Ed25519", "Verify", verifyTotal / int64(i+1), len(sig), valid})
	}
	results = append(results, Result{"Ed25519", "Sign", signTotal / int64(iterations), len(sig), true})

	tampered := []byte("tampered")
	valid := ed25519.Verify(pub, tampered, sig)
	results = append(results, Result{"Ed25519", "VerifyTampered", 0, len(sig), valid})
	return results
}

func testHAPQS() {
	fmt.Println("HAPQS Hybrid Aggregate PQ Signature Demo")
    keys := aggregate.HAPQSKeyGen()
	msg := []byte("Hybrid aggregate PQ signature message")
	sig := aggregate.HAPQSSign(keys, msg)
	
	// Defensive checks for signature
	if  len(sig.FalconSig) == 0 || len(sig.SphincsSig) == 0 {
		fmt.Println("[ERROR] HAPQSSign returned empty signature!")
		return
	}
	valid := aggregate.HAPQSVerify(keys, msg, sig)
	fmt.Println("Signature valid?", valid)
	// Tamper check:
	tampered := []byte("Tampered message")
	validTampered := aggregate.HAPQSVerify(keys, tampered, sig)
	fmt.Println("Tampered valid (should be false)?", validTampered)
}

func benchmarkHAPQS(iterations int) []Result {
	results := []Result{}
	msg := []byte("PQC Benchmark test message")
	var signTotal, verifyTotal int64
	var sig *aggregate.HAPQSSignature
	var keys *aggregate.HAPQSKeys
	var pkSize, skSize, sigSize int

	for i := 0; i < iterations; i++ {
		start := time.Now()
		keys = aggregate.HAPQSKeyGen()
		pkSize = len(keys.FalconPK) + len(keys.SphincsPK)
		skSize = len(keys.FalconSK) + len(keys.SphincsSK)
		keygenTime := time.Since(start)
		if i == 0 {
			results = append(results, Result{"HAPQS", "KeyGen", keygenTime.Nanoseconds(), pkSize + skSize, true})
		}

		start = time.Now()
		sig = aggregate.HAPQSSign(keys, msg)
		signTotal += time.Since(start).Nanoseconds()

		start = time.Now()
		valid := aggregate.HAPQSVerify(keys, msg, sig)
		verifyTotal += time.Since(start).Nanoseconds()
		sigSize = len(sig.FalconSig) + len(sig.SphincsSig)
		results = append(results, Result{"HAPQS", "Verify", verifyTotal / int64(i+1), sigSize, valid})
	}
	results = append(results, Result{"HAPQS", "Sign", signTotal / int64(iterations), sigSize, true})
	tampered := []byte("tampered")
	valid := aggregate.HAPQSVerify(keys, tampered, sig)
	results = append(results, Result{"HAPQS", "VerifyTampered", 0, sigSize, valid})
	return results
}


func saveCSV(filename string, results []Result) error {
	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer f.Close()
	w := csv.NewWriter(f)
	defer w.Flush()
	w.Write([]string{"Scheme", "Op", "TimeNs", "SizeBytes", "IsValid"})
	for _, r := range results {
		w.Write([]string{
			r.Scheme,
			r.Op,
			fmt.Sprintf("%d", r.TimeNs),
			fmt.Sprintf("%d", r.SizeBytes),
			fmt.Sprintf("%v", r.IsValid),
		})
	}
	return nil
}

func main() {
	fmt.Println("==== PQ-Blend+ & Classical Benchmark Suite ====")
	iterations := 10
	allResults := []Result{}

	// ---- Falcon ----
	fmt.Println("\n[Falcon]")
	falconResults := benchmarkSig(
		"Falcon",
		func() (interface{}, interface{}) {
			pk, sk := falcon.KeyGen()
			return pk, sk
		},
		func(sk interface{}, msg []byte) []byte {
			return falcon.Sign(sk.([]byte), msg)
		},
		func(pk interface{}, msg, sig []byte) bool {
			return falcon.Verify(pk.([]byte), msg, sig)
		},
		iterations,
	)
	allResults = append(allResults, falconResults...)

	// ---- Sphincs+ ----
	fmt.Println("\n[Sphincs+]")
	sphincsResults := benchmarkSig(
		"Sphincs+",
		func() (interface{}, interface{}) {
			pk, sk := sphincs.KeyGen()
			return pk, sk
		},
		func(sk interface{}, msg []byte) []byte {
			return sphincs.Sign(sk.([]byte), msg)
		},
		func(pk interface{}, msg, sig []byte) bool {
			return sphincs.Verify(pk.([]byte), msg, sig)
		},
		iterations,
	)
	allResults = append(allResults, sphincsResults...)

	// ---- Dilithium (from hybrid) ----
	fmt.Println("\n[Dilithium]")
	dilithiumResults := benchmarkSig(
		"Dilithium",
		func() (interface{}, interface{}) {
			pk, sk := hybrid.DilithiumKeyGen()
			return pk, sk
		},
		func(sk interface{}, msg []byte) []byte {
			return hybrid.DilithiumSign(sk.(*mode2.PrivateKey), msg)
		},
		func(pk interface{}, msg, sig []byte) bool {
			return hybrid.DilithiumVerify(pk.(*mode2.PublicKey), msg, sig)
		},
		iterations,
	)
	allResults = append(allResults, dilithiumResults...)

	// ---- Kyber (KEM) ----
	fmt.Println("\n[Kyber]")
	kyberResults := benchmarkKEM(
		"Kyber",
		func() (interface{}, interface{}) {
			pk, sk := hybrid.KyberKeyGen()
			return pk, sk
		},
		func(pk interface{}) ([]byte, []byte) {
			return hybrid.KyberEncaps(pk.(*kyber512.PublicKey))
		},
		func(sk interface{}, ct []byte) []byte {
			return hybrid.KyberDecaps(sk.(*kyber512.PrivateKey), ct)
		},
		800, 1632, // adjust if needed
		iterations,
	)
	allResults = append(allResults, kyberResults...)

	// ---- Classical ----
	fmt.Println("\n[RSA-2048]")
	allResults = append(allResults, benchmarkRSA(iterations)...)
	fmt.Println("\n[ECDSA-P256]")
	allResults = append(allResults, benchmarkECDSA(iterations)...)
	fmt.Println("\n[Ed25519]")
	allResults = append(allResults, benchmarkEd25519(iterations)...)

	// ---- HAPQS (Hybrid Aggregate PQ Signature) ----
	fmt.Println("\n[HAPQS Hybrid Aggregate PQ Signature]")
	hapqsResults := benchmarkHAPQS(iterations)
	allResults = append(allResults, hapqsResults...)

	// ---- Save CSV ----
	err := saveCSV("pqbenchmarks.csv", allResults)
	if err != nil {
		fmt.Println("Failed to save CSV:", err)
	} else {
		fmt.Println("\n[+] Benchmark results written to pqbenchmarks.csv")
	}
	// RunBenchmarks()
	testHAPQS()
	inputCSV := "governors_county_candidate.csv"
    outputCSV := "HAPQS_proof_report.csv"
    maxRows := 20

    if len(os.Args) > 1 {
        inputCSV = os.Args[1]
    }
    if len(os.Args) > 2 {
        outputCSV = os.Args[2]
    }
    if len(os.Args) > 3 {
        if n, err := strconv.Atoi(os.Args[3]); err == nil && n > 0 {
            maxRows = n
        }
    }

    fmt.Println("========== HAPQS Benchmark Tool ==========")
    fmt.Printf("Input CSV:    %s\n", inputCSV)
    fmt.Printf("Output CSV:   %s\n", outputCSV)
    fmt.Printf("Max Rows:     %d\n", maxRows)
    fmt.Println("------------------------------------------")

    err = BenchmarkHAPQS(inputCSV, outputCSV, maxRows)
    if err != nil {
        fmt.Printf("[ERROR] %v\n", err)
        os.Exit(1)
    }

	 VerboseResultBenchmark()
}

