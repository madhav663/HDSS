package hybrid

import (
    "encoding/csv"
    "os"
    "strconv"
    "time"
    "github.com/cloudflare/circl/kem"
    "github.com/cloudflare/circl/sign/dilithium/mode2"
)


type BenchmarkResult struct {
    TestType    string
    DurationNs  int64
    OutputBytes int
}

func BenchmarkDilithiumSign(keys PQBlendKeys, msg []byte, N int) (avgTimeNs int64, sigSize int) {
    var total int64
    var sig []byte
    for i := 0; i < N; i++ {
        start := time.Now()
        sig = DilithiumSign(keys.DilithiumSK, msg)
        total += time.Since(start).Nanoseconds()
    }
    return total / int64(N), len(sig)
}

func BenchmarkDilithiumVerify(keys PQBlendKeys, msg []byte, sig []byte, N int) (avgTimeNs int64) {
    var total int64
    for i := 0; i < N; i++ {
        start := time.Now()
        _ = DilithiumVerify(keys.DilithiumPK, msg, sig)
        total += time.Since(start).Nanoseconds()
    }
    return total / int64(N)
}

func BenchmarkDilithiumKeyGen(N int) (avgTimeNs int64, pkSize, skSize int) {
    var total int64
    var pk *mode2.PublicKey
    var sk *mode2.PrivateKey
    for i := 0; i < N; i++ {
        start := time.Now()
        pk, sk = DilithiumKeyGen()
        total += time.Since(start).Nanoseconds()
    }
    return total / int64(N), len(pk.Bytes()), len(sk.Bytes())
}

// Similarly, you can add Kyber benchmarks:
func BenchmarkKyberKeyGen(N int) (avgTimeNs int64, pkSize, skSize int) {
    var total int64
    var pk kem.PublicKey
    var sk kem.PrivateKey
    var pkb, skb []byte
    for i := 0; i < N; i++ {
        start := time.Now()
        pk, sk = KyberKeyGen()
        total += time.Since(start).Nanoseconds()
        pkb, _ = pk.MarshalBinary()
        skb, _ = sk.MarshalBinary()
    }
    return total / int64(N), len(pkb), len(skb)
}


func BenchmarkKyberKEM(keys PQBlendKeys, N int) (avgEncNs, avgDecNs int64, ctSize, ssSize int) {
    var encTotal, decTotal int64
    var ct, ss, ss2 []byte
    for i := 0; i < N; i++ {
        start := time.Now()
        ct, ss = KyberEncaps(keys.KyberPK)
        encTotal += time.Since(start).Nanoseconds()
        start = time.Now()
        ss2 = KyberDecaps(keys.KyberSK, ct)
        decTotal += time.Since(start).Nanoseconds()
        _ = ss2 // for correctness you could compare ss and ss2 here
    }
    return encTotal / int64(N), decTotal / int64(N), len(ct), len(ss)
}

// Write benchmark results to CSV
func WriteBenchmarksCSV(filename string, results []BenchmarkResult) error {
    f, err := os.Create(filename)
    if err != nil {
        return err
    }
    defer f.Close()
    w := csv.NewWriter(f)
    defer w.Flush()
    // Write header
    w.Write([]string{"TestType", "DurationNs", "OutputBytes"})
    for _, r := range results {
        w.Write([]string{r.TestType, strconv.FormatInt(r.DurationNs, 10), strconv.Itoa(r.OutputBytes)})
    }
    return nil
}
