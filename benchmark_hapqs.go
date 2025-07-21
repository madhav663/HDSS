package main

import (
    "crypto/ecdsa"
    "crypto/elliptic"
    "crypto/rand"
    "crypto/rsa"
    "crypto/sha256"
    "encoding/csv"
    "encoding/hex"
    "fmt"
    "os"
    "strings"
    "time"
    "strconv"

    "github.com/madhav663/pq-blend-go/aggregate"
    sphincs "github.com/madhav663/pq-blend-go/wrappers/sphincsplus"
    falcon "github.com/madhav663/pq-blend-go/wrappers/falcon"
)

type ResultRow struct {
    RowNum        int
    Message       string
    Scheme        string
    SigHex        string
    SignTimeNs    int64
    VerifyTimeNs  int64
    Valid         bool
    TamperedValid bool
}

func BenchmarkHAPQS(inputCSV string, outputCSV string, maxRows int) error {
    // Read input CSV
    file, err := os.Open(inputCSV)
    if err != nil {
        return fmt.Errorf("Failed to open input: %v", err)
    }
    defer file.Close()
    r := csv.NewReader(file)
    rows, err := r.ReadAll()
    if err != nil {
        return fmt.Errorf("Failed to read csv: %v", err)
    }

    // Prepare keys ONCE
    falconPK, falconSK := falcon.KeyGen()
    sphincsPK, sphincsSK := sphincs.KeyGen()
    hapqsKeys := aggregate.HAPQSKeyGen()

    // Classical keys
    rsaSK, _ := rsa.GenerateKey(rand.Reader, 2048)
    rsaPK := &rsaSK.PublicKey
    ecdsaSK, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
    ecdsaPK := &ecdsaSK.PublicKey

    var allResults []ResultRow

    for rowIdx, row := range rows {
        if rowIdx == 0 && strings.Contains(strings.ToLower(strings.Join(row, ",")), "id") {
            continue // skip header
        }
        if rowIdx >= maxRows {
            break
        }
        msg := []byte(strings.Join(row, ","))

        // --- Falcon ---
        start := time.Now()
        fSig := falcon.Sign(falconSK, msg)
        signTime := time.Since(start).Nanoseconds()

        start = time.Now()
        fValid := falcon.Verify(falconPK, msg, fSig)
        verifyTime := time.Since(start).Nanoseconds()

        tampered := append([]byte{}, msg...)
        if len(tampered) > 0 {
            tampered[0] ^= 0xAA
        }
        fTampered := falcon.Verify(falconPK, tampered, fSig)

        allResults = append(allResults, ResultRow{
            RowNum: rowIdx + 1, Message: string(msg), Scheme: "Falcon",
            SigHex: fmt.Sprintf("%x", fSig), SignTimeNs: signTime, VerifyTimeNs: verifyTime,
            Valid: fValid, TamperedValid: fTampered,
        })

        // --- Sphincs+ ---
        start = time.Now()
        sSig := sphincs.Sign(sphincsSK, msg)
        signTime = time.Since(start).Nanoseconds()

        start = time.Now()
        sValid := sphincs.Verify(sphincsPK, msg, sSig)
        verifyTime = time.Since(start).Nanoseconds()
        sTampered := sphincs.Verify(sphincsPK, tampered, sSig)

        allResults = append(allResults, ResultRow{
            RowNum: rowIdx + 1, Message: string(msg), Scheme: "Sphincs+",
            SigHex: fmt.Sprintf("%x", sSig), SignTimeNs: signTime, VerifyTimeNs: verifyTime,
            Valid: sValid, TamperedValid: sTampered,
        })

        // --- HAPQS ---
        start = time.Now()
        hapqsSig := aggregate.HAPQSSign(hapqsKeys, msg)
        signTime = time.Since(start).Nanoseconds()

        start = time.Now()
        hValid := aggregate.HAPQSVerify(hapqsKeys, msg, hapqsSig)
        verifyTime = time.Since(start).Nanoseconds()
        hTampered := aggregate.HAPQSVerify(hapqsKeys, tampered, hapqsSig)
        sigProof := fmt.Sprintf("Falcon=%x | Sphincs=%x", hapqsSig.FalconSig, hapqsSig.SphincsSig)

        allResults = append(allResults, ResultRow{
            RowNum: rowIdx + 1, Message: string(msg), Scheme: "HAPQS",
            SigHex: sigProof, SignTimeNs: signTime, VerifyTimeNs: verifyTime,
            Valid: hValid, TamperedValid: hTampered,
        })

        // --- RSA-2048 ---
        start = time.Now()
        rsaHash := sha256.Sum256(msg)
        rsaSig, _ := rsa.SignPKCS1v15(rand.Reader, rsaSK, 0, rsaHash[:])
        signTime = time.Since(start).Nanoseconds()

        start = time.Now()
        rsaErr := rsa.VerifyPKCS1v15(rsaPK, 0, rsaHash[:], rsaSig)
        verifyTime = time.Since(start).Nanoseconds()
        rsaValid := rsaErr == nil

        // Tampered for RSA
        rsaTamperedHash := sha256.Sum256(tampered)
        rsaErrTampered := rsa.VerifyPKCS1v15(rsaPK, 0, rsaTamperedHash[:], rsaSig)
        rsaTampered := rsaErrTampered == nil

        allResults = append(allResults, ResultRow{
            RowNum: rowIdx + 1, Message: string(msg), Scheme: "RSA-2048",
            SigHex: fmt.Sprintf("%x", rsaSig), SignTimeNs: signTime, VerifyTimeNs: verifyTime,
            Valid: rsaValid, TamperedValid: rsaTampered,
        })

        // --- ECDSA-P256 ---
        start = time.Now()
        ecdsaHash := sha256.Sum256(msg)
        r, s, _ := ecdsa.Sign(rand.Reader, ecdsaSK, ecdsaHash[:])
        sigBytes := append(r.Bytes(), s.Bytes()...)
        signTime = time.Since(start).Nanoseconds()

        start = time.Now()
        ecdsaValid := ecdsa.Verify(ecdsaPK, ecdsaHash[:], r, s)
        verifyTime = time.Since(start).Nanoseconds()

        // Tampered for ECDSA
        ecdsaTamperedHash := sha256.Sum256(tampered)
        ecdsaTampered := ecdsa.Verify(ecdsaPK, ecdsaTamperedHash[:], r, s)

        allResults = append(allResults, ResultRow{
            RowNum: rowIdx + 1, Message: string(msg), Scheme: "ECDSA-P256",
            SigHex: hex.EncodeToString(sigBytes), SignTimeNs: signTime, VerifyTimeNs: verifyTime,
            Valid: ecdsaValid, TamperedValid: ecdsaTampered,
        })

        fmt.Printf("[Row %d] Falcon:%v Sphincs+:%v HAPQS:%v RSA:%v ECDSA:%v\n", rowIdx+1, fValid, sValid, hValid, rsaValid, ecdsaValid)
    }

    // Write results to CSV
    out, err := os.Create(outputCSV)
    if err != nil {
        return fmt.Errorf("Failed to create output file: %v", err)
    }
    defer out.Close()
    w := csv.NewWriter(out)
    defer w.Flush()
    w.Write([]string{"Row", "Scheme", "Signature", "SignTimeNs", "VerifyTimeNs", "Valid", "TamperedValid", "Message"})
    for _, res := range allResults {
        w.Write([]string{
            strconv.Itoa(res.RowNum), res.Scheme, res.SigHex,
            fmt.Sprintf("%d", res.SignTimeNs), fmt.Sprintf("%d", res.VerifyTimeNs),
            fmt.Sprintf("%v", res.Valid), fmt.Sprintf("%v", !res.TamperedValid),
            res.Message,
        })
    }

    fmt.Printf("Benchmark done! Results/proof written to %s\n", outputCSV)
    return nil
}
