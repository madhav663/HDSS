package main

import (
    "encoding/csv"
    "fmt"
    "os"
    "strings"
    "time"

    "github.com/madhav663/pq-blend-go/aggregate"
)

type VerboseResult struct {
    RowNum        int
    Message       string
    Signature     string
    Valid         bool
    TamperedValid bool
    SignTimeNs    int64
    VerifyTimeNs  int64
}

func VerboseResultBenchmark() {
    inputCSV := "governors_county_candidate.csv" // Update to your actual CSV file
    outputCSV := "hapqs_verbose_proof.csv"
    maxRows := 30 // You can increase or decrease as needed

    // Load CSV
    file, err := os.Open(inputCSV)
    if err != nil {
        panic(err)
    }
    defer file.Close()
    r := csv.NewReader(file)
    rows, err := r.ReadAll()
    if err != nil {
        panic(err)
    }

    // Generate HAPQS keys ONCE
    hapqsKeys := aggregate.HAPQSKeyGen()

    var allResults []VerboseResult

    for rowIdx, row := range rows {
        if rowIdx == 0 && strings.Contains(strings.ToLower(strings.Join(row, ",")), "id") {
            continue // skip header
        }
        if rowIdx >= maxRows {
            break
        }
        msg := []byte(strings.Join(row, ","))

        // HAPQS
        start := time.Now()
        sig := aggregate.HAPQSSign(hapqsKeys, msg)
        signTime := time.Since(start).Nanoseconds()

        start = time.Now()
        valid := aggregate.HAPQSVerify(hapqsKeys, msg, sig)
        verifyTime := time.Since(start).Nanoseconds()

        // Tampering: flip first byte if possible
        tampered := append([]byte{}, msg...)
        if len(tampered) > 0 {
            tampered[0] ^= 0xAA
        }
        tamperedValid := aggregate.HAPQSVerify(hapqsKeys, tampered, sig)

        result := VerboseResult{
            RowNum:        rowIdx + 1,
            Message:       string(msg),
            Signature:     fmt.Sprintf("Falcon=%x|Sphincs=%x", sig.FalconSig, sig.SphincsSig),
            Valid:         valid,
            TamperedValid: tamperedValid,
            SignTimeNs:    signTime,
            VerifyTimeNs:  verifyTime,
        }

        allResults = append(allResults, result)
        // No verbose output here!
    }

    // Write to CSV (only necessary columns)
    out, err := os.Create(outputCSV)
    if err != nil {
        panic(err)
    }
    defer out.Close()
    w := csv.NewWriter(out)
    defer w.Flush()
    w.Write([]string{"Row", "Message", "Signature", "Valid", "TamperedValid", "SignTimeNs", "VerifyTimeNs"})
    for _, res := range allResults {
        w.Write([]string{
            fmt.Sprintf("%d", res.RowNum), res.Message, res.Signature,
            fmt.Sprintf("%v", res.Valid), fmt.Sprintf("%v", !res.TamperedValid),
            fmt.Sprintf("%d", res.SignTimeNs), fmt.Sprintf("%d", res.VerifyTimeNs),
        })
    }

    fmt.Printf("\n[DONE] Verbose proof written to %s\n", outputCSV)
}
