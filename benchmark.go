package main

import (
    "encoding/csv"
    "fmt"
    "os"
    "path/filepath"
    "strings"
    "sync"
    "time"

    "github.com/madhav663/pq-blend-go/aggregate"
    sphincs "github.com/madhav663/pq-blend-go/wrappers/sphincsplus"
    falcon "github.com/madhav663/pq-blend-go/wrappers/falcon"
)

type BenchResult struct {
    Dataset      string
    File         string
    Row          int
    Scheme       string
    SignTimeNs   int64
    VerifyTimeNs int64
    SigSize      int
    Valid        bool
}

func readCSVFilesFromFolder(folder string, maxRows int) ([][]string, error) {
    var messages [][]string
    total := 0
    err := filepath.Walk(folder, func(path string, info os.FileInfo, err error) error {
        if err != nil {
            return err
        }
        if !info.IsDir() && strings.HasSuffix(strings.ToLower(info.Name()), ".csv") {
            fmt.Println("[INFO] Reading", path)
            f, err := os.Open(path)
            if err != nil {
                return err
            }
            defer f.Close()
            r := csv.NewReader(f)
            rows, err := r.ReadAll()
            if err != nil {
                return err
            }
            if len(rows) > 1 && strings.Contains(strings.ToLower(strings.Join(rows[0], ",")), "id") {
                rows = rows[1:]
            }
            for _, row := range rows {
                messages = append(messages, row)
                total++
                if total >= maxRows {
                    return nil
                }
            }
        }
        return nil
    })
    return messages, err
}

const (
    maxRows    = 1000
    numWorkers = 8
)

func RunBenchmarks() {
    datasetFolders := []string{
        "datasets/usa2020/",
        "datasets/synthea_sample_data/",
        "datasets/traffic_flow/",
    }

    falconPK, falconSK := falcon.KeyGen()
    sphincsPK, sphincsSK := sphincs.KeyGen()
    hapqsKeys := aggregate.HAPQSKeyGen()

    var allResults []BenchResult

    for _, folder := range datasetFolders {
        datasetName := filepath.Base(strings.TrimRight(folder, "/\\"))
        messages, err := readCSVFilesFromFolder(folder, maxRows)
        if err != nil {
            fmt.Printf("[ERROR] Reading CSV files from %s: %v\n", folder, err)
            continue
        }

        results := make([]BenchResult, 0, len(messages)*3)
        resultsChan := make(chan BenchResult, len(messages)*3)
        var wg sync.WaitGroup

        worker := func(rows <-chan struct {
            rowIdx int
            row    []string
        }) {
            defer wg.Done()
            for job := range rows {
                msg := []byte(strings.Join(job.row, ","))

                st := time.Now()
                falconSig := falcon.Sign(falconSK, msg)
                signTime := time.Since(st).Nanoseconds()
                st = time.Now()
                valid := falcon.Verify(falconPK, msg, falconSig)
                verifyTime := time.Since(st).Nanoseconds()
                resultsChan <- BenchResult{
                    Dataset: datasetName, File: "", Row: job.rowIdx + 1, Scheme: "Falcon",
                    SignTimeNs: signTime, VerifyTimeNs: verifyTime, SigSize: len(falconSig), Valid: valid,
                }

                st = time.Now()
                sphincsSig := sphincs.Sign(sphincsSK, msg)
                signTime = time.Since(st).Nanoseconds()
                st = time.Now()
                valid = sphincs.Verify(sphincsPK, msg, sphincsSig)
                verifyTime = time.Since(st).Nanoseconds()
                resultsChan <- BenchResult{
                    Dataset: datasetName, File: "", Row: job.rowIdx + 1, Scheme: "Sphincs+",
                    SignTimeNs: signTime, VerifyTimeNs: verifyTime, SigSize: len(sphincsSig), Valid: valid,
                }

                st = time.Now()
                hapqsSig := aggregate.HAPQSSign(hapqsKeys, msg)
                signTime = time.Since(st).Nanoseconds()
                st = time.Now()
                valid = aggregate.HAPQSVerify(hapqsKeys, msg, hapqsSig)
                verifyTime = time.Since(st).Nanoseconds()
                sigSize := len(hapqsSig.FalconSig) + len(hapqsSig.SphincsSig)
                resultsChan <- BenchResult{
                    Dataset: datasetName, File: "", Row: job.rowIdx + 1, Scheme: "HAPQS",
                    SignTimeNs: signTime, VerifyTimeNs: verifyTime, SigSize: sigSize, Valid: valid,
                }

                if job.rowIdx%100 == 0 {
                    fmt.Printf("[INFO] %s: processed %d rows\n", datasetName, job.rowIdx)
                }
            }
        }

        jobs := make(chan struct {
            rowIdx int
            row    []string
        }, maxRows)
        for w := 0; w < numWorkers; w++ {
            wg.Add(1)
            go worker(jobs)
        }

        for rowIdx, row := range messages {
            jobs <- struct {
                rowIdx int
                row    []string
            }{rowIdx, row}
        }
        close(jobs)

        wg.Wait()
        close(resultsChan)

        for res := range resultsChan {
            results = append(results, res)
        }
        allResults = append(allResults, results...)
        fmt.Printf("[INFO] Completed dataset: %s\n", datasetName)
    }

    outFile := "benchmark_results.csv"
    f, err := os.Create(outFile)
    if err != nil {
        fmt.Println("[ERROR] Cannot write output file:", err)
        return
    }
    defer f.Close()
    w := csv.NewWriter(f)
    defer w.Flush()
    w.Write([]string{"Dataset", "File", "Row", "Scheme", "SignTimeNs", "VerifyTimeNs", "SigSize", "Valid"})
    for _, r := range allResults {
        w.Write([]string{
            r.Dataset,
            r.File,
            fmt.Sprintf("%d", r.Row),
            r.Scheme,
            fmt.Sprintf("%d", r.SignTimeNs),
            fmt.Sprintf("%d", r.VerifyTimeNs),
            fmt.Sprintf("%d", r.SigSize),
            fmt.Sprintf("%v", r.Valid),
        })
    }
    fmt.Println("[DONE] Results written to", outFile)
}
