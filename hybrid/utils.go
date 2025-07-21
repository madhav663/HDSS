package hybrid

import (
    "encoding/hex"
    "fmt"
    "crypto/rand"
)

// Generates random bytes of specified length
func RandBytes(length int) []byte {
    b := make([]byte, length)
    _, err := rand.Read(b)
    if err != nil {
        panic(fmt.Sprintf("RandBytes error: %v", err))
    }
    return b
}

// Hex encoding/decoding for display
func BytesToHex(b []byte) string {
    return hex.EncodeToString(b)
}
