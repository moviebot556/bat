package main

import (
	"bytes"
	"crypto/sha256"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"golang.org/x/crypto/ripemd160"
)

func TestMontgomeryBatchCorrectness(t *testing.T) {
	startPrivInt, _ := new(big.Int).SetString("20000000000000000", 16)

	var startScalar secp256k1.ModNScalar
	startScalar.SetByteSlice(startPrivInt.Bytes())

	var current secp256k1.JacobianPoint
	secp256k1.ScalarBaseMultNonConst(&startScalar, &current)

	var one secp256k1.ModNScalar
	one.SetInt(1)
	var gJacobian secp256k1.JacobianPoint
	secp256k1.ScalarBaseMultNonConst(&one, &gJacobian)

	var points [BatchSize]secp256k1.JacobianPoint
	var zList [BatchSize]secp256k1.FieldVal
	var zInvList [BatchSize]secp256k1.FieldVal
	var prod [BatchSize]secp256k1.FieldVal
	var compressed [33]byte
	var sumBuf [20]byte
	hasher := ripemd160.New()

	batchStartScalar := startScalar

	// 1. Generate points
	for j := 0; j < BatchSize; j++ {
		secp256k1.AddNonConst(&current, &gJacobian, &current)
		points[j] = current
		zList[j] = current.Z
	}

	// 2. Montgomery inversion
	prod[0] = zList[0]
	for j := 1; j < BatchSize; j++ {
		prod[j].Mul2(&prod[j-1], &zList[j])
	}
	var totalInv secp256k1.FieldVal = prod[BatchSize-1]
	totalInv.Inverse()
	for j := BatchSize - 1; j > 0; j-- {
		zInvList[j].Mul2(&totalInv, &prod[j-1])
		totalInv.Mul(&zList[j])
	}
	zInvList[0] = totalInv

	// 3. Verify each point against independent btcec calculation
	for j := 0; j < BatchSize; j++ {
		var z2, z3, affineX, affineY secp256k1.FieldVal
		z2.SquareVal(&zInvList[j])
		z3.Mul2(&z2, &zInvList[j])
		affineX.Mul2(&points[j].X, &z2)
		affineY.Mul2(&points[j].Y, &z3)
		affineX.Normalize()
		affineY.Normalize()

		compressed[0] = secp256k1.PubKeyFormatCompressedEven
		if affineY.IsOdd() {
			compressed[0] = secp256k1.PubKeyFormatCompressedOdd
		}
		affineX.PutBytesUnchecked(compressed[1:33])

		sha := sha256.Sum256(compressed[:])
		hasher.Reset()
		hasher.Write(sha[:])
		batchHash := hasher.Sum(sumBuf[:0])

		var matchScalar secp256k1.ModNScalar = batchStartScalar
		var jScalar secp256k1.ModNScalar
		jScalar.SetInt(uint32(j + 1))
		matchScalar.Add(&jScalar)

		var matchPrivBytes [32]byte
		matchScalar.PutBytes(&matchPrivBytes)

		_, expectedPubKey := btcec.PrivKeyFromBytes(matchPrivBytes[:])
		expectedCompressed := expectedPubKey.SerializeCompressed()

		expectedSha := sha256.Sum256(expectedCompressed)
		hasher.Reset()
		hasher.Write(expectedSha[:])
		expectedHash := hasher.Sum(nil)

		if !bytes.Equal(compressed[:], expectedCompressed) {
			t.Fatalf("Step %d: Compressed pubkey mismatch! Got %x, expected %x", j, compressed, expectedCompressed)
		}
		if !bytes.Equal(batchHash, expectedHash) {
			t.Fatalf("Step %d: Hash160 mismatch! Got %x, expected %x", j, batchHash, expectedHash)
		}
	}
}

func TestAddressRoundtrip(t *testing.T) {
	testAddrs := []string{
		"1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
		"1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH",
		"1CUNEBjYrCn2y1SdiUMohaKUi4wpP326Lb",
		"1JtK9CQw1syfWj1WtFMWomrYdV3W2tWBF9",
		"1BY8GQbnueYofwSuFAT3USAhGjPrkxDdW9",
		"19vkiEajfhuZ8bs8Zu2jgmC6oqZbWqhxhG",
	}

	for _, addr := range testAddrs {
		h160, ok := decodeBase58AddressToHash160(addr)
		if !ok {
			t.Fatalf("Failed to decode %s", addr)
		}
		reconstructed := hash160ToAddress(h160)
		if reconstructed != addr {
			t.Fatalf("Mismatch! Got %s, expected %s", reconstructed, addr)
		}
	}
}

func TestWIFEncoding(t *testing.T) {
	var privBytes [32]byte
	privBytes[31] = 1
	wif := wifEncode(privBytes[:])
	expected := "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn"
	if wif != expected {
		t.Fatalf("WIF mismatch! Got %s, expected %s", wif, expected)
	}
}

func TestMatchSaving(t *testing.T) {
	// Clean previous test files
	os.Remove("test_matches.txt")
	os.Remove("test_detailed.json")
	ResultsFile = "test_matches.txt"
	DetailedFile = "test_detailed.json"
	defer os.Remove("test_matches.txt")
	defer os.Remove("test_detailed.json")

	setupMatchSaver()

	match := MatchRecord{
		Address:    "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH",
		PrivateHex: "0000000000000000000000000000000000000000000000000000000000000001",
		PrivateDec: "1",
		PrivateBin: "1",
		WIF:        "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn",
		FoundAt:    "2026-08-24T21:45:00Z",
	}

	matchChan <- match
	// Give match saver goroutine 50ms to write file
	time.Sleep(50 * time.Millisecond)

	stats.matchLock.RLock()
	foundLen := len(stats.RecentMatches)
	stats.matchLock.RUnlock()

	if foundLen == 0 {
		t.Fatalf("Expected recent match to be added to stats!")
	}
}

func BenchmarkMontgomeryStep(b *testing.B) {
	var priv secp256k1.ModNScalar
	priv.SetInt(123456789)

	var pub secp256k1.JacobianPoint
	secp256k1.ScalarBaseMultNonConst(&priv, &pub)

	var one secp256k1.ModNScalar
	one.SetInt(1)
	var gJacobian secp256k1.JacobianPoint
	secp256k1.ScalarBaseMultNonConst(&one, &gJacobian)

	var points [BatchSize]secp256k1.JacobianPoint
	var zList [BatchSize]secp256k1.FieldVal
	var zInvList [BatchSize]secp256k1.FieldVal
	var prod [BatchSize]secp256k1.FieldVal

	var compressed [33]byte
	hasher := ripemd160.New()
	var h160Buf [20]byte
	var sumBuf [20]byte

	current := pub

	b.ResetTimer()
	for i := 0; i < b.N; i += BatchSize {
		for j := 0; j < BatchSize; j++ {
			secp256k1.AddNonConst(&current, &gJacobian, &current)
			points[j] = current
			zList[j] = current.Z
		}

		prod[0] = zList[0]
		for j := 1; j < BatchSize; j++ {
			prod[j].Mul2(&prod[j-1], &zList[j])
		}

		var totalInv secp256k1.FieldVal = prod[BatchSize-1]
		totalInv.Inverse()

		for j := BatchSize - 1; j > 0; j-- {
			zInvList[j].Mul2(&totalInv, &prod[j-1])
			totalInv.Mul(&zList[j])
		}
		zInvList[0] = totalInv

		for j := 0; j < BatchSize; j++ {
			var z2, z3, affineX, affineY secp256k1.FieldVal
			z2.SquareVal(&zInvList[j])
			z3.Mul2(&z2, &zInvList[j])

			affineX.Mul2(&points[j].X, &z2)
			affineY.Mul2(&points[j].Y, &z3)

			affineX.Normalize()
			affineY.Normalize()

			compressed[0] = secp256k1.PubKeyFormatCompressedEven
			if affineY.IsOdd() {
				compressed[0] = secp256k1.PubKeyFormatCompressedOdd
			}
			affineX.PutBytesUnchecked(compressed[1:33])

			sha := sha256.Sum256(compressed[:])
			hasher.Reset()
			hasher.Write(sha[:])
			sum := hasher.Sum(sumBuf[:0])
			copy(h160Buf[:], sum)
		}
	}
}
