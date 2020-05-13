package schnorr

import (
	"bufio"
	"bytes"
	"encoding/csv"
	"io"
	"log"
	"math/big"
	"os"
	"strconv"
	"testing"
)

func Test(t *testing.T) {
	f, _ := os.Open("test-vectors.csv")
	reader := csv.NewReader(bufio.NewReader(f))
	var sk []byte
	for {
		record, error := reader.Read()
		if error == io.EOF {
			break
		} else if error != nil {
			log.Fatal(error)
		}
		i, err := strconv.ParseInt(record[0], 0, 0)
		if err != nil {
			continue
		}
		testsign := false
		if record[1] != "" {
			skint, _ := new(big.Int).SetString(record[1], 16)
			sk = pad(skint.Bytes(), 32)
			testsign = true
		}
		pkint, _ := new(big.Int).SetString(record[2], 16)
		pk := pad(pkint.Bytes(), 32)
		mint, _ := new(big.Int).SetString(record[3], 16)
		m := pad(mint.Bytes(), 32)
		sig := make([]byte, 0)
		if testsign {
			sig = Sign(sk, m)
			expectedsigint, _ := new(big.Int).SetString(record[4], 16)
			expectedsig := expectedsigint.Bytes()
			if !bytes.Equal(sig, expectedsig) {
				t.Errorf("Error on sign %v", i)
				t.Errorf("Expected %x", expectedsigint)
				t.Errorf("Got      %x", new(big.Int).SetBytes(sig))
			}
		} else {
			sigint, _ := new(big.Int).SetString(record[4], 16)
			sig = bytes64(sigint)
		}
		ver := Verify(pk, m, sig)
		expected, _ := strconv.ParseBool(record[5])
		if ver != expected {
			t.Errorf("Error on verify %v", i)
		}
	}
	u := 0
	var pks, ms, sigs [][]byte
	f.Seek(0, io.SeekStart)
	for {
		record, error := reader.Read()
		if error == io.EOF {
			break
		} else if error != nil {
			log.Fatal(error)
		}
		_, err := strconv.ParseInt(record[0], 0, 0)
		if err != nil {
			continue
		}
		if record[1] != "" {
			skint, _ := new(big.Int).SetString(record[1], 16)
			sk = pad(skint.Bytes(), 32)
		}
		pkint, _ := new(big.Int).SetString(record[2], 16)
		pk := pad(pkint.Bytes(), 32)
		mint, _ := new(big.Int).SetString(record[3], 16)
		m := pad(mint.Bytes(), 32)
		sigint, _ := new(big.Int).SetString(record[4], 16)
		sig := bytes64(sigint)
		expected, _ := strconv.ParseBool(record[5])
		if !expected {
			continue
		}
		u += 1
		pks = append(pks, pk)
		ms = append(ms, m)
		sigs = append(sigs, sig)
	}
	res := BatchVerify(u, pks, ms, sigs)
	if !res {
		t.Errorf("Batch verify failed")
	}
}
