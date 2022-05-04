// Copyright (c) 2022 barrystyle
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

package main

import (
	"fmt"
	"strconv"
	"strings"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/btcutil/bech32"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
)

const (
	ERR_XPUB_INVALID int = 0
	ERR_XPUB_DERIV       = 1
	ERR_XPUB_WIF         = 2
	ERR_DERIVPATH        = 3
	OK_COMPLETED         = 4
)

func is_xpub_valid(xpubkey string) (*hdkeychain.ExtendedKey, int) {

	extKey, err := hdkeychain.NewKeyFromString(xpubkey)
	if err != nil {
		return nil, ERR_XPUB_INVALID
	}

	return extKey, OK_COMPLETED
}

func is_path_valid(path string) bool {

	// expecting m/1/2/3/x
	keyPath := strings.Split(path, "/")

	// must start with hardened xpub
	if keyPath[0] != "m" {
		return false
	}

	// must be in range m/x - m/0/0/0/0/0/0/x
	pathLen := len(keyPath)
	if pathLen < 2 || pathLen > 8 {
		return false
	}

	// each new child mustnt be hardened
	for b := 1; b < pathLen-1; b++ {
		childInt, err := strconv.Atoi(keyPath[b])
		if (err != nil) {
			return false
		}
		if childInt < 0 || childInt > 2147483647 {
			return false
		}
	}

	// last item should be x
	if keyPath[pathLen-1] !=  "x" {
		return false
	}

	return true
}

func deriv_from_xpub(xpubkey string, path string, depth uint32) (string, int) {

	// basic sanity checks
        extKey, ret := is_xpub_valid(xpubkey)
        if ret != OK_COMPLETED {
                return "", ERR_XPUB_INVALID
        }

	pathValid := is_path_valid(path)
	if !pathValid {
		return "", ERR_DERIVPATH
	}

	// extract path data
	keyPath := strings.Split(path, "/")
	pathLen := len(keyPath)

	var err error
	for b := 1; b < pathLen - 1; b++ {
		childInt, _ := strconv.Atoi(keyPath[b])
		extKey, err = extKey.Derive(uint32(childInt))
		if err != nil {
			return "", ERR_XPUB_DERIV
		}
	}

	// m/0/x
       	extKey, err = extKey.Derive(depth)
       	if err != nil {
               	return "", ERR_XPUB_DERIV
      	}

	// wif format
        pubStr, err := extKey.Address(&chaincfg.MainNetParams)
        if err != nil {
		return "", ERR_XPUB_WIF
	}

	// encode p2pkh
	if strings.Contains(xpubkey, "xpub") {
		return pubStr.String(), OK_COMPLETED
	}

	// otherwise p2wpkh
	bech32Bytes, err := bech32.ConvertBits(pubStr.ScriptAddress(), 8, 5, true)
	if err != nil {
		return "", ERR_XPUB_DERIV
	}
	segwitaddr, err := bech32.Encode("bc", bech32Bytes)
	if err != nil {
		return "", ERR_XPUB_DERIV
	}

	return segwitaddr, OK_COMPLETED
}

func main() {

	test_xpubkey := "xpub661MyMwAqRbcGYzUcVc8JSnN3RcM47JHWMaqtE8yhMfHZohujgvQjX2ezdw2qw6sSMu8B694BQebnASCNvbkZWiBVRvFimSAwgVphguL6LD"
	// test_xpubkey := "zpub6nSMtU4kF9sZLDrbfRQZYDiJxBxGbXvc3xMraPAveA6VfhRdyrkWSw8hDsdTdAYSxCyR824f1DYHzJ7syUW93zNS23dmJjR8mCvfbrju481"

	path := "m/1/2/3/4/5/6/x"
	for depth:= uint32(0) ; depth < 20 ; depth++ {
		address, errlevel := deriv_from_xpub(test_xpubkey, path, depth)
		if errlevel != OK_COMPLETED {
			return
		}
		fmt.Printf("%s\n", address)
	}

	return
}
