// Copyright (c) 2022 barrystyle
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

package main

import (
	"fmt"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
)

const (
	ERR_XPUB_INVALID int = 0
	ERR_XPUB_DERIV       = 1
	ERR_XPUB_WIF         = 2
	OK_COMPLETED         = 3
)

func is_xpub_valid(xpubkey string) (*hdkeychain.ExtendedKey, int) {

	extKey, err := hdkeychain.NewKeyFromString(xpubkey)
	if err != nil {
		return nil, ERR_XPUB_INVALID
	}

	return extKey, OK_COMPLETED
}

func deriv_from_xpub(xpubkey string, depth uint32) (string, int) {

        extKey, ret := is_xpub_valid(xpubkey)
        if ret != OK_COMPLETED {
                return "", ERR_XPUB_INVALID
        }

	// m/0
	var err error
	extKey, err = extKey.Derive(0)
	if err != nil {
		return "", ERR_XPUB_DERIV
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

	return pubStr.String(), OK_COMPLETED
}

func main() {

	test_xpubkey := "xpub661MyMwAqRbcGYzUcVc8JSnN3RcM47JHWMaqtE8yhMfHZohujgvQjX2ezdw2qw6sSMu8B694BQebnASCNvbkZWiBVRvFimSAwgVphguL6LD"

	for path:= uint32(0) ; path < 20 ; path++ {
		address, errlevel := deriv_from_xpub(test_xpubkey, path)
		if errlevel != OK_COMPLETED {
			return
		}
		fmt.Printf("m/%2d - address: %s\n", path, address)
	}

	return
}
