package lib

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
	"strings"

	"github.com/eywa-protocol/bls-crypto/bls"
)

const (
	ENVKEY_PRIVKEY_HEX = "BLS_PRIVKEY"
	ENVKEY_HOME        = "HOME"
	HOME_DIR           = ".bls"
)

func GenerateKeyPair() (bls.PrivateKey, bls.PublicKey) {
	priv, pub := bls.GenerateRandomKey()
	return priv, pub
}

// Look in all the standard places and if not found, error
// TODO move to cmd/handlers.go
func FindPrivateKey() (bls.PrivateKey, error) {
	privhex, ok := os.LookupEnv(ENVKEY_PRIVKEY_HEX)
	if ok {
		privbytes, err := hex.DecodeString(privhex)
		if err != nil {
			return bls.PrivateKey{}, err
		}

		priv, err := bls.UnmarshalPrivateKey(privbytes)
		if err != nil {
			return bls.PrivateKey{}, err
		}
		return priv, nil
	}
	return bls.PrivateKey{}, fmt.Errorf("Couldn't find private key anywhere expected!")
}

func Sign(priv bls.PrivateKey, message []byte) bls.Signature {
	return priv.Sign(message)
}

func Multisign(priv bls.PrivateKey, message []byte, aggPub []byte, memberKey /*sig?*/ []byte) (bls.Signature, error) {
	aggpk, err := bls.UnmarshalPublicKey(aggPub)
	if err != nil {
		return bls.ZeroSignature(), err
	}
	mk, err := bls.UnmarshalSignature(memberKey)
	if err != nil {
		return bls.ZeroSignature(), err
	}
	return priv.Multisign(message, aggpk, mk), nil
}

func AggregateSignatures(sigBytes [][]byte, pubBytes [][]byte, bitmask *big.Int) (bls.PublicKey, bls.Signature, error) {
	pub := bls.ZeroPublicKey()
	sig := bls.ZeroSignature()
	if len(sigBytes) != len(pubBytes) {
		return pub, sig, fmt.Errorf("Signatures and public keys must match! %d != %d", len(sigBytes), len(pubBytes))
	}
	for i := 0; i < len(sigBytes); i++ {
		s, err := bls.UnmarshalSignature(sigBytes[i])
		if err != nil {
			return pub, sig, err
		}
		p, err := bls.UnmarshalPublicKey(pubBytes[i])
		if err != nil {
			return pub, sig, err
		}
		if bitmask.Bit(i) != 0 {
			sig = sig.Aggregate(s)
			pub = pub.Aggregate(p)
		}
	}
	return pub, sig, nil
}

func AggregateMemberKeys(ms [][]string) ([]bls.Signature, error) {
	// fmt.Println(len(ms))
	// fmt.Println(ms)
	res := make([]bls.Signature, len(ms))
	// fmt.Println(res)
	for i := 0; i < len(ms); i++ {
		res[i] = bls.ZeroSignature()
		for j := 0; j < len(ms); j++ {
			// fmt.Printf("\t%s\n", ms[j][i])
			b, err := hex.DecodeString(ms[j][i])
			if err != nil {
				return res, err
			}
			sig, err := bls.UnmarshalSignature(b)
			// fmt.Printf("\t%+v\n", sig)
			if err != nil {
				return res, err
			}
			res[i] = res[i].Aggregate(sig)
		}
		// fmt.Println("-----")
	}
	// fmt.Println(res)
	return res, nil
}

func VerifyMultisig(subSigBytes []byte, aggPubBytes []byte, subPubBytes []byte, message []byte, bitmask *big.Int) (bool, error) {
	sig, err := bls.UnmarshalSignature(subSigBytes)
	if err != nil {
		return false, err
	}
	aggpub, err := bls.UnmarshalPublicKey(aggPubBytes)
	if err != nil {
		return false, err
	}
	subpub, err := bls.UnmarshalPublicKey(subPubBytes)
	if err != nil {
		return false, err
	}
	ok := sig.VerifyMultisig(aggpub, subpub, message, bitmask)
	return ok, nil
}

func BitStringToBigInt(bits string) *big.Int {
	bi := big.NewInt(0)
	a := strings.Split(bits, "")
	for i := len(a) - 1; i >= 0; i-- {
		j := (len(a) - 1) - i
		if a[i] == "1" {
			bi.SetBit(bi, j, 1)
		} else {
			bi.SetBit(bi, j, 0)
		}
	}
	return bi
}