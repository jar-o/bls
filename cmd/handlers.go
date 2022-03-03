package main

import (
	"bls/pkg/lib"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
)

var genKeyPairSaveTo string
var signDataHex string
var signDataBase64 string
var verifyPubKey string
var verifySig string
var genMembershipKeyCount string
var genMembershipAggPub string
var msignAggPub string
var msignMemberKey string
var aggregateSigsPubKeys string
var aggregateSigsBitmask string
var aggregateVerifySubsig string
var aggregateVerifySubpub string
var aggregateVerifyAggpub string
var aggregateVerifyBitmask string

func panicIf(err error) {
	if err != nil {
		panic(err)
	}
}

func errorExit(m string) {
	fmt.Println(m)
	os.Exit(1)
}

func panicIfExists(path string) {
	if _, err := os.Stat(path); err == nil {
		panic(fmt.Sprintf("%s already exists! %s", path, err))
	}
}

func genKeyPairHandler(cmd *cobra.Command, args []string) {
	priv, pub := lib.GenerateKeyPair()
	if genKeyPairSaveTo == "" {
		fmt.Printf("private: %s\npublic: %s\n", hex.EncodeToString(priv.Marshal()), hex.EncodeToString(pub.Marshal()))
	} else {
		info, err := os.Stat(genKeyPairSaveTo)
		panicIf(err)
		if !info.IsDir() {
			errorExit(fmt.Sprintf("You must provide a folder that already exists."))
		}
		privkeyFile := filepath.Join(genKeyPairSaveTo, lib.PRIVKEY_DEFAULT)
		panicIfExists(privkeyFile)
		ioutil.WriteFile(privkeyFile, []byte(hex.EncodeToString(priv.Marshal())), 0600)
		pubkeyFile := filepath.Join(genKeyPairSaveTo, lib.PUBKEY_DEFAULT)
		panicIfExists(pubkeyFile)
		ioutil.WriteFile(pubkeyFile, []byte(hex.EncodeToString(pub.Marshal())), 0600)
	}
}

func signHandler(cmd *cobra.Command, args []string) {
	priv, err := lib.FindPrivateKey()
	panicIf(err)
	if len(args) == 1 { // Input default expectation is UTF8 string
		sig := lib.Sign(priv, []byte(args[0]))
		fmt.Printf("signature: %s\n", hex.EncodeToString(sig.Marshal()))
		return
	} else {
		if signDataHex != "" { // TODO
			fmt.Println("TODO")
		}
		if signDataBase64 != "" {
			fmt.Println("TODO")
		}
	}
	fmt.Println("Something went wrong... missing data perhaps? Please try again.")
	os.Exit(1)
}

func verifyHandler(cmd *cobra.Command, args []string) {
	if verifySig == "" || verifyPubKey == "" {
		errorExit("Please supply a signature and public key to verify.")
	}

	if len(args) != 1 {
		errorExit("Please also supply a signature in hex format.")
	}

	sigBytes, err := hex.DecodeString(verifySig)
	panicIf(err)

	pubkeyBytes, err := hex.DecodeString(verifyPubKey)
	panicIf(err)

	ok, err := lib.Verify(sigBytes, pubkeyBytes, []byte(args[0]))
	panicIf(err)

	if !ok {
		errorExit("Message not verified!")
	}
	fmt.Println("Ok")
}

func msignHandler(cmd *cobra.Command, args []string) {
	if msignAggPub == "" {
		errorExit("Please provide aggregate public key. --agg-pubkey")
	}
	if msignMemberKey == "" {
		errorExit("Please provide your membership key. --membership-key")
	}
	if len(args) != 1 {
		errorExit("Please provide the message to sign.")
	}
	aggpubBytes, err := hex.DecodeString(msignAggPub)
	panicIf(err)

	memberKeyBytes, err := hex.DecodeString(msignMemberKey)
	panicIf(err)

	priv, err := lib.FindPrivateKey()
	panicIf(err)

	s, err := lib.Multisign(priv, []byte(args[0]), aggpubBytes, memberKeyBytes)
	panicIf(err)

	fmt.Printf("%s\n", hex.EncodeToString(s.Marshal()))
}

func aggPubkeyHandler(cmd *cobra.Command, args []string) {
	if len(args) == 0 {
		errorExit("Please specify a list of public keys to combine.")
	}

	pubkeyBytes := make([][]byte, 0)
	for _, pkhex := range args {
		pkbytes, err := hex.DecodeString(pkhex)
		panicIf(err)
		pubkeyBytes = append(pubkeyBytes, pkbytes)
	}

	aggpubkey, anticoefs, err := lib.GenerateAggregatePubKey(pubkeyBytes)
	panicIf(err)

	fmt.Printf("public: %s\n", hex.EncodeToString(aggpubkey.Marshal()))

	var acoefs string
	for i, a := range anticoefs {
		if i == 0 {
			acoefs = fmt.Sprintf("%x", &a)
		} else {
			acoefs += fmt.Sprintf(" %x", &a)
		}
	}
	fmt.Printf("anti-coefficients: %s\n", acoefs)
}

func genMembershipKeyHandler(cmd *cobra.Command, args []string) {
	if genMembershipKeyCount == "" {
		errorExit("You must tell me how many keys there are in total. --total-keys")
	}
	if genMembershipAggPub == "" {
		errorExit("Please provide aggregate public key. --agg-pubkey")
	}
	if len(args) != 1 {
		errorExit("You must provide an anti-coefficient, which is generated with --aggregate-pubkeys.")
	}

	keycount, err := strconv.Atoi(genMembershipKeyCount)
	panicIf(err)

	priv, err := lib.FindPrivateKey()
	panicIf(err)

	coef := new(big.Int)
	coef.SetString(args[0], 16)

	aggpubBytes, err := hex.DecodeString(genMembershipAggPub)
	panicIf(err)

	sigs, err := lib.GenerateMembershipKeyParts(priv, aggpubBytes, coef, keycount)
	panicIf(err)
	for i := 0; i < keycount; i++ {
		s := hex.EncodeToString(sigs[i].Marshal())
		if i == 0 {
			fmt.Printf("%s", s)
		} else {
			fmt.Printf(" %s", s)
		}
	}
}

func aggregateMemberKeysCmdHandler(cmd *cobra.Command, args []string) {
	if len(args) == 0 {
		fmt.Println("You must specify a set of membership keys provided by signers.")
		os.Exit(1)
	}
	ms := make([][]string, 0)
	for _, s := range args {
		as := strings.Split(s, ",")
		ms = append(ms, as)
	}
	sigs, err := lib.AggregateMemberKeys(ms)
	panicIf(err)
	for i, sig := range sigs {
		if i == 0 {
			fmt.Printf("%s", hex.EncodeToString(sig.Marshal()))
		} else {
			fmt.Printf(" %s", hex.EncodeToString(sig.Marshal()))
		}
	}
	fmt.Printf("\n")
}

func aggregateSigsHandler(cmd *cobra.Command, args []string) {
	if aggregateSigsPubKeys == "" {
		errorExit("Must provide a comma separated list of public keys corresponding to signatures.")
	}
	if aggregateSigsBitmask == "" {
		errorExit("Must provide a bitmask string, e.g. '11101'")
	}
	if len(args) == 0 {
		errorExit("Must provide a space separated list of signatures to aggregate.")
	}

	pubsHex := strings.Split(aggregateSigsPubKeys, ",")
	pubBytes := make([][]byte, 0)
	for _, ph := range pubsHex {
		h, err := hex.DecodeString(ph)
		panicIf(err)
		pubBytes = append(pubBytes, h)
	}

	sigBytes := make([][]byte, 0)
	for _, sh := range args {
		h, err := hex.DecodeString(sh)
		panicIf(err)
		sigBytes = append(sigBytes, h)
	}

	mask := lib.BitStringToBigInt(aggregateSigsBitmask)
	pub, sig, err := lib.AggregateSignatures(sigBytes, pubBytes, mask)
	panicIf(err)

	fmt.Printf("public: %s\n", hex.EncodeToString(pub.Marshal()))
	fmt.Printf("signature: %s\n", hex.EncodeToString(sig.Marshal()))
}

func bitmaskToIntHandler(cmd *cobra.Command, args []string) {
	if len(args) != 1 {
		errorExit("Please provide a bit string, e.g. '1101'")
	}
	fmt.Println(lib.BitStringToBigInt(args[0]))
}

func aggregateVerifyHandler(cmd *cobra.Command, args []string) {
	if aggregateVerifySubsig == "" {
		errorExit("Must provide subset signature: --sub-sig")
	}
	if aggregateVerifySubpub == "" {
		errorExit("Must provide subset public key: --sub-pubkey")
	}
	if aggregateVerifyAggpub == "" {
		errorExit("Must provide aggregated public key: --agg-pubkey")
	}
	if aggregateVerifyBitmask == "" {
		errorExit("Must provide bitmask: --bitmask")
	}

	subSigBytes, err := hex.DecodeString(aggregateVerifySubsig)
	panicIf(err)
	aggPubBytes, err := hex.DecodeString(aggregateVerifyAggpub)
	panicIf(err)
	subPubBytes, err := hex.DecodeString(aggregateVerifySubpub)
	panicIf(err)
	mask := lib.BitStringToBigInt(aggregateVerifyBitmask)

	///TODO message needs to be handled as base64 and/or HEX... possibly --from-file
	//if len(args) == 0 {...}

	ok, err := lib.VerifyMultisig(subSigBytes, aggPubBytes, subPubBytes, []byte(args[0]), mask)
	if err != nil {
		errorExit(err.Error())
	}
	if ok {
		fmt.Println("ok")
	} else {
		errorExit("Could not verify signature. <sad horn>")
	}
}
