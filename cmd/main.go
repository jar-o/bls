package main

/*

CLI:
	bls gen-key-pair											# generate a key pair
	bls sign $data												# BLS_KEYSTORE=...	|| looks in $HOME/.bls-keystore
	bls verify $signature										# BLS_KEYSTORE=...	|| looks in $HOME/.bls-keystore
	bls msign $data										# see james/app/util.SignMultisigPartially()#line47
	bls aggregate-sign --sigs $sig0... --pubs $pub0... --mask 111 --agg-pub-key $k			# see james/app/util.SignMultisigPartially()

Also need a library encapsulating the above functionality

*/

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
	"strconv"
	"strings"

	"bls/pkg/lib"

	"github.com/eywa-protocol/bls-crypto/bls"
	"github.com/spf13/cobra"
	// "encoding/hex" */
	// "math/big" */
	// "github.com/eywa-protocol/bls-crypto/bls" */
)

//TODO move flags + handlers into handlers.go
// Global flags
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

// Handlers hence
func genKeyPairHandler(cmd *cobra.Command, args []string) {
	priv, pub := lib.GenerateKeyPair()
	if genKeyPairSaveTo == "" {
		fmt.Printf("private: %s\npublic: %s\n", hex.EncodeToString(priv.Marshal()), hex.EncodeToString(pub.Marshal()))
	} else {
		fmt.Println("TODO write to file...")
	}
}

func signHandler(cmd *cobra.Command, args []string) {
	priv, err := lib.FindPrivateKey()
	panicIf(err)           // TODO if we only panic in FindPrivateKey() we don't need to return err..
	if signDataHex != "" { // TODO
	}
	if signDataBase64 != "" {
	}
	if len(args) == 1 { // Input default expectation is UTF8 string
		sig := lib.Sign(priv, []byte(args[0]))
		fmt.Printf("signature: %s\n", hex.EncodeToString(sig.Marshal()))
		return
	}
	fmt.Println("Something went wrong... missing data perhaps? Please try again.")
	os.Exit(1)
}

func verifyHandler(cmd *cobra.Command, args []string) {
	if verifySig == "" || verifyPubKey == "" {
		fmt.Println("Please supply a signature and public key to verify.")
		os.Exit(1)
	}

	if len(args) != 1 {
		fmt.Println("Please also supply a signature in hex format.")
		os.Exit(1)
	}

	//TODO move into lib
	sigbytes, err := hex.DecodeString(verifySig)
	panicIf(err)
	sig, err := bls.UnmarshalSignature(sigbytes)
	panicIf(err)

	pubkeybytes, err := hex.DecodeString(verifyPubKey)
	panicIf(err)
	pubkey, err := bls.UnmarshalPublicKey(pubkeybytes)
	panicIf(err)

	ok := sig.Verify(pubkey, []byte(args[0]))
	if !ok {
		fmt.Println("Message not verified!")
		os.Exit(1)
	}
	fmt.Println("Ok")
}
func errorExit(m string) {
	fmt.Println(m)
	os.Exit(1)
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
	pubkeys := make([]bls.PublicKey, 0)
	for _, pkhex := range args {
		pkbytes, err := hex.DecodeString(pkhex)
		panicIf(err)
		pk, err := bls.UnmarshalPublicKey(pkbytes)
		panicIf(err)
		pubkeys = append(pubkeys, pk)
	}
	anticoefs := bls.CalculateAntiRogueCoefficients(pubkeys)
	aggpubkey := bls.AggregatePublicKeys(pubkeys, anticoefs)
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
		fmt.Println("You must tell me how many keys there are in total. --total-keys")
		os.Exit(1)
	}
	if genMembershipAggPub == "" {
		errorExit("Please provide aggregate public key. --agg-pubkey")
	}
	if len(args) != 1 {
		fmt.Println("You must provide an anti-coefficient, which will be generated")
		fmt.Println("with the 'aggregate-pubkeys' option.")
		os.Exit(1)
	}
	keycount, err := strconv.Atoi(genMembershipKeyCount)
	panicIf(err)
	priv, err := lib.FindPrivateKey()
	panicIf(err)
	coef := new(big.Int)
	coef.SetString(args[0], 16)

	aggpubBytes, err := hex.DecodeString(genMembershipAggPub)
	panicIf(err)

	aggpub, err := bls.UnmarshalPublicKey(aggpubBytes)
	panicIf(err)

	for i := 0; i < keycount; i++ {
		s := hex.EncodeToString(priv.GenerateMembershipKeyPart(byte(i), aggpub, *coef).Marshal())
		if i == 0 {
			fmt.Printf("%s", s)
		} else {
			fmt.Printf(" %s", s)
		}
	}
	fmt.Printf("\n")
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

	// fmt.Println(sig.VerifyMultisig(aggpk, subpub, message, bitmask))
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

func main() {
	rootCmd := &cobra.Command{
		Short: "Do BLS12-381 signing and verification.",
	}

	genKeyPairCmd := &cobra.Command{
		Use:   "gen-key-pair",
		Short: "Generate a BLS keypair.",
		Run:   genKeyPairHandler,
	}
	genKeyPairCmd.Flags().StringVar(&genKeyPairSaveTo, "save-to", "", "--save-to=path/to/folder")

	signCmd := &cobra.Command{
		Use:   "sign",
		Short: "Sign some data with your key. If binary data use one of the flags below.",
		Run:   signHandler,
	}
	signCmd.Flags().StringVar(&signDataHex, "data-from-hex", "", "--data-hex=68656C6F7772640A")
	signCmd.Flags().StringVar(&signDataBase64, "data-from-base64", "", "--data-base64=aGVsb3dybGQK")

	verifyCmd := &cobra.Command{
		Use:   "verify",
		Short: "Verify a signature.",
		Run:   verifyHandler,
	}
	verifyCmd.Flags().StringVar(&verifySig, "sig", "", "--sig=68656C6F7772640A")
	verifyCmd.Flags().StringVar(&verifyPubKey, "pubkey", "", "--pubkey=DEADBEEF0123")

	aggPubkeyCmd := &cobra.Command{
		Use:   "aggregate-pubkeys",
		Short: "Combine public keys into one aggregate public key.",
		Run:   aggPubkeyHandler,
	}

	genMembershipKeyCmd := &cobra.Command{
		Use:   "gen-membership-key",
		Short: "Generate a membership key.",
		Run:   genMembershipKeyHandler,
	}
	genMembershipKeyCmd.Flags().StringVar(&genMembershipKeyCount, "total-keys", "", "--total-keys=3")
	genMembershipKeyCmd.Flags().StringVar(&genMembershipAggPub, "agg-pubkey", "", "--agg-pubkey=DEADBEEF123")

	aggregateMemberKeysCmd := &cobra.Command{
		Use:   "aggregate-member-keys",
		Short: "Combine membership keys.",
		Run:   aggregateMemberKeysCmdHandler,
	}

	multiSignCmd := &cobra.Command{
		Use:   "msign",
		Short: "Sign for aggregation (threshold signature).",
		Run:   msignHandler,
	}
	multiSignCmd.Flags().StringVar(&msignAggPub, "agg-pubkey", "", "--agg-pubkey=DEADBEEF123")
	multiSignCmd.Flags().StringVar(&msignMemberKey, "membership-key", "", "--membership-key=BEEF456DEAD")

	aggregateSigsCmd := &cobra.Command{
		Use:   "aggregate-sigs",
		Short: "Combine signatures and public keys.",
		Run:   aggregateSigsHandler,
	}
	aggregateSigsCmd.Flags().StringVar(&aggregateSigsPubKeys, "public-keys", "", "--public-keys=BEEF456,DEAD123,...")
	aggregateSigsCmd.Flags().StringVar(&aggregateSigsBitmask, "bitmask", "", "--bitmask=111")

	aggregateVerifyCmd := &cobra.Command{
		Use:   "aggregate-verify",
		Short: "Verify aggregate signature.",
		Run:   aggregateVerifyHandler,
	}
	aggregateVerifyCmd.Flags().StringVar(&aggregateVerifySubsig, "sub-sig", "", "--sub-sig=DEADBEEF")
	aggregateVerifyCmd.Flags().StringVar(&aggregateVerifySubpub, "sub-pubkey", "", "--sub-pubkey=DEAD123")
	aggregateVerifyCmd.Flags().StringVar(&aggregateVerifyAggpub, "agg-pubkey", "", "--agg-pubkey=BEEF456")
	aggregateVerifyCmd.Flags().StringVar(&aggregateVerifyBitmask, "bitmask", "", "--bitmask=111")

	rootCmd.AddCommand(genKeyPairCmd)
	rootCmd.AddCommand(signCmd)
	rootCmd.AddCommand(verifyCmd)
	rootCmd.AddCommand(aggPubkeyCmd)
	rootCmd.AddCommand(multiSignCmd)
	rootCmd.AddCommand(aggregateSigsCmd)
	rootCmd.AddCommand(genMembershipKeyCmd)
	rootCmd.AddCommand(aggregateMemberKeysCmd)
	rootCmd.AddCommand(aggregateVerifyCmd)
	rootCmd.Execute()
}
