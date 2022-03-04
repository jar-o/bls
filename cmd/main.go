package main

import (
	"github.com/spf13/cobra"
)

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
		Short: "Sign some data with your key. If binary data you use one of the flags below.",
		Run:   signHandler,
	}
	signCmd.Flags().StringVar(&messageAsHex, "message-from-hex", "", "--message-from-hex=68656C6F7772640A")
	signCmd.Flags().StringVar(&messageAsBase64, "message-from-base64", "", "--message-from-base64=aGVsb3dybGQK")

	verifyCmd := &cobra.Command{
		Use:   "verify",
		Short: "Verify a signature.",
		Run:   verifyHandler,
	}
	verifyCmd.Flags().StringVar(&verifySig, "sig", "", "--sig=68656C6F7772640A")
	verifyCmd.Flags().StringVar(&verifyPubKey, "pubkey", "", "--pubkey=DEADBEEF0123")
	verifyCmd.Flags().StringVar(&messageAsHex, "message-from-hex", "", "--message-from-hex=68656C6F7772640A")
	verifyCmd.Flags().StringVar(&messageAsBase64, "message-from-base64", "", "--message-from-base64=aGVsb3dybGQK")

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
	multiSignCmd.Flags().StringVar(&messageAsHex, "message-from-hex", "", "--message-from-hex=68656C6F7772640A")
	multiSignCmd.Flags().StringVar(&messageAsBase64, "message-from-base64", "", "--message-from-base64=aGVsb3dybGQK")

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
	aggregateVerifyCmd.Flags().StringVar(&messageAsHex, "message-from-hex", "", "--message-from-hex=68656C6F7772640A")
	aggregateVerifyCmd.Flags().StringVar(&messageAsBase64, "message-from-base64", "", "--message-from-base64=aGVsb3dybGQK")

	bitmaskToIntCmd := &cobra.Command{
		Use:   "bitmask-to-int",
		Short: "Utility for converting a bitstring (e.g. '1101') to an integer value.",
		Run:   bitmaskToIntHandler,
	}

	rootCmd.AddCommand(genKeyPairCmd)
	rootCmd.AddCommand(signCmd)
	rootCmd.AddCommand(verifyCmd)
	rootCmd.AddCommand(aggPubkeyCmd)
	rootCmd.AddCommand(multiSignCmd)
	rootCmd.AddCommand(aggregateSigsCmd)
	rootCmd.AddCommand(genMembershipKeyCmd)
	rootCmd.AddCommand(aggregateMemberKeysCmd)
	rootCmd.AddCommand(aggregateVerifyCmd)
	rootCmd.AddCommand(bitmaskToIntCmd)
	rootCmd.Execute()
}
