#!/usr/bin/env bash

gofiles='cmd/*.go'

te() {
    echo; echo "=> $1"
}
oks=OK
noks=NOK

ok() {
    if $1; then
        echo "$oks: $2"
    else
        echo "$noks: $2"
    fi
}

ok_fail() {
    if [[ $? = 0 ]]; then
        echo "$noks: $1"
    else
        echo "$oks: $1"
    fi
}

ok_abort() {
    failcode=$?
    [[ $? = 0 ]] || {
        ok false "$1"
        exit "$failcode"
    }
    ok true "$1"
}

message=helowrld

# Primary key pair
sk=3136333735383137353832353831343131373733333134393633353135303132303835383337323436383231313836313135303133393139303436363339343035393337373339393730353733
pk=21a0027f94614611baafd41d2d7f0c2d0e8ff37c14aec54791628c872c5dd4500a433c29d2ab3bd0dd9e3a1b2cd99f676ec7b8bea8197c5bb7baf06dfc4e20502935dc9597a45d7ff5c964fbada6fc88de640c0ef843b993f90c052c8d2700fa1558a26d7292283325ecfd58a9dc9bd8c732a476a360597cf2ab924ec4e15576

# Mult-sig keys
sk1=39363837333135313131303236303432303132353831363835393931333939333939373531353039343634313130373031353531313939353937373530353630353131323434393731323333
pk1=2fb1e8e67b0c70b019234d38c3a48726ab2912c3331405614220b1c80ae8e060295389e9a560c7f589bb2a93f056d434c5d180126763da4a02e197e92a92c63b0f3f9e5bbb2764dfcdb7e3a6d7e8f466aee4241ccee993422fbbdf8d4aee69db2980cae996ae23fb91ee3caf3349608f01e8f702d5377bc17f0947927543d816
sk2=3130383937383138353539343635353935353035383235353634333433303538373338333435313330373432343934353234353339393330383232323530313530383030303630383133333538
pk2=0b7a661373b8df757e6b5ebfcb20e42b6a4e405678e5ad671e6498d03e0d2db403ce75c95b3a86c6d884b687f3d2650e57307d3d1aeec8799a7b110f53c36fa12f7292b08be13bde998824f4c41828b3940ab5c20653d1ab86ea75c59f1eee8d0c842606fd044eee606b38d46c9a2842757138b6861c5fa292a9ecf81624c982
sk3=363734383735313735393735343138333939343138383232303831343235363032323531333433333337393337393231333235303630393132363734333135333134373331313335393939
pk3=269069de7a413f718cdb77048b52aeafce45009a1fc7839b1fcfa07882cea63e0b0e6a08a6e46b4a75f07b661e7ba6c10c432ee8abf4dd25681eb27a0fa79bc305b348a23bc77f5e0cf45223cecf80a094d2fb3fc63b043aa9529f51ddc18bfb24e57b42366740a81a170b40a330b92c151e0b5db798bd3ecc2724f74f4f7196


te "Signing message: $message ..."
res=$(BLS_PRIVKEY=$sk go run $gofiles sign helowrld)
ok_abort "bls sign"
echo "$res"
sig=$(echo "$res" | awk '{print $2}')

# hex conversion
res=$(BLS_PRIVKEY=$sk go run $gofiles sign $(printf $message | xxd -p))
sigcheck=$(echo "$res" | awk '{print $2}')
test "$sig" = "$sigcheck"
ok_abort "--message-from-hex"

# base64 conversion
res=$(BLS_PRIVKEY=$sk go run $gofiles sign $(printf $message | base64))
sigcheck=$(echo "$res" | awk '{print $2}')
test "$sig" = "$sigcheck"
ok_abort "--message-from-base64"

te "Verifying message: $message ..."
res=$(go run $gofiles verify $message --sig $sig --pubkey $pk)
ok_abort "bls verify"
res=$(go run $gofiles verify --sig $sig --pubkey $pk --message-from-hex $(printf $message | xxd -p))
ok_abort "bls verify --message-from-hex"
res=$(go run $gofiles verify --sig $sig --pubkey $pk --message-from-base64 $(printf $message | base64))
ok_abort "bls verify --message-from-base64"

te "Checking verify against wrong message..."
res=$(go run $gofiles verify --sig $sig --pubkey $pk wrong_message)
ok_fail "$res"

te "Checking verify against wrong signature..."
wrong_sig=10ae339d6f41321eb50d677bdd9ba6a527f4455a3ced3c511982dbec3baa67030d398a3c455035de88e9e69dfadf5e8361be45e0acf2da39b9c190428686863c
res=$(go run $gofiles verify --sig $wrong_sig --pubkey $pk $message)
ok_fail "$res"

te "Mult-sig test..."

te "Generate aggregate public key..."
res=$(go run $gofiles aggregate-pubkeys $pk1 $pk2 $pk3)
echo "$res"
aggpub=$(echo "$res" | grep public | awk '{print $2}')
acoefs=$(echo "$res" | grep anti-coefficients | awk '{$1=""; print $0}' | xargs)


te "Generate member keys..."
i=1
memberkeys=""
for a in $acoefs; do
    user_sk=$(eval "echo \$sk${i}")
    res=$(BLS_PRIVKEY=$user_sk go run $gofiles gen-membership-key $a --agg-pubkey $aggpub --total-keys 3)
    ok_abort "gen-membership-key / $res"
    i=$((i+1))
    comma=$(echo "$res" | tr ' ' ',')
    memberkeys="$memberkeys $comma"
done
memberkeys=$(echo "$memberkeys" | xargs)

te "Aggregate the member keys..."
membersigs=$(go run $gofiles aggregate-member-keys $memberkeys)
ok_abort "bls aggregate-member-keys"
echo "$membersigs" | tr ' ' '\n'

te "Signers 'msign' with aggregate keys..."
i=1
aggsigs=""
for mk in $(echo "$membersigs" | tr ' ' '\n'); do
    user_sk=$(eval "echo \$sk${i}")
    res=$(BLS_PRIVKEY=$user_sk go run $gofiles msign $message --agg-pubkey $aggpub --membership-key $mk)
    ok_abort "bls msign / $res"
    aggsigs="$aggsigs $res"
    i=$((i+1))
done
aggsigs=$(echo "$aggsigs"|xargs)

te "Aggregate into threshold signature..."
res=$(go run $gofiles aggregate-sigs $aggsigs --public-keys="$pk1,$pk2,$pk3" --bitmask '111')
ok_abort "bls aggregate-sigs / $res"
subsig=$(echo "$res" | grep signature: | awk '{print $2}')
subpub=$(echo "$res" | grep public: | awk '{print $2}')

te "Verify multsig..."
res=$(go run $gofiles aggregate-verify $message --sub-sig $subsig --sub-pubkey $subpub --agg-pubkey $aggpub --bitmask 111)
ok_abort "bls aggregate-verify"
res=$(go run $gofiles aggregate-verify $message --sub-sig $subsig --sub-pubkey $subpub --agg-pubkey $aggpub --bitmask 00000111)
ok_abort "bls aggregate-verify"

te "Bad bitmask fails..."
res=$(go run $gofiles aggregate-verify $message --sub-sig $subsig --sub-pubkey $subpub --agg-pubkey $aggpub --bitmask 101)
ok_fail "$res"

te "Other bad bitmask fails..."
res=$(go run $gofiles aggregate-verify $message --sub-sig $subsig --sub-pubkey $subpub --agg-pubkey $aggpub --bitmask 11100000)
ok_fail "$res"

te "Bad signature fails..."
res=$(go run $gofiles aggregate-verify $message --sub-sig $wrong_sig --sub-pubkey $subpub --agg-pubkey $aggpub --bitmask 111)
ok_fail "$res"
