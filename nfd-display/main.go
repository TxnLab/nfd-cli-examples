/*
 * Copyright (c) 2022. TxnLab Inc.
 * MIT License
 */

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"unicode"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
	"github.com/algorand/go-algorand-sdk/v2/client/v2/common/models"
	"github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/types"
	"github.com/mailgun/holster/v4/syncutil"
)

var (
	registryAppID uint64
	algoClient    *algod.Client
)

type NFDProperties struct {
	Internal    map[string]string `json:"internal"`
	UserDefined map[string]string `json:"userDefined"`
	Verified    map[string]string `json:"verified"`
}

func main() {
	var (
		ctx     = context.Background()
		err     error
		name    = flag.String("name", "", ".algo Name for forward lookup")
		address = flag.String("addr", "", "Algorand address for reverse-address lookup")
		network = flag.String("network", "mainnet", "network: mainnet, testnet, or specify algod, token, regApp parameters")
		algoUrl = flag.String("algod", "", "url of algod host to connect to (ie: http://localhost:8080)")
		token   = flag.String("token", "", "api key token to pass to algod (if needed)")
		regApp  = flag.Uint64("regApp", 0, "registry smart contract ID (for local dev)")
	)
	flag.Parse()

	if *name == "" && *address == "" {
		flag.Usage()
		log.Fatalln("You must specify a name, or an address")
	}
	if *algoUrl != "" {
		algoClient, err = algod.MakeClient(*algoUrl, *token)
		registryAppID = *regApp
	} else {
		// Set registry id and set up algod connection to public algod endpoint
		switch *network {
		case "testnet":
			registryAppID = 84366825
			algoClient, err = algod.MakeClient("https://testnet-api.algonode.cloud", "")
		case "mainnet":
			registryAppID = 760937186
			algoClient, err = algod.MakeClient("https://mainnet-api.algonode.cloud", "")
		default:
			flag.Usage()
			log.Fatalln("unknown network:", *network)
		}
		if err != nil {
			log.Fatalln(err)
		}
	}

	if *name != "" {
		appID, err := FindNFDAppIDByName(ctx, *name)
		if err != nil {
			log.Fatalln("Error in findind/fetching name:", *name, "error:", err)
		}
		displayNFD(ctx, appID)
	} else if *address != "" {
		appIDs, err := FindNFDAppIDsByAddress(ctx, *address)
		if err != nil {
			log.Fatalln("Error in finding/fetching address:", *address, "error:", err)
		}
		for _, appID := range appIDs {
			displayNFD(ctx, appID)
		}
	}
}

func displayNFD(ctx context.Context, appID uint64) {
	fmt.Println("NFD AppID:", appID)

	// Load the global state of this NFD
	appData, err := algoClient.GetApplicationByID(appID).Do(ctx)
	if err != nil {
		log.Fatalln(err)
	}
	// Now load all the box data (V2) in parallel
	boxData, err := GetApplicationBoxes(ctx, appID)
	if err != nil {
		log.Fatalln(err)
	}
	fmt.Println("Byte-code hash:", crypto.AddressFromProgram(appData.Params.ApprovalProgram).String())

	// Fetch everything into key/value map...
	properties := FetchAllStateAsNFDProperties(appData.Params.GlobalState, boxData)
	// ...then merge properties like bio_00, bio_01, into 'bio'
	properties.UserDefined = MergeNFDProperties(properties.UserDefined)
	prettyJson, _ := json.MarshalIndent(properties, "", "  ")

	fmt.Println(string(prettyJson))
}

func GetApplicationBoxes(ctx context.Context, appID uint64) (map[string][]byte, error) {
	var (
		wg      syncutil.WaitGroup
		boxData = map[string][]byte{}
		mapLock sync.Mutex
	)

	// First fetch the list of boxes
	boxes, err := algoClient.GetApplicationBoxes(appID).Do(ctx)
	if err != nil {
		return nil, fmt.Errorf("unable to retrieve boxes list: %w", err)
	}

	// Now fetch the data of all the boxes in parallel
	for _, box := range boxes.Boxes {
		wg.Run(func(val interface{}) error {
			boxName := val.([]byte)
			boxValue, err := algoClient.GetApplicationBoxByName(appID, boxName).Do(ctx)
			if err != nil {
				return fmt.Errorf("unable to fetch box:%s, error:%w", string(boxName), err)
			}
			mapLock.Lock()
			boxData[string(boxName)] = boxValue.Value
			mapLock.Unlock()
			return nil
		}, box.Name)
	}
	errs := wg.Wait()
	if errs != nil {
		return nil, fmt.Errorf("error retrieving box data: %w", errs[0])
	}
	return boxData, nil
}

func FindNFDAppIDByName(ctx context.Context, nfdName string) (uint64, error) {
	// First try to resolve via V2
	boxValue, err := algoClient.GetApplicationBoxByName(registryAppID, GetRegistryBoxNameForNFD(nfdName)).Do(ctx)
	if err == nil {
		// The box data is stored as
		// {ASA ID}{APP ID} - packed 64-bit ints
		if len(boxValue.Value) != 16 {
			return 0, fmt.Errorf("box data is invalid - length:%d but should be 16 for nfd name:%s", len(boxValue.Value), nfdName)
		}
		fmt.Println("Found as V2 name")
		return binary.BigEndian.Uint64(boxValue.Value[8:]), nil
	}
	// fall back to V1 approach
	nameLSIG, err := GetNFDSigNameLSIG(nfdName, registryAppID)
	if err != nil {
		return 0, fmt.Errorf("failed to get nfd sig name lsig: %w", err)
	}
	// Read the local state for our registry SC from this specific account
	address, _ := nameLSIG.Address()
	account, err := algoClient.AccountApplicationInformation(address.String(), registryAppID).Do(ctx)
	if err != nil {
		return 0, fmt.Errorf("failed to get account data for account:%s : %w", address, err)
	}

	// We found our registry contract in the local state of the account
	nfdAppID, _ := FetchBToIFromState(account.AppLocalState.KeyValue, "i.appid")
	if nfdAppID == 0 {
		return 0, errors.New("no NFD found by that name")
	}
	fmt.Println("Found as V1 name")
	return nfdAppID, nil
}

func FindNFDAppIDsByAddress(ctx context.Context, lookupAddress string) ([]uint64, error) {
	var nfdAppIDs []uint64
	// sanity check that this is valid address
	algoAddress, err := types.DecodeAddress(lookupAddress)
	if err != nil {
		return nil, err
	}

	// First try to resolve via V2
	boxValue, err := algoClient.GetApplicationBoxByName(registryAppID, GetRegistryBoxNameForAddress(algoAddress)).Do(ctx)
	if err == nil {
		// Get the set of nfd app ids referenced by this address - we just grab the first for now
		nfdAppIDs, err = FetchUInt64sFromPackedValue(boxValue.Value)
		if err != nil {
			return nil, fmt.Errorf("box address lookup data is invalid, error: %w", err)
		}
		fmt.Printf("Found %d NFDs linked as V2 address\n", len(nfdAppIDs))
	} else {
		// error should be 404 not found and checked, but but this is simple example, so... assume it's just not found
		// fall back to V1 approach
		revAddressLSIG, err := GetNFDSigRevAddressLSIG(algoAddress, registryAppID)
		if err != nil {
			return nil, fmt.Errorf("failed to get nfd sig name lsig: %w", err)
		}
		// Read the local state for our registry SC from this specific account
		address, _ := revAddressLSIG.Address()
		fmt.Printf("V1 Rev-Address used:%s\n", address.String())
		account, err := algoClient.AccountApplicationInformation(address.String(), registryAppID).Do(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to get account data for account:%s : %w", address, err)
		}

		// We found our registry contract in the local state of the account
		for idx := 0; idx < 16; idx++ {
			thisKeyIDs, _ := FetchUint64sFromState(account.AppLocalState.KeyValue, fmt.Sprintf("i.apps%d", idx))
			if thisKeyIDs == nil {
				break
			}
			nfdAppIDs = append(nfdAppIDs, thisKeyIDs...)
		}
		fmt.Printf("Found %d NFDs linked as V1 address\n", len(nfdAppIDs))
	}
	if len(nfdAppIDs) == 0 {
		return nil, fmt.Errorf("no NFDs found for this address")
	}
	return nfdAppIDs, nil
}

func GetRegistryBoxNameForNFD(nfdName string) []byte {
	hash := sha256.Sum256([]byte("name/" + nfdName))
	return hash[:]
}

func GetRegistryBoxNameForAddress(algoAddress types.Address) []byte {
	return algoAddress[:]
}

func getLookupLSIG(prefixBytes, lookupBytes string, registryAppID uint64) (crypto.LogicSigAccount, error) {
	/*
		#pragma version 5
		intcblock 1
		pushbytes 0x0102030405060708
		btoi
		store 0
		txn ApplicationID
		load 0
		==
		txn TypeEnum
		pushint 6
		==
		&&
		txn OnCompletion
		intc_0 // 1
		==
		txn OnCompletion
		pushint 0
		==
		||
		&&
		bnz label1
		err
		label1:
		intc_0 // 1
		return
		bytecblock "xxx"
	*/
	sigLookupByteCode := []byte{
		0x05, 0x20, 0x01, 0x01, 0x80, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
		0x07, 0x08, 0x17, 0x35, 0x00, 0x31, 0x18, 0x34, 0x00, 0x12, 0x31, 0x10,
		0x81, 0x06, 0x12, 0x10, 0x31, 0x19, 0x22, 0x12, 0x31, 0x19, 0x81, 0x00,
		0x12, 0x11, 0x10, 0x40, 0x00, 0x01, 0x00, 0x22, 0x43, 0x26, 0x01,
	}
	contractSlice := sigLookupByteCode[6:14]
	if !reflect.DeepEqual(contractSlice, []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}) {
		return crypto.LogicSigAccount{}, errors.New("Lookup template doesn't match expectation")
	}
	// Bytes 6-13 [0-index] with 0x01-0x08 placeholders is where we put the Registry Contract App ID bytes in big-endian
	binary.BigEndian.PutUint64(contractSlice, registryAppID)

	// We then 'append' the bytes of the prefix + lookup to the end in a bytecblock chunk
	// ie: name/patrick.algo, or address/RXZRFW26WYHFV44APFAK4BEMU3P54OBK47LCAZQJPXOTZ4AZPSFDAKLIQY
	// - the 0x26 0x01 at end of sigLookupByteCode is the bytecblock opcode and specifying a single value is being added

	// We write the uvarint length of our lookup bytes.. then append the bytes of that lookpup string..
	bytesToAppend := bytes.Join([][]byte{[]byte(prefixBytes), []byte(lookupBytes)}, nil)
	uvarIntBytes := make([]byte, binary.MaxVarintLen64)
	nBytes := binary.PutUvarint(uvarIntBytes, uint64(len(bytesToAppend)))
	composedBytecode := bytes.Join([][]byte{sigLookupByteCode, uvarIntBytes[:nBytes], bytesToAppend}, nil)

	logicSig, _ := crypto.MakeLogicSigAccountEscrowChecked(composedBytecode, [][]byte{})
	return logicSig, nil
}

func GetNFDSigNameLSIG(nfdName string, registryAppID uint64) (crypto.LogicSigAccount, error) {
	return getLookupLSIG("name/", nfdName, registryAppID)
}

func GetNFDSigRevAddressLSIG(pointedToAddress types.Address, registryAppID uint64) (crypto.LogicSigAccount, error) {
	return getLookupLSIG("address/", pointedToAddress.String(), registryAppID)
}

// FetchBToIFromState fetches a specific key from application state - stored as big-endian 64-bit value
// Returns value,and whether it w found or not.
func FetchBToIFromState(appState []models.TealKeyValue, key string) (uint64, bool) {
	for _, kv := range appState {
		decodedKey, _ := base64.StdEncoding.DecodeString(kv.Key)
		if string(decodedKey) == key {
			if kv.Value.Type == 1 /* bytes */ {
				value, _ := base64.StdEncoding.DecodeString(kv.Value.Bytes)
				return binary.BigEndian.Uint64(value), true
			}
			return 0, false
		}
	}
	return 0, false
}

// FetchUint64sFromState fetches a specific key from application state - stored as set of 64-bit values (up to 15) // Returns array of values, and optional error
func FetchUint64sFromState(appState []models.TealKeyValue, key string) ([]uint64, error) {
	for _, kv := range appState {
		decodedKey, _ := base64.StdEncoding.DecodeString(kv.Key)
		if string(decodedKey) == key {
			if kv.Value.Type == 1 /* bytes */ {
				value, _ := base64.StdEncoding.DecodeString(kv.Value.Bytes)
				return FetchUInt64sFromPackedValue(value)
			}
			return nil, nil
		}
	}
	return nil, nil
}

// RawPKAsAddress is simplified version of types.EncodeAddress and that returns Address type, not string verison.
func RawPKAsAddress(byteData []byte) types.Address {
	var addr types.Address
	copy(addr[:], []byte(byteData))
	return addr
}

// FetchUInt64sFromPackedValue returns all non-zero 64-bit ints contained in the slice (up to 15 for a single
// local-state fetch for example)
func FetchUInt64sFromPackedValue(data []byte) ([]uint64, error) {
	if len(data)%8 != 0 {
		return nil, fmt.Errorf("data length %d is not a multiple of 8", len(data))
	}
	var ints []uint64
	for offset := 0; offset < len(data); offset += 8 {
		fetchedInt := binary.BigEndian.Uint64(data[offset : offset+8])
		if fetchedInt == 0 {
			continue
		}
		ints = append(ints, fetchedInt)
	}
	return ints, nil
}

// FetchAlgoAddressesFromPackedValue returns all non-zero Algorand 32-byte PKs encoded in a value (up to 3)
func FetchAlgoAddressesFromPackedValue(data []byte) ([]string, error) {
	if len(data)%32 != 0 {
		return nil, fmt.Errorf("data length %d is not a multiple of 32", len(data))
	}
	var algoAddresses []string
	// This is a caAlgo.X.as key (we read them in order because we sorted the keys) so we can append
	// safely and the order is preserved.
	for offset := 0; offset < len(data); offset += 32 {
		addr := RawPKAsAddress(data[offset : offset+32])
		if addr.IsZero() {
			continue
		}
		algoAddresses = append(algoAddresses, addr.String())
	}
	return algoAddresses, nil
}

// We need to be able to sort keys returned in global state by the decoded key name, so define an implementation
// of the Sort interface for the state key names.
type byKeyName []models.TealKeyValue

func (a byKeyName) Len() int      { return len(a) }
func (a byKeyName) Swap(i, j int) { a[i], a[j] = a[j], a[i] }
func (a byKeyName) Less(i, j int) bool {
	keyI, _ := base64.StdEncoding.DecodeString(a[i].Key)
	keyJ, _ := base64.StdEncoding.DecodeString(a[j].Key)
	return bytes.Compare(keyI, keyJ) == -1
}

func FetchAllStateAsNFDProperties(appState []models.TealKeyValue, boxData map[string][]byte) NFDProperties {
	isStringPrintable := func(str string) bool {
		for _, strRune := range str {
			if !strconv.IsPrint(strRune) {
				return false
			}
		}
		return true
	}
	var (
		state = NFDProperties{
			Internal:    map[string]string{},
			UserDefined: map[string]string{},
			Verified:    map[string]string{},
		}
		key           string
		valAsStr      string
		algoAddresses []string
	)
	// Some keys must be sorted to ensure proper ordering of decoding (v.caAlgo.0.as, v.caAlgo.1.as, .. for eg)
	sort.Sort(byKeyName(appState))

	processKeyAndVal := func(key string, valType uint64, intVal uint64, stringVal []byte) {
		switch valType {
		case 1: // bytes
			if strings.HasSuffix(key, ".as") { // caAlgo.##.as (sets of packed algorand addresses)
				addresses, err := FetchAlgoAddressesFromPackedValue(stringVal)
				if err != nil {
					valAsStr = err.Error()
					break
				}
				algoAddresses = append(algoAddresses, addresses...)
				// Don't set into the state map - just collect the addresses and we set them into a single caAlgo field
				// at the end, as a comma-delimited string.
				return
			} else if len(stringVal) == 32 && strings.HasSuffix(key, ".a") {
				// 32 bytes and key name has .a [algorand address] suffix - parse accordingly - strip suffix
				valAsStr = RawPKAsAddress(stringVal).String()
				key = strings.TrimSuffix(key, ".a")
			} else if len(stringVal) == 8 && !isStringPrintable(string(stringVal)) {
				// Assume it's a big-endian integer
				valAsStr = strconv.FormatUint(binary.BigEndian.Uint64(stringVal), 10)
			} else {
				valAsStr = string(stringVal)
			}
		case 2: // uint
			valAsStr = strconv.FormatUint(intVal, 10)
		default:
			valAsStr = "unknown"
		}
		switch key[0:2] {
		case "i.":
			state.Internal[key[2:]] = valAsStr
		case "u.":
			state.UserDefined[key[2:]] = valAsStr
		case "v.":
			state.Verified[key[2:]] = valAsStr
		}
	}

	for _, kv := range appState {
		rawKey, _ := base64.StdEncoding.DecodeString(kv.Key)
		key = string(rawKey)
		if kv.Value.Type == 1 {
			value, _ := base64.StdEncoding.DecodeString(kv.Value.Bytes)
			processKeyAndVal(key, kv.Value.Type, kv.Value.Uint, value)
		} else {
			processKeyAndVal(key, kv.Value.Type, kv.Value.Uint, nil)
		}
	}
	for key, val := range boxData {
		processKeyAndVal(key, 1, 0, val)
	}
	if len(algoAddresses) > 0 {
		state.Verified["caAlgo"] = strings.Join(algoAddresses, ",")
	}
	return state
}

// MergeNFDProperties - take a set of 'split' values spread across multiple keys
// like address_00, address_01 and merge into single address value, combining the
// values into single 'address'.
func MergeNFDProperties(properties map[string]string) map[string]string {
	var (
		mergedMap  = map[string]string{}
		fieldNames = make([]string, 0, len(properties))
		valAsStr   string
	)
	// Get key names, then sort..
	for key := range properties {
		fieldNames = append(fieldNames, key)
	}
	// Sort the keys so that keys like address_00, address_01, .. are in order...
	sort.Strings(fieldNames)
	for _, key := range fieldNames {
		valAsStr = string(properties[key])

		// If key ends in _{digit}{digit} then we combine into a single value as we read them (in order)
		if len(key) > 3 && key[len(key)-3] == '_' && unicode.IsDigit(rune(key[len(key)-2])) && unicode.IsDigit(rune(key[len(key)-1])) {
			// Chop off the _{digit}{digit} portion in the key.. leave the rest
			// This processing assumes just strings, ie, address_00, address_01, etc.
			key = key[:len(key)-3]
		}

		// See if the keyname is reused (via our _{digit} processing} and append to existing value if so
		if curVal, found := mergedMap[key]; found {
			mergedMap[key] = curVal + valAsStr
		} else {
			mergedMap[key] = valAsStr
		}
	}
	return mergedMap
}
