package client

// CS 161 Project 2

// You MUST NOT change these default imports. ANY additional imports
// may break the autograder!

import (
	"encoding/json"
	"strconv"
	"unsafe"

	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"

	// hex.EncodeToString(...) is useful for converting []byte to string

	// Useful for string manipulation
	"strings"

	// Useful for formatting strings (e.g. `fmt.Sprintf`).
	"fmt"

	// Useful for creating new error messages to return using errors.New("...")
	"errors"

	// Optional.
	_ "strconv"
)

const keysize = 16

// This serves two purposes: it shows you a few useful primitives,
// and suppresses warnings for imports not being used. It can be
// safely deleted!
func someUsefulThings() {

	// Creates a random UUID.
	randomUUID := uuid.New()

	// Prints the UUID as a string. %v prints the value in a default format.
	// See https://pkg.go.dev/fmt#hdr-Printing for all Golang format string flags.
	userlib.DebugMsg("Random UUID: %v", randomUUID.String())

	// Creates a UUID deterministically, from a sequence of bytes.
	hash := userlib.Hash([]byte("user-structs/alice"))
	deterministicUUID, err := uuid.FromBytes(hash[:keysize])
	if err != nil {
		// Normally, we would `return err` here. But, since this function doesn't return anything,
		// we can just panic to terminate execution. ALWAYS, ALWAYS, ALWAYS check for errors! Your
		// code should have hundreds of "if err != nil { return err }" statements by the end of this
		// project. You probably want to avoid using panic statements in your own code.
		panic(errors.New("An error occurred while generating a UUID: " + err.Error()))
	}
	userlib.DebugMsg("Deterministic UUID: %v", deterministicUUID.String())

	// Declares a Course struct type, creates an instance of it, and marshals it into JSON.
	type Course struct {
		name      string
		professor []byte
	}

	course := Course{"CS 161", []byte("Nicholas Weaver")}
	courseBytes, err := json.Marshal(course)
	if err != nil {
		panic(err)
	}

	userlib.DebugMsg("Struct: %v", course)
	userlib.DebugMsg("JSON Data: %v", courseBytes)

	// Generate a random private/public keypair.
	// The "_" indicates that we don't check for the error case here.
	var pk userlib.PKEEncKey
	var sk userlib.PKEDecKey
	pk, sk, _ = userlib.PKEKeyGen()
	userlib.DebugMsg("PKE Key Pair: (%v, %v)", pk, sk)

	// Here's an example of how to use HBKDF to generate a new key from an input key.
	// Tip: generate a new key everywhere you possibly can! It's easier to generate new keys on the fly
	// instead of trying to think about all of the ways a key reuse attack could be performed. It's also easier to
	// store one key and derive multiple keys from that one key, rather than
	originalKey := userlib.RandomBytes(keysize)
	derivedKey, err := userlib.HashKDF(originalKey, []byte("mac-key"))
	if err != nil {
		panic(err)
	}
	userlib.DebugMsg("Original Key: %v", originalKey)
	userlib.DebugMsg("Derived Key: %v", derivedKey)

	// A couple of tips on converting between string and []byte:
	// To convert from string to []byte, use []byte("some-string-here")
	// To convert from []byte to string for debugging, use fmt.Sprintf("hello world: %s", some_byte_arr).
	// To convert from []byte to string for use in a hashmap, use hex.EncodeToString(some_byte_arr).
	// When frequently converting between []byte and string, just marshal and unmarshal the data.
	//
	// Read more: https://go.dev/blog/strings

	// Here's an example of string interpolation!
	_ = fmt.Sprintf("%s_%d", "file", 1)
	fmt.Println("qx")
}

// This is the type definition for the User struct.
// A Go struct is like a Python or Java class - it can have attributes
// (e.g. like the Username attribute) and methods (e.g. like the StoreFile method below).

// You can add other attributes here if you want! But note that in order for attributes to
// be included when this struct is serialized to/from JSON, they must be capitalized.
// On the flipside, if you have an attribute that you want to be able to access from
// this struct's methods, but you DON'T want that value to be included in the serialized value
// of this struct that's stored in datastore, then you can use a "private" variable (e.g. one that
// begins with a lowercase letter).

type User struct {
	Username      string
	Password      string
	UserEK        []byte
	UserPKEDecKey userlib.PKEDecKey
	UserDSSignKey userlib.DSSignKey
}

type FileMetaData struct {
	Original          bool
	FileUUID          userlib.UUID
	FileKeyPtr        userlib.UUID
	ChildrenKeyPtrMap map[string]userlib.UUID
	SourceKey         []byte
}

type FileKey struct {
	EncKey []byte
}

type File struct {
	FileBlockCnt int
	Salt         string
}

type FileBlock struct {
	Content []byte
}

type Invitation struct {
	Sender     string
	Receiver   string
	FileUUID   userlib.UUID
	FileKeyPtr userlib.UUID
	SourceKey  []byte
}

type DTO struct {
	Encrypted []byte
	MAC       []byte
}

func byte2Str(b []byte) string {
	return *(*string)(unsafe.Pointer(&b))
}

// source string -> UUID, rememeber to check err after calling it
func getUUID(source string) (UUID userlib.UUID, err error) {
	UUID, err = uuid.FromBytes(userlib.Hash([]byte(source))[:keysize])
	if err != nil {
		return UUID, err
	}
	return UUID, nil
}

// wrap struct into encrypted DTO and store into datastore, rememeber to check err after calling it
func dtoWrappingAndStore(v interface{}, EK []byte, UUID userlib.UUID, macInfo string) (err error) {
	var dto DTO
	var vjson []byte

	//mashal and encrypt
	vjson, err = json.Marshal(v)
	if err != nil {
		return err
	}
	dto.Encrypted = userlib.SymEnc(EK, userlib.RandomBytes(keysize), vjson)

	// MAC
	var MK []byte
	MK, err = userlib.HashKDF(EK, []byte(macInfo))
	if err != nil {
		return err
	}
	dto.MAC, err = userlib.HMACEval(MK[:keysize], dto.Encrypted)
	if err != nil {
		return err
	}

	// store dto into datastore
	var dtojson []byte
	dtojson, err = json.Marshal(dto)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(UUID, dtojson)
	return nil
}

// Fetching dto from datastore, verfiy mac and decrypt it to the origin plainText
func dtoUnwrap(EK []byte, macInfo string, dtojson []byte) (structjson []byte, err error) {
	var dto DTO
	err = json.Unmarshal(dtojson, &dto)
	if err != nil {
		return nil, err
	}
	// get MK and EK
	var MK []byte
	MK, err = userlib.HashKDF(EK, []byte(macInfo))
	if err != nil {
		return nil, err
	}
	// verify MAC
	var MAC []byte
	MAC, err = userlib.HMACEval(MK[:keysize], dto.Encrypted)
	if err != nil {
		return nil, err
	}
	equal := userlib.HMACEqual(MAC, dto.MAC)
	if !equal {
		return nil, errors.New("User struct is tampered.")
	}
	// decrypt and get userjson
	structjson = userlib.SymDec(EK, dto.Encrypted)
	return structjson, nil
}

func InitUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	userdata.Username = username
	userdata.Password = byte2Str(userlib.Hash([]byte(password + username)))

	// RSA key management
	var RSApk userlib.PublicKeyType
	var RSAsk userlib.PrivateKeyType
	RSApk, RSAsk, err = userlib.PKEKeyGen()
	if err != nil {
		return nil, err
	}
	err = userlib.KeystoreSet(username+"public_enc", RSApk)
	if err != nil {
		return nil, err
	}
	userdata.UserPKEDecKey = RSAsk

	// DS key management
	var DSpk userlib.DSVerifyKey
	var DSsk userlib.DSSignKey
	DSsk, DSpk, err = userlib.DSKeyGen()
	if err != nil {
		return nil, err
	}
	err = userlib.KeystoreSet(username+"digital_sig", DSpk)
	if err != nil {
		return nil, err
	}
	userdata.UserDSSignKey = DSsk

	// dto struct initialization
	EK := userlib.Argon2Key([]byte(password), []byte(username), keysize)
	userdata.UserEK = EK
	var UUID userlib.UUID
	UUID, err = getUUID(username)
	if err != nil {
		return nil, err
	}
	err = dtoWrappingAndStore(userdata, EK, UUID, "mac_user")
	if err != nil {
		return nil, err
	}

	// return result
	return &userdata, nil
}

func GetUser(username string, password string) (userdataptr *User, err error) {
	// get dtojson
	var UUID userlib.UUID
	UUID, err = getUUID(username)
	if err != nil {
		return nil, err
	}
	dtojson, ok := userlib.DatastoreGet(UUID)
	if !ok {
		return nil, errors.New("No corresponding user found.")
	}
	//get EK and unmarshal dtojson to userjson
	EK := userlib.Argon2Key([]byte(password), []byte(username), keysize)
	userjson, err := dtoUnwrap(EK, "mac_user", dtojson)
	if err != nil {
		return nil, err
	}
	// get user struct
	var userdata User
	err = json.Unmarshal(userjson, &userdata)
	if err != nil {
		return nil, err
	}
	userdataptr = &userdata
	return userdataptr, nil
}

func (userdata *User) StoreFile(filename string, content []byte) (err error) {
	// check existence of file metadata
	var metaUUID userlib.UUID
	metaUUID, err = getUUID(userdata.Username + filename)
	if err != nil {
		return err
	}
	metajson, ok := userlib.DatastoreGet(metaUUID)
	if !ok {
		// create new file process: 1. FileKey 2. File 3. MetaData 4.FileBlock
		SourceKey := userlib.RandomBytes(keysize)
		// 1.create FileKey and store
		fileKey := FileKey{userlib.RandomBytes(keysize)}
		fileKeyEK, err := userlib.HashKDF(SourceKey, []byte("encrypt_file_key"))
		if err != nil {
			return err
		}
		var filekeyUUID userlib.UUID
		filekeyUUID, err = getUUID(userdata.Username + userdata.Username + filename + "key")
		if err != nil {
			return err
		}
		err = dtoWrappingAndStore(fileKey, fileKeyEK, filekeyUUID, "mac_file_key")
		if err != nil {
			return err
		}
		// 2.create File and store
		file := File{1, byte2Str(userlib.RandomBytes(keysize))}
		var fileUUID userlib.UUID
		fileUUID, err = getUUID(userdata.Username + filename + file.Salt)
		if err != nil {
			return err
		}
		err = dtoWrappingAndStore(file, fileKey.EncKey, fileUUID, "mac_file")
		if err != nil {
			return err
		}
		// 3. create MetaData and store
		var ChildrenKeyPtrMap map[string]userlib.UUID
		ChildrenKeyPtrMap = make(map[string]userlib.UUID)
		metadata := FileMetaData{true, fileUUID, filekeyUUID, ChildrenKeyPtrMap, SourceKey}
		var metadataEK []byte
		metadataEK, err = userlib.HashKDF(userdata.UserEK, []byte("encrypt_file_meta"))
		if err != nil {
			return err
		}
		var metadataUUID userlib.UUID
		metadataUUID, err = getUUID(userdata.Username + filename)
		if err != nil {
			return err
		}
		err = dtoWrappingAndStore(metadata, metadataEK, metadataUUID, "mac_file_meta")
		if err != nil {
			return err
		}
		// 4. create FileBlock and store
		fileBlock := FileBlock{content}
		var fileBlockEK []byte
		fileBlockEK, err = userlib.HashKDF(fileKey.EncKey, []byte("encrypt_file_node"+strconv.Itoa(0)))
		if err != nil {
			return err
		}
		var fileBlockUUID userlib.UUID
		fileBlockUUID, err = getUUID(userdata.Username + filename + "0" + file.Salt)
		if err != nil {
			return err
		}
		err = dtoWrappingAndStore(fileBlock, fileBlockEK, fileBlockUUID, "mac_file_node0")
		if err != nil {
			return err
		}

	}

	// overwrite file

	storageKey, err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username))[:16])
	if err != nil {
		return err
	}
	contentBytes, err := json.Marshal(content)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(storageKey, contentBytes)
	return
}

func (userdata *User) AppendToFile(filename string, content []byte) error {
	return nil
}

func (userdata *User) LoadFile(filename string) (content []byte, err error) {
	storageKey, err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username))[:16])
	if err != nil {
		return nil, err
	}
	dataJSON, ok := userlib.DatastoreGet(storageKey)
	if !ok {
		return nil, errors.New(strings.ToTitle("file not found"))
	}
	err = json.Unmarshal(dataJSON, &content)
	return content, err
}

func (userdata *User) CreateInvitation(filename string, recipientUsername string) (
	invitationPtr uuid.UUID, err error) {
	fileMetaDataUUID, err := getUUID(userdata.Username + filename)
	if err != nil {
		return uuid.Nil, errors.New("You don't have this file")
	}

	FileMetaDataJson, ok := userlib.DatastoreGet(fileMetaDataUUID)
	if !ok {
		return uuid.Nil, err
	}

	EK, err := userlib.HashKDF(userdata.UserEK, []byte("encrypt_file_key"))
	if err != nil {
		return uuid.Nil, err
	}

	fileMetaDataJson, err := dtoUnwrap(EK, "mac_file_key", FileMetaDataJson)
	var fileMetaData FileMetaData
	err = json.Unmarshal(fileMetaDataJson, fileMetaData)
	if err != nil {
		return uuid.Nil, err
	}

	var invitation Invitation
	invitation.Sender = userdata.Username
	invitation.Receiver = recipientUsername
	invitation.FileUUID = fileMetaData.FileUUID
	invitation.FileKeyPtr = fileMetaData.FileKeyPtr
	invitation.SourceKey = fileMetaData.SourceKey

	invitationJson, err := json.Marshal(invitation)
	invitationUUID, err := getUUID(invitation.Sender + invitation.Receiver + filename)
	if err != nil {
		return uuid.Nil, err
	}

	receiverSk, ok := userlib.KeystoreGet(recipientUsername + "public_enc")
	if !ok {
		return uuid.Nil, err
	}

	var invitationDTO DTO
	invitationDTO.Encrypted, err = userlib.PKEEnc(receiverSk, invitationJson)
	if err != nil {
		return uuid.Nil, err
	}
	invitationDTO.MAC, err = userlib.DSSign(userdata.UserDSSignKey, invitationDTO.Encrypted)
	invitationDTOJson, err := json.Marshal(invitationDTO)
	userlib.DatastoreSet(invitationUUID, invitationDTOJson)
	return invitationUUID, err
}

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) error {
	return nil
}

func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {
	return nil
}
