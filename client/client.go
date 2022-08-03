package client

// CS 161 Project 2

// You MUST NOT change these default imports. ANY additional imports
// may break the autograder!

import (
	"encoding/hex"
	"encoding/json"
	"strconv"

	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"

	// hex.EncodeToString(...) is useful for converting []byte to string

	// Useful for string manipulation

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
	return hex.EncodeToString(b)
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
	dto.MAC, err = userlib.HMACEval(MK, dto.Encrypted)
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

// dtojson to actual struct, remember to check err after calling it
func dtoUnwrap(EK []byte, macInfo string, dtojson []byte, vptr interface{}) (err error) {
	var dto DTO
	err = json.Unmarshal(dtojson, &dto)
	if err != nil {
		return err
	}
	// get MK and EK
	var MK []byte
	MK, err = userlib.HashKDF(EK, []byte(macInfo))
	if err != nil {
		return err
	}
	// verify MAC
	var MAC []byte
	MAC, err = userlib.HMACEval(MK[:keysize], dto.Encrypted)
	if err != nil {
		return err
	}
	equal := userlib.HMACEqual(MAC, dto.MAC)
	if !equal {
		return errors.New("User struct is tampered.")
	}
	// decrypt and get userjson
	structjson := userlib.SymDec(EK, dto.Encrypted)
	err = json.Unmarshal(structjson, vptr)
	if err != nil {
		return err
	}
	return nil
}

func structWrapAndStoreWithHashKDF(v interface{}, sourceKey []byte, encInfo string, macInfo string, uuidstr string) (UUID userlib.UUID, err error) {
	EK, err := userlib.HashKDF(sourceKey, []byte(encInfo))
	EK = EK[:keysize]
	if err != nil {
		return UUID, err
	}
	UUID, err = getUUID(uuidstr)
	if err != nil {
		return UUID, err
	}
	err = dtoWrappingAndStore(v, EK, UUID, macInfo)
	if err != nil {
		return UUID, err
	}
	return UUID, nil
}

func (userdata *User) getMetaDataAndKeyFromJSON(dtojson []byte, fileMetaData *FileMetaData, fileKey *FileKey) (err error) {
	// step 1:get file metadata
	var metaDataEK []byte
	metaDataEK, err = userlib.HashKDF(userdata.UserEK, []byte("encrypt_file_meta"))
	metaDataEK = metaDataEK[:keysize]
	if err != nil {
		return err
	}
	err = dtoUnwrap(metaDataEK, "mac_file_meta", dtojson, fileMetaData)
	if err != nil {
		return err
	}
	// step 2:get file key
	var ok bool
	dtojson, ok = userlib.DatastoreGet(fileMetaData.FileKeyPtr)
	if !ok {
		return errors.New("No corresponding file key found.")
	}
	var fileKeyEK []byte
	fileKeyEK, err = userlib.HashKDF(fileMetaData.SourceKey, []byte("encrypt_file_key"))
	fileKeyEK = fileKeyEK[:keysize]
	if err != nil {
		return err
	}
	err = dtoUnwrap(fileKeyEK, "mac_file_key", dtojson, fileKey)
	if err != nil {
		return err
	}
	return nil
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
	var userdata User
	err = dtoUnwrap(EK, "mac_user", dtojson, &userdata)
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
	dtojson, ok := userlib.DatastoreGet(metaUUID)
	if !ok {
		// create new file process: 1. FileKey 2. File 3. MetaData 4.FileBlock
		sourceKey := userlib.RandomBytes(keysize)
		// 1.create FileKey and store
		fileKey := FileKey{userlib.RandomBytes(keysize)}
		var filekeyUUID userlib.UUID
		filekeyUUID, err = structWrapAndStoreWithHashKDF(fileKey, sourceKey, "encrypt_file_key", "mac_file_key", userdata.Username+userdata.Username+filename+"key")
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
		metaData := FileMetaData{true, fileUUID, filekeyUUID, ChildrenKeyPtrMap, sourceKey}
		_, err = structWrapAndStoreWithHashKDF(metaData, userdata.UserEK, "encrypt_file_meta", "mac_file_meta", userdata.Username+filename)
		if err != nil {
			return err
		}
		// 4. create FileBlock and store
		fileBlock := FileBlock{content}
		_, err = structWrapAndStoreWithHashKDF(fileBlock, fileKey.EncKey, "encrypt_file_node0", "mac_file_node0", fileUUID.String()+file.Salt+"0")
		if err != nil {
			return err
		}
		return nil
	}
	// overwrite file
	var fileMetaData FileMetaData
	var fileKey FileKey
	err = userdata.getMetaDataAndKeyFromJSON(dtojson, &fileMetaData, &fileKey)
	if err != nil {
		return err
	}
	// step 3:get and modify file
	dtojson, ok = userlib.DatastoreGet(fileMetaData.FileUUID)
	if !ok {
		return errors.New("No corresponding file found.")
	}
	var file File
	err = dtoUnwrap(fileKey.EncKey, "mac_file", dtojson, &file)
	if err != nil {
		return err
	}
	file.FileBlockCnt = 1
	// step 4:get and modify file block
	var fileBlockUUID userlib.UUID
	fileBlockUUID, err = getUUID(fileMetaData.FileUUID.String() + file.Salt + "0")
	if err != nil {
		return err
	}
	dtojson, ok = userlib.DatastoreGet(fileBlockUUID)
	if !ok {
		return errors.New("No corresponding fileBlock found.")
	}
	var fileBlockEK []byte
	fileBlockEK, err = userlib.HashKDF(fileKey.EncKey, []byte("encrypt_file_node0"))
	if err != nil {
		return err
	}
	var fileBlock FileBlock
	err = dtoUnwrap(fileBlockEK, "mac_file_node0", dtojson, &fileBlock)
	if err != nil {
		return err
	}
	fileBlock.Content = content
	// step 5: store file and file block into datastore
	// file
	err = dtoWrappingAndStore(file, fileKey.EncKey, fileMetaData.FileUUID, "mac_file")
	// file block
	err = dtoWrappingAndStore(fileBlock, fileBlockEK, fileBlockUUID, "mac_file_node0")
	if err != nil {
		return err
	}
	return nil
}

func (userdata *User) AppendToFile(filename string, content []byte) (err error) {
	// check existence of file metadata
	var metaUUID userlib.UUID
	metaUUID, err = getUUID(userdata.Username + filename)
	if err != nil {
		return err
	}
	dtojson, ok := userlib.DatastoreGet(metaUUID)
	if !ok {
		return errors.New("No corresponding file metadata found.")
	}
	// load file
	var fileMetaData FileMetaData
	var fileKey FileKey
	err = userdata.getMetaDataAndKeyFromJSON(dtojson, &fileMetaData, &fileKey)
	if err != nil {
		return err
	}
	// step 3:get and modify file
	dtojson, ok = userlib.DatastoreGet(fileMetaData.FileUUID)
	if !ok {
		return errors.New("No corresponding file found.")
	}
	var file File
	err = dtoUnwrap(fileKey.EncKey, "mac_file", dtojson, &file)
	if err != nil {
		return err
	}
	file.FileBlockCnt++
	// step 4:create new file block
	var fileBlockUUID userlib.UUID
	var fileBlockEK []byte
	var fileBlock FileBlock
	fileBlockUUID, err = getUUID(fileMetaData.FileUUID.String() + file.Salt + strconv.Itoa(file.FileBlockCnt-1))
	if err != nil {
		return err
	}
	dtojson, ok = userlib.DatastoreGet(fileBlockUUID)
	fileBlockEK, err = userlib.HashKDF(fileKey.EncKey, []byte("encrypt_file_node"+strconv.Itoa(file.FileBlockCnt-1)))
	fileBlockEK = fileBlockEK[:keysize]
	if err != nil {
		return err
	}
	err = dtoUnwrap(fileBlockEK, "mac_file_node"+strconv.Itoa(file.FileBlockCnt-1), dtojson, &fileBlock)
	if err != nil {
		return err
	}
	fileBlock.Content = content
	// step 5: store file and file block into datastore
	// file
	err = dtoWrappingAndStore(file, fileKey.EncKey, fileMetaData.FileUUID, "mac_file")
	// file block
	err = dtoWrappingAndStore(fileBlock, fileBlockEK, fileBlockUUID, "mac_file_node"+strconv.Itoa(file.FileBlockCnt-1))
	if err != nil {
		return err
	}
	return nil
}

func (userdata *User) LoadFile(filename string) (content []byte, err error) {
	// check existence of file metadata
	var metaUUID userlib.UUID
	metaUUID, err = getUUID(userdata.Username + filename)
	if err != nil {
		return nil, err
	}
	dtojson, ok := userlib.DatastoreGet(metaUUID)
	if !ok {
		return nil, errors.New("No corresponding file metadata found.")
	}
	// load file
	var fileMetaData FileMetaData
	var fileKey FileKey
	err = userdata.getMetaDataAndKeyFromJSON(dtojson, &fileMetaData, &fileKey)
	if err != nil {
		return nil, err
	}
	// step 3:get file
	dtojson, ok = userlib.DatastoreGet(fileMetaData.FileUUID)
	if !ok {
		return nil, errors.New("No corresponding file found.")
	}
	var file File
	err = dtoUnwrap(fileKey.EncKey, "mac_file", dtojson, &file)
	if err != nil {
		return nil, err
	}
	// step 4:get file block
	var res []byte
	var fileBlockUUID userlib.UUID
	var fileBlockEK []byte
	var fileBlock FileBlock
	for i := 0; i < file.FileBlockCnt; i++ {
		fileBlockUUID, err = getUUID(fileMetaData.FileUUID.String() + file.Salt + strconv.Itoa(i))
		if err != nil {
			return nil, err
		}
		dtojson, ok = userlib.DatastoreGet(fileBlockUUID)
		if !ok {
			return nil, errors.New("No corresponding fileBlock found.")
		}
		fileBlockEK, err = userlib.HashKDF(fileKey.EncKey, []byte("encrypt_file_node"+strconv.Itoa(i)))
		fileBlockEK = fileBlockEK[:keysize]
		if err != nil {
			return nil, err
		}
		err = dtoUnwrap(fileBlockEK, "mac_file_node"+strconv.Itoa(i), dtojson, &fileBlock)
		if err != nil {
			return nil, err
		}
		res = append(res, fileBlock.Content...)
	}
	return res, nil
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
	EK = EK[:keysize]
	if err != nil {
		return uuid.Nil, err
	}
	var fileMetaData FileMetaData
	err = dtoUnwrap(EK, "mac_file_key", FileMetaDataJson, &fileMetaData)
	if err != nil {
		return uuid.Nil, err
	}

	// Create a new FileKeyPtr points to the same FileKey for each receiver
	if fileMetaData.Original {
		// Retrieve the FileKey by FileKeyPtr
		dtojson, ok := userlib.DatastoreGet(fileMetaData.FileKeyPtr)
		if !ok {
			return uuid.Nil, errors.New("No corresponding file key found.")
		}

		fileKeyEK, err := userlib.HashKDF(fileMetaData.SourceKey, []byte("encrypt_file_key"))
		if err != nil {
			return uuid.Nil, err
		}

		var fileKey FileKey
		err = dtoUnwrap(fileKeyEK, "mac_file_key", dtojson, &fileKey)
		if err != nil {
			return uuid.Nil, err
		}

		// Store a new FileKeyPtr -> FileKey into datastore
		newFilekeyPtr, err := getUUID(userdata.Username + recipientUsername + filename + "key")
		if err != nil {
			return uuid.Nil, err
		}

		err = dtoWrappingAndStore(fileKey, fileKeyEK, newFilekeyPtr, "mac_file_key")
		if err != nil {
			return uuid.Nil, err
		}

		fileMetaData.ChildrenKeyPtrMap[recipientUsername] = newFilekeyPtr
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
	// Get the invitation information
	invitationDTOJson, ok := userlib.DatastoreGet(invitationPtr)
	if !ok {
		return errors.New("Cannot find invitation")
	}

	var invitationDTO DTO
	json.Unmarshal(invitationDTOJson, &invitationDTO)

	senderVerifyKey, ok := userlib.KeystoreGet(senderUsername + "digital_sig")
	if !ok {
		return errors.New("Cannot find sender's verify key")
	}
	err := userlib.DSVerify(senderVerifyKey, invitationDTO.Encrypted, invitationDTO.MAC)
	if err != nil {
		return err
	}

	invitationJson, err := userlib.PKEDec(userdata.UserPKEDecKey, invitationDTO.Encrypted)
	if err != nil {
		return err
	}
	var invitation Invitation
	json.Unmarshal(invitationJson, &invitation)

	// Create a new file metadata in user's namespace
	var fileMetaData FileMetaData
	fileMetaData.Original = false
	fileMetaData.FileUUID = invitation.FileUUID
	fileMetaData.FileKeyPtr = invitation.FileKeyPtr
	fileMetaData.ChildrenKeyPtrMap = nil
	fileMetaData.SourceKey = invitation.SourceKey
	var fileMetaDataUUID userlib.UUID
	fileMetaDataUUID, err = getUUID(userdata.Username + filename)
	if err != nil {
		return err
	}
	err = dtoWrappingAndStore(fileMetaData, userdata.UserEK, fileMetaDataUUID, "mac_file_meta")
	return err
}

func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {
	fileMetaDataUUID, err := getUUID(userdata.Username + filename)
	if err != nil {
		return err
	}
	fileMetaDataDTOJson, ok := userlib.DatastoreGet(fileMetaDataUUID)
	if !ok {
		return errors.New("Cannot find FileMetaData")
	}

	metadataEK, err := userlib.HashKDF(userdata.UserEK, []byte("encrypt_file_meta"))
	metadatakEK = metadataEK[:keysize]
	if err != nil {
		return err
	}

	var fileMetaData FileMetaData
	err = dtoUnwrap(metadataEK, "mac_file_meta", fileMetaDataDTOJson, &fileMetaData)
	if err != nil {
		return err
	}

	if !fileMetaData.Original {
		return errors.New("Cannot revoke the shared file")
	}

	// Step1: Update the FileKey for users except the revoked user
	// Optional: Delete the FileMetaData in the revoked user's namespace (Maybe done elsewhere)
	dtojson, ok := userlib.DatastoreGet(fileMetaData.FileKeyPtr)
	if !ok {
		return errors.New("No corresponding file key found.")
	}

	fileKeyEK, err := userlib.HashKDF(fileMetaData.SourceKey, []byte("encrypt_file_key"))
	fileKeyEK = fileKeyEK[:keysize]
	if err != nil {
		return err
	}

	var oldFileKey FileKey
	err = dtoUnwrap(fileKeyEK, "mac_file_key", dtojson, &oldFileKey)
	if err != nil {
		return err
	}

	newFileKey := FileKey{userlib.RandomBytes(keysize)}
	for name, fkptr := range fileMetaData.ChildrenKeyPtrMap {
		if name != recipientUsername {
			err = dtoWrappingAndStore(newFileKey, fileKeyEK, fkptr, "mac_file_key")
			if err != nil {
				return err
			}
		}
	}

	// Step2: Re-encrypt the File and generate new File salt
	newFileSalt := string(userlib.RandomBytes(keysize))
	fileDTOjson, ok := userlib.DatastoreGet(fileMetaData.FileUUID)
	if !ok {
		return errors.New("No corresponding file found.")
	}

	var file File
	err = dtoUnwrap(oldFileKey.EncKey, "mac_file", fileDTOjson, &file)
	if err != nil {
		return err
	}

	file.Salt = newFileSalt
	dtoWrappingAndStore(file, newFileKey.EncKey, fileMetaData.FileUUID, "mac_file")

	// Step3: Re-encrypt all the FileBlocks
	for i := 0; i < file.FileBlockCnt; i++ {
		fileBlockUUID, err := getUUID(string(fileMetaData.FileUUID.String() + file.Salt + strconv.Itoa(i)))
		if err != nil {
			return err
		}

		dtojson, ok = userlib.DatastoreGet(fileBlockUUID)
		if !ok {
			return errors.New("No corresponding fileBlock found.")
		}

		fileBlockEK, err := userlib.HashKDF(oldFileKey.EncKey, []byte("encrypt_file_node"+strconv.Itoa(i)))
		fileBlockEK = fileBlockEK[:keysize]
		if err != nil {
			return err
		}

		var fileBlock FileBlock
		err = dtoUnwrap(fileBlockEK, "mac_file_node"+strconv.Itoa(i), dtojson, &fileBlock)
		if err != nil {
			return err
		}

		newFileBlockUUID, err := getUUID(string(fileMetaData.FileUUID.String() + newFileSalt + strconv.Itoa(i)))
		if err != nil {
			return err
		}

		newFileBlockEK, err := userlib.HashKDF(newFileKey.EncKey, []byte("encrypt_file_node"+strconv.Itoa(i)))
		newFileBlockEK = newFileBlockEK[:keysize]
		if err != nil {
			return err
		}

		userlib.DatastoreDelete(fileBlockUUID)
		err = dtoWrappingAndStore(fileBlock, newFileBlockEK, newFileBlockUUID, "mac_file_node"+strconv.Itoa(file.FileBlockCnt))
		if err != nil {
			return err
		}
	}

	return nil
}
