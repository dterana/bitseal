// Package testvectors holds golden encrypted files that lock the on-disk
// formats: if a test using them fails, files written by an earlier build would
// no longer decrypt. Never regenerate an existing vector; add a new one.
//
// Every registered cipher version must have at least one vector (see the
// registry tests in internal/seal). To add one for a new version, encrypt the
// plaintext below with a throwaway test and paste the hex here.
package testvectors

// Vector is one golden encrypted file and what it must decrypt to.
type Vector struct {
	Name      string
	Version   byte
	Hex       string
	Password  string
	KeyFile   string // empty when the file has no key file
	Plaintext string
}

const (
	Password = "golden-pw"
	KeyFile  = "golden-keyfile"

	Plaintext         = "golden plaintext"
	MultiPlaintext    = "0123456789abcdefghijklmnopqrstuvwxyzABCD" // 40 bytes
	BoundaryPlaintext = "0123456789abcdefghijklmnopqrstuv"         // 32 bytes

	// V1: written by the original release.
	V1Hex = "014cae3ada8566a4c02117ea032a5f2e650a831777de434371b75af0e0b29aeb7e39b62311b84c8c248384d35e"
	// V2 with the default parameters (Argon2id t=3 m=64MiB p=4, 64 KiB chunks).
	V2Hex = "02001000000003000100000405e4bf680ce996c7f29c3a7360835f9eddb2603c845cfee290597ce556562d85473e3e1ece1d3e671f9a91717342fbfdd76a87b4ecbbd9"
	// V2, 40 bytes in 16 byte chunks, KDF t=2 m=64KiB p=2 (parameters come from the header).
	V2MultiHex = "02000400000002000000400250cd70a56ffea5f810b244684a8fb60fa04ef7b4853235cf56c98111f834a123e2771dae54f8536a34a2880bada226054e3a383e0d3560def71431dd0282e2890c2312bfd3a166370cb1d96463ddb0db9e4d8d986d93d3d8c4b50e24215a242b0f4819d042d6496ef066fbed246e71"
	// V2, 32 bytes in two full 16 byte chunks (last chunk is full).
	V2BoundaryHex = "020004000000010000004001f5ab379d2321766f319a7df69c31c7b11a75a9fc670c255845a4957f1b370f4131e4b356336d9d4dc8dc2f1ff7298c3b8faef2f21dda31f6cf5d8f79d79df7e0a838e85804438192536620e3bd46cb3cf0d45ea5e7ce3f"
	// V2 with a key file, KDF t=1 m=64KiB p=1, 64 byte chunks.
	V2KeyFileHex = "0201060000000100000040018e0c8f5aca5d7f8122b492a603bd2faad3740f6ae7c94fef71178ccea1c3aa5467be76abad881b6d644b6501f28499ac2af791ddd02dd1"
)

// All lists every vector, including which cipher version wrote it.
var All = []Vector{
	{Name: "v1", Version: 1, Hex: V1Hex, Password: Password, Plaintext: Plaintext},
	{Name: "v2 default params", Version: 2, Hex: V2Hex, Password: Password, Plaintext: Plaintext},
	{Name: "v2 multi chunk, params from header", Version: 2, Hex: V2MultiHex, Password: Password, Plaintext: MultiPlaintext},
	{Name: "v2 exact chunk boundary", Version: 2, Hex: V2BoundaryHex, Password: Password, Plaintext: BoundaryPlaintext},
	{Name: "v2 key file", Version: 2, Hex: V2KeyFileHex, Password: Password, KeyFile: KeyFile, Plaintext: Plaintext},
}
