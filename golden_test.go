package main

// Golden vectors lock the on-disk formats: if a test using them fails, files
// written by an earlier build would no longer decrypt.
//
// All use password "golden-pw". Plaintexts:
//
//	v1, v2:       "golden plaintext"
//	v2 multi:     "0123456789abcdefghijklmnopqrstuvwxyzABCD" (40 bytes, 16 byte chunks, KDF t=2 m=64KiB p=2)
//	v2 boundary:  "0123456789abcdefghijklmnopqrstuv" (32 bytes, 2 full 16 byte chunks, last one full)
//	v2 keyfile:   "golden plaintext" with key file "golden-keyfile"
const (
	goldenPassword = "golden-pw"
	goldenKeyFile  = "golden-keyfile"

	goldenV1Hex         = "014cae3ada8566a4c02117ea032a5f2e650a831777de434371b75af0e0b29aeb7e39b62311b84c8c248384d35e"
	goldenV2Hex         = "02001000000003000100000405e4bf680ce996c7f29c3a7360835f9eddb2603c845cfee290597ce556562d85473e3e1ece1d3e671f9a91717342fbfdd76a87b4ecbbd9"
	goldenV2MultiHex    = "02000400000002000000400250cd70a56ffea5f810b244684a8fb60fa04ef7b4853235cf56c98111f834a123e2771dae54f8536a34a2880bada226054e3a383e0d3560def71431dd0282e2890c2312bfd3a166370cb1d96463ddb0db9e4d8d986d93d3d8c4b50e24215a242b0f4819d042d6496ef066fbed246e71"
	goldenV2BoundaryHex = "020004000000010000004001f5ab379d2321766f319a7df69c31c7b11a75a9fc670c255845a4957f1b370f4131e4b356336d9d4dc8dc2f1ff7298c3b8faef2f21dda31f6cf5d8f79d79df7e0a838e85804438192536620e3bd46cb3cf0d45ea5e7ce3f"
	goldenV2KeyFileHex  = "0201060000000100000040018e0c8f5aca5d7f8122b492a603bd2faad3740f6ae7c94fef71178ccea1c3aa5467be76abad881b6d644b6501f28499ac2af791ddd02dd1"

	goldenPlaintext         = "golden plaintext"
	goldenMultiPlaintext    = "0123456789abcdefghijklmnopqrstuvwxyzABCD"
	goldenBoundaryPlaintext = "0123456789abcdefghijklmnopqrstuv"
)
