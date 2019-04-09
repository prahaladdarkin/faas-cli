package schema

type SignedTagInfo struct {
	SignedTag string
	Digest    string
	Signers   []string
}

type KeyInfo struct {
	ID string
}

type AdministrativeKeyInfo struct {
	Name string
	Keys []KeyInfo
}

type Signatures struct {
	SignedTags []SignedTagInfo
}

type SignerInfo struct {
	Name string
	Keys []KeyInfo
}

type TrustInfo struct {
	Name               string
	SignedTags         []SignedTagInfo
	Signers            []SignerInfo
	AdministrativeKeys []AdministrativeKeyInfo
}
