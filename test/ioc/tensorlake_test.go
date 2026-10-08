package ioc_test

import (
	"testing"

	"shai-hulud-scanner/pkg/ioc"
)

func TestTensorlakeHashes(t *testing.T) {
	// SafeDep's October 8 advisory lists three file SHA-256s and one tarball SHA-1.
	for _, hash := range []string{
		"25a0735d0db7dc40e5d45ce42d9c106067e6a66e184d967cfecfab17c3bcb5ef",
		"b50a00900399ba99fb6ce1fc151519cb99d44320ef2a631f2237e1aea0ad6fec",
		"03aa53f01b5b0fc4899c44041da90d7c5aa29fd90e4d99a5b70270f672ee43e1",
	} {
		if _, ok := ioc.IsMaliciousSHA256(hash); !ok {
			t.Errorf("missing tensorlake SHA-256: %s", hash)
		}
	}
	if _, ok := ioc.IsMaliciousSHA1("843a898ab72793568d77c53ff9282e6ce7c66aea"); !ok {
		t.Error("missing tensorlake tarball SHA-1")
	}
}
