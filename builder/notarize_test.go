package builder

import (
	"testing"
)

func Test_Notarize(t *testing.T) {

}

func getBaseImageNameForTest(dockerFile string) (string, error) {
	return "imagename:latest", nil
}

func getDockerInspectTrustCommandForTest(imageName string) []string {
	trustInspectCmd := []string{"docker", "trust", "inspect"}
	trustInspectCmd = append(trustInspectCmd, imageName)
	return trustInspectCmd
}

func getExecuteCommandWithOutputForTest(command []string, skipError bool) string {
	var result = `[
    {
        "Name": "imagename",
        "SignedTags": [
            {
                "SignedTag": "latest",
                "Digest": "fdb1ba78f4269815da2dd8c69a8bcdd29a8e9d70d61ec9b7dba05a895bab0909",
                "Signers": [
                    "prahaladd",
                    "johndoe"
                ]
            }
        ],
        "Signers": [
            {
                "Name": "prahaladd",
                "Keys": [
                    {
                        "ID": "bef44f712cbb7d70cbac5bedc71232f067ef433a055388c5afd7b6d42f3e5b41"
                    }
                ]
            },
            {
                "Name": "johndoe",
                "Keys": [
                    {
                        "ID": "7f0aa567f8910d11c8c35de6c9bddccb25324be6e7419ad8c5f707c541fc2b8a"
                    }
                ]
            }
        ],
        "AdministrativeKeys": [
            {
                "Name": "Root",
                "Keys": [
                    {
                        "ID": "ffbe47b35969cc3c83e43e9e52f59f14646a608f8909812875bd8595d25f9437"
                    }
                ]
            },
            {
                "Name": "Repository",
                "Keys": [
                    {
                        "ID": "920b816eca89a42c16361d6a5e8ab4f279a21dd077d5e9b8421570cd5d209cfe"
                    }
                ]
            }
        ]
    }
]`
	return result
}

func getExecuteCommandWithOutputForTestAnyOneSigner(command []string, skipError bool) string {
	var result = `[
    {
        "Name": "imagename",
        "SignedTags": [
            {
                "SignedTag": "latest",
                "Digest": "fdb1ba78f4269815da2dd8c69a8bcdd29a8e9d70d61ec9b7dba05a895bab0909",
                "Signers": [
                    "prahaladd"
                ]
            }
        ],
        "Signers": [
            {
                "Name": "prahaladd",
                "Keys": [
                    {
                        "ID": "bef44f712cbb7d70cbac5bedc71232f067ef433a055388c5afd7b6d42f3e5b41"
                    }
                ]
            }
        ],
        "AdministrativeKeys": [
            {
                "Name": "Root",
                "Keys": [
                    {
                        "ID": "ffbe47b35969cc3c83e43e9e52f59f14646a608f8909812875bd8595d25f9437"
                    }
                ]
            },
            {
                "Name": "Repository",
                "Keys": [
                    {
                        "ID": "920b816eca89a42c16361d6a5e8ab4f279a21dd077d5e9b8421570cd5d209cfe"
                    }
                ]
            }
        ]
    }
]`
	return result
}

type MockWhitelist struct {
	validSigners []string
}

func (mwl *MockWhitelist) SetSigners(signers []string) {
	mwl.validSigners = make([]string, len(signers))
	copy(mwl.validSigners, signers)
}
func (mwl *MockWhitelist) GetSigners() ([]string, error) {
	return mwl.validSigners, nil
}
func TestValidSigners(t *testing.T) {
	defer func() { baseImageNameProvider = getFunctionBaseImageName }()
	defer func() { dockerInspectTrustCommand = getDockerInspectTrustCommand }()
	baseImageNameProvider = getBaseImageNameForTest
	dockerInspectTrustCommand = getDockerInspectTrustCommandForTest
	executeCommand = getExecuteCommandWithOutputForTest
	mwl := &MockWhitelist{validSigners: []string{"prahaladd", "johndoe"}}
	err := notarizeImage("", mwl)
	if err != nil {
		t.Errorf("Expected notarize check to pass. But failed with error %#v", err)
	}

}

func TestAdditionalSigners(t *testing.T) {
	defer func() { baseImageNameProvider = getFunctionBaseImageName }()
	defer func() { dockerInspectTrustCommand = getDockerInspectTrustCommand }()
	baseImageNameProvider = getBaseImageNameForTest
	dockerInspectTrustCommand = getDockerInspectTrustCommandForTest
	executeCommand = getExecuteCommandWithOutputForTest
	mwl := &MockWhitelist{validSigners: []string{"prahaladd"}}
	err := notarizeImage("", mwl)
	if err == nil {
		t.Errorf("Expected notarize check to fail with %#v. But passed", err)
	}

}

func TestAnyOneSigner(t *testing.T) {
	defer func() { baseImageNameProvider = getFunctionBaseImageName }()
	defer func() { dockerInspectTrustCommand = getDockerInspectTrustCommand }()
	baseImageNameProvider = getBaseImageNameForTest
	dockerInspectTrustCommand = getDockerInspectTrustCommandForTest
	executeCommand = getExecuteCommandWithOutputForTestAnyOneSigner
	mwl := &MockWhitelist{validSigners: []string{"prahaladd", "johndoe"}}
	err := notarizeImage("", mwl)
	if err != nil {
		t.Errorf("Expected notarize check to pass but failed with %#v.", err)
	}
}
