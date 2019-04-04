package builder

import (
	"bufio"
	"fmt"
	"os"

	"github.com/morikuni/aec"
)

//SignersWhitelist abstracts out a provider of a valid list of signers for an image. Implementations
//of this interface can perform the required steps to finally provide a set of valid signers
//to the invoker. For e.g. the signers can be read off from a file or from AD or from projects in repositories
//like VMWare Harbor and Quay repositories
type SignersWhitelist interface {
	GetSigners(whitelistURL string) ([]string, error)
}

//FileBackedSignersWhitelist implements a simple file based signer's whitelist
type FileBackedSignersWhitelist struct{}

//GetSigners gets a list of signers from a file names signers.txt
func (fbwl *FileBackedSignersWhitelist) GetSigners(whitelistURL string) ([]string, error) {
	//loop through the list of valid signers and ensure that the image signers are a subset of that list
	if _, err := os.Stat(whitelistURL); os.IsNotExist(err) {
		return nil, fmt.Errorf(aec.RedF.Apply("No signers.txt present at path. Cannot perform signature validation"))
	}
	file, err := os.Open(whitelistURL)
	defer file.Close()
	if err != nil {
		return nil, fmt.Errorf(aec.RedF.Apply("Cannot read file 'signers.txt'. Could not perform signature validation"), err)
	}
	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)
	allowedSigners := make([]string, 0)
	for scanner.Scan() {
		allowedSigners = append(allowedSigners, scanner.Text())
	}
	return allowedSigners, nil
}
