package builder

import (
	"bufio"
	"fmt"
	"os"

	"github.com/morikuni/aec"
)

type SignersWhitelist interface {
	GetSigners() ([]string, error)
}

type FileBackedSignersWhitelist struct {
	filePath string
}

func (fbwl *FileBackedSignersWhitelist) GetSigners() ([]string, error) {
	fmt.Printf(aec.YellowF.Apply("Reading from file:%s\n"), fbwl.filePath)
	//loop through the list of valid signers and ensure that the image signers are a subset of that list
	if _, err := os.Stat(fbwl.filePath); os.IsNotExist(err) {
		return nil, fmt.Errorf(aec.RedF.Apply("No %s present at path. Cannot perform signature validation\n"), fbwl.filePath)
	}
	file, err := os.Open(fbwl.filePath)
	defer file.Close()
	if err != nil {
		return nil, fmt.Errorf(aec.RedF.Apply("Cannot read file %s. Could not perform signature validation\n"), fbwl.filePath, err)
	}
	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)
	allowedSigners := make([]string, 0)
	for scanner.Scan() {
		fmt.Println("Signers :", scanner.Text())
		allowedSigners = append(allowedSigners, scanner.Text())
	}
	fmt.Printf("Allowed signers : %v\n", allowedSigners)
	return allowedSigners, nil
}
