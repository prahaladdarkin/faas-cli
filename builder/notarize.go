package builder

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/morikuni/aec"
	"github.com/openfaas/faas-cli/schema"
)

//package level private fn vars to be overridden by tests
var baseImageNameProvider = getFunctionBaseImageName
var dockerInspectTrustCommand = getDockerInspectTrustCommand
var executeCommand = ExecCommandWithOutput

func notarizeImage(tempPath string, whitelist SignersWhitelist) error {
	dockerFile := filepath.Join(tempPath, "Dockerfile")
	imageName, err := baseImageNameProvider(dockerFile)
	if err != nil {
		return err
	}
	fmt.Printf(aec.YellowF.Apply(" Validating  signatures for image %s.\n"), imageName)
	var image = ""
	tag := "latest"
	imageNameComponents := strings.Split(imageName, ":")
	if len(imageNameComponents) < 2 {
		fmt.Printf(aec.YellowF.Apply(" No tag found for image %s. Assuming latest..\n"), imageNameComponents[0])
	} else {
		image = imageNameComponents[0]
		tag = imageNameComponents[1]
	}
	trusts := executeCommand(dockerInspectTrustCommand(imageName), false)
	trustInfos := make([]schema.TrustInfo, 0)
	decoder := json.NewDecoder(bytes.NewBufferString(trusts))
	decodeError := decoder.Decode(&trustInfos)
	if decodeError != nil {
		return decodeError
	}
	if (len(trustInfos)) == 0 {
		return fmt.Errorf(aec.RedF.Apply("The base image %s is not signed"), imageName)
	}
	//loop through the list of valid signers and ensure that the image signers are a subset of that list
	allowedSigners := make(map[string]bool, 0)
	signersWhileList, err := whitelist.GetSigners("signers.txt")
	if err != nil {
		return err
	}

	for _, signer := range signersWhileList {
		allowedSigners[signer] = true
	}
	fmt.Printf("Allowed signers : %v\n", allowedSigners)
	//loop through the list of signers and validate that they exist
	//in the list of signers
	imageSigners := make(map[string]bool, 0)

	for _, trust := range trustInfos {

		if trust.Name != image {
			//can never happen. pathological case
			return fmt.Errorf(aec.RedF.Apply("Image name in trust info does not match base image name"))
		}
		for _, signer := range trust.Signers {

			imageSigners[signer.Name] = true
		}
		//loop through the signed tags list and identify the signers for the tag
		//that forms the base image.

		for _, signedTag := range trust.SignedTags {
			if signedTag.SignedTag != tag {
				continue
			}
			for _, signer := range signedTag.Signers {
				imageSigners[signer] = true
			}
		}
	}
	fmt.Printf("Image signers : %v\n", imageSigners)
	//compare if the image signers are in the list of allowed signers
	if len(imageSigners) == 0 {
		return fmt.Errorf(aec.RedF.Apply("Image is not signed by any user"))
	}
	for signer := range imageSigners {
		if _, ok := allowedSigners[signer]; !ok {
			return fmt.Errorf(aec.RedF.Apply("Image contains unauthorized signatures by user : %s"), signer)
		}
	}
	fmt.Printf(aec.GreenF.Apply("Signature validation successful.\n"))
	return nil
}

func getDockerInspectTrustCommand(imageName string) []string {
	command := []string{"docker", "trust", "inspect"}
	command = append(command, imageName)
	return command
}

func getFunctionBaseImageName(dockerFile string) (string, error) {
	f, err := os.Open(dockerFile)
	if err != nil {
		return "", fmt.Errorf("Could not validate signature of base image. Docker file :%s", dockerFile)
	}
	scanner := bufio.NewScanner(f)
	scanner.Split(bufio.ScanLines)

	for scanner.Scan() {
		currentText := scanner.Text()
		components := strings.Split(currentText, " ")
		if len(components) == 0 {
			continue
		}
		directive := components[0]
		if directive == "FROM" {
			fmt.Printf("Encountered FROM directive with image name:%s\n", components[1])
			return components[1], nil
		}

		fmt.Println("Skipping Dockerfile directive ", directive)

	}
	return "", fmt.Errorf("Could not validate signature of base image. Docker file :%s", dockerFile)
}
