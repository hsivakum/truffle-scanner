package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	"os"
	"os/exec"
	"path"
	"strconv"
	"strings"
	// Import the necessary PostgreSQL client package(s)
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"

	"truffle-scanner/constants"
)

type DetectedSecret struct {
	SourceMetadata struct {
		Data struct {
			Git struct {
				Commit     string `json:"commit"`
				File       string `json:"file"`
				Email      string `json:"email"`
				Repository string `json:"repository"`
				Timestamp  string `json:"timestamp"`
				Line       int    `json:"line"`
			} `json:"Git"`
		} `json:"Data"`
	} `json:"SourceMetadata"`
	SourceID       int         `json:"SourceID"`
	SourceType     int         `json:"SourceType"`
	SourceName     string      `json:"SourceName"`
	DetectorType   int         `json:"DetectorType"`
	DetectorName   string      `json:"DetectorName"`
	DecoderName    string      `json:"DecoderName"`
	Verified       bool        `json:"Verified"`
	Raw            string      `json:"Raw"`
	RawV2          string      `json:"RawV2"`
	Redacted       string      `json:"Redacted"`
	ExtraData      interface{} `json:"ExtraData"`
	StructuredData interface{} `json:"StructuredData"`
}

func main() {
	// Consume environment variables
	repoURL := os.Getenv("URL")
	isPrivate, err := strconv.ParseBool(os.Getenv("IS_PRIVATE"))
	if err != nil {
		log.Panicln(err)
	}
	encryptedToken := os.Getenv("ENCRYPTED_TOKEN")
	keyVaultURL := os.Getenv("KEY_VAULT_URL")
	token := ""

	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		panic(err)
	}

	azkeysClient, err := azkeys.NewClient(keyVaultURL, cred, nil)
	if err != nil {
		panic(err)
	}

	// Check if the repository is private and decrypt the token if needed
	if isPrivate {
		// Use Azure Key Vault SDK to decrypt the token
		// Replace this with your actual code to interact with Azure Key Vault
		version := ""
		algorithmRSAOAEP := azkeys.EncryptionAlgorithmRSAOAEP
		decrypt, err := azkeysClient.Decrypt(context.TODO(), constants.TokenKey, version, azkeys.KeyOperationParameters{
			Algorithm: &algorithmRSAOAEP,
			Value:     []byte(encryptedToken),
		}, nil)
		if err != nil {
			log.Panic("Unable to decrypt token using token key ", err)
		}

		token = string(decrypt.Result)
		// Use the decrypted token for authentication
	}

	// Clone the repository to the scan-volume path
	name, _ := getRepoName(repoURL)
	repoPath := "/home/scanner/" + name // Adjust this path as needed
	if isPrivate {
		err := cloneRepository(repoURL, repoPath, token)
		if err != nil {
			log.Fatal("Failed to clone the repository:", err)
		}
	}

	// Run Trufflehog as an executable and capture its output
	output, err := runTrufflehog(repoPath, repoURL, isPrivate)
	if err != nil {
		log.Fatal("Failed to run Trufflehog:", err)
	}

	// Parse the JSON output from Trufflehog
	results, err := parseTrufflehogOutput(output)
	if err != nil {
		log.Fatal("Failed to parse Trufflehog output:", err)
	}

	log.Println(results)
	// Construct a PostgreSQL database object and write the parsed data
	// Replace this with your code to interact with PostgreSQL
	// Example: saveToDatabase(results)
}

// Function to decrypt the token using Azure Key Vault SDK
func decryptToken(encryptedToken string) (string, error) {
	// Implement decryption logic using Azure Key Vault SDK
	// Return the decrypted token
	return "", nil
}

// Function to clone the repository
func cloneRepository(url, repoPath, token string) error {
	// Split the Git URL into hostname and path
	hostname, namespaceRepoName := splitGitURL(url)

	// Construct the clone URL by injecting the access token
	cloneURL := constructCloneURL(hostname, namespaceRepoName, token)
	cmd := exec.Command("git", "clone", cloneURL, repoPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// Function to run Trufflehog and capture its output
func runTrufflehog(repoPath string, url string, private bool) (string, error) {
	cmd := &exec.Cmd{}
	if private {
		cmd = exec.Command("trufflehog", "--no-verification", "--json", "filesystem", repoPath)
	} else {
		cmd = exec.Command("trufflehog", "--no-verification", "--json", "git", url)
	}

	// Capture the output from stdout
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}

	return string(output), nil
}

// Function to parse Trufflehog output in new line separated JSON format
func parseTrufflehogOutput(output string) ([]DetectedSecret, error) {
	lines := strings.Split(strings.TrimSpace(output), "\n")

	var results []DetectedSecret

	for _, line := range lines {
		var result DetectedSecret
		err := json.Unmarshal([]byte(line), &result)
		if err != nil {
			return nil, err
		}

		results = append(results, result)
	}

	return results, nil
}

// Function to save the parsed data to a PostgreSQL database
func saveToDatabase(results []DetectedSecret) {
	// Implement your code to interact with the PostgreSQL database and save the data
}

// Split the Git URL into hostname and path
func splitGitURL(gitURL string) (string, string) {
	// Remove "https://" if it's present in the Git URL
	gitURL = strings.TrimPrefix(gitURL, "https://")

	// Split the URL into hostname and path
	parts := strings.Split(gitURL, "/")

	// The first part is the hostname, and the rest is the path
	namespace := parts[0]
	repoName := strings.Join(parts[1:], "/")

	return namespace, repoName
}

// Construct the clone URL by injecting the access token
func constructCloneURL(hostname, path, token string) string {
	// Use the HTTPS Git URL format and inject the token
	cloneURL := fmt.Sprintf("https://%s:%s@%s/%s", "token", token, hostname, path)

	return cloneURL
}

func getRepoName(repoURL string) (string, error) {
	// Parse the repository URL
	u, err := url.Parse(repoURL)
	if err != nil {
		return "", err
	}

	// Extract the path from the URL
	repoPath := u.Path

	// Trim leading and trailing slashes
	repoPath = strings.Trim(repoPath, "/")

	// Extract the last segment of the path, which is the repository name
	repoName := path.Base(repoPath)

	return repoName, nil
}
