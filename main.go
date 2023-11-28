package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	"os"
	"os/exec"
	"path"
	"strconv"
	"strings"
	"time"

	_ "github.com/lib/pq"
	// Import the necessary PostgreSQL client package(s)
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"

	"truffle-scanner/constants"
)

type ScanResult struct {
	ScanID             string     `json:"scanID"`
	File               string     `json:"file"`
	URL                string     `json:"url"`
	CommitSHA          string     `json:"commitSHA"`
	RedactedSecret     string     `json:"redactedSecret"`
	Raw                string     `json:"raw"`
	DetectorName       string     `json:"detectorName"`
	IsVerified         bool       `json:"isVerified"`
	ScanCompletionTime *time.Time `json:"scanCompletionTime"`
	CreatedAt          time.Time  `json:"createdAt"`
	ModifiedAt         *time.Time `json:"modifiedAt"`
	DeletedAt          *time.Time `json:"deletedAt"`
}

func insertIntoDB(db *sql.DB, results []ScanResult) error {
	// Prepare the query template
	query := `
		INSERT INTO scan_results (
			scan_id, file, url, commit_sha, redacted_secret, raw, detector_name, is_verified, scan_completion_time
		) VALUES %s ON CONFLICT DO NOTHING;`

	// Define the maximum number of parameters supported by PostgreSQL
	maxParams := 65535

	// Calculate the batch size based on the number of columns and maxParams
	columnsPerRow := 9
	batchSize := maxParams / columnsPerRow

	// Create a slice to hold the values for multiple rows
	var values []interface{}

	// Create a slice to hold the value placeholders for a single row
	valuePlaceholders := make([]string, 0, len(results)*columnsPerRow)
	for i, result := range results {
		valuePlaceholders = append(valuePlaceholders,
			fmt.Sprintf("($%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d)",
				(i*columnsPerRow)+1, (i*columnsPerRow)+2, (i*columnsPerRow)+3,
				(i*columnsPerRow)+4, (i*columnsPerRow)+5, (i*columnsPerRow)+6,
				(i*columnsPerRow)+7, (i*columnsPerRow)+8, (i*columnsPerRow)+9))

		values = append(values,
			result.ScanID, result.File, result.URL, result.CommitSHA, result.RedactedSecret, result.Raw,
			result.DetectorName, result.IsVerified, result.ScanCompletionTime,
		)

		// If we reach the batch size or the end of the results, execute the query
		if (i+1)%batchSize == 0 || i == len(results)-1 {
			valuesBinding := strings.Join(valuePlaceholders, ",")
			execQuery := fmt.Sprintf(query, valuesBinding)

			// Execute the query
			_, err := db.Exec(execQuery, values...)
			if err != nil {
				log.Println("Error inserting into database:", err)
				return err
			}

			// Reset values and placeholders for the next batch
			values = nil
			valuePlaceholders = nil
		}
	}

	return nil
}

func updateStatus(db *sql.DB, status string, scanID string) error {
	// Prepare the SQL statement
	query := `UPDATE scan_requests
		SET queue_status = $1, modified_at = current_timestamp
		WHERE scan_id = $2`

	// Execute the SQL statement
	_, err := db.Exec(query, status, scanID)
	if err != nil {
		log.Println("Error updating status in database:", err)
		return err
	}

	log.Printf("Updated status for scan ID %s.\n", scanID)
	return nil
}

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
	scanID := os.Getenv("SCAN_ID")
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

	azSecretsClient, err := azsecrets.NewClient(keyVaultURL, cred, nil)
	if err != nil {
		panic(err)
	}

	secret, err := azSecretsClient.GetSecret(context.TODO(), "DB-PASSWORD", "", &azsecrets.GetSecretOptions{})
	if err != nil {
		panic(err)
	}

	// PostgreSQL connection details
	dbInfo := url.URL{
		Scheme:   "postgres",
		User:     url.UserPassword(os.Getenv("DB_USER"), *secret.Value),
		Host:     fmt.Sprintf("%s:%s", os.Getenv("DB_HOST"), os.Getenv("DB_PORT")),
		Path:     os.Getenv("DB_NAME"),
		RawQuery: "sslmode=disable",
	}

	// Connect to the database
	db, err := sql.Open("postgres", dbInfo.String())
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	// Check the connection
	if err := db.Ping(); err != nil {
		log.Fatal(err)
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
		err = updateStatus(db, "Failed", scanID)
		if err != nil {
			log.Printf("Unable to insert scan result records %v", err)
			return
		}
		log.Fatal("Failed to parse Trufflehog output:", err)
	}

	var scanResults []ScanResult
	for _, detectedSecret := range results {
		if len(strings.TrimSpace(detectedSecret.DetectorName)) == 0 {
			continue
		}
		now := time.Now()
		scanResults = append(scanResults, ScanResult{
			ScanID:             scanID,
			File:               detectedSecret.SourceMetadata.Data.Git.File,
			URL:                repoURL,
			CommitSHA:          detectedSecret.SourceMetadata.Data.Git.Commit,
			RedactedSecret:     detectedSecret.Redacted,
			Raw:                detectedSecret.Raw,
			DetectorName:       detectedSecret.DetectorName,
			IsVerified:         detectedSecret.Verified,
			ScanCompletionTime: &now,
		})
	}

	err = insertIntoDB(db, scanResults)
	if err != nil {
		log.Panicf("Unable to insert scan result records %v", err)
	}

	err = updateStatus(db, "Processed", scanID)
	if err != nil {
		log.Panicf("Unable to insert scan result records %v", err)
	}

	log.Println("Updated the status to processed")
	// Construct a PostgreSQL database object and write the parsed data
	// Replace this with your code to interact with PostgreSQL
	// Example: saveToDatabase(results)
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

	if cmd.Err != nil {
		log.Printf("Unable to run trufflehog %v", cmd.Err)
		return "", cmd.Err
	}

	// Capture the output from stdout
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("Trufflehog command failed: %v\nCombined output:\n%s", err, output)
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
