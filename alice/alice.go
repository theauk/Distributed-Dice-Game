package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"dice_game/utils"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/google/keytransparency/core/crypto/commitments"
)

func main() {
	// Get needed variables from the command line
	serverHost := flag.String("serverHost", "localhost", "Bob's host name")
	caCertFile := flag.String("cacert", "", "Required, the name of the CA that signed the Bob's certificate")
	clientCertFile := flag.String("clientcert", "", "Required, the name of Alice's certificate file")
	clientKeyFile := flag.String("clientkey", "", "Required, the file name of the Alice's private key file")
	flag.Parse()

	if *caCertFile == "" {
		log.Fatalln("cacert is required but missing")
	}

	// Set up certificate files
	var cert tls.Certificate
	var err error
	if *clientCertFile != "" && *clientKeyFile != "" {
		cert, err = tls.LoadX509KeyPair(*clientCertFile, *clientKeyFile) // Configure Alice's certificate and key
		if err != nil {
			log.Fatalf("Error creating x509 keypair from Alice's cert file %s and Alice's key file %s", *clientCertFile, *clientKeyFile)
		}
	}

	caCert, err := os.ReadFile(*caCertFile)
	if err != nil {
		log.Fatalf("Error opening cert file %s, Error: %s", *caCertFile, err)
	}
	caCertPool := x509.NewCertPool() // Create certificate pool that will also hold Bob's certificate
	caCertPool.AppendCertsFromPEM(caCert)

	// Configurations for the HTTPS client
	t := &http.Transport{
		TLSClientConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			RootCAs:      caCertPool,
		},
	}

	client := http.Client{Transport: t, Timeout: 15 * time.Second}

	// Create a commitment with Alice's dice roll and send it to Bob
	alice := createCommitment()
	log.Println("Alice sends commitment to Bob")

	// Receive Bob's dice roll
	respBodySendCommitment := sendRequest(client, serverHost, "sendCommit", alice.Commitment)
	log.Printf("Bob has sent dice roll: %s", respBodySendCommitment)

	// Send commitment information so that Bob can verify Alice's commitment
	aliceJson, _ := json.Marshal(alice)
	sendRequest(client, serverHost, "verifyInfo", aliceJson)
	log.Println("Alice sends commitment verification info to Bob")

	// Compute common dice roll
	utils.GetDiceRollResult(alice.DiceRoll, string(respBodySendCommitment))
}

// sendRequest Sends specified request to Bob
func sendRequest(client http.Client, serverHost *string, endpoint string, message []byte) []byte {
	req, err := http.NewRequest(http.MethodPost, fmt.Sprintf("https://%s/%s", *serverHost, endpoint), bytes.NewBuffer(message))
	req.Header.Set("Content-Type", "application/json")
	if err != nil {
		log.Fatalf("unable to create http request due to error %s", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		switch e := err.(type) {
		case *url.Error:
			log.Fatalf("url.Error received on http request: %s", e)
		default:
			log.Fatalf("Unexpected error received: %s", err)
		}
	}

	body, err := io.ReadAll(resp.Body)
	defer resp.Body.Close()
	if err != nil {
		log.Fatalf("unexpected error reading response body: %s", err)
	}

	if resp.StatusCode != http.StatusOK {
		log.Printf("Could not send information to endpoint: %s\n", endpoint)
	}

	return body
}

// createCommitment Creates Alice's dice roll commitment
func createCommitment() *utils.Alice {
	diceRoll := utils.RollDice()
	log.Printf("Alice has rolled: %s", diceRoll)
	diceData := []byte(diceRoll)
	userID := "alice"
	nonce, errProfile := commitments.GenCommitmentKey()
	if errProfile != nil {
		log.Fatal(errProfile)
	}

	// Use Go's crypto package to create commitment
	commitment := commitments.Commit(userID, diceData, nonce)

	alice := &utils.Alice{
		UserID:     userID,
		Nonce:      nonce,
		DiceRoll:   diceRoll,
		Commitment: commitment,
	}

	return alice
}
