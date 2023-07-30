package main

import (
	"crypto/tls"
	"crypto/x509"
	"dice_game/utils"
	"encoding/json"
	"flag"
	"github.com/google/keytransparency/core/crypto/commitments"
	"io"
	"log"
	"net/http"
	"os"
	"time"
)

type Bob struct {
	bobDiceRoll string
	aliceCommit []byte
}

func main() {
	// Get needed variables from the command line
	host := flag.String("host", "", "Required flag, must be the hostname that is resolvable via DNS, or 'localhost'")
	port := flag.String("port", "443", "The https port, defaults to 443")
	serverCert := flag.String("srvcert", "", "Required, the name of Alice's certificate file")
	caCert := flag.String("cacert", "", "Required, the name of the CA that signed Alice's certificate")
	srcKey := flag.String("srvkey", "", "Required, the file name of Bob's private key file")
	flag.Parse()

	if *host == "" || *serverCert == "" || *caCert == "" || *srcKey == "" {
		log.Fatalln("One or more required fields missing")
	}

	// Create a HTTPS server (listening port, timeouts for read and write, TLS options)
	server := &http.Server{
		Addr:         ":" + *port,
		ReadTimeout:  5 * time.Minute,
		WriteTimeout: 10 * time.Second,
		TLSConfig:    getTLSConfig(*host, *caCert),
	}

	// Struct to hold Bob's dice roll and the commitment received from Alice
	bob := &Bob{}

	// Endpoint to receive Alice's commitment
	http.HandleFunc("/sendCommit", func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			log.Fatalf("error reading commitment request body: %s\n", err)
		}

		log.Println("Received Alice's commitment")

		// Store Alice's commit
		bob.aliceCommit = body

		// Bob rolls dice and sends it to Alice
		bob.bobDiceRoll = utils.RollDice()
		_, err = w.Write([]byte(bob.bobDiceRoll))
		if err != nil {
			log.Fatalf("Bob could not send dice roll: %s\n", err)
		}

		log.Printf("Bob sends dice roll: %s", bob.bobDiceRoll)
	})

	// Endpoint to receive information needed to verify Alice's commitment
	http.HandleFunc("/verifyInfo", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		body, err := io.ReadAll(r.Body)
		if err != nil {
			log.Fatalf("error reading commitment verification info request body: %s\n", err)
		}

		// Struct to store commitment verification info received from Alice (sent as a JSON)
		alice := utils.Alice{}
		err = json.Unmarshal(body, &alice)
		if err != nil {
			log.Fatalf("Could not unmarshal JSON: %s\n", err)
		}

		// Send acknowledgement message to Alice
		_, err = w.Write([]byte("Received verification info"))
		if err != nil {
			log.Printf("Bob could not send acknowledgement to receiving verification info: %s\n", err)
		}

		log.Println("Received Alice's verification info")

		// Verify Alice's commitment
		err2 := commitments.Verify(alice.UserID, alice.Commitment, []byte(alice.DiceRoll), alice.Nonce)
		if err2 != nil {
			log.Fatalf("Could not verify Alice's commitment")
		} else {
			log.Printf("Alice's dice roll has been verified. She rolled: %s\n", alice.DiceRoll)
			utils.GetDiceRollResult(alice.DiceRoll, bob.bobDiceRoll)
		}
	})

	// Make the server listen for incoming requests
	log.Printf("Starting Bob's HTTPS server on host %s and port %s", *host, *port)
	if err := server.ListenAndServeTLS(*serverCert, *srcKey); err != nil {
		log.Fatal(err)
	}
}

// getTLSConfig Sets up TLS configurations (given the server's hostname and the CA that signed the client’s certificate)
func getTLSConfig(host, caCertFile string) *tls.Config {
	var caCert []byte
	var err error
	var caCertPool *x509.CertPool         // Set up a new certificate pool that will store the certificate of the CA that signed the client’s certificate
	caCert, err = os.ReadFile(caCertFile) // Get the CA certificate file needed to validate Alice's certificate and later place it into the caCertPool
	if err != nil {
		log.Fatal("Error opening cert file", caCertFile, ", error ", err)
	}
	caCertPool = x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	return &tls.Config{
		ServerName: host,
		ClientAuth: tls.RequireAndVerifyClientCert, // Client certificate will be required and must be present in the bob's Certificate Pool
		ClientCAs:  caCertPool,
		MinVersion: tls.VersionTLS12, // Minimum TLS required
	}
}
