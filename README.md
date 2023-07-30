# Distributed Dice Game

Alice and Bob wants to throw a virtual 6-sided dice over an insecure network. However, they do not trust each other and an adversary with access to the network must not be able to see that they are playing dice. This project simulates the game with a protocol to ensure confidentiality, authenticity, and integrity.

## How to Run
Create a `certs/out` folder and generate ([guide](https://youngkin.github.io/post/gohttpsclientserver/)):
- client.crt, client.csr, client.key
- ExampleCA.crl, ExampleCA.crt, ExampleCA.key
- localhost.crt, localhost.csr, localhost.key

First run Bob (the server) in the main (code) directory with the command:
`go run bob/bob.go -host "localhost" -srvcert "certs/out/localhost.crt" -cacert "certs/out/ExampleCA.crt" -srvkey "certs/out/localhost.key" -port 443`

Then run Alice (the client) in the main (code) directory with the command:
`go run alice/alice.go -clientcert "certs/out/client.crt" -clientkey "certs/out/client.key" -cacert "certs/out/ExampleCA.crt"`

Note: Bob (the server) will stay open after the dice roll. To roll another dice, rerun Alice’s command.