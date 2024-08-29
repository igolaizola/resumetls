# End to end tests using OpenSSL

## Test client

Launch first the server bash script

```bash
./cmd/e2e/server.sh
```

Then launch the client go command

```bash
go run cmd/e2e/main.go client
```

You should see strawberries 🍓 and bananas 🍌 being printed on the server side.

## Test server

Launch first the server go command

```bash
go run cmd/e2e/main.go server
```

Then launch the client script

```bash
./cmd/e2e/client.sh
```

You should see strawberries 🍓 and bananas 🍌 being printed on the client side.
