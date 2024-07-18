# resumetls

Resumable TLS client connection without doing any additional handshake operations, implemented in golang

## Details
- `Client` stores some handshake data and TLS inner sequential numbers
- `State` object needed for resume a connection is public and serializable

## Usage
```
// Start a new TLS client
cli := resumetls.Client(conn, &tls.Config{}, nil)
cli.Handshake()

// Perform multiple cli.Read and cli.Write here
...

// Get State whenever we want to pause the client
state := cli.State()

// Resume client using previously obtained state
cli2 := resumetls.Client(conn, &tls.Config{}, state)

// Continue with cli2.Read and cli2.Write here
...

```
