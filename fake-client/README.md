# Fake Client Demo

This binary (`fake-client`) is a demonstration of a client attempting to connect to the `server` **without** the required client-side TLS certificate.

The purpose is to show that the server's security is working correctly by rejecting unauthorized clients.

## How it Works

- The `server` is configured to require and verify a client certificate, signed by its trusted root CA (`certs/root-ca.pem`).
- The real `client` and `client-lib` are configured to present a valid client certificate (`certs/client.pem`) during the TLS handshake.
- This `fake-client` intentionally does **not** configure a client certificate. It only loads the root CA to verify the server's identity.

When the `fake-client` attempts to connect, the server will request a certificate. Since the fake client cannot provide one, the server will terminate the TLS handshake, and the connection will fail.

## How to Run the Demo

1.  **Start the server** in one terminal:
    ```sh
    cargo run --bin server
    ```

2.  In a second terminal, **run the fake client**:
    ```sh
    cargo run --bin fake-client
    ```
    You will see output indicating that the connection failed, which is the expected and correct behavior.

3.  (Optional) In a third terminal, **run the real client** to confirm it can still connect successfully:
    ```sh
    cargo run --bin client ping "it works"
    ```
