# FlyMe Server

This is the server component of the FlyMe secure IPC system. It is designed to run as a privileged process (e.g., as `root`) and expose a limited, secure API to unprivileged clients.

## Functionality

-   **Listens on a Local Socket**: Creates a namespaced local socket for IPC, avoiding TCP/IP networking for better security and performance.
-   **Enforces Mutual TLS (mTLS)**:
    -   Presents its own server certificate for clients to verify.
    -   Requires every connecting client to present a client certificate.
    -   Verifies that the client's certificate is signed by the trusted root CA (`certs/root-ca.pem`).
-   **Asynchronous Connection Handling**: Spawns a new thread for each incoming connection to handle multiple clients concurrently.
-   **Command Processing**: Deserializes `IpcMessage` objects from clients, processes requests like `status`, `list`, etc., and sends back a serialized response.

## Security Considerations

-   **Run as Root**: This server is intended to run with elevated privileges to perform system-level tasks that unprivileged clients cannot. The code includes a check to warn the user if it's not run as root.
-   **Certificate Paths**: The paths to the TLS certificates are currently hardcoded. In a production system, these should be configurable and stored in a secure location (e.g., `/etc/flyme/certs`).

## How to Run

1.  **Prerequisites**: Ensure the required certificates (`server.pem`, `server.key.pem`, `root-ca.pem`) are present in the `certs/` directory at the project root.

2.  **Start the Server**:
    ```sh
    # Use sudo to run with root privileges
    sudo cargo run --bin server
    ```

3.  **Logging**: The log level can be adjusted with the `--log-level` flag.
    ```sh
    # For more detailed output:
    sudo cargo run --bin server -- --log-level debug
    ```

When running, the server will log that it is listening for connections. It will also log details for each client connection, including the TLS handshake, received messages, and any errors.
