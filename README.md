# A.P.E. - Authorized Primate Encryption

**A.P.E.** is the central, secure secrets management and encryption service for the Monkeys news and media platform. It is the definitive source for accessing, leasing, and auditing all privileged credentials and sensitive data.

In the jungle of the internet, **trust no banana, secure every byte.**

---

## Core Features

*   **Secrets as a Service:** Dynamic, on-demand generation of database credentials, API keys, and other sensitive data for primate-powered applications.
*   **Encryption as a Service:** Centralized cryptographic functions for the platform. Encrypt, decrypt, and sign data without exposing raw keys to your application.
*   **Leasing and Revocation:** All secrets are leased with strict Time-To-Live (TTL) policies. Compromised credentials can be revoked instantly, minimizing blast radius.
*   **Privileged Access Management:** Fine-grained access control policies (e.g., ABAC - Attribute-Based Access Control) define precisely which services or users can access which secrets.
*   **Detailed Audit Logs:** A immutable record of every authentication, secret access, and management operation, providing a clear trail of who accessed what and when.

## Quick Start

### 1. Authenticate with A.P.E.
A.P.E. provides multiple auth methods. For machines, we recommend the AppRole method.

```bash
# Authenticate and receive a client token
$ curl --request POST \
       --data '{"role_id": "your_role_id", "secret_id": "your_secret_id"}' \
       https://ape.service.simiansphere.io/v1/auth/approle/login
```

### 2. Request a Secret
Use the obtained client token to request a secret from a defined path.

```bash
# Retrieve database credentials for the 'blog-posts' service
$ curl --header "X-Ape-Token: <your_client_token>" \
       https://ape.service.simiansphere.io/v1/secret/data/blog-posts/db-creds
```

### 3. Use the Secret
The response will be a JSON object containing the leased credentials.

```json
{
  "data": {
    "data": {
      "username": "blog-posts-user-aj83nFx0",
      "password": "dg0sDf8sdl23...",
      "lease_duration": 3600
    }
  }
}
```

## Why A.P.E.?

Before A.P.E., secrets were scattered like bananas across the platform—in config files, environment variables, and other insecure locations. **A.P.E. provides a single, secure, and auditable source of truth for all secrets**, ensuring that our primate bloggers can focus on their content without worrying about the security of their data.

## Philosophy

Our security philosophy is simple: **Secrets should be ephemeral, access should be minimal, and every action should be logged.** A.P.E. is built to enforce this by default.

## Documentation

For full documentation, including advanced topics like policy creation, encryption key rotation, and disaster recovery, please visit the [**Official A.P.E. Manual**](https://docs.simiansphere.io/ape).

## License

A.P.E. is released under the **Primate Public License**. See the `LICENSE` file for details.

> **Warning:** This is a critical security service. Misconfiguration can lead to significant platform instability or security breaches. Access is strictly limited to the **Orangutan Operations Team**.