# xades-bas-signer

XAdES-BES signer for Node/TypeScript — utilities to load certificates and create XAdES-BES XML signatures.

A compact TypeScript library that helps you manage certificate files (P12) and produce the canonical building blocks needed for XAdES-BES signatures in Node.js applications.

## Features

- Load and manage certificate files using a [FileManager](src/libs/files.ts#L3).
- Convert hex, bigint, and SHA-1 digests to Base64.
- Utilities for deterministic formatting of Base64 output.
- Test suite with example environment-driven cert path to validate file handling.

## Quick Start

- Prerequisites: Node.js >= 16 (as declared in package.json), npm install.
- Set up:
  - Create a .env file in Create a `.env` in repository root with:
    - [CERT_PATH=./credentials/your-cert.p12](./test/libs/files.test.ts#L8)
    - [CERT_KEY=certificate-key](./test/libs/credentials.test.ts#L16)
- Install:

```sh
npm install
```

- Run tests:

````ssh
npm test

````
## Licence
MIT (see [LICENSE](./LICENSE)).
