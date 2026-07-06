# Aegis Documentation

This folder contains documentation assets for the Aegis Provenance Proxy.

- `aegis-architecture.svg`: architecture diagram showing the request flow through Aegis.

## Architecture

Aegis builds a safer LLM request pipeline by:

1. Ingesting spans and signing them with Ed25519.
2. Marking untrusted content as inert and wrapping it in explicit framing.
3. Calling the model with the assembled context.
4. Running deterministic attribution checks on any tool call.
5. Persisting a hash-linked receipt trail for audit.

The diagram shows how the application, ingest, assembly, model, attribution, and receipt store interact.
