# enterprise

Enterprise features — SSO, SAML, SCIM, white-labeling, audit logs.

## Overview

The `enterprise` crate provides premium enterprise capabilities for ApexMail. It implements Single Sign-On via SAML and OIDC, SCIM-based user provisioning, white-label branding customization, and comprehensive audit logging to meet the security and compliance needs of large organizations.

## Usage

This crate is an internal workspace member of the ApexMail mail-server. Add it as a dependency:

```toml
enterprise = { path = "../enterprise" }
```

## Development

```sh
cargo test -p enterprise
cargo clippy -p enterprise
```
