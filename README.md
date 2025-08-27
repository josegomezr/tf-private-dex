TF Private Dex
==============

Minimal OpenTofu/Terraform private registry

This is not a production-ready implementation in any way, shape or form. It's designed to serve as an alternative host for hosting privately providers and/or testing your providers when hosting your providers following the "In-House" method [1] is not enough.

Uploading / Mirroring providers
----

Not supported yet. You must prepopulate the filesystem with the provider binaries compressed & signed as terraform/opentofu expects it.

Storage structure
----

Directory structure follows the Provider Registry protocol [1] structure.

```
storage/providers/%namespace%/%type%/%version%
```

And inside of each provider directory there must be the following 4 files:

```
terraform-provider-%type%_%version%_linux_amd64.zip
terraform-provider-%type%_%version%_SHA256SUMS
terraform-provider-%type%_%version%_SHA256SUMS.sig
terraform-provider-%type%_%version%_SHA256SUMS.sig.asc
```

- `terraform-provider-%type%_%version%_linux_amd64.zip` is a zip containing the provider binary, it seems that it must be named: `terraform-provider-%type%_v%version%` [notice the v before `%version%`].
- `terraform-provider-%type%_%version%_SHA256SUMS` is a `sha256sum`-compatible dump containing an entry for `terraform-provider-%type%_%version%_linux_amd64.zip`.
- `terraform-provider-%type%_%version%_SHA256SUMS.sig` is a NOT-ARMORED! gpg signature of `terraform-provider-%type%_%version%_SHA256SUMS`
- `terraform-provider-%type%_%version%_SHA256SUMS.sig.asc` is the ARMORED [yeah, I know] public key that terraform/opentofu will use to validate the signature.


Export public key
---

```
GPG_FINGERPRINT=BEEFCAFEBEEFCAFE
gpg --armor --export "$GPG_FINGERPRINT"
```

[1]: https://developer.hashicorp.com/terraform/language/providers/requirements#in-house-providers
[2]: https://opentofu.org/docs/internals/provider-registry-protocol/

TODO
====

- Better matching on tests: Status code & serialize & deserialize response structures.
- Really validate GPG public keys
- Document better how to populate it.

