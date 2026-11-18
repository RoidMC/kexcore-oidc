# How to contribute to the KexCore OIDC SDK for Go

## Did you find a bug?

Please file an issue [here](https://github.com/RoidMC/kexcore-oidc/issues/new/choose).

Bugs are triaged as soon as possible.

## Enhancement

Do you miss a feature? Please file an issue [here](https://github.com/RoidMC/kexcore-oidc/issues/new/choose).

Enhancements are discussed and evaluated in the issue tracker.

## Grab an Issue

We add the label "good first issue" for problems we think are a good starting point to contribute to the OIDC SDK.

* [Issues for first time contributors](https://github.com/RoidMC/kexcore-oidc/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22)
* [All issues](https://github.com/RoidMC/kexcore-oidc/issues)

## Submitting a pull request (PR)

If you like to contribute, fork the KexCore OIDC repository. After you implemented the new feature create a Pull Request in the repository.

Make sure you use [semantic release messages format](https://github.com/angular/angular.js/blob/master/DEVELOPERS.md#type).

`<type>(<scope>): <short summary>`

### Type

Allowed values are listed in [`.github/semantic.yml`](.github/semantic.yml) under `types:`.

### Scope

This is optional to indicate which component is affected.
Allowed values are listed in [`.github/semantic.yml`](.github/semantic.yml) under `scopes:`.
When in doubt, omit the scope — `<type>: <short summary>` is always valid.

#### Short summary

Provide a brief description of the change.

## Want to use the library?

Checkout the [examples folder](example) for different client and server implementations.

The SDK powers the [KexCore](https://github.com/RoidMC/KexCore) IAM backend.

## **Did you find a security flaw?**

* Please read [Security Policy](SECURITY.md).
