## Legal

By submitting a pull request, you represent that you have the right to license
your contribution to Apple and the community, and agree by submitting the patch
that your contributions are licensed under the Apache 2.0 license (see
`LICENSE.txt`).


## How to submit a bug report

Please ensure to specify the following:

* swift-crypto commit hash
* Contextual information (e.g. what you were trying to achieve with swift-crypto)
* Simplest possible steps to reproduce
  * More complex the steps are, lower the priority will be.
  * A pull request with failing test case is preferred, but it's just fine to paste the test case into the issue description.
* Anything that might be relevant in your opinion, such as:
  * Swift version or the output of `swift --version`
  * OS version and the output of `uname -a`


### Example

```
swift-crypto commit hash: 22ec043dc9d24bb011b47ece4f9ee97ee5be2757

Context:
While using HMAC<SHA256> to verify received data I noticed that we leaked 1kB of memory per invocation.

Steps to reproduce:
1. ...
2. ...
3. ...
4. ...

$ swift --version
Swift version 5.1.2 (swift-5.1.2-RELEASE)
Target: x86_64-unknown-linux-gnu

Operating system: Ubuntu Linux 16.04 64-bit

$ uname -a
Linux beefy.machine 4.4.0-101-generic #124-Ubuntu SMP Fri Nov 10 18:29:59 UTC 2017 x86_64 x86_64 x86_64 GNU/Linux
```

## Writing a Patch

A good swift-crypto patch is:

1. Concise, and contains as few changes as needed to achieve the end result.
2. Tested, ensuring that any tests provided failed before the patch and pass after it.
3. Documented, adding API documentation as needed to cover new functions and properties.
4. Accompanied by a great commit message, using our commit message template.


## How to contribute your work

Please open a pull request at https://github.com/apple/swift-crypto. Make sure the CI passes, and then wait for code review.

## API Evolution

swift-crypto is a unique project in that it is an open-source reimplementation of APIs provided by an Apple system library. For this reason, it is intended to remain compatible with those APIs.

As a result, while we will discuss and in many cases accept additive changes to the API, these changes will potentially get handled in multiple different ways.

If an API is considered worth adding to the system CryptoKit library, we will initially merge it but not ship it in a tagged release. If it's important to use this API early, we will use a transitional namespace that is only present in the swift-crypto library to make the feature available until it can make its way into the OS proper.

Some use-cases will not meet the requirements of CryptoKit itself, but will still be useful for server use-cases. Where the swift-crypto team believe it is possible to craft good, misuse-resistant APIs for the functionality, we will consider adding these APIs under a Server namespace. This will make it clear that CryptoKit is not intending to support these use-cases, and so they will never graduate to the mainstream namespace.

Please do consider proposing new API: we'll take these on a case-by-case basis. Where we elect not to support a given primitive, we will provide a detailed rationale for why we believe it is out of scope.

### Proposing New API

When you propose new API, it would help to fill out the following template. This will allow us to get a better understanding of the scope of the proposal and the utility it provides.

#### New API Template

```
### New API Proposal: <Feature Name>

Motivation:

<What use-case is this API proposal trying to serve? Are there any protocols in existence that require this API? If so, which? Please provide links to specifications where applicable, or peer implementations when attempting to perform interop work.>

Importance:

<Does this API unlock entirely new use-cases, or is it possible to achieve the same functionality with existing API, but in easier ways?>
```

### BoringSSL Restrictions

New APIs must be able to be implemented on top of BoringSSL: that is, BoringSSL must have an implementation that we can use.


