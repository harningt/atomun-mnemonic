# atomun-mnemonic

[![License](http://img.shields.io/badge/license-Apache_2-red.svg)][Apache2.0]

[![Build Status](https://travis-ci.org/harningt/atomun-mnemonic.svg?branch=develop)](https://travis-ci.org/harningt/atomun-mnemonic)

Enter Atomun - the Java Bitcoin utility library collection.

This library implements Mnemonic transformations to address human data
backup / transfer using word sequences.

## Versioning

This library will follow the guidelines set forth in [Semantic Versioning 2.0][SemVer2.0]

Public APIs not marked with @Beta are considered under the purview of the versioning rules.

@Beta items follow the attached documentation to the annotation, shortly put:

> Do not rely on this to exist in the future as it is not "API-frozen".
> It may change functionality or be removed in any future release.

## License

This library is covered under the [Apache 2.0 license][Apache2.0] as indicated in the LICENSE file.

## Repository Details

The repository is managed using the Gitflow workflow. Note that any published
feature/* branches are subject to history modification, so beware working
off of those.

Non-annotated tags will be added in the form vMAJOR.MINOR.MICRO-dev to denote the
start of a new feature. This will guide the next release to be versioned as
vMAJOR.MINOR.MICRO. Without this, the next expected version would be a MICRO-change.

Signed and annotated tags will be added in the form vMAJOR.MINOR.MICRO to denote
releases.

## Maven Artifacts

Maven Group ID: us.eharning.atomun
Name: atomun-mnemonic

Unsigned SNAPSHOT artifacts are pushed per-commit by Travis-CI to oss.jfrog.org's
SNAPSHOT archive.

<http://oss.jfrog.org/artifactory/simple/oss-snapshot-local/>

Signed release artifacts will be pushed to oss.jfrog.org's release archive and
synced to Maven Central ASAP.

<http://oss.jfrog.org/artifactory/simple/oss-release-local/>

The project will also have a present at:

<https://bintray.com/harningt/atomun>

## Release Signing

Releases will be signed by the following privately held GPG key. It doesn't
get published to Travis-CI, nor Bintray.

    pub   2048R/F8908096 2014-10-29 [expires: 2016-10-28]
          Key fingerprint = B6CC 560D F1C0 991E 08AA  555A ED63 F369 F890 8096
    uid                  Thomas Harning Jr (CODE SIGNING KEY) <harningt@gmail.com>

See also <http://www.eharning.us/gpg/>

## Tag Signing

Tags will be signed by the following privately held hardware-based GPG key.

    pub   3072R/B1DBAD54 2011-04-19
          Key fingerprint = 2F0A FF2E A8A0 1485 C95B  8650 F0A4 C0F7 B1DB AD54
    uid                  Thomas Harning Jr <harningt@gmail.com>

# Algorithms

## Legacy Electrum

This library implements the "Legacy Electrum" algorithm from Electrum, prior to
the newer BIP0039-derived algorithm in use. It uses a dictionary of 1625 words
to create a mnemonic strictly derived from the indices in the sorted dictionary.

## BIP0039

Based on the draft [BIP](BIP0039Spec) with English and Japanese dictionaries
along with the relevant unit tests for each.

## Dependencies
### Build

 * Gradle

### Runtime

 * Guava 18.0

### Test

 * Spock Framework

# Acknowledgements

Thanks to the Electrum team for preparing the [original implementation][LegacyElectrumImplementation]
that I used the algorithm and dictionary from.

Thanks to the Trezor team for preparing the baseline (python implementation of BIP0039)[PythonBIP0039]
and maintaining test cases.

Thanks to the BitcoinJ team for preparing an implementation of (BIP0039)[BitcoinJBIP0039]
that I used for inspiration.

## Other Builds

| Wercker | Shippable |
|---------|-----------|
| [![wercker status](https://app.wercker.com/status/258a1e486d24bacab7d80220616b4212/m "wercker status")](https://app.wercker.com/project/bykey/258a1e486d24bacab7d80220616b4212) | [![Build Status](https://api.shippable.com/projects/5445e7fcb904a4b21567c19b/badge?branchName=develop)](https://app.shippable.com/projects/5445e7fcb904a4b21567c19b/builds/latest) |

[Apache2.0]: http://www.apache.org/licenses/LICENSE-2.0
[SemVer2.0]: http://semver.org/spec/v2.0.0.html
[LegacyElectrumImplementation]: https://github.com/spesmilo/electrum/blob/4dcdcbc068d0d42ac7edc27c7d618b53cb6f706d/lib/old_mnemonic.py
[BIP0039Spec]: https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki
[PythonBIP0039]: https://github.com/trezor/python-mnemonic
[BitcoinJBIP0039]: https://code.google.com/p/bitcoinj/source/browse/core/src/main/java/com/google/bitcoin/crypto/MnemonicCode.java
