# atomun-mnemonic

[![License](http://img.shields.io/badge/license-Apache_2-red.svg)][Apache2.0]

[![Build Status](https://travis-ci.org/harningt/atomun-mnemonic.svg?branch=develop)](https://travis-ci.org/harningt/atomun-mnemonic)

Enter Atomun - the Java Bitcoin utility library collection.

This library implements Mnemonic transformations to address human data
backup / transfer using word sequences.

## Versioning

This library will follow the guidelines set forth in [Semantic Versioning 2.0][SemVer2.0]

## License

This library is covered under the [Apache 2.0 license][Apache2.0] as indicated in the LICENSE file.

## Repository Details

The repository is managed using the Gitflow workflow. Note that any published
feature/* branches are subject to history modification, so beware working
off of those.

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

## Dependencies
### Build

 * Gradle

### Runtime

 * Guava 18.0

### Test

 * Spock Framework

## Other Builds

| Wercker | Shippable |
|---------|-----------|
| [![wercker status](https://app.wercker.com/status/258a1e486d24bacab7d80220616b4212/m "wercker status")](https://app.wercker.com/project/bykey/258a1e486d24bacab7d80220616b4212) | [![Build Status](https://api.shippable.com/projects/5445e7fcb904a4b21567c19b/badge?branchName=develop)](https://app.shippable.com/projects/5445e7fcb904a4b21567c19b/builds/latest) |

[Apache2.0]: http://www.apache.org/licenses/LICENSE-2.0
[SemVer2.0]: http://semver.org/spec/v2.0.0.html
