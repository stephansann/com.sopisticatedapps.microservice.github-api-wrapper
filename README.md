# GitHub API Wrapper

Attention:
This Microservice application is glued together in a hurry, has a bad exception handling, a questionable design and is not tested well.
As such it should not be used by anybody.

However, it seems to work. So if you are okay with the things that were said before, here is how it works.

The following examples are using the repository "Document-Archiver/com.sophisticatedapps.archiving.document-archiver".
The name of the repository has to be URL-encoded, so "Document-Archiver%2Fcom.sophisticatedapps.archiving.document-archiver".

If your repository is "Foo/com.bar.magic", use "Foo%2Fcom.bar.magic" within the URL.

### latestReleaseTag

Will return the tag of the latest release.

Request
```
http://hostname:8082/githubApiWrapper/Document-Archiver%2Fcom.sophisticatedapps.archiving.document-archiver/latestReleaseTag
```

Response
```
v2.1.0
```

### latestReleaseAssetDownloadUrl

Will return the download URL of an asset of the latest release. If no recognizer is given, the first URL found.

Request
```
http://hostname:8082/githubApiWrapper/Document-Archiver%2Fcom.sophisticatedapps.archiving.document-archiver/latestReleaseAssetDownloadUrl
```

Response
```
https://github.com/Document-Archiver/com.sophisticatedapps.archiving.document-archiver/releases/download/v2.1.0/DocumentArchiver_macos_2_1_0.dmg
```

If a recognizer is given, it will be checked against the download link. For example use "unix" to find the Unix download.

Request
```
http://hostname:8082/githubApiWrapper/Document-Archiver%2Fcom.sophisticatedapps.archiving.document-archiver/latestReleaseAssetDownloadUrl?aRecognizer=unix
```

Response
```
https://github.com/Document-Archiver/com.sophisticatedapps.archiving.document-archiver/releases/download/v2.1.0/DocumentArchiver_unix_2_1_0.sh
```

# How to build it

```
git clone https://github.com/stephansann/com.sopisticatedapps.microservice.github-api-wrapper.git

cd com.sopisticatedapps.microservice.github-api-wrapper

[optional: change port to desired value in src/main/resources/application.yml]

gradle assemble

cd build/libs
```
**Startup (example - version will vary)**

```
java -jar github-api-wrapper-0.1-all.jar
```
