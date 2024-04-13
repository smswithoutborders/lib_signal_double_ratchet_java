# SMSWithoutBorders LibSignal DoubleRatchet

## Maven Release

- https://central.sonatype.org/publish/publish-gradle/#javadoc-and-sources-attachmentso
 
- https://docs.gradle.org/current/userguide/signing_plugin.html

### Sign
```bash
gpg --list-secret-keys --keyid-format SHORT
```

```bash
./gradlew signReleasePublication
```

### Publish
```bash
./gradlew publish
```