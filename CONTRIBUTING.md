# Contributing

Use Java 17 or newer and the checked-in Gradle wrapper. Before opening a pull request run:

```bash
./gradlew clean test build
```

Keep the Montoya API as `compileOnly`; it must not be bundled in the release JAR. New detection
rules need tests, a concrete security rationale, bounded input handling and false-positive notes.
Network-active behavior must be off by default, visibly labelled and restricted to the user's
chosen scope. New threads/resources must be closed from the registered unload handler. Do not add
telemetry, remote code, hidden network calls or secrets to the repository.

