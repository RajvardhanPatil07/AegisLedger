# Authorization safety model

`Authorization.tla` models proposal reservation, signing, submission, settlement,
revert, denial, and expiry. TLC checks three release invariants:

- signing states are unreachable without an authorization event;
- pending reservations plus settled spend never exceed the cap;
- every protected in-flight state has exactly one live reservation.

Run the pinned model checker from the repository root:

```sh
java -jar tools/tla2tools.jar -config formal/Authorization.cfg formal/Authorization.tla
```

CI downloads the official TLA+ Tools release, verifies its checksum, and runs
this command on every change to the authorization model or service.
