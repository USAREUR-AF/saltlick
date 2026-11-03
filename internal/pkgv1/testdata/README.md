# Test fixtures

`full-offer-xaa.json` is the `compose-full` conformance vector's xaa package,
copied verbatim. It carries `transport_offer`, `data_offer` and `cut`, which is
exactly why it is here: it is a real, valid, correctly signed federation package
that a directory must nonetheless refuse.

`xaa.public.b64` and `xaa.seed.hex` are the published conformance-vector test
keys. **The private seed is public on purpose**, so anyone can reproduce the
vector signatures without running anyone's code. They are worthless: a package
signed by one proves nothing about who produced it, and binding one to a real
`sovereign_id` would make that party impersonable by anyone. They are here so
that this repository's canonicalisation and signature check can be tested
against a signature produced by a different implementation.
