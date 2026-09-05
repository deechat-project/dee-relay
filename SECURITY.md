# Reporting a security issue

Use this repository's **Security** tab → *Report a vulnerability*. That opens a
thread only you and the maintainers can read. Please do not open a public issue
for anything that would let someone read, forge or destroy a user's mail.

There is deliberately no email address here. This project has no domain, and an
address that bounces is worse than no address at all.

Include the commit you were looking at, what you did, and what happened. A
proof-of-concept is welcome but never required — a clear description of the flaw
is enough to act on. You will get a first reply within 5 working days, and we
will say what we found and when a fix lands rather than going quiet.

## What is in scope

This repository is the relay: a stateless Go service that holds opaque encrypted
envelopes, ack records and attachment chunks in RAM and hands them to whoever can
prove they own the queue. The interesting questions here are therefore:

- **Reading someone else's queue.** `GET /messages` and `GET /acks` serve a record
  only to a caller who proves ownership of the tag it carries. Anything that gets
  a record out without that proof, or that turns the endpoint into an oracle for
  *whether* a queue exists, is a finding.
- **Writing into someone else's queue.** The same proof gates the writes: an ack
  is proved against the acked message's tag, because five of the six ack types
  delete the message they name, and a prekey pool is keyed by its owner's tag
  rather than by a routing id, so it can only be filled or asked after by its
  owner. Anything that deletes a queued message, fills a pool, or learns what a
  pool holds without the secret behind that tag is a finding.
- **The mesh.** `/mesh/*` must never be reachable from the public listener, and
  the pool secret must never be inferable from a public response.
- **Admission.** Redeeming a credential you were not issued, extending a window,
  or getting service from an enforcing relay without a valid code.
- **Durable state.** The relay claims to keep nothing across a restart; anything
  that writes envelope content, tags or keys to disk contradicts the claim the
  `internal/audit` tests exist to enforce.
- **Resource exhaustion** that a documented cap should have bounded — a body, a
  queue, an attachment reservation or a peer set that grows past its configured
  ceiling.

## What is out of scope

- **The client applications.** They are a separate, proprietary repository. Report
  client-side findings through the same Security tab, but nothing in this repo
  will show you the code.
- **A relay operator seeing their own traffic.** The relay is designed to be
  untrusted: it sees ciphertext, routing tags, sizes and timing, and this is
  documented rather than defended against. That the operator can count your
  envelopes is the threat model, not a break of it.
- **Claims about a *running* host.** A digest in `deploy/FINGERPRINTS.md` attests
  to an artifact, never to the process a given relay is running. "Relay X might
  not be running this code" is true by construction and stated in the README.
- Missing hardening headers, TLS configuration or rate limits on a deployment you
  do not operate — those are that operator's proxy, not this source.

## Known, and already stated

Reporting these is not wasted effort, but you will get back a pointer to this
list rather than news:

- **An ack for a message this relay never carried is stored without proof.**
  `POST /acks` is proved against the acked message's `recipientTag`, so it cannot
  delete mail; where the relay holds nothing about the message id there is no tag
  to prove and the ack is stored anyway, because refusing would break a late ack
  for a message that has already expired — and because a refusal there would be
  the existence oracle the first bullet above calls a finding. What such a caller
  occupies is a slot in the caller-posted share of the ack lane, which is capped
  at `DEE_NODE_MAX_ACKS` minus `DEE_NODE_MAX_MESSAGES` and expires within the
  retention ceiling. That is parity with what posting to a fabricated recipient
  already gets, and it is why the bound rather than the proof is the answer here.
- **A caller that proves nothing about itself shares one presence bucket with
  every other such caller.** Heartbeats are held in one global table of 5000
  records. A heartbeat may present the queue capability, and one that does gets a
  share of the table under a key nobody else can claim; a heartbeat that presents
  neither a capability nor an admission session is charged to a single shared
  bucket, so a burst of junk grant hashes can crowd out other unattributed
  callers. What it can no longer do is hold the table: once full, a slot goes to
  the record with the weakest claim on it — an offline lease first, then one held
  by a caller past its share — so a burst has to keep re-sending every record it
  holds to keep the table, and a live lease from a caller inside its share is
  never the one taken. A lease whose five-minute window has passed can be, by
  anybody: it is kept for the *last seen* answer, and that is what it is worth
  against a caller with none. No mail is affected either way.

## Before you report

Two commands answer a good share of "is this real":

```bash
go test ./...                # the behaviour, including the auth and cap tests
go test ./internal/audit     # the no-durable-state and exposure audits
```

If one of those fails on unmodified `main`, that alone is worth reporting.
