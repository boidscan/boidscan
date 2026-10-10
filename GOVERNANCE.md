# Governance

Draft. Most of what this page describes is not built yet. Until it is, boidscan runs only in closed test flocks, and no public seed is published.

Boidscan has no master server, and anyone can run a boid. Those are good properties for a volunteer project. They would also make a misused network hard to stop. This page describes how the flock stays accountable.

## What governance can and cannot do

Boidscan is free software. Anyone can fork it, remove every rule on this page and run their own network. Governance cannot prevent that, and tools such as ZMap already let a single host scan the whole internet.

What governance does:

- It keeps *this* flock from being used for anything other than building a public index.
- It lets the community pause the flock, reject a misbehaving boid or retire a broken release.
- It makes the flock stop on its own if nobody looks after it any more.

## The protocol only knows one kind of work

Boids never send each other commands, probes, payloads or scan rates. A unit of work is a block of addresses plus a group of ports, taken from a fixed catalog of ports and handshake modules. Every boid in the flock uses the same catalog.

Requests from users do not create new kinds of scans. If a user asks for an address that has no recent data, the flock scans that block sooner than it otherwise would, with the usual ports and modules. Each block can be moved up the queue only so often, and every such request is logged publicly.

No boid scans a block more often than the flock policy allows, whoever asks.

## The flock policy

The rules that apply to the whole flock are in a short document, the flock policy. It sets:

- whether the flock is paused
- the oldest boidscan version allowed to scan
- the highest scan rate (a boid may always scan slower)
- how often a block may be scanned
- the port and module catalog
- the boids that are no longer part of the flock
- the seeds new boids use to find the flock
- the maintainers and how many of them must sign

Maintainers sign the policy with their own keys, offline. A policy is valid only with enough signatures. Every boid passes the policy on to its peers, and no boid can forge it. A copy that arrived through gossip, a web page or DNS is as good as one from the project.

**Every policy expires**, 14 days after it is signed. A boid with no valid policy stops scanning and keeps serving the data it has. If the maintainers disappear, the flock winds down instead of running on without anyone responsible.

Maintainers set rules. They do not decide who scans what. Scanning work is still shared out between the boids with no one in charge.

## How decisions are made

- Policy changes are proposed as pull requests to the `boidscan/flock-policy` repository, so every change and its reasons are public.
- A change is merged after a review period of at least 7 days, then signed by enough maintainers.
- In an emergency, a single maintainer may sign a pause. It lasts 48 hours at most, unless enough maintainers sign a policy that confirms it.
- GitHub is where proposals are discussed and decisions recorded. Signatures are what make a policy valid, so a compromised GitHub account cannot change the policy.

## Maintainers

The project starts with one maintainer, the project's founder, and one signature is enough. That will change to three signatures out of five maintainers once five people are willing to take the role.

New maintainers are proposed by pull request to this file and accepted with the same number of signatures as a policy change. A maintainer who has been inactive for 6 months, or who asks to step down, is removed the same way.

Maintainer keys are listed in the flock policy. The first set is built into boidscan. Any later set must be signed by the set before it.

## Removing a boid from the flock

A boid can be removed when its operator:

- ignores the rate limit or the catalog
- reports results it did not observe
- does not answer abuse reports sent to its contact address
- scans from addresses other than the ones it lists

A removal starts as a public issue with evidence. The operator gets 7 days to respond, except in an emergency. Once a policy with the boid's key on the removed list is signed, the other boids stop working with it and drop the data it reported that nobody else has confirmed.

Removed boids keep their entry in a public list, so that people can still block them in their firewalls.

## Reporting abuse

Every boid names an abuse contact in its scans and on its info page. Write to that contact first. If the operator does not answer, or you think the flock itself is misused, open an issue in `boidscan/flock-policy`.
