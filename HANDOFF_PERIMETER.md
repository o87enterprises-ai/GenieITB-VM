# HANDOFF — "Repels-from-Outside" VM (perimeter + anti-lateral-movement)

**Purpose.** This is the design brief and action plan for the *next* build:
a VM that protects a **trusted** workload (an agent, a compute job, a service)
from (1) an **external network attacker** and (2) **lateral movement from a
compromised peer agent**. It reuses the engine you have already proven; it
does not start over.

Read this with the honest framing up front: you are building a layer that
**bounds, mediates, and records** what can reach the workload and what the
workload can do. You are not building something that prevents all intrusion.
A hypervisor/kernel 0-day, or abuse of a channel you explicitly allowed,
still gets through. Everything below is scoped to that truth.

---

## 1. Current project state (what you already have)

| Asset | What it gives you | Reuse for the new build |
|---|---|---|
| **MonkeyITM-VM** (`broker`) | "No ambient authority": the broker holds the keys, **decides** every action, **performs** it, and **records** every intent. Halts attacks **from the inside** well today (your words). | This is the core. The new build applies the same thesis to the **network boundary** and the **inter-agent** channel instead of to syscalls. |
| **GenieITB-VM SS1** (this repo) | Firecracker microVM harness; kernel-enforced Landlock + seccomp; vsock control channel; hash-chained receipts + `broker verify`; a tripwire/kill-switch; a reproducible boot/test loop. Post-review it also denies `AF_UNIX`/`io_uring` and fails closed on truncated receipts. | The **enclosure + control plane + audit + kill-switch** are all directly reusable. The vsock pattern (control on vsock, deny-by-default, receipt every line) is exactly the pattern for the new control plane. |
| **Hash-chain receipts** | Tamper-evident record of every allow/deny; `broker verify` rejects any edit/reorder. | Becomes the audit trail for every **ingress** and **egress** decision. |

**The gap (what none of it does yet):** there is no inbound mediation, no
network policy, no egress/exfil control, and no enforced isolation *between*
agents. SS1's threat model is "untrusted code inside the box"; your new goal
is "trusted workload, hostile things coming at it." Same engine, opposite
orientation.

---

## 2. Target architecture

**One principle, applied at the boundary:** *the workload has no ambient
network authority and no direct path to its peers. A broker mediates every
packet in and out and every inter-agent call, denies by default, records
every attempt, and trips a kill-switch on anomaly.*

```
            EXTERNAL NETWORK (hostile)
                     │
          ┌──────────▼───────────┐
          │  INGRESS BROKER       │  default-deny; schema-validate;
          │  (host-side proxy)    │  record every inbound attempt
          └──────────┬───────────┘
                     │ vsock / single mediated tap
   ┌─────────────────▼──────────────────┐
   │  PROTECTED VM (trusted workload)     │   NO direct NIC.
   │   agent / compute / service          │   NO ambient egress.
   └─────────────────┬──────────────────┘
                     │ all egress via broker
          ┌──────────▼───────────┐
          │  EGRESS BROKER        │  allowlist destinations only;
          │  (host-side proxy)    │  deny+record exfil attempts
          └──────────┬───────────┘
                     │
            ALLOWLISTED DESTINATIONS

   Peer agents reach each other ONLY through the broker
   (no shared fs, no direct socket) — lateral movement must
   cross a default-deny, fully-recorded boundary.
```

### Layers
1. **Network boundary (perimeter — threat 1).** The protected VM gets **no
   direct NIC**. All traffic traverses a host-side broker/proxy that owns the
   tap device and enforces policy. Default-deny **ingress** (only expected,
   validated inbound reaches the workload) and default-deny **egress** (the
   workload can only talk to allowlisted destinations). Every packet/flow
   decision is a receipt line.
2. **Inter-agent isolation (threat 2).** One microVM (or at minimum one
   distinct UID + Landlock domain) **per agent**. No shared writable
   filesystem. No direct agent-to-agent socket. Agent A can only reach Agent
   B through the broker, which denies by default and records — so a
   compromised A cannot silently pivot to B.
3. **Ingress inspection.** Inbound is schema/policy-validated *before* it
   reaches the workload; malformed or unexpected input → deny + receipt. The
   workload never parses raw untrusted input directly. This is where you
   "repel" the external chain's first stage.
4. **Egress / exfil control.** This is where you actually stop the *pivot and
   exfiltrate* step of an attack chain. Allowlist outbound; anything else →
   deny + receipt + (optionally) trip.
5. **Tripwire (cross-cutting).** N denied ingress/egress attempts, or any
   lateral-movement attempt, trips the kill-switch for that workload/agent
   group — reuse SS1's tripwire logic (including the F5 positive-prefix
   counting lesson: count by allowlist of benign events, not by one prefix).
6. **Receipts + anchor.** Every ingress, egress, allow, deny is hash-chained
   and `broker verify`-able. Add the out-of-band **anchor** (head hash + row
   count written somewhere the VM can't reach) so truncation/rewrite is
   caught — this is the SS1 F8 item, and it matters more here because the
   adversary is now external and motivated to hide their tracks.

---

## 3. Action plan (phased)

Each phase names what to build, what "green" looks like, and what to reuse.
Build in order; each phase is demonstrable on its own.

### P0 — Threat model + policy schema
- Write the explicit policy: per workload, the **allowed inbound** (ports,
  message shapes) and **allowed outbound** (destinations). Deny-by-default is
  the baseline; the policy is the allowlist.
- **Green:** a single `policy.yaml` a human can read that says exactly what
  may enter and leave. Nothing runs without it.

### P1 — Network broker (the perimeter)
- Host-side proxy process owns the VM's tap device (Firecracker network
  interface). It enforces P0's ingress/egress allowlists and writes every
  decision to the chain. The VM itself has **no route** except through it.
- Reuse: the SS1 vsock listener pattern (accept → decide → record → ack/deny)
  and the receipt append path.
- **Green:** an inbound connection to a non-allowlisted port is denied and
  appears as a `DENY ingress ... ` receipt line; an allowlisted one reaches
  the workload and is recorded as `ALLOW ingress ...`.

### P2 — Inter-agent isolation
- One microVM (or distinct UID + Landlock domain) per agent; no shared
  writable mount; inter-agent calls only via the broker.
- Reuse: SS1's Firecracker boot harness and Landlock rulesets (one ruleset,
  restrict_self once — the SS1 stacking lesson).
- **Green:** agent A attempting a direct socket/fs path to agent B is denied
  and recorded; the only successful A→B path goes through the broker.

### P3 — Ingress inspection
- Schema-validate inbound before the workload sees it; reject malformed or
  oversized input (reuse the F3 truncation lesson: never forward a partial
  message as if whole; record a `TRUNCATION`/`REJECT` event instead).
- **Green:** a malformed/oversized inbound request is rejected at the broker
  with a receipt; the workload never receives it.

### P4 — Egress / exfil control
- Allowlist outbound destinations; deny + record anything else; optionally
  trip the kill-switch on repeated exfil attempts.
- **Green:** the workload attempting to reach a non-allowlisted host is denied
  and recorded; repeated attempts trip the wire.

### P5 — Tripwire + anchor
- Wire cross-boundary denial counting into the tripwire (positive-prefix
  counting, per F5). Write the anchor (head + rows) to an out-of-band store
  on every run (the F8 item) and verify against it.
- **Green:** 3 denied cross-boundary attempts halt the group; `verify`
  against the anchor rejects a truncated chain.

### P6 — Adversarial validation (control-validation tests)
- Write tests that *attempt* the thing you defend against and **assert the
  deny + receipt** — same shape as SS1's T8 probe. For example: a test that
  connects to a denied port and asserts `EACCES`/`REJECT`; a test that an
  agent's direct peer-reach is denied; a test that egress to a non-allowlisted
  host is blocked.
- **Green:** each control-validation test passes (the defense denied and
  recorded), and the chain verifies.

> Note on scope for P6: these are **validation tests of your own defenses**
> (attempt → assert denied), not attack tooling. Keep them that way — assert
> the control works; don't build working exploit chains.

---

## 4. Tips, suggestions, and pitfalls

**Do**
- **Reuse the broker and the receipt chain.** The whole thesis — no ambient
  authority, broker decides/performs/records — is already built in MonkeyITM.
  The new work is pointing it at the network/inter-agent boundary.
- **Control plane on vsock, data plane through a mediating proxy.** vsock is
  proven in SS1 and can't be reached from the external network. Keep control
  traffic there; make the data path go through the host-side broker.
- **Default-deny everywhere.** Ingress, egress, inter-agent. The policy file
  is the *only* source of "allowed." If it's not in the allowlist, it's denied
  and recorded.
- **Treat the broker as the source of truth, not the workload.** SS1's lesson:
  trust the `DENY` line the enforcer emits, not the agent's self-report. Same
  here — the broker's record is the evidence, not anything the workload says.
- **Prioritize egress control.** That's where you actually stop exfiltration
  and the "pivot outward" stage of a real chain. It's higher leverage than
  perfect ingress filtering.
- **Add the anchor early.** An external adversary is motivated to erase the
  receipt. A chain without an out-of-band anchor is a log, not evidence.

**Watch out for**
- **Ambient network leaking around the broker.** If the VM has *any* route
  that doesn't traverse the broker (a second NIC, a host bridge, DNS to the
  host resolver), the perimeter is void. Audit the VM's actual routing table.
- **Shared filesystem between agents.** A shared writable mount is a lateral
  path Landlock won't save you from if both agents can write it. One agent,
  one domain, no shared writable state.
- **Trusting inbound TLS you can't inspect.** If the broker can't see inside
  an encrypted channel, your ingress inspection is metadata-only — be honest
  about that in the policy.
- **Hypervisor/kernel trust.** Firecracker should run **behind the jailer**
  here (the SS1 F10 item you can now actually justify spending on) — an
  external-facing VMM without the jailer is a bigger risk than an
  inward-facing demo without it.
- **Receipt without an anchor** (F8), and **truncated/partial messages
  forwarded as whole** (F3) — both already cost you findings; don't repeat
  them in the new boundary code.

**Honest scope to put in front of any user (carry it verbatim like SS1's):**
> This is a defense-in-depth boundary that **reduces attack surface**,
> **mediates ingress and egress**, **contains lateral movement between
> agents**, and produces **verifiable incident records**. It does **not**
> prevent hypervisor/kernel exploits, does **not** stop abuse of channels you
> explicitly allowed, does **not** inspect traffic it cannot decrypt, and does
> **not** claim 100% anything. Claims are scoped to what the policy allows and
> the receipts prove.

---

## 5. What it will / won't protect (set expectations up front)

**Will**
- Keep inbound to the allowlisted, schema-validated set — unexpected inbound
  is denied before the workload sees it.
- Block unexpected egress — the "pivot and exfiltrate" stage of a chain is
  denied and recorded.
- Deny direct agent-to-agent lateral movement — a compromised peer can't
  silently reach another; it must cross a default-deny, recorded boundary.
- Record and trip — every decision is tamper-evident; anomalies halt the group.

**Won't**
- Stop a hypervisor/kernel/Firecracker 0-day (run behind the jailer to reduce,
  not eliminate, this).
- Stop abuse of an allowed channel (if you allow outbound to X, a compromised
  workload can still talk to X).
- Inspect traffic it can't decrypt (metadata-only on opaque TLS).
- Survive host-root compromise or a bypassed broker (the perimeter is only as
  real as the "no ambient route" invariant).

---

## 6. Where to build it

This can be a new phase in this repo or a new sibling repo (e.g.
`GenieITB-Perimeter`). Given it reuses the MonkeyITM broker and the GenieITB
harness, a sibling repo that depends on both keeps the inward (SS1) and
outward (perimeter) stories cleanly separated — recommended, but your call.

Start at **P0** (write the policy schema). Everything else hangs off it.
