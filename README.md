# ActionGate

ActionGate is a small, reviewable prototype of an authorization gateway for AI agent actions. Every proposal is evaluated against explicit policy before the demo can simulate its execution. A decision is **allowed**, **blocked**, or **held for approval**.

> **Prototype only.** Execution is simulated and no external system is contacted. The demo actor selector and `x-actiongate-actor-id` header are not authentication. Do not use this project to authorize production actions or submit real customer data.

## What it demonstrates

- Unknown agents, unrecognized action types, missing impact details, and disallowed arguments fail closed.
- Per-agent permissions and action-specific impact limits determine the policy decision.
- The advisory signal can only raise an otherwise allowed request to review; it cannot grant permission or clear an explicit policy hold.
- Approvals bind to the complete canonical action using SHA-256. A changed proposal needs a new decision, and requesters cannot approve their own proposals.
- Decisions and refusals are stored in a SHA-256 hash-linked JSONL ledger, with a verifier that compares the chain and request snapshots.
- The demo works with the advisory unavailable or unusable and records the decision path used.

## Run locally

Requirements: Node.js 20 or newer. The project has no third-party runtime dependencies.

~~~powershell
cd D:\dmnan\Desktop\Coding\projects\actiongate
Copy-Item .env.example .env
npm start
~~~

Open [http://127.0.0.1:3000](http://127.0.0.1:3000). The app stores its demo state in `data/state.json` and the event history in `data/audit.jsonl`. Both files are ignored by Git. Choose the advisory path in the interface to explore unavailable, unusable, and simulated advisory outcomes.

The API uses `x-actiongate-actor-id` to demonstrate requester/reviewer separation. This header is intentionally unauthenticated and must never be trusted outside this local demo.

## API overview

- `GET /api/status` — runtime mode, policy version, and ledger integrity
- `GET /api/policies` — registered demo agents and explicit policy limits
- `GET /api/actions` — current demo action requests
- `POST /api/actions` — evaluate and record a proposal
- `POST /api/actions/:id/approve` — approve a held request using `{ "actionHash": "…" }`
- `POST /api/actions/:id/revise` — revise and reauthorize a request
- `POST /api/actions/:id/block` — record a reviewer block
- `POST /api/actions/:id/execute` — simulate an execution using the current `{ "actionHash": "…" }`
- `GET /api/audit` and `POST /api/audit/verify` — inspect and verify the hash chain

All execution endpoints are simulations. There are no integrations to payment, email, CRM, or other external systems.

## Decision rules in the demo

| Action | Automatic threshold | Hard limit | Additional review |
| --- | ---: | ---: | --- |
| Delete records | 10 records | 250 records | Bulk or irreversible deletion |
| Send message | 20 recipients | 5,000 recipients | External, bulk, or irreversible message |
| Update account | Registered fields only | N/A | Irreversible update |
| Issue refund | USD 500.00 | USD 5,000.00 | Higher-value or irreversible refund |

Policy and agent permissions live in `src/policy.js`. These demonstration thresholds are not a recommended production policy.

## Deployment

`vercel.json` serves the static dashboard from `public/`. A static Vercel deployment runs the **browser-local demo**: it stores requests in that browser's local storage and does not host the Node API or its hash-linked JSONL ledger. Deploying it does not create a production authorization service. For durable hosted use, this prototype needs authenticated identities, protected persistence, and a server-side execution adapter designed for the target systems.

The local Node server serves both the dashboard and demo API. Vercel's static deployment is only for sharing the interface and browser simulation.

## Repository checks

GitHub Actions runs `npm run check` on pushes and pull requests. This checks JavaScript syntax; it is not a security certification or production readiness review.

## Security

Read [SECURITY.md](SECURITY.md) before using or reporting an issue. The intended use is educational demonstration and design discussion.
