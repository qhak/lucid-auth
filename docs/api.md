# REST API

All timestamps are Unix milliseconds. Requests with a body use `Content-Type: application/json`. Browser mutations require the canonical `Origin` header and use same-origin credentials. A JSON failure has this structure:

```json
{
  "error": { "code": "AUTH_REQUIRED", "message": "Sign in to continue." }
}
```

Use the status and machine-readable code. Common statuses include 400 for invalid input, 401 for failed sign-in or expired access, 403 for invalid origins or permissions, 404 for absent or inaccessible tenant resources, 409 for conflicting state, 413 for oversized input, and 429 with `Retry-After` for rate limits.

## Authentication and account

| Method and path                    | Request and response                                                                              |
| ---------------------------------- | ------------------------------------------------------------------------------------------------- |
| `GET /api/settings`                | Enabled provider and email flags.                                                                 |
| `POST /api/auth/register`          | `{ email, password }`. Returns 202 for accepted requests.                                         |
| `POST /api/auth/verify`            | `{ token }` from the original browser's email verification link.                                  |
| `POST /api/auth/login`             | `{ email, password }`. Sets access and refresh cookies.                                           |
| `POST /api/auth/forgot-password`   | `{ email }`. Returns 202 for accepted requests.                                                   |
| `POST /api/auth/reset-password`    | `{ token, password }`. Revokes sessions and passkeys for the recovered account.                   |
| `GET /api/session`                 | `{ user: { id, email }, session: { id, expiresAt } }`.                                            |
| `POST /api/auth/refresh`           | Rotates both cookies. Coordinate concurrent refreshes and retry the original protected call once. |
| `POST /api/auth/logout`            | Revokes the current browser session and clears both cookies.                                      |
| `POST /api/auth/logout-all`        | Revokes all sessions for the authenticated account.                                               |
| `GET /api/account/sessions`        | `{ items: [{ id, createdAt, expiresAt }] }`; expiry here is the refresh deadline.                 |
| `DELETE /api/account/sessions/:id` | Revokes one of the authenticated account's sessions.                                              |
| `GET /api/account/passkeys`        | `{ items: [{ id, createdAt }] }` for the current account.                                         |
| `DELETE /api/account/passkeys/:id` | Removes an owned passkey after a recent sign-in.                                                  |
| `DELETE /api/account`              | `{ confirm: true }`. Transfer ownership first if you are the sole owner of an organization.       |

Successful mutations use `{ ok: true }` unless otherwise listed. Verification, reset, and WebAuthn tokens are one-use. For auth recovery and sign-in examples, see [sdk/index.ts](../sdk/index.ts).

### Google and passkeys

Start Google sign-in with `POST /api/auth/google/start` and navigate to the returned `{ url }`. Google redirects to `GET /api/auth/google/callback`, which navigates back to the console. The flow cookie must remain available across redirects.

Passkey ceremonies use `POST /api/auth/passkeys/{register,login}/options` and return `{ id, options }`. Pass `options` to `startRegistration` or `startAuthentication` from `@simplewebauthn/browser`. Post `{ id, response }` to the corresponding `/verify` endpoint. Enrollment needs a verified session created in the past 15 minutes. Both ceremonies require authenticator user verification and support discoverable credentials.

## Organizations

| Method and path                                 | Request and response                                                     |
| ----------------------------------------------- | ------------------------------------------------------------------------ |
| `GET /api/orgs`                                 | `{ items: [{ id, name, role }] }` for the caller.                        |
| `POST /api/orgs`                                | `{ name }`. Returns 201 and `{ id }`; the caller becomes owner.          |
| `PATCH /api/orgs/:org`                          | `{ name }`.                                                              |
| `GET /api/orgs/:org/permissions`                | `{ permissions: string[] }` for the caller's current role.               |
| `GET /api/orgs/:org/overview`                   | `{ users, sessions, events, teams }` counts.                             |
| `GET /api/orgs/:org/members`                    | `{ items: [{ id, email, role }], total }`.                               |
| `PUT /api/orgs/:org/members`                    | `{ email, role }`. Adds an existing verified user or changes their role. |
| `DELETE /api/orgs/:org/members/:id`             | Revokes membership and removes corresponding team entries.               |
| `GET /api/orgs/:org/sessions`                   | `{ items: [{ id, email, createdAt, expiresAt }], total }`.               |
| `DELETE /api/orgs/:org/sessions/:id`            | Revokes the session's access to this organization.                       |
| `GET /api/orgs/:org/events`                     | `{ items: [{ id, action, actorEmail, subject, createdAt }], total }`.    |
| `GET /api/orgs/:org/teams`                      | `{ items: [{ id, name }], total }`.                                      |
| `POST /api/orgs/:org/teams`                     | `{ name }`. Returns 201 and `{ id }`.                                    |
| `DELETE /api/orgs/:org/teams/:id`               | Deletes the scoped team and its roster.                                  |
| `GET /api/orgs/:org/teams/:id/members`          | `{ items: [{ id, email, role }] }`.                                      |
| `PUT /api/orgs/:org/teams/:id/members`          | `{ email }` of an existing organization member.                          |
| `DELETE /api/orgs/:org/teams/:id/members/:user` | Removes a member from the scoped team.                                   |

Lists with a `total` accept `page` (1-based, 20 items per page) and `q` (literal substring). Events accept `kind=auth` or `kind=audit`. Tenant identifiers select a resource. The server independently derives the caller from the session and checks their current membership and grants.
