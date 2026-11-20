# Incognito Mode

Incognito mode hides your own names from the AI model. When it is on, the app replaces host names, IP addresses, users, custom indexes, apps, saved searches, and similar values with stand-ins such as `host_0012` before anything is sent to the AI model. When the reply comes back, the app puts the real names back, so you still see real names on screen. Splunk's own names (built-in indexes, sourcetypes, fields, and Splunk apps) stay visible because the AI model needs them to write correct SPL.

Incognito mode first shipped in release 2.2.0.

## Who it is for

- Teams that use a cloud AI model and do not want their host names, users, or network layout to leave the network
- Admins who must show that a cloud AI model never saw identifying names, with a record of exactly what was sent
- Anyone who wants to share a report or chat outside the team with names replaced

## Turning it on

Select **Incognito off** or **Incognito on** in the top bar. The popover explains the current state and has a **Hide my names from the AI model** switch.

- With sign-in on, each user has their own choice. With sign-in off, everyone shares one choice
- **Use the server default instead** clears your own choice and follows the admin's default
- When an admin requires incognito mode for cloud AI models and the AI model in use runs on a cloud service, the switch is locked on and shows a lock icon. The server refuses requests to turn it off (HTTP 409), so the lock does not depend on the browser
- While incognito mode is on, the chat composer says so, and each answer that used the AI model has a **What the AI saw** button

Background jobs (discovery and AI summaries) keep the state they started with. A discovery started in incognito mode stays masked even if someone turns incognito mode off while it runs.

## Admin settings

Admins find **Incognito Mode** on the Settings **Security** tab. These settings save on their own, separate from **Save Settings**.

| Setting | What it does |
| --- | --- |
| Require for cloud AI models | Forces incognito mode on for everyone while the AI model in use runs on a cloud service. Users cannot turn it off |
| On by default | Turns incognito mode on for anyone who has not made their own choice |
| Always replace these terms | One term per line. Project names, building names, or anything else discovery cannot find. Each gets a `term_NNNN` stand-in |
| Never replace these terms | One term per line. Names that look private but are safe to show, such as a vendor product name |
| Reset Stand-ins | Forgets every stand-in, so the AI model sees new numbers from the next request on. Records already saved keep the old stand-ins |
| Preview | Paste text to see exactly what the AI model would get with the saved settings |

The AI model counts as local when its endpoint is on this machine or a private network address, or when it is Ollama without an endpoint. Azure OpenAI, Anthropic, Gemini, Cohere, Bedrock, and Vertex always count as cloud, even through a private link. Anything the app cannot confirm as local counts as cloud, so a required policy errs toward masking.

If the saved settings cannot be read (for example, after the key file changes), incognito mode turns on by default and is required for cloud AI models until an admin saves the settings again.

## What is replaced and what stays

Replaced with stand-ins:

| Kind | Stand-in |
| --- | --- |
| Hosts | `host_NNNN` |
| Custom indexes | `idx_NNNN` |
| Users | `user_NNNN` |
| Apps that are not Splunk's own | `app_NNNN` |
| Saved searches | `search_NNNN` |
| Knowledge objects | `object_NNNN` |
| KV store collections | `kv_NNNN` |
| Roles | `role_NNNN` |
| Secrets such as tokens and passwords | `secret_NNNN` |
| Admin terms | `term_NNNN` |
| Email addresses | `email_NNNN@example.com` |
| Domains | `domain_NNNN.example` |
| IPv4 addresses | Internal addresses become `198.18.x.x` (then `240` to `247.x.x.x`), and public ones become `192.0.2.x`, `198.51.100.x`, or `203.0.113.x` (then `248` to `254.x.x.x`). Addresses in the same subnet stay in the same stand-in subnet |
| IPv6 addresses | `2001:db8::/32` |
| MAC addresses, GUIDs, Windows SIDs | Placeholders such as `02:00:00:00:00:01`, `00000000-0000-4000-8000-000000000001`, and `S-1-5-21-0-0-1` |

Kept visible: Splunk's built-in indexes (such as `_internal`, `main`, and `notable`), sourcetypes, field names, Splunk and vendor apps, well-known accounts (such as `admin`, `root`, and `splunk-system-user`), vendor domains, loopback and multicast addresses, and ordinary words.

Names come from three places:

1. **Discovery**: hosts, indexes, users, apps, saved searches, knowledge objects, KV store collections, and roles from the latest discovery reports, plus field values found inside saved-search SPL
2. **Patterns**: IP addresses, MAC addresses, email addresses, domain names, GUIDs, SIDs, home folder paths, and secrets, wherever they appear
3. **Admin terms**: the Always replace list

Incognito mode cannot replace a name it does not know. A host that discovery has not seen and that does not look like a domain name, written in free text, can reach the AI model. Run discovery before you rely on incognito mode, and add anything else to **Always replace these terms**. Use **Preview** to check.

Some names are also ordinary words or very short, such as an index named `firewall` or `web`, or a name of three letters or fewer. Incognito mode replaces these only where they appear as a value: `index=web` in SPL, a host field in search results, or an index list in a report. The same word in a sentence or as a JSON key stays as written, so the instructions and SPL the AI model reads are not garbled. If such a name is sensitive on its own, add it to **Always replace these terms**. That replaces the word everywhere, including where it is used as an ordinary word, so the AI model may understand the text less well.

## How a request is protected

1. The app builds the request as usual, then replaces every known name and pattern with its stand-in
2. It checks the masked text again for any known real name. If one is still there, it stops the request and sends nothing (see Blocked requests)
3. It adds a short note to the instructions that explains the stand-in format, so the AI model uses stand-ins exactly as written, including inside SPL
4. The AI model replies with stand-ins. The app puts the real names back before it shows the reply or runs a search the reply asks for
5. Splunk search results go back to the AI model masked field by field. Raw event text (`_raw`) is left out in incognito mode
6. The app saves a record of the masked text it sent, which only the person who asked can open

A name gets the same stand-in in every feature until an admin resets the stand-ins, so a follow-up question, a summary, and a shared export all use the same `host_0012`.

If the AI model writes a stand-in it was never shown, the app does not guess. Chat skips a search that uses one and asks the AI model to correct it. In a reply, the stand-in stays as written and **What the AI saw** lists it.

### Features covered

Every feature that sends Splunk data to the AI model goes through the same masking:

- Chat, including Knowledge Base passages, earlier turns, and search results
- Chat goals: planning and progress checks
- Discovery analysis (patterns, recommendations, and suggested use cases), run in the background worker
- AI summaries, run in the background worker
- Task verification and remediation steps in summaries
- The M-26-14 AI Review
- Summary infographics. The picture shows stand-ins, and the app says so after it is made

Not covered:

- Summaries and other AI output made before incognito mode was turned on keep the real names they were made with
- The external RAG API and inbound MCP surface do not use the AI model. They return real data to holders of a valid token
- Settings > Troubleshoot sends a fixed test prompt with no Splunk data

## What the AI saw

Each answer made in incognito mode has a **What the AI saw** button (a reply toggle in chat, and a note on summaries, verification, remediation, and the M-26-14 AI Review). It shows:

- how many stand-ins of each kind the AI model saw
- each request: the instructions, the messages or data, and the reply, exactly as sent after masking. A request that was sent but got no reply shows the error instead
- any stand-ins the AI model wrote that it was never shown

Records are kept per person: with sign-in on, only the user who asked can open a record. The app keeps the newest 300 records. Each record keeps up to 24 requests, and very long texts are shortened in the middle.

## Blocked requests

Incognito mode never falls back to sending real names. The app stops a request and sends nothing when:

- a known real name is still present after masking
- the stand-in file cannot be read or written
- the names from discovery cannot be loaded

Chat shows the reason in place of an answer, and other features show it as their error. Fix the cause (for example, add a term to **Never replace these terms** if it is safe to show) and try again.

## Sharing with stand-ins

You can download a copy with stand-ins in place of real names, whether or not incognito mode is on for you:

- **Chat**: the button with the incognito icon in the chat header downloads the conversation as Markdown, named `chat-...-stand-ins.md`
- **Reports**: **Export with Stand-ins** in the report viewer downloads the report. JSON reports keep their structure. Pictures cannot be exported this way, because names in an image cannot be replaced

Shared copies use the same stand-ins as the AI model. If a known name would remain, the app refuses to create the copy (HTTP 409) instead of producing a copy that leaks it. Exports are limited to 5,000,000 characters and are not added to What the AI saw.

## Storage and keys

Everything stays on the app server, under `output/incognito/`:

| File | Contents |
| --- | --- |
| `policy.enc` | Admin settings and term lists |
| `preferences.enc` | Each person's on or off choice |
| `vaults/<id>.vault` | The mapping between real names and stand-ins |
| `ledger/<id>.rec` | Records of what the AI saw |

All of these files are encrypted with Fernet, using a key derived with HKDF-SHA256 from the app key in `.config.key`. They are written with owner-only permissions. The stand-in mapping never leaves the server and is never sent to the AI model. Back up `.config.key` with `output/`; without it, the files cannot be read.

## API

| Method and route | Who | Purpose |
| --- | --- | --- |
| `GET /api/incognito/status` | Any signed-in user | Your state, your choice, the policy flags, and whether you can manage the settings |
| `POST /api/incognito/preference` | Any signed-in user | `{"enabled": true}`, `false`, or `null` for the server default. 409 when the policy locks it on |
| `GET` and `POST /api/incognito/policy` | Admin | Read or change the admin settings |
| `POST /api/incognito/rotate` | Admin | Reset the stand-ins |
| `POST /api/incognito/preview` | Admin | `{"text": "..."}` returns the masked text and counts (up to 20,000 characters) |
| `GET /api/incognito/ledger/{ledger_id}` | The person who asked | One record of what the AI saw |
| `POST /api/incognito/export` | Any signed-in user | `{"text": "...", "filename": "..."}` returns a copy with stand-ins |
| `GET /api/incognito/export/report/{filename}` | Any signed-in user with access to the report | A saved report with stand-ins |

With sign-in off, every request counts as an admin.

## For developers

The code is in `src/incognito/` and has no FastAPI dependency:

| Module | Role |
| --- | --- |
| `vocabulary.py` | Names that stay visible (Splunk indexes, accounts, apps, vendor domains, common words) |
| `patterns.py` | Regular expressions for IPs, MACs, emails, domains, GUIDs, SIDs, home paths, and secrets |
| `vault.py` | The encrypted, file-locked mapping between names and stand-ins, shared by the server and its workers |
| `masker.py` | Replaces names in text, structured data, SPL, and result rows, finds leaks, and restores replies |
| `seeding.py` | Loads names from discovery reports and saved-search SPL |
| `session.py` | Per-request state, the stand-in note for the AI model, and the record of what was sent |
| `store.py` | The policy, choices, vaults, and records on disk |
| `client.py` | `IncognitoLLMClient`, which wraps any AI client so `generate_response` and `analyze_data` mask and restore |
| `provider.py` | Decides whether the AI model is local or cloud |

`web_app.get_or_create_llm_client()` returns the wrapped client, and the current session travels in a context variable. A new feature that calls the AI model gets masking by opening a session (`incognito_session_for_request(request, "feature name")`) and running its AI calls inside `incognito_session_scope(session)`, then calling `attach_incognito_result(session, result)` so the response carries the `incognito` summary for the **What the AI saw** note. Background jobs pass `incognito_job_payload(owner)` in the job and open the session with `open_incognito_session_for_job`.

Tests: `tests/test_incognito.py` (masking, vault, policy), `tests/test_incognito_app.py` (endpoints, chat, exports), and `tests/test_incognito_leaks.py` (end-to-end checks that no seeded name reaches a fake AI model). The contrast browser check audits the popover, the chat panel, the What the AI saw dialog, and the admin settings in every theme.
