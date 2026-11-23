# Splunk Dashboards

Discovery Tool and Constellation each support standalone use. With the optional Splunk Dashboards capability, Discovery drafts a plan from your current chat or an open discovery report. When you select **Create Dashboard**, Discovery sends the reviewed plan to Constellation through Splunk MCP Server as your Splunk user. A successful creation returns a private Dashboard Studio dashboard and a Constellation draft you can keep editing. [Constellation repository](https://github.com/LeiterConsulting/constellation)

## Version and verification

Discovery Tool 3.0.0 includes the optional Splunk Dashboards capability, building on Factory's original Discovery client integration. It uses version 1 of the dashboard MCP contract. [Factory integration commit](https://github.com/LeiterConsulting/splunk-discovery-tool/commit/aff54a8c0cec88185ac6f24415afa804ddd1fb5e)

The November 23, 2026 lab test paired Discovery with [Constellation 1.1.0-preview.2](https://github.com/LeiterConsulting/constellation/releases/tag/v1.1.0-preview.2) (build 70). Chat and Report each proposed a four-panel outline that created a dashboard without edits. Both used the active workspace's Knowledge Base and the same inspected synthetic SPL. Each dashboard rendered 12 requests, 3 failures, a failure trend, and a service comparison. Saved Studio definitions matched the editable private drafts, and each saved panel search began with the exact inspected SPL.

Discovery also verified that a connection without the Constellation tools shows setup guidance and that tool availability returns automatically when switching to a connection that offers them. Constellation's authoring mode verifies the Splunk caller, provider route, and native dashboard before saving. Probe mode checks identity and argument mapping with writes disabled, and fixture mode uses fixed recipes.

## What each Splunk environment needs

The app talks to Constellation only through the Splunk MCP server of each connection. Each Splunk environment where you want dashboards needs:

- **Splunk MCP Server**: [Splunk MCP Server on Splunkbase](https://splunkbase.splunk.com/app/7931)
- **Constellation** with `constellation_create_dashboard` and `constellation_get_creation_status` registered and enabled in Splunk MCP Server. Register and enable `constellation_inspect_dashboard_source` too if you want live source inspection. [Verified Constellation package](https://github.com/LeiterConsulting/constellation/releases/tag/v1.1.0-preview.2)

The app reads each connection's MCP tool list and shows one of these states:

- **Dashboard tools found** means both tools are visible with contract schema version 1. The result of a request depends on the server's mode and the caller's permissions
- **Potential capability** means the connection does not list both tools. The Capabilities tab links to Constellation and Splunk MCP Server
- **Unsupported version**: the tools are listed, but their arguments do not match. Update Constellation in that Splunk environment
- **Checking** or **Not checked**: the tool list is still loading, or the connection could not be read
- **No connection**: you have no Splunk connection to create dashboards with, such as when sign-in is on and no connection is assigned to you

Discovery verifies the connection's Splunk user with `splunk_get_user_info` and checks authoring with a fresh request ID through the status tool. The check sends no brief, report text, or chat context to Constellation. It runs before Discovery drafts a chat or report plan, and again at Create.

When Constellation reports authoring mode, the Capabilities card identifies the eligible Splunk user. Discovery stops before drafting if Constellation is off, probe-only, fixture-only, rejects the caller, or cannot be reached. Older builds can accept the user's status request without reporting their mode. Discovery keeps the existing plan flow available on those builds and shows that the mode is unconfirmed. Provider, data, and save checks still run during creation.

## Set it up

1. On the **Capabilities** tab, select **Install** and then **Turn on** for Splunk Dashboards. With sign-in on, only admins can do this
2. Select **Test** to check the connection's tool list and authoring mode for your Splunk user
3. Optional: open **Splunk connections and Splunk Web addresses** (admins). It shows the state of every saved connection. Dashboard links are shown only when they point to the connection's Splunk Web address, which the app guesses as the MCP host on port 8000. If that guess is wrong, enter the right address and select **Save Addresses**

Admins can also change three timing settings in the capability's configuration:

| Setting | Default | Range |
| --- | --- | --- |
| `create_timeout_seconds` (wait for the create reply) | 180 | 30 to 900 |
| `status_timeout_seconds` (wait for each status reply) | 20 | 5 to 60 |
| `max_wait_seconds` (keep checking a running request) | 600 | 60 to 3600 |

## Create a dashboard

- **From chat**: ask in your own words, such as "Create a dashboard that tracks failed logins in index main" or "Turn this into a dashboard". You can also start with **Ask in Chat** on an Overview change and continue the investigation there. Questions about how to build a dashboard get a normal answer
- **From a report**: open a discovery report and select **Create Dashboard**. The plan starts from the report's findings

For a chat request, the app's AI model uses an excerpt from the current conversation, a discovery summary from your workspace, and the known indexes and sourcetypes for that Splunk environment. From a report, it uses an excerpt of the selected report. When **Search the Knowledge Base** is on, both entry points retrieve relevant passages for the active Splunk workspace. When no AI model is available, you get a starter plan to fill in. The plan card includes the following fields.

- a title, a purpose, and optional requirements (units, definitions, exclusions)
- one data source: an index with an optional sourcetype, or one read-only search
- a time range: the last 15 minutes, hour, 24 hours, or 7 days
- one or two pages with up to six panels in total, and up to four findings
- the Splunk connection and Splunk user the dashboard will be created with

For an index-based plan, select **Browse Splunk data** to choose an index and time range using the connection shown on the card. The picker then offers up to 25 sourcetypes observed for that index and range. You can use the whole index or choose a sourcetype. The lookup uses the plan's Splunk identity and returns names to the picker. Your other plan edits carry through.

On connections that offer Constellation source inspection, the card loads a small sample profile for the selected index and time range. For an SPL source, select **Inspect search** after reviewing the query. The card shows field names and how often they were present in the sampled rows. Search output can contain aggregate rows. Partial coverage and an inconclusive check are shown separately from a complete sample that returned no rows.

Discovery keeps a single read-only SPL block supplied in the request or selected report as the plan's source. The card shows the inspected SPL that Create will send and asks for a new inspection if you change that search or its time range. The **Panel outline** shows the pages and ordered panels Constellation will receive, including changes you make in **Edit plan**.

When you request a specific number of panels, Discovery checks the outline against that count and retries an incomplete draft. If the model still cannot fill the outline, the starter plan shows that it needs panels before Create.

Select **Suggest panels** to give your configured AI model the dashboard intent and sampled field metadata. Review the suggestions and select **Use suggested panels** to replace the proposed pages and panels while keeping the selected source and time range. The card discards inspection results when the source, range, or connection changes. **Refresh inspection** requests a new sample. You can continue to edit or create a dashboard when inspection is unavailable.

Discovery uses its bundled dashboard design guidance when drafting or revising plans. See the [Discovery and Constellation workflow plan](SPLUNK_DASHBOARD_COLLABORATION.md) for the next work on source-grounded planning and dashboard opportunities.

Select **Edit Plan** to enter a source manually or edit the dashboard, **Cancel** to drop it, or **Create Dashboard** to send it to Constellation. Constellation checks the selected source and validates the dashboard during creation.

After you create it, the app saves the request first, sends it, and follows its progress. The card ends in one of these results:

- **Dashboard created**: with **Open Dashboard** and **Edit in Constellation** links
- **Saved as a Constellation draft**: Constellation saved a draft but not a Splunk dashboard. Open the draft to finish it
- **Review source** opens the source controls for a data or search issue. **Revise panels** keeps the saved plan and can offer a smaller or clearer version with **Suggest a fix**. Review and apply a suggestion before choosing **Create Dashboard** again.
- A connection or model issue explains what to check in Constellation Settings. Older Constellation versions may provide only a general validation result.
- If you see **Splunk could not confirm the result** or **Waiting for Splunk to confirm**, select **Check Status** to look up the original request as the same Splunk user. Discovery sends the request ID without attaching the plan.

If the first Create reply is lost and Constellation confirms the request is absent, Discovery can resend the approved plan once under the original request ID. A probe-mode response leaves the outcome open. Discovery also keeps the request checkable if Splunk previously accepted it and its receipt becomes unavailable.

The Capabilities tab lists your recent dashboards with their links.

## Who can create dashboards

- **Sign-in off**: anyone who can use the app, through the active connection. The plan card shows the Splunk user the connection's token belongs to
- **Sign-in on**: admins and analysts, only through their own assigned MCP connection. There is no fallback to the shared connection, because Splunk creates the dashboard as the connection's Splunk user. Viewers cannot create dashboards
- With sign-in on, only admins can install, turn on, turn off, remove, test, or configure Splunk Dashboards (and every other capability). Everyone can see its status
- Each person sees only their own requests. With sign-in off, everyone shares one list

## Incognito mode

Dashboards cannot be created while incognito mode is on for you, or while an admin requires incognito mode for cloud AI models. Constellation sends the plan to its own AI model with the real names, where incognito mode cannot replace them. Status, your recent dashboards, and **Check Status** still work.

## What stays private

- Receipts, dashboard links, request IDs, and Splunk user names never go to the AI model
- The server log records only the outcome of each step, such as `created` or an error code, never the plan, links, or user names
- Links from Constellation are shown only when they point to the connection's Splunk Web address and to the dashboard or draft that was created
- Requests are saved in `output/chat_data/dashboards/operations.json`, a file only the app's user can read. The plan is kept for 24 hours (as long as Constellation accepts a resend of the same request), each request for 7 days, and up to 50 requests per person

## Troubleshooting

| Message | What to do |
| --- | --- |
| This Splunk environment does not offer the dashboard tools yet | Check that an MCP-enabled Constellation build is installed and both tools are registered and enabled for your connection. Then select **Check Again** |
| This Splunk environment lists the dashboard tools, but not in the version this app supports | Update Constellation in that Splunk environment |
| None is assigned to you | Ask an admin to assign an MCP connection to your user in Settings. Admins assign one to their own user in **Settings > Users** |
| Your role cannot create dashboards | Ask an admin for the analyst role |
| Could not confirm which Splunk user this connection signs in as | Check the connection's token in Settings, and that Splunk MCP Server offers `splunk_get_user_info` |
| Dashboards cannot be created while incognito mode is on | Turn incognito mode off, or ask an admin about the cloud AI model rule |
| The dashboard is created but has no links | Enter the connection's Splunk Web address under **Splunk connections and Splunk Web addresses** |

## API

All routes need a signed-in user when sign-in is on.

- `GET /api/dashboards/status?refresh=false`: whether you can create dashboards on your connection, and why not
- `POST /api/dashboards/propose`: draft a plan from a report (`report_name`, optional `focus`). Nothing is sent to Splunk
- `POST /api/dashboards/create`: send a reviewed plan (`proposal_id`, `brief`, `binding_key`)
- `GET /api/dashboards/operations` and `GET /api/dashboards/operations/{request_id}`: your requests
- `POST /api/dashboards/operations/{request_id}/check`: ask Splunk for the current result, on the same connection and Splunk user
- `GET /api/capabilities/splunk_dashboards/connections?refresh=false` (admin): the state and Splunk Web address of every saved connection

The contract between this app and Constellation is defined by the Constellation project. The code is in `src/capabilities/tools/dashboards.py` (contract and checks), `dashboard_service.py` (requests and status), `dashboard_store.py` (saved requests), and `src/capabilities/connection_support.py` (tool list checks).
