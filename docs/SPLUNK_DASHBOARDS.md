# Splunk Dashboards

Splunk Dashboards is an optional capability that creates Splunk Dashboard Studio dashboards from a chat or a discovery report. The app does not build the dashboard itself. It drafts a plan for you to review, and when you select **Create Dashboard** it sends the plan to Constellation, a Splunk app that builds the dashboard in Splunk as your Splunk user. Each result is a private Splunk dashboard plus a Constellation draft you can keep editing.

## What each Splunk environment needs

The app talks to Constellation only through the Splunk MCP server of each connection. Each Splunk environment where you want dashboards needs:

- **Splunk MCP Server**: [Splunk MCP Server on Splunkbase](https://splunkbase.splunk.com/app/7931)
- **Constellation**: [Constellation releases](https://github.com/LeiterConsulting/constellation/releases). It adds two tools to Splunk MCP Server: `constellation_create_dashboard` and `constellation_get_creation_status`

The app reads each connection's MCP tool list and shows one of these states:

- **Dashboard tools found**: both tools are listed with the arguments this app supports (contract schema version 1)
- **Potential capability**: the tools are not listed. The Capabilities tab explains that Constellation must be installed in that Splunk environment and links to both apps. Nothing else in the app changes
- **Unsupported version**: the tools are listed, but their arguments do not match. Update Constellation in that Splunk environment
- **Checking** or **Not checked**: the tool list is still loading, or the connection could not be read

The app also calls `splunk_get_user_info`, one of the standard Splunk MCP tools, to confirm which Splunk user the connection signs in as.

## Set it up

1. On the **Capabilities** tab, select **Install** and then **Turn on** for Splunk Dashboards. With sign-in on, only admins can do this
2. Select **Test** to read the connection's tool list again. The card shows whether dashboards can be created and, if not, why
3. Optional: open **Splunk connections and Splunk Web addresses** (admins). It shows the state of every saved connection. Dashboard links are shown only when they point to the connection's Splunk Web address, which the app guesses as the MCP host on port 8000. If that guess is wrong, enter the right address and select **Save Addresses**

Admins can also change three timing settings in the capability's configuration:

| Setting | Default | Range |
| --- | --- | --- |
| `create_timeout_seconds` (wait for the create reply) | 180 | 30 to 900 |
| `status_timeout_seconds` (wait for each status reply) | 20 | 5 to 60 |
| `max_wait_seconds` (keep checking a running request) | 600 | 60 to 3600 |

## Create a dashboard

- **From chat**: ask in your own words, such as "Create a dashboard that tracks failed logins in index main" or "Turn this into a dashboard". Questions about how to build a dashboard get a normal answer
- **From a report**: open a discovery report and select **Create Dashboard**. The plan starts from the report's findings

Either way, the app's AI model drafts a plan from the conversation or the report, using index and sourcetype names the app has seen in the environment. When no AI model is available, you get a starter plan to fill in. The plan appears as a card with:

- a title, a purpose, and optional requirements (units, definitions, exclusions)
- one data source: an index with an optional sourcetype, or one read-only search
- a time range: the last 15 minutes, hour, 24 hours, or 7 days
- one or two pages with up to six panels in total, and up to four findings
- the Splunk connection and Splunk user the dashboard will be created with

Select **Edit Plan** to change the plan, **Cancel** to drop it, or **Create Dashboard** to send it. The card lists anything to fix before it can be sent, such as a missing index. Nothing goes to Splunk until you select **Create Dashboard**.

After you create it, the app saves the request first, sends it, and follows its progress. The card ends in one of these results:

- **Dashboard created**: with **Open Dashboard** and **Edit in Constellation** links
- **Saved as a Constellation draft**: Constellation saved a draft but not a Splunk dashboard. Open the draft to finish it
- **Constellation needs more detail**: change the plan and try again
- **The dashboard was not created**: with the reason
- **Splunk could not confirm the result** or **Waiting for Splunk to confirm**: select **Check Status**. The app never sends a second request it cannot prove is the same one

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
| This Splunk environment does not offer the dashboard tools yet | Install Constellation in that Splunk environment, then select **Check Again** |
| This Splunk environment lists the dashboard tools, but not in the version this app supports | Update Constellation in that Splunk environment |
| None is assigned to you | Ask an admin to assign an MCP connection to your user in Settings |
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
