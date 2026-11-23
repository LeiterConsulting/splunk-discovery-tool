# Discovery and Constellation dashboard workflow

When you ask for a dashboard in Discovery, it should carry the source, time range, and purpose forward from the investigation. The next useful response is a short plan, a focused question, or a concrete way to repair the plan. You decide when to create the dashboard.

## Delivery order

1. **Recover the current plan.** Constellation returns a stable reason when it stops before saving. Discovery uses the reason to reopen the relevant part of the plan and offer a source check, a panel repair, or a settings check. A repair uses the original question and current source evidence. The user reviews the changes before submitting again. An uncertain save keeps its original request and uses status recovery.
2. **Ground the first plan in data and design.** Discovery supplies a small versioned dashboard-design pack in both planning and panel revision. Use a fresh profile for the exact caller, source, and range when the source is already known. If scope or metric meaning is unclear, ask one question and preserve the rest of the investigation. Constellation can later expose a read-only feasibility check for an explicit set of proposed panels. It can validate source compatibility and field bindings before Save where practical, without running a full authoring pass twice.
3. **Surface dashboard opportunities.** Start with a follow-up on successful chat results, then add the same action to report findings and Overview. Show a single **Plan a dashboard** action with the measure and suggested time trend or breakdown. Carry the exact supported SPL or index, time range, and provenance into the planner. A documented aggregation, usable time or grouping field, adequate coverage, and a recurring decision make a useful candidate. Partial or stale coverage, unknown measures, unsupported scopes, and one-off samples call for a clarification or no promotion. The dashboard capability supplies general design and field-role guidance. An organization can augment it with reviewed metric definitions, templates, and standards in its Knowledge Base.
4. **Verify the paired workflow.** Qualify the Constellation package through Splunk MCP on the lab connection before testing authorized synthetic saves. Run an ordinary chat journey and a report journey. Verify identity and scope through planning, an actionable failure and successful repair, and private draft and Studio readback. Exercise unsupported capability, changed credentials, Incognito, empty and partial data, and an uncertain write. Confirm the result cards open both saved artifacts.

## MCP boundaries

| Phase | Discovery | Constellation |
| --- | --- | --- |
| Investigate | Recognizes chartable evidence in authorized results and scopes it to the current investigation | Profiles a selected index or reviewed SPL under the same caller |
| Plan | Retrieves design guidance and uses the source evidence to propose panels or ask a focused question | Supplies version-aware Studio guidance and can report feasibility |
| Recover | Preserves the plan and offers a specific repair from a bounded reason | Returns the same reason on Create and Status and protects uncertain saves |
| Create | Submits the user-reviewed plan once under its existing request identity | Rechecks permissions, provider and current data, validates native layout and field bindings, then verifies private saves |

The inspect and create requests stay keyed to the authenticated Splunk identity. Scope and coverage are evidence for planning. Native validation and write authority stay in Constellation. Optional inspection and design references can improve the plan while existing Create and Status clients continue to work.
