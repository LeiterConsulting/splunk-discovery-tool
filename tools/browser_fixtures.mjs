// Deterministic discovery session fixtures shared by the browser regression suites.

export const OPERATOR_FIXTURE_TIMESTAMP = '20260522_010203';
export const OPERATOR_FIXTURE_CREATED_AT = '2026-05-22T01:02:03Z';

export function buildOperatorFixtureBlueprint(timestamp = OPERATOR_FIXTURE_TIMESTAMP, createdAt = OPERATOR_FIXTURE_CREATED_AT) {
    return {
        schema_version: '2.0',
        generated_at: createdAt,
        analysis_depth: 'seeded_browser_fixture',
        readiness_score: 78,
        overview: {
            total_indexes: 12,
            total_sourcetypes: 34,
            total_hosts: 5,
            total_sources: 22,
            total_users: 9,
            total_knowledge_objects: 17,
            total_kv_collections: 2,
            splunk_version: '9.3.0',
            license_state: 'valid',
            server_roles: ['search_head'],
            data_volume_24h: '18 GB',
        },
        capability_graph: {
            data_surface: {
                indexes: 12,
                sourcetypes: 34,
                hosts: 5,
                sources: 22,
            },
            operations_surface: {
                users: 9,
                knowledge_objects: 17,
                kv_collections: 2,
            },
            platform_surface: {
                splunk_version: '9.3.0',
                license_state: 'valid',
                server_roles: ['search_head'],
            },
        },
        finding_ledger: [
            {
                step: 1,
                title: 'Captured authentication telemetry',
                timestamp: createdAt,
                findings: [
                    'Repeated failed logins detected in _internal telemetry.',
                    'Search-head authentication review path is available.',
                ],
                data: {
                    indexes: ['_internal'],
                    sourcetypes: ['splunkd'],
                    hosts: ['search-head-01'],
                },
                data_keys: ['hosts', 'indexes', 'sourcetypes'],
            },
        ],
        classification_map: {
            security: ['Authentication Monitoring'],
        },
        coverage_gaps: [
            {
                gap: 'Admin login failures are not tied to an explicit alert.',
                why_it_matters: 'Repeated auth failures can be missed during routine operations.',
                priority: 'high',
            },
        ],
        risk_register: [
            {
                risk: 'Delayed authentication anomaly detection',
                severity: 'high',
                domain: 'security',
                impact: 'Repeated failed logins may continue without a formal escalation path.',
                mitigation: 'Validate alert coverage and promote the known-good SPL query.',
            },
        ],
        trend_signals: {
            evidence_steps: 3,
            high_priority_recommendations: 1,
            coverage_gap_count: 1,
            recommendation_by_domain: {
                security: 1,
                performance: 0,
                data_quality: 0,
                compliance: 0,
            },
        },
        vulnerability_hypotheses: [
            {
                hypothesis: 'Authentication drift is increasing on the primary search head.',
                rationale: 'Failed logins recur often enough to justify a focused validation loop.',
                validation_loop: 'Re-run the auth failure query after alert tuning and compare counts.',
                priority: 'high',
            },
        ],
        recursive_investigations: [
            {
                loop: 'Authentication Review Loop',
                objective: 'Re-check admin authentication anomalies after alert tuning.',
                next_iteration_trigger: 'Any repeated failed login activity over baseline.',
                output: 'Updated anomaly count and closure evidence for the operator runbook.',
            },
        ],
        recommendations: [
            {
                title: 'Validate authentication monitoring coverage',
                priority: 'high',
                category: 'security',
                description: 'Confirm repeated failed logins in _internal generate an actionable signal.',
                suggested_actions: 'Compare the auth-failure query against current alert coverage.',
            },
        ],
        suggested_use_cases: [
            {
                title: 'Authentication monitoring validation',
                persona: 'admin',
                description: 'Validate auth-failure alert coverage before the next review loop.',
            },
        ],
        timestamp,
    };
}

export function buildOperatorFixtureSummary(timestamp = OPERATOR_FIXTURE_TIMESTAMP) {
    return {
        schema_version: '2.0',
        timestamp,
        ai_summary: [
            '## Executive Summary',
            'This run confirms a reusable authentication-monitoring workflow for the current environment.',
            'Operators already have enough evidence to validate alert coverage without waiting for a new discovery run.',
            '',
            '## Priority Actions',
            '1. Validate repeated failed-logins coverage in `_internal` telemetry.',
            '2. Review search-head authentication drift for `search-head-01`.',
            '',
            '## Quick Wins',
            '- Save the auth-failure SPL baseline to the SPL library for operator reuse.',
            '- Compare current alert logic to the known-good search-head authentication query.',
            '',
            '## Risk Areas',
            '- Authentication anomalies may remain under-monitored if alert coverage is incomplete.',
            '',
            '## Trend Story',
            '- Failed logins are low volume but persistent enough to justify a focused review loop.',
            '',
            '## Next Check',
            '- Re-run the auth-failure validation query after alert tuning and compare the next session against this cached baseline.',
        ].join('\n'),
        readiness_score: 78,
        trend_signals: {
            evidence_steps: 3,
            high_priority_recommendations: 1,
            coverage_gap_count: 1,
            recommendation_by_domain: {
                security: 1,
                performance: 0,
                data_quality: 0,
                compliance: 0,
            },
        },
        risk_register: [
            {
                risk: 'Delayed authentication anomaly detection',
                severity: 'high',
                domain: 'security',
                impact: 'Repeated failed logins may continue without a formal escalation path.',
                mitigation: 'Validate alert coverage and promote the known-good SPL query.',
            },
        ],
        coverage_gaps: [
            {
                gap: 'Admin login failures are not tied to an explicit alert.',
                why_it_matters: 'Repeated auth failures can be missed during routine operations.',
                priority: 'high',
            },
        ],
        recursive_investigations: [
            {
                loop: 'Authentication Review Loop',
                objective: 'Re-check admin authentication anomalies after alert tuning.',
                next_iteration_trigger: 'Any repeated failed login activity over baseline.',
                output: 'Updated anomaly count and closure evidence for the operator runbook.',
            },
        ],
        unknown_data: [],
        spl_queries: [
            {
                title: 'Authentication Failure Validation',
                category: 'Security & Compliance',
                query: 'search index=_internal sourcetype=splunkd failed password | stats count by user host',
                query_source: 'fixture',
            },
        ],
        admin_tasks: [
            {
                title: 'Validate authentication alert coverage',
                details: 'Confirm repeated failed logins on search-head-01 create an actionable signal.',
                effort: 'lightweight',
                next_step: 'Compare the auth-failure SPL against existing alert rules.',
            },
        ],
        follow_up_questions: [
            'Which failed-login threshold should trigger escalation for search-head authentication events?',
        ],
        stats: {
            categories: ['Security & Compliance'],
            unknown_items: 0,
        },
        context_explorer: {
            overview: {
                headline: 'Authentication coverage needs a focused operator review.',
            },
            patterns: [
                {
                    title: 'Authentication drift',
                    description: 'Repeated failed logins are recurring in internal telemetry.',
                    signal: 'failed logins trending above the quiet baseline',
                },
            ],
            anchors: {
                indexes: [
                    {
                        name: '_internal',
                        summary: 'Primary internal telemetry index for platform health and auth review.',
                        actions: [
                            {
                                label: 'Inspect recent failed logins',
                                prompt: 'Investigate recent failed logins in _internal and compare them to current alert coverage.',
                            },
                        ],
                    },
                ],
                sourcetypes: [
                    {
                        name: 'splunkd',
                        summary: 'Splunk daemon telemetry containing authentication events.',
                        actions: [
                            {
                                label: 'Review splunkd auth events',
                                prompt: 'Review splunkd authentication events for repeated failures and noisy patterns.',
                            },
                        ],
                    },
                ],
                hosts: [
                    {
                        name: 'search-head-01',
                        summary: 'Primary search head requiring auth anomaly validation.',
                        actions: [
                            {
                                label: 'Check search head health',
                                prompt: 'Assess authentication health for search-head-01 and capture any drift indicators.',
                            },
                        ],
                    },
                ],
            },
            lanes: {
                unknown_entities: [
                    {
                        name: 'auth-threshold-policy',
                        description: 'Escalation thresholds for auth failures are not yet documented.',
                        actions: [
                            {
                                label: 'Define auth threshold',
                                prompt: 'Define the auth-failure threshold that should trigger escalation for this environment.',
                            },
                        ],
                    },
                ],
                coverage_gaps: [
                    {
                        title: 'Missing admin login alert',
                        description: 'Repeated failed admin logins need a first-class alert path.',
                        actions: [
                            {
                                label: 'Draft alert plan',
                                prompt: 'Draft the alerting plan for repeated admin login failures.',
                            },
                        ],
                    },
                ],
                risks: [
                    {
                        title: 'Delayed auth anomaly detection',
                        description: 'Auth anomalies may persist until manually reviewed.',
                        actions: [
                            {
                                label: 'Review auth anomalies',
                                prompt: 'Review authentication anomalies that may be missing alert coverage.',
                            },
                        ],
                    },
                ],
                priority_tasks: [
                    {
                        title: 'Validate authentication monitoring',
                        description: 'Confirm alert coverage and preserve the known-good query path.',
                        actions: [
                            {
                                label: 'Open monitoring plan',
                                prompt: 'Outline the operator plan for validating authentication monitoring coverage.',
                            },
                        ],
                    },
                ],
            },
        },
    };
}

export function buildCompletedDiscoveryPhasePlan(completedAt) {
    const phases = [
        { key: 'pipeline_boot', label: 'Prepare', detail: 'Settings checked.' },
        { key: 'signal_capture', label: 'Survey the environment', detail: 'Survey complete.' },
        { key: 'evidence_collection', label: 'Collect details', detail: 'Details collected.' },
        { key: 'classification_map', label: 'Classify data', detail: 'Data classified.' },
        { key: 'recommendation_queue', label: 'Recommend actions', detail: 'Recommendations written.' },
        { key: 'use_case_generation', label: 'Suggest use cases', detail: 'Use cases suggested.' },
        { key: 'blueprint_assembly', label: 'Assemble results', detail: 'Results assembled.' },
        { key: 'artifact_packaging', label: 'Save reports', detail: 'Reports saved.' },
    ];

    return phases.map((phase, index) => ({
        key: phase.key,
        label: phase.label,
        title: phase.label,
        description: phase.detail,
        progress_start: index === 0 ? 0 : Math.round((index / phases.length) * 100),
        progress_end: Math.round(((index + 1) / phases.length) * 100),
        baseline_seconds: 60,
        progress_percent: Math.round(((index + 1) / phases.length) * 100),
        status: 'completed',
        started_at: completedAt,
        completed_at: completedAt,
        last_detail: phase.detail,
    }));
}
