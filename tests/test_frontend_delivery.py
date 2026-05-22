import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))


import frontend_delivery


class FrontendDeliveryTests(unittest.TestCase):
    def test_static_bundle_matches_legacy_frontend_source(self):
        status = frontend_delivery.get_frontend_sync_status()
        self.assertTrue(status["ok"], "\n".join(status["issues"]))

    def test_build_manifest_matches_current_artifacts(self):
        manifest = frontend_delivery.load_build_manifest()
        self.assertEqual(
            manifest.get("source"),
            frontend_delivery.compute_source_fingerprint(),
            "Legacy frontend source fingerprint drifted from the recorded build manifest.",
        )
        self.assertEqual(
            manifest.get("artifacts"),
            frontend_delivery.compute_artifact_fingerprint(),
            "Generated frontend artifacts drifted from the recorded build manifest.",
        )

    def test_summary_verification_state_wiring_is_declared(self):
        template_source = (ROOT / "src" / "frontend_legacy_template.html").read_text(encoding="utf-8")

        self.assertIn("const [showHistory, setShowHistory] = useState(null);", template_source)
        self.assertIn("setShowHistory(showHistory === taskIndex ? null : taskIndex);", template_source)
        self.assertIn("{showHistory === taskIndex && (() => {", template_source)

    def test_summary_action_handlers_are_declared(self):
        template_source = (ROOT / "src" / "frontend_legacy_template.html").read_text(encoding="utf-8")

        self.assertIn("const launchChatInvestigation = async (prompt, options = {}) => {", template_source)
        self.assertIn("const buildRiskInvestigationPrompt = (risk) => [", template_source)
        self.assertIn("const buildUnknownEntityValidationChatPrompt = (item) => {", template_source)
        self.assertIn("const focusRiskControlPath = (risk) => {", template_source)
        self.assertIn("const focusQueriesForRisk = (risk) => {", template_source)
        self.assertIn("const focusQueriesForTask = (task) => {", template_source)
        self.assertIn("buildUnknownEntityValidationChatPrompt(item)", template_source)
        self.assertIn("const saveSummaryContextAssetToLibrary = async (action) => {", template_source)
        self.assertIn("const executeSummaryContextAction = async (action) => {", template_source)
        self.assertIn("const renderSummaryContextActionButtons = (actions, options = {}) => {", template_source)
        self.assertIn("renderSummaryContextActionButtons(item.actions)", template_source)
        self.assertIn("renderSummaryContextActionButtons(risk.actions)", template_source)
        self.assertIn("renderSummaryContextActionButtons(gap.actions)", template_source)
        self.assertIn("renderSummaryContextActionButtons(task.actions)", template_source)
        self.assertIn("data-testid={action.kind === 'save_context_asset' ? 'summary-context-save-action' : 'summary-context-action-button'}", template_source)

    def test_capability_detail_modal_wiring_is_declared(self):
        template_source = (ROOT / "src" / "frontend_legacy_template.html").read_text(encoding="utf-8")

        self.assertIn("const [selectedCapabilityDetailName, setSelectedCapabilityDetailName] = useState(null);", template_source)
        self.assertIn("const openCapabilityDetail = (name) => {", template_source)
        self.assertIn("const renderCapabilityDetailModal = () => {", template_source)
        self.assertIn("const capabilityOverlayTopOffset = Math.max(headerHeight, 0);", template_source)
        self.assertIn("const capabilityDetailOverlayStyle = {", template_source)
        self.assertIn("const windowedCapabilityDetailDialogStyle = {", template_source)
        self.assertIn("maxHeight: `calc(100dvh - ${capabilityOverlayTopOffset}px - 1.5rem)`", template_source)
        self.assertIn("style={capabilityDetailOverlayStyle}", template_source)
        self.assertIn("style={windowedCapabilityDetailDialogStyle}", template_source)
        self.assertIn("<div className=\"min-h-full w-full flex items-start justify-center\">", template_source)
        self.assertIn("<div className=\"min-h-0 flex-1 overflow-y-auto px-4 py-4 sm:px-6 sm:py-5\">", template_source)
        self.assertIn("renderCapabilityDetailModal()", template_source)
        self.assertIn("onClick={() => openCapabilityDetail(capability.name)}", template_source)

    def test_frontend_follow_on_list_extraction_wiring_is_declared(self):
        template_source = (ROOT / "src" / "frontend_legacy_template.html").read_text(encoding="utf-8")

        self.assertIn("const assistantFollowOnListItemPattern = /^\\s*(?:[-*•]+|\\d+[.)])\\s+(.+?)\\s*$/;", template_source)
        self.assertIn("const assistantFollowOnInlineMarkerPattern = /(?:(?<=^)|(?<=[\\s,;]))(?:\\d+[.)]|[-*•])\\s+/g;", template_source)
        self.assertIn("const assistantFollowOnTruncatedInlineContainerPattern = /:\\s*(?:\\d+[.)]?|[-*•])$/;", template_source)
        self.assertIn("const isAssistantFollowOnListLeadIn = (line) => {", template_source)
        self.assertIn("const isAssistantFollowOnWrapperPrompt = (prompt) => {", template_source)
        self.assertIn("const expandAssistantInlineFollowOnActions = (actionText) => {", template_source)
        self.assertIn("const extractAssistantListedFollowOnActions = (cleanedResponse, seenPrompts, ignoredPrefixes) => {", template_source)
        self.assertIn("actions.push(...extractAssistantListedFollowOnActions(cleanedResponse, seenPrompts, ignoredPrefixes));", template_source)
        self.assertIn("for (const pattern of inlineListPatterns) {", template_source)

    def test_spl_library_wiring_is_declared(self):
        template_source = (ROOT / "src" / "frontend_legacy_template.html").read_text(encoding="utf-8")

        self.assertIn("const SPL_LIBRARY_ASSET_TYPE = 'spl_query_library';", template_source)
        self.assertIn("const importKnowledgeAssetToLibrary = async (payload, options = {}) => {", template_source)
        self.assertIn("const saveSplQueryToLibrary = async (splQuery, options = {}) => {", template_source)
        self.assertIn("const savedAssetId = savedAsset?.asset_id || null;", template_source)
        self.assertIn("const useSplQueryInChat = (splQuery, options = {}) => {", template_source)
        self.assertIn("const renderSplQueryActionButtons = (splQuery, options = {}) => {", template_source)
        self.assertIn("const getKnowledgeAssetSplIntelligence = (attributes) => {", template_source)
        self.assertIn("const renderSplQueryIntelligence = (attributes, options = {}) => {", template_source)
        self.assertIn("asset_type: SPL_LIBRARY_ASSET_TYPE,", template_source)
        self.assertIn("const reportSplQueries = Array.isArray(reportContent?.spl_queries) ? reportContent.spl_queries : [];", template_source)
        self.assertIn("{ key: 'spl_library', label: `SPL Library (${ragSplLibraryAssetCount})` },", template_source)
        self.assertIn("renderSplQueryActionButtons(msg.spl_query, {", template_source)
        self.assertIn("renderSplQueryActionButtons(task.verification_spl, {", template_source)
        self.assertIn("reusable_queries: Array.isArray(usage?.reusable_queries)", template_source)
        self.assertIn("const renderCapabilityReusableQueryCards = (usage) => {", template_source)
        self.assertIn("data-testid=\"chat-capability-reusable-query-card\"", template_source)
        self.assertIn("data-testid=\"chat-capability-evidence\"", template_source)
        self.assertNotIn("open={msg.capability_usage.some((usage) => Array.isArray(usage?.reusable_queries) && usage.reusable_queries.length > 0)}", template_source)
        self.assertIn("const normalizeSummaryContextPatternEntry = (pattern) => {", template_source)
        self.assertIn("const normalizeSummaryContextPatterns = (rawPatterns) => {", template_source)
        self.assertIn("const contextPatterns = normalizeSummaryContextPatterns(contextExplorer?.patterns);", template_source)
        self.assertIn("const visibleContextPatterns = contextPatterns.slice(0, 4);", template_source)
        self.assertIn("Lead pattern", template_source)
        self.assertIn("const isSplLibraryOnlyView = ragLibraryFilter === 'spl_library' && Boolean(savedSplQuery);", template_source)
        self.assertIn("data-testid=\"report-viewer-spl-blocks\"", template_source)
        self.assertIn("data-testid=\"context-library-spl-query-card\"", template_source)
        self.assertIn("data-testid=\"context-library-spl-only-query\"", template_source)
        self.assertIn("testIdPrefix: isSplLibraryOnlyView ? 'context-library-spl' : '',", template_source)
        self.assertIn("buildTestId('fit-status')", template_source)
        self.assertIn("buildTestId('validation-status')", template_source)
        self.assertIn("buildTestId('reuse-tier')", template_source)
        self.assertIn("buildTestId('feedback-counts')", template_source)
        self.assertIn("data-testid=\"context-library-detail-spl-query\"", template_source)
        self.assertIn("renderSplQueryIntelligence(detailAttributes, { testIdPrefix: 'context-library-detail-spl' })", template_source)
        self.assertIn("data-testid=\"discovery-report-year-toggle\"", template_source)
        self.assertIn("data-testid=\"discovery-report-session-toggle\"", template_source)
        self.assertIn("data-testid=\"discovery-report-row\"", template_source)

    def test_context_workspace_entrypoint_is_declared(self):
        template_source = (ROOT / "src" / "frontend_legacy_template.html").read_text(encoding="utf-8")

        self.assertIn("const openRagCapabilitiesWorkspace = (options = {}) => {", template_source)
        self.assertIn("if (options.libraryFilter) {", template_source)
        self.assertIn("setRagLibraryFilter(options.libraryFilter);", template_source)
        self.assertIn("id=\"workspace-tab-context\"", template_source)
        self.assertIn("data-testid=\"workspace-tab-context\"", template_source)
        self.assertIn("aria-selected={isCapabilitiesRagView}", template_source)
        self.assertIn("onClick={() => openRagCapabilitiesWorkspace({ libraryFilter: 'spl_library' })}", template_source)
        self.assertIn("Refresh Context", template_source)

    def test_header_llm_status_is_config_driven_without_credential_load_toast(self):
        template_source = (ROOT / "src" / "frontend_legacy_template.html").read_text(encoding="utf-8")

        self.assertIn("setSelectedModel(data.llm.model || '');", template_source)
        self.assertIn("{config?.active_credential_name || config?.llm?.model || 'Not configured'}", template_source)
        self.assertNotIn("await loadCredentialIntoSettings(data.active_credential_name);", template_source)
        self.assertNotIn("Credential Loaded!", template_source)

    def test_discovery_status_declares_passive_polling_fallback(self):
        template_source = (ROOT / "src" / "frontend_legacy_template.html").read_text(encoding="utf-8")

        self.assertIn("const discoveryStatusPollIntervalMs = (discoveryStatus === 'starting' || discoveryStatus === 'running')", template_source)
        self.assertIn("? 1000", template_source)
        self.assertIn(": 5000;", template_source)
        self.assertIn("loadDiscoveryStatus();", template_source)
        self.assertIn("}, discoveryStatusPollIntervalMs);", template_source)

    def test_mission_workspace_declares_freshness_and_action_layers(self):
        template_source = (ROOT / "src" / "frontend_legacy_template.html").read_text(encoding="utf-8")

        self.assertIn("const parseMissionSessionDate = (value) => {", template_source)
        self.assertIn("const getMissionFreshnessMeta = (value) => {", template_source)
        self.assertIn("const selectedPackageSessionLabel = formatMissionSessionSelectionLabel(compareSelection.current);", template_source)
        self.assertIn("Mission Status", template_source)
        self.assertIn("What Changed Since Last Run", template_source)
        self.assertIn("Admin Next Actions", template_source)
        self.assertIn("Analyst Investigation Tracks", template_source)
        self.assertIn("Executive Readout", template_source)
        self.assertIn("formatMissionSessionSelectionLabel(session.timestamp)", template_source)

    def test_workspace_declares_shared_operator_voice_control(self):
        template_source = (ROOT / "src" / "frontend_legacy_template.html").read_text(encoding="utf-8")

        self.assertIn("const OPERATOR_VOICE_PREFERENCE_KEY = 'dt4sms_operator_voice';", template_source)
        self.assertIn("const OPERATOR_VOICE_OPTIONS = [", template_source)
        self.assertIn("const [operatorVoice, setOperatorVoice] = useState(() => {", template_source)
        self.assertIn("data-testid=\"workspace-operator-voice-select\"", template_source)
        self.assertIn("operatorVoiceDefinition.label", template_source)
        self.assertIn("localStorage.setItem(OPERATOR_VOICE_PREFERENCE_KEY, operatorVoice);", template_source)
        self.assertIn("if (voice) params.set('voice', voice);", template_source)
        self.assertIn("const ensureCurrentRunbookPayload = async () => {", template_source)
        self.assertIn("String(runbookPayload?.voice || '').trim() === operatorVoice", template_source)
        self.assertIn("voice: operatorVoice,", template_source)

    def test_intelligence_workspace_declares_briefing_and_voice_layers(self):
        template_source = (ROOT / "src" / "frontend_legacy_template.html").read_text(encoding="utf-8")

        self.assertIn("const intelligenceHeadline = (() => {", template_source)
        self.assertIn("const intelligencePriorityBoard = [", template_source)
        self.assertIn("Intelligence Status", template_source)
        self.assertIn("Priority Board", template_source)
        self.assertIn("Admin Control Brief", template_source)
        self.assertIn("Analyst Investigation Brief", template_source)
        self.assertIn("Executive Framing", template_source)
        self.assertIn("Priority Coverage Gaps", template_source)
        self.assertIn("Highest-Signal Evidence", template_source)
        self.assertIn("Investigation Opportunities", template_source)
        self.assertIn("onClick={refreshIntelligenceWorkspace}", template_source)

    def test_intelligence_workspace_declares_structured_notable_patterns_tile(self):
        template_source = (ROOT / "src" / "frontend_legacy_template.html").read_text(encoding="utf-8")

        self.assertIn("const intelligenceNotablePatterns = Array.isArray(v2Intelligence?.notable_patterns)", template_source)
        self.assertIn("const [showAllIntelligencePatterns, setShowAllIntelligencePatterns] = useState(false);", template_source)
        self.assertIn("const getIntelligencePatternEyebrowLabel = (pattern, idx) => {", template_source)
        self.assertIn("const getDistinctIntelligencePatternEvidence = (pattern) => {", template_source)
        self.assertIn("const hasExpandableIntelligencePatterns = intelligenceNotablePatterns.length > intelligencePatternDisplayLimit;", template_source)
        self.assertIn("const visibleIntelligenceNotablePatterns = showAllIntelligencePatterns", template_source)
        self.assertIn("const intelligenceExecutivePatternItems = intelligenceNotablePatterns", template_source)
        self.assertIn("data-testid=\"intelligence-notable-patterns\"", template_source)
        self.assertIn("data-testid=\"intelligence-notable-pattern-card\"", template_source)
        self.assertIn("data-testid=\"intelligence-notable-patterns-toggle\"", template_source)
        self.assertIn("{getIntelligencePatternEyebrowLabel(pattern, idx)}", template_source)
        self.assertIn("const distinctEvidenceItems = getDistinctIntelligencePatternEvidence(pattern);", template_source)
        self.assertIn("return 'Volume profile';", template_source)
        self.assertIn("View all ${intelligenceNotablePatterns.length} patterns", template_source)
        self.assertIn("Show fewer", template_source)
        self.assertIn("Lead signal:", template_source)
        self.assertIn("reduced into readable operator cues instead of raw pattern blobs", template_source)

    def test_security_access_settings_gate_auth_enable_with_info_modal(self):
        template_source = (ROOT / "src" / "frontend_legacy_template.html").read_text(encoding="utf-8")

        self.assertIn("const [isAuthEnableInfoModalOpen, setIsAuthEnableInfoModalOpen] = useState(false);", template_source)
        self.assertIn("const [hasReviewedAuthEnableInfo, setHasReviewedAuthEnableInfo] = useState(false);", template_source)
        self.assertIn("const [pendingAuthEnableReview, setPendingAuthEnableReview] = useState(false);", template_source)
        self.assertIn("if (config?.security?.auth_enabled) {", template_source)
        self.assertIn("const authEnableGateActive = !securityConfig.auth_enabled && !hasReviewedAuthEnableInfo;", template_source)
        self.assertIn("data-testid=\"settings-auth-enable-info-button\"", template_source)
        self.assertIn("data-testid=\"settings-auth-enable-toggle\"", template_source)
        self.assertIn("data-testid=\"auth-enable-info-modal\"", template_source)
        self.assertIn("Review the authentication guide before enabling this control.", template_source)
        self.assertIn("Review authentication methods before enabling access control", template_source)
        self.assertIn("Local Password", template_source)
        self.assertIn("OIDC / Enterprise SSO", template_source)
        self.assertIn("Contained settings", template_source)
        self.assertIn("What changes when auth is enabled", template_source)
        self.assertIn("Continue to enable", template_source)
        self.assertIn("Mark as reviewed", template_source)
        self.assertIn("{renderAuthEnableInfoModal()}", template_source)

    def test_welcome_splash_modal_and_settings_reset_are_declared(self):
        template_source = (ROOT / "src" / "frontend_legacy_template.html").read_text(encoding="utf-8")

        self.assertIn("const WELCOME_SPLASH_PREFERENCE_KEY = 'dt4sms_welcome_splash_dismissed_v1';", template_source)
        self.assertIn("const loadWelcomeSplashDismissed = () => {", template_source)
        self.assertIn("const persistWelcomeSplashDismissed = (dismissed) => {", template_source)
        self.assertIn("const [isWelcomeSplashOpen, setIsWelcomeSplashOpen] = useState(() => !initialWelcomeSplashDismissed);", template_source)
        self.assertIn("const [hasDismissedWelcomeSplash, setHasDismissedWelcomeSplash] = useState(() => initialWelcomeSplashDismissed);", template_source)
        self.assertIn("const renderWelcomeSplashModal = () => {", template_source)
        self.assertIn("data-testid=\"welcome-splash-modal\"", template_source)
        self.assertIn("data-testid=\"welcome-splash-dismiss-checkbox\"", template_source)
        self.assertIn("data-testid=\"settings-preview-welcome-splash\"", template_source)
        self.assertIn("data-testid=\"settings-reset-welcome-splash\"", template_source)
        self.assertIn("overflow-hidden bg-black/86", template_source)
        self.assertIn("<div className=\"h-full w-full relative flex items-start justify-center\">", template_source)
        self.assertIn("aria-hidden=\"true\"", template_source)
        self.assertIn("radial-gradient(circle at 50% 18%", template_source)
        self.assertIn("boxShadow: isDarkTheme", template_source)
        self.assertIn("Welcome to DT4SMS", template_source)
        self.assertIn("Don&apos;t show this again on this browser.", template_source)
        self.assertIn("Preview Welcome Splash", template_source)
        self.assertIn("Reset for Demo", template_source)
        self.assertIn("{renderWelcomeSplashModal()}", template_source)

    def test_security_access_settings_reflect_live_oidc_provider_support(self):
        template_source = (ROOT / "src" / "frontend_legacy_template.html").read_text(encoding="utf-8")

        self.assertIn("const oidcCanEnableAuth = !!oidcStatus?.can_enable_auth;", template_source)
        self.assertIn("auth_enabled: !!current?.security?.auth_enabled,", template_source)
        self.assertIn("OIDC sign-in is implemented and ready to enable with the current provider settings.", template_source)
        self.assertIn("ready to enable auth", template_source)
        self.assertIn("provider flow live", template_source)
        self.assertNotIn("provider runtime lands", template_source)
        self.assertNotIn("implementation pending", template_source)
        self.assertNotIn("future provider slice", template_source)

    def test_workspace_exports_surface_voice_metadata(self):
        template_source = (ROOT / "src" / "frontend_legacy_template.html").read_text(encoding="utf-8")

        self.assertIn("const packageTargetLabel = `${selectedPackageSessionLabel} / ${packagePersonaLabel} persona / ${operatorVoiceDefinition.label} voice`;", template_source)
        self.assertIn("Voice: {runbookPayload.voice_label || operatorVoiceDefinition.label}", template_source)
        self.assertIn("Voice: {exportBuildState.bundle.operator_voice_label}", template_source)
        self.assertIn("title: `${operatorVoiceDefinition.label} ${workflowTab} discovery package`", template_source)

    def test_discovery_workspace_declares_runtime_monitoring(self):
        template_source = (ROOT / "src" / "frontend_legacy_template.html").read_text(encoding="utf-8")

        self.assertIn("const [discoveryLastUpdatedAt, setDiscoveryLastUpdatedAt] = useState(null);", template_source)
        self.assertIn("const [discoveryPhasePlan, setDiscoveryPhasePlan] = useState([]);", template_source)
        self.assertIn("const [discoveryActionDialog, setDiscoveryActionDialog] = useState(null);", template_source)
        self.assertIn("const loadDiscoveryStatus = async () => {", template_source)
        self.assertIn("const executeDiscoveryStart = async () => {", template_source)
        self.assertIn("const executeDiscoveryAbort = async () => {", template_source)
        self.assertIn("const confirmDiscoveryAction = async () => {", template_source)
        self.assertIn("const discoverySummarySession = discoverySummarySessionTimestamp", template_source)
        self.assertIn("const isDiscoverySummaryReady = discoveryStatusNormalized === 'completed'", template_source)
        self.assertIn("case 'discovery_status':", template_source)
        self.assertIn("const isMissionDiscoveryActive = discoveryStatus === 'starting' || discoveryStatus === 'running';", template_source)
        self.assertIn("data-testid=\"header-discovery-status-chip\"", template_source)
        self.assertIn("data-testid=\"discovery-ledger-summary-action\"", template_source)
        self.assertIn("Discovery Control Center", template_source)
        self.assertIn("Discovery Stage Ledger", template_source)
        self.assertIn("Mission Handoff", template_source)
        self.assertIn("Header monitor stays visible across workspaces", template_source)
        self.assertIn("Run discovery without losing workspace context", template_source)
        self.assertIn("Completed: {discoveryCompletedLabel}", template_source)
        self.assertIn("Run discovery with the current local LLM?", template_source)
        self.assertIn("Abort the current discovery run?", template_source)
        self.assertIn("onClick={openDiscoveryWorkspace}", template_source)

    def test_summary_surface_normalizes_numbered_markdown_section_titles(self):
        template_source = (ROOT / "src" / "frontend_legacy_template.html").read_text(encoding="utf-8")

        self.assertIn("const normalizeSummarySectionTitle = (value) => {", template_source)
        self.assertIn(".replace(/^\\d+[.)]\\s+/, '')", template_source)
        self.assertIn("title: normalizeSummarySectionTitle(headingMatch[1]),", template_source)
        self.assertIn("const normalizedTitle = normalizeSummarySectionTitle(title).toLowerCase();", template_source)

    def test_summary_surface_declares_first_party_local_runtime_dialog(self):
        template_source = (ROOT / "src" / "frontend_legacy_template.html").read_text(encoding="utf-8")

        self.assertIn("const [summaryActionDialog, setSummaryActionDialog] = useState(null);", template_source)
        self.assertIn("const executeSummaryOpen = async (sessionId, options = {}) => {", template_source)
        self.assertIn("const confirmSummaryAction = async () => {", template_source)
        self.assertIn("Generate summary with the current local LLM?", template_source)
        self.assertIn("Cached View Summary paths skip this prompt because no new LLM work is required.", template_source)
        self.assertIn("openSummaryModal(session.timestamp, { hasSummary: session.hasSummary });", template_source)
        self.assertIn("openSummaryModal(discoverySummarySession.timestamp, { hasSummary: discoverySummarySession.hasSummary })", template_source)
        self.assertNotIn("Continue with summarization?", template_source)

    def test_summary_surface_declares_worker_resume_and_abort_controls(self):
        template_source = (ROOT / "src" / "frontend_legacy_template.html").read_text(encoding="utf-8")

        self.assertIn("const summaryRequestAbortRef = useRef(null);", template_source)
        self.assertIn("const getSummaryProgressSnapshot = async (sessionId) => {", template_source)
        self.assertIn("Reconnect to the running summary worker?", template_source)
        self.assertIn("Use the loading workspace Abort Summary control if you need to stop the worker after reconnecting.", template_source)
        self.assertIn("const abortSummaryRun = async () => {", template_source)
        self.assertIn("await fetch('/abort-summary', {", template_source)
        self.assertIn("summaryRequestAbortRef.current.abort();", template_source)
        self.assertIn("Connected to worker PID {summaryWorkerPid}.", template_source)
        self.assertIn("Abort Summary", template_source)

    def test_discovery_surface_polls_worker_snapshot_and_activity_log(self):
        template_source = (ROOT / "src" / "frontend_legacy_template.html").read_text(encoding="utf-8")

        self.assertIn("const discoveryStatusPollIntervalMs = (discoveryStatus === 'starting' || discoveryStatus === 'running')", template_source)
        self.assertIn("}, discoveryStatusPollIntervalMs);", template_source)
        self.assertIn("const nextActivityLog = Array.isArray(snapshot?.activity_log)", template_source)
        self.assertIn("setMessages(nextActivityLog);", template_source)
        self.assertIn("entry?.id || `${entry?.timestamp || 'discovery'}-${index}`", template_source)

    def test_workspace_shell_expands_full_width_when_no_sidebar_is_present(self):
        template_source = (ROOT / "src" / "frontend_legacy_template.html").read_text(encoding="utf-8")

        self.assertIn("const workspaceShellWidthClass = 'max-w-[1800px]';", template_source)
        self.assertIn("const showWorkspaceRail = false;", template_source)
        self.assertIn("const workspaceShellClass = showWorkspaceRail", template_source)
        self.assertIn("const discoveryWorkspaceSplitClass = 'grid grid-cols-1 gap-6 lg:grid-cols-3';", template_source)
        self.assertIn("<div className=\"min-w-0 lg:col-span-2\">", template_source)
        self.assertIn("<div className=\"min-w-0 lg:col-span-1\">", template_source)
        self.assertIn("const workspaceRailClass = showWorkspaceRail", template_source)
        self.assertIn("const workspaceRailListClass = showWorkspaceRail", template_source)
        self.assertIn("const discoveryActivityShellClass = discoveryHasFocusedReport", template_source)
        self.assertIn("const renderReportViewerPanel = () => {", template_source)
        self.assertIn("const renderArtifactEmptyState = () => (", template_source)
        self.assertIn("const renderDiscoveryReportLibraryPanel = () => (", template_source)
        self.assertIn("const [isChatFullscreen, setIsChatFullscreen] = useState(false);", template_source)
        self.assertIn("const isChatTab = isChatFullscreen && workspaceTab === 'chat';", template_source)
        self.assertIn("const enterChatFullscreen = () => {", template_source)
        self.assertIn("const [isSummaryFullscreen, setIsSummaryFullscreen] = useState(false);", template_source)
        self.assertIn("const isSummaryTab = isSummaryFullscreen && workspaceTab === 'summary-workspace';", template_source)
        self.assertIn("const enterSummaryFullscreen = () => {", template_source)