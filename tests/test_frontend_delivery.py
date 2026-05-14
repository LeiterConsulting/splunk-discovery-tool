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