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
        self.assertIn("onClick={() => focusRiskControlPath(risk)}", template_source)
        self.assertIn("onClick={() => focusQueriesForRisk(risk)}", template_source)
        self.assertIn("onClick={() => focusQueriesForTask(task)}", template_source)
        self.assertIn("buildUnknownEntityValidationChatPrompt(item)", template_source)

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