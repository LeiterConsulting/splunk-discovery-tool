(() => {
  const { useState, useEffect, useRef } = React;
  const generateChatSessionId = () => {
    const now = /* @__PURE__ */ new Date();
    const stamp = now.toISOString().replace(/[-:T\.Z]/g, "").slice(0, 14);
    const rand = Math.random().toString(36).slice(2, 8);
    return `chat_${stamp}_${rand}`;
  };
  const CHAT_STATE_STORAGE_KEY = "dt4sms_chat_state_v1";
  const WELCOME_SPLASH_PREFERENCE_KEY = "dt4sms_welcome_splash_dismissed_v1";
  const buildAssistantFollowOnLabel = (prompt, limit = 72) => {
    const label = String(prompt || "").trim().replace(/\.+$/, "");
    if (label.length <= limit) {
      return label;
    }
    const shortened = label.slice(0, limit).replace(/\s+\S*$/, "").trim();
    return `${shortened || label.slice(0, limit).trim()}...`;
  };
  const normalizeAssistantFollowOnText = (actionText) => {
    let cleaned = String(actionText || "").replace(/\s+/g, " ").trim();
    cleaned = cleaned.replace(/^[\s:*•-]+|[\s:*•-]+$/g, "");
    cleaned = cleaned.replace(/^[`'"]+|[`'"]+$/g, "");
    cleaned = cleaned.replace(/^to\s+/i, "");
    cleaned = cleaned.replace(/^also\s+/i, "");
    cleaned = cleaned.replace(/\s+(?:for you|if helpful|if that helps|if you want)$/i, "");
    cleaned = cleaned.replace(/[ .;:]+$/g, "");
    if (!cleaned) {
      return "";
    }
    return cleaned.charAt(0).toUpperCase() + cleaned.slice(1);
  };
  const dedupeAssistantFollowOnActions = (actions, limit = 3) => {
    const deduped = [];
    const seen = /* @__PURE__ */ new Set();
    for (const action of Array.isArray(actions) ? actions : []) {
      if (!action || typeof action !== "object") {
        continue;
      }
      const prompt = typeof action.prompt === "string" ? action.prompt.trim() : "";
      const kind = typeof action.kind === "string" ? action.kind.trim().toLowerCase() : "";
      if (!prompt) {
        continue;
      }
      const key = `${kind}::${prompt.toLowerCase()}`;
      if (seen.has(key)) {
        continue;
      }
      seen.add(key);
      deduped.push({
        label: typeof action.label === "string" && action.label.trim() ? action.label.trim() : buildAssistantFollowOnLabel(prompt),
        prompt,
        kind: kind || "assistant_response_follow_up"
      });
      if (deduped.length >= limit) {
        break;
      }
    }
    return deduped;
  };
  const assistantFollowOnListItemPattern = /^\s*(?:[-*•]+|\d+[.)])\s+(.+?)\s*$/;
  const assistantFollowOnInlineMarkerPattern = /(?:(?<=^)|(?<=[\s,;]))(?:\d+[.)]|[-*•])\s+/g;
  const assistantFollowOnTruncatedInlineContainerPattern = /:\s*(?:\d+[.)]?|[-*•])$/;
  const isAssistantFollowOnListLeadIn = (line) => {
    const normalized = String(line || "").replace(/\s+/g, " ").trim().toLowerCase().replace(/[ :;,.]+$/g, "");
    if (!normalized) {
      return false;
    }
    const triggerMatch = normalized.startsWith("if you'd like") || normalized.startsWith("if you’d like") || normalized.startsWith("if you would like") || normalized.startsWith("if you want") || normalized.startsWith("if helpful") || normalized.startsWith("things i can do next") || normalized.startsWith("next steps i can") || normalized.startsWith("here are") || normalized.startsWith("here's");
    if (!triggerMatch) {
      return false;
    }
    return normalized.endsWith("i can") || normalized.endsWith("following") || normalized.endsWith("make this") || normalized.endsWith("turn this into") || normalized.includes("next steps") || normalized.includes("options") || normalized.includes("things i can do next") || normalized.includes("things i can");
  };
  const isAssistantFollowOnWrapperPrompt = (prompt) => {
    const normalized = String(prompt || "").replace(/\s+/g, " ").trim().toLowerCase().replace(/[ :;,.]+$/g, "");
    if (!normalized) {
      return false;
    }
    if (["following", "the following", "next steps", "options", "things i can do next"].includes(normalized)) {
      return true;
    }
    return /^(?:do|help with|take|offer)(?:\s+(?:any|one|some))?\s*(?:of\s+)?(?:the|these)?\s*(?:following|next steps|options)$/i.test(normalized);
  };
  const expandAssistantInlineFollowOnActions = (actionText) => {
    const rawAction = String(actionText || "").replace(/\s+/g, " ").trim();
    if (!rawAction) {
      return [];
    }
    const separatorIndex = rawAction.indexOf(":");
    if (separatorIndex === -1) {
      const normalizedAction2 = normalizeAssistantFollowOnText(rawAction);
      return normalizedAction2 ? [normalizedAction2] : [];
    }
    const prefix = rawAction.slice(0, separatorIndex).trim();
    const suffix = rawAction.slice(separatorIndex + 1);
    const matches = Array.from(suffix.matchAll(assistantFollowOnInlineMarkerPattern));
    if (matches.length === 0) {
      const normalizedAction2 = normalizeAssistantFollowOnText(rawAction);
      return normalizedAction2 ? [normalizedAction2] : [];
    }
    const cleanedPrefix = normalizeAssistantFollowOnText(prefix);
    const prompts = [];
    for (let index = 0; index < matches.length; index += 1) {
      const start = matches[index].index + matches[index][0].length;
      const end = index + 1 < matches.length ? matches[index + 1].index : suffix.length;
      let itemText = suffix.slice(start, end).trim().replace(/^[,;\s]+|[,;\s]+$/g, "");
      itemText = itemText.replace(/^(?:and|or)\s+/i, "");
      itemText = itemText.replace(/(?:,|;)\s*(?:and|or)\s*$/i, "");
      if (!itemText) {
        continue;
      }
      if (cleanedPrefix && !isAssistantFollowOnWrapperPrompt(cleanedPrefix)) {
        const combinedPrompt = normalizeAssistantFollowOnText(`${prefix} ${itemText}`);
        if (combinedPrompt) {
          prompts.push(combinedPrompt);
        }
        continue;
      }
      const normalizedItem = normalizeAssistantFollowOnText(itemText);
      if (normalizedItem) {
        prompts.push(normalizedItem);
      }
    }
    if (prompts.length > 0) {
      return prompts;
    }
    const normalizedAction = normalizeAssistantFollowOnText(rawAction);
    return normalizedAction ? [normalizedAction] : [];
  };
  const extractAssistantListedFollowOnActions = (cleanedResponse, seenPrompts, ignoredPrefixes) => {
    const actions = [];
    const lines = String(cleanedResponse || "").split(/\r?\n/);
    for (let lineIndex = 0; lineIndex < lines.length; lineIndex += 1) {
      if (!isAssistantFollowOnListLeadIn(lines[lineIndex])) {
        continue;
      }
      let candidateIndex = lineIndex + 1;
      let foundListItem = false;
      while (candidateIndex < lines.length) {
        const rawLine = lines[candidateIndex];
        const strippedLine = String(rawLine || "").trim();
        if (!strippedLine) {
          if (foundListItem) {
            break;
          }
          candidateIndex += 1;
          continue;
        }
        const match = rawLine.match(assistantFollowOnListItemPattern);
        if (!match) {
          break;
        }
        foundListItem = true;
        const prompt = normalizeAssistantFollowOnText(match[1]);
        const loweredPrompt = prompt.toLowerCase();
        if (prompt && prompt.split(/\s+/).length >= 3 && !ignoredPrefixes.some((prefix) => loweredPrompt.startsWith(prefix)) && !isAssistantFollowOnWrapperPrompt(prompt) && !seenPrompts.has(loweredPrompt)) {
          seenPrompts.add(loweredPrompt);
          actions.push({
            label: buildAssistantFollowOnLabel(prompt),
            prompt,
            kind: "assistant_response_follow_up"
          });
        }
        candidateIndex += 1;
      }
      lineIndex = candidateIndex > lineIndex ? candidateIndex - 1 : lineIndex;
    }
    return actions;
  };
  const extractAssistantResponseFollowOnActions = (assistantResponse) => {
    const cleanedResponse = String(assistantResponse || "").replace(/\*\*(.*?)\*\*/g, "$1").replace(/__(.*?)__/g, "$1").replace(/`+/g, "");
    if (!cleanedResponse.trim()) {
      return [];
    }
    const patterns = [
      /\ba good follow[ -]?up(?: question| step| action)?\s+(?:would be(?: to)?|is|might be|could be)\s+([^.!?\n]+)/gi,
      /\bif you(?:'d|’d|\swould)? like,?\s+i can\s+([^.!?\n]+)/gi,
      /\bif you want(?:\s+[^,.!?\n]+)?[,;]?\s+i can\s+([^.!?\n]+)/gi,
      /\bif helpful,?\s+i can\s+([^.!?\n]+)/gi,
      /\bor i can\s+([^.!?\n]+)/gi,
      /\bi can also\s+([^.!?\n]+)/gi,
      /\bi can\s+((?:list|show|compare|check|validate|investigate|review|summarize|break down|trend|prototype|measure|explain|help you find|query|estimate|calculate|get|look up|pull|retrieve)[^.!?\n]+)/gi
    ];
    const inlineListPatterns = [
      /\bif you(?:'d|’d|\swould)? like,?\s+i can\s+([^\n]+?:\s*(?:\d+[.)]|[-*•])[^\n]*)/gi,
      /\bif you want(?:\s+[^,.!?\n]+)?[,;]?\s+i can\s+([^\n]+?:\s*(?:\d+[.)]|[-*•])[^\n]*)/gi,
      /\bif helpful,?\s+i can\s+([^\n]+?:\s*(?:\d+[.)]|[-*•])[^\n]*)/gi,
      /\bor i can\s+([^\n]+?:\s*(?:\d+[.)]|[-*•])[^\n]*)/gi,
      /\bi can also\s+([^\n]+?:\s*(?:\d+[.)]|[-*•])[^\n]*)/gi,
      /\bi can\s+([^\n]+?:\s*(?:\d+[.)]|[-*•])[^\n]*)/gi
    ];
    const ignoredPrefixes = [
      "do that",
      "help with that",
      "continue",
      "keep going",
      "take it further",
      "go deeper"
    ];
    const actions = [];
    const seenPrompts = /* @__PURE__ */ new Set();
    actions.push(...extractAssistantListedFollowOnActions(cleanedResponse, seenPrompts, ignoredPrefixes));
    for (const pattern of inlineListPatterns) {
      let match;
      while ((match = pattern.exec(cleanedResponse)) !== null) {
        for (const prompt of expandAssistantInlineFollowOnActions(match[1])) {
          const loweredPrompt = prompt.toLowerCase();
          if (!prompt || prompt.split(/\s+/).length < 3 || ignoredPrefixes.some((prefix) => loweredPrompt.startsWith(prefix)) || isAssistantFollowOnWrapperPrompt(prompt) || assistantFollowOnTruncatedInlineContainerPattern.test(prompt)) {
            continue;
          }
          if (seenPrompts.has(loweredPrompt)) {
            continue;
          }
          seenPrompts.add(loweredPrompt);
          actions.push({
            label: buildAssistantFollowOnLabel(prompt),
            prompt,
            kind: "assistant_response_follow_up"
          });
        }
      }
    }
    for (const pattern of patterns) {
      let match;
      while ((match = pattern.exec(cleanedResponse)) !== null) {
        for (const prompt of expandAssistantInlineFollowOnActions(match[1])) {
          const loweredPrompt = prompt.toLowerCase();
          if (!prompt || prompt.split(/\s+/).length < 3 || ignoredPrefixes.some((prefix) => loweredPrompt.startsWith(prefix)) || isAssistantFollowOnWrapperPrompt(prompt) || assistantFollowOnTruncatedInlineContainerPattern.test(prompt)) {
            continue;
          }
          if (seenPrompts.has(loweredPrompt)) {
            continue;
          }
          seenPrompts.add(loweredPrompt);
          actions.push({
            label: buildAssistantFollowOnLabel(prompt),
            prompt,
            kind: "assistant_response_follow_up"
          });
        }
      }
    }
    return dedupeAssistantFollowOnActions(actions, 3);
  };
  const mergeAssistantFollowOnActions = (assistantContent, existingActions) => {
    const responseActions = extractAssistantResponseFollowOnActions(assistantContent);
    const normalizedExistingActions = Array.isArray(existingActions) ? existingActions.map((action) => ({
      label: typeof (action == null ? void 0 : action.label) === "string" ? action.label : "",
      prompt: typeof (action == null ? void 0 : action.prompt) === "string" ? action.prompt.trim() : "",
      kind: typeof (action == null ? void 0 : action.kind) === "string" ? action.kind : "follow_up"
    })).filter((action) => action.prompt) : [];
    return dedupeAssistantFollowOnActions([...responseActions, ...normalizedExistingActions], 3);
  };
  const compactPersistedChatMessages = (items) => {
    if (!Array.isArray(items)) return [];
    return items.slice(-24).map((msg, idx) => {
      var _a, _b, _c, _d, _e, _f, _g;
      const messageType = (msg == null ? void 0 : msg.type) || "assistant";
      const messageContent = typeof (msg == null ? void 0 : msg.content) === "string" ? msg.content : "";
      const followOnActions = messageType === "assistant" ? mergeAssistantFollowOnActions(messageContent, msg == null ? void 0 : msg.follow_on_actions) : Array.isArray(msg == null ? void 0 : msg.follow_on_actions) ? msg.follow_on_actions.slice(0, 3) : [];
      return {
        id: (msg == null ? void 0 : msg.id) || `persisted_${idx}_${Date.now()}`,
        type: messageType,
        content: messageContent,
        timestamp: (msg == null ? void 0 : msg.timestamp) || (/* @__PURE__ */ new Date()).toISOString(),
        spl_query: typeof (msg == null ? void 0 : msg.spl_query) === "string" ? msg.spl_query : void 0,
        spl_in_text: typeof (msg == null ? void 0 : msg.spl_in_text) === "string" ? msg.spl_in_text : void 0,
        visualization_spec: (msg == null ? void 0 : msg.visualization_spec) && typeof msg.visualization_spec === "object" ? {
          chart_type: typeof ((_a = msg.visualization_spec) == null ? void 0 : _a.chart_type) === "string" ? msg.visualization_spec.chart_type : void 0,
          title: typeof ((_b = msg.visualization_spec) == null ? void 0 : _b.title) === "string" ? msg.visualization_spec.title : void 0,
          summary_text: typeof ((_c = msg.visualization_spec) == null ? void 0 : _c.summary_text) === "string" ? msg.visualization_spec.summary_text : void 0,
          x_field: typeof ((_d = msg.visualization_spec) == null ? void 0 : _d.x_field) === "string" ? msg.visualization_spec.x_field : void 0,
          y_field: typeof ((_e = msg.visualization_spec) == null ? void 0 : _e.y_field) === "string" ? msg.visualization_spec.y_field : void 0,
          point_count: typeof ((_f = msg.visualization_spec) == null ? void 0 : _f.point_count) === "number" ? msg.visualization_spec.point_count : void 0,
          points: Array.isArray((_g = msg.visualization_spec) == null ? void 0 : _g.points) ? msg.visualization_spec.points.slice(0, 8).map((point) => ({
            label: typeof (point == null ? void 0 : point.label) === "string" ? point.label : "",
            full_label: typeof (point == null ? void 0 : point.full_label) === "string" ? point.full_label : void 0,
            value: Number.isFinite(Number(point == null ? void 0 : point.value)) ? Number(point.value) : void 0
          })).filter((point) => Number.isFinite(point.value)) : []
        } : void 0,
        capability_usage: Array.isArray(msg == null ? void 0 : msg.capability_usage) ? msg.capability_usage.slice(0, 2).map((usage, usageIdx) => ({
          name: typeof (usage == null ? void 0 : usage.name) === "string" ? usage.name : `capability_${usageIdx}`,
          title: typeof (usage == null ? void 0 : usage.title) === "string" ? usage.title : typeof (usage == null ? void 0 : usage.name) === "string" ? usage.name : "Capability",
          category: typeof (usage == null ? void 0 : usage.category) === "string" ? usage.category : void 0,
          used_in: typeof (usage == null ? void 0 : usage.used_in) === "string" ? usage.used_in : void 0,
          contribution: typeof (usage == null ? void 0 : usage.contribution) === "string" ? usage.contribution : "",
          reusable_queries: Array.isArray(usage == null ? void 0 : usage.reusable_queries) ? usage.reusable_queries.slice(0, 2).map((candidate, candidateIdx) => ({
            title: typeof (candidate == null ? void 0 : candidate.title) === "string" ? candidate.title : `Reusable query ${candidateIdx + 1}`,
            query: typeof (candidate == null ? void 0 : candidate.query) === "string" ? candidate.query : "",
            reuse_tier: typeof (candidate == null ? void 0 : candidate.reuse_tier) === "string" ? candidate.reuse_tier : void 0,
            known_good: Boolean(candidate == null ? void 0 : candidate.known_good),
            why_reuse: typeof (candidate == null ? void 0 : candidate.why_reuse) === "string" ? candidate.why_reuse : "",
            environment_fit_status: typeof (candidate == null ? void 0 : candidate.environment_fit_status) === "string" ? candidate.environment_fit_status : void 0,
            validation_status: typeof (candidate == null ? void 0 : candidate.validation_status) === "string" ? candidate.validation_status : void 0,
            success_count: Number.isFinite(Number(candidate == null ? void 0 : candidate.success_count)) ? Number(candidate.success_count) : 0,
            failure_count: Number.isFinite(Number(candidate == null ? void 0 : candidate.failure_count)) ? Number(candidate.failure_count) : 0,
            app: typeof (candidate == null ? void 0 : candidate.app) === "string" ? candidate.app : void 0,
            earliest: typeof (candidate == null ? void 0 : candidate.earliest) === "string" ? candidate.earliest : void 0,
            latest: typeof (candidate == null ? void 0 : candidate.latest) === "string" ? candidate.latest : void 0
          })).filter((candidate) => candidate.query) : [],
          chunks: Array.isArray(usage == null ? void 0 : usage.chunks) ? usage.chunks.slice(0, 3).map((chunk, chunkIdx) => ({
            source: typeof (chunk == null ? void 0 : chunk.source) === "string" ? chunk.source : `artifact_${chunkIdx + 1}`,
            score: typeof (chunk == null ? void 0 : chunk.score) === "number" ? chunk.score : void 0,
            snippet: typeof (chunk == null ? void 0 : chunk.snippet) === "string" ? chunk.snippet : "",
            source_type: typeof (chunk == null ? void 0 : chunk.source_type) === "string" ? chunk.source_type : void 0
          })).filter((chunk) => chunk.snippet) : []
        })) : [],
        has_follow_on: followOnActions.length > 0,
        follow_on_actions: followOnActions,
        status_timeline: Array.isArray(msg == null ? void 0 : msg.status_timeline) ? msg.status_timeline.slice(-8) : [],
        iterations: typeof (msg == null ? void 0 : msg.iterations) === "number" ? msg.iterations : 0,
        execution_time: typeof (msg == null ? void 0 : msg.execution_time) === "string" ? msg.execution_time : void 0
      };
    });
  };
  const compactPersistedConversationHistory = (history) => {
    if (!Array.isArray(history)) return null;
    return history.slice(-16).filter((entry) => entry && typeof entry === "object").map((entry) => ({
      role: typeof entry.role === "string" ? entry.role : "user",
      content: typeof entry.content === "string" ? entry.content : ""
    })).filter((entry) => entry.content);
  };
  const loadPersistedChatState = () => {
    try {
      if (typeof window === "undefined" || !window.localStorage) {
        return {};
      }
      const raw = window.localStorage.getItem(CHAT_STATE_STORAGE_KEY);
      if (!raw) {
        return {};
      }
      const parsed = JSON.parse(raw);
      if (!parsed || typeof parsed !== "object") {
        return {};
      }
      return {
        ...parsed,
        chatMessages: compactPersistedChatMessages(parsed.chatMessages),
        serverConversationHistory: compactPersistedConversationHistory(parsed.serverConversationHistory)
      };
    } catch (error) {
      console.warn("Failed to load persisted chat state", error);
      return {};
    }
  };
  const savePersistedChatState = (state) => {
    try {
      if (typeof window === "undefined" || !window.localStorage) {
        return;
      }
      window.localStorage.setItem(CHAT_STATE_STORAGE_KEY, JSON.stringify(state));
    } catch (error) {
      console.warn("Failed to save persisted chat state", error);
    }
  };
  const clearPersistedChatState = () => {
    try {
      if (typeof window === "undefined" || !window.localStorage) {
        return;
      }
      window.localStorage.removeItem(CHAT_STATE_STORAGE_KEY);
    } catch (error) {
      console.warn("Failed to clear persisted chat state", error);
    }
  };
  const loadWelcomeSplashDismissed = () => {
    try {
      if (typeof window === "undefined" || !window.localStorage) {
        return false;
      }
      return window.localStorage.getItem(WELCOME_SPLASH_PREFERENCE_KEY) === "1";
    } catch (error) {
      console.warn("Failed to load welcome splash preference", error);
      return false;
    }
  };
  const persistWelcomeSplashDismissed = (dismissed) => {
    try {
      if (typeof window === "undefined" || !window.localStorage) {
        return;
      }
      if (dismissed) {
        window.localStorage.setItem(WELCOME_SPLASH_PREFERENCE_KEY, "1");
        return;
      }
      window.localStorage.removeItem(WELCOME_SPLASH_PREFERENCE_KEY);
    } catch (error) {
      console.warn("Failed to persist welcome splash preference", error);
    }
  };
  const normalizeProvider = (provider) => {
    const value = String(provider || "openai").toLowerCase().trim();
    if (value === "custom endpoint") return "custom";
    if (value === "azure openai") return "azure";
    if (value === "claude") return "anthropic";
    if (value === "google" || value === "google ai") return "gemini";
    return value;
  };
  class ErrorBoundary extends React.Component {
    constructor(props) {
      super(props);
      this.state = { hasError: false, error: null, errorInfo: null };
    }
    static getDerivedStateFromError(error) {
      return { hasError: true };
    }
    componentDidCatch(error, errorInfo) {
      console.error("React Error Boundary caught:", error, errorInfo);
      this.setState({ error, errorInfo });
    }
    render() {
      if (this.state.hasError) {
        return /* @__PURE__ */ React.createElement("div", { className: "min-h-screen bg-gray-100 flex items-center justify-center p-4" }, /* @__PURE__ */ React.createElement("div", { className: "bg-white rounded-lg shadow-xl p-8 max-w-2xl" }, /* @__PURE__ */ React.createElement("h1", { className: "text-2xl font-bold text-red-600 mb-4" }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-exclamation-triangle mr-2" }), "Application Error"), /* @__PURE__ */ React.createElement("p", { className: "text-gray-700 mb-4" }, "Something went wrong. Please refresh the page to continue."), /* @__PURE__ */ React.createElement("div", { className: "bg-gray-100 p-4 rounded mb-4 overflow-auto max-h-64" }, /* @__PURE__ */ React.createElement("pre", { className: "text-sm text-red-600" }, this.state.error && this.state.error.toString())), /* @__PURE__ */ React.createElement(
          "button",
          {
            onClick: () => window.location.reload(),
            className: "px-4 py-2 bg-indigo-600 text-white rounded hover:bg-indigo-700"
          },
          /* @__PURE__ */ React.createElement("i", { className: "fas fa-sync-alt mr-2" }),
          "Reload Page"
        )));
      }
      return this.props.children;
    }
  }
  const visualizationSearchParams = new URLSearchParams(window.location.search);
  const isVisualizationRegressionView = visualizationSearchParams.get("view") === "visualization-regression";
  const formatVisualizationNumber = (value) => {
    const numericValue = Number(value);
    if (!Number.isFinite(numericValue)) {
      return String(value != null ? value : "");
    }
    if (Math.abs(numericValue) >= 1e3) {
      return numericValue.toLocaleString();
    }
    if (Math.abs(numericValue) >= 10 || Number.isInteger(numericValue)) {
      return numericValue.toFixed(0);
    }
    return numericValue.toFixed(2).replace(/\.00$/, "");
  };
  const truncateVisualizationLabel = (value, maxLength = 16) => {
    const label = String(value != null ? value : "").trim();
    if (!label) {
      return "";
    }
    if (label.length <= maxLength) {
      return label;
    }
    const safeLength = Math.max(6, maxLength);
    return `${label.slice(0, Math.max(3, safeLength - 3))}...`;
  };
  const getDenseBarLabelCharacterLimit = (slotWidth, pointCount) => {
    const widthDrivenLimit = Math.floor((slotWidth + 18) / 6);
    const densityPenalty = pointCount >= 10 ? 3 : pointCount >= 8 ? 2 : pointCount >= 6 ? 1 : 0;
    return Math.max(6, Math.min(16, widthDrivenLimit - densityPenalty));
  };
  function VisualizationPreviewCard({ spec, isDarkTheme, headingClass, subtextClass, mutedTextClass, testIdPrefix, sourceQuery, canOpenSplunk = false, onOpenSplunk }) {
    const [hoveredIndex, setHoveredIndex] = useState(null);
    const [selectedIndex, setSelectedIndex] = useState(null);
    const rawPoints = Array.isArray(spec == null ? void 0 : spec.points) ? spec.points : [];
    const points = rawPoints.map((point) => {
      const numericValue = Number(point == null ? void 0 : point.value);
      if (!Number.isFinite(numericValue)) {
        return null;
      }
      const label = typeof (point == null ? void 0 : point.label) === "string" ? point.label.trim() : "";
      const fullLabel = typeof (point == null ? void 0 : point.full_label) === "string" && point.full_label.trim() ? point.full_label.trim() : label;
      return {
        label,
        fullLabel,
        value: numericValue
      };
    }).filter(Boolean);
    if (points.length === 0) {
      return null;
    }
    const chartType = String((spec == null ? void 0 : spec.chart_type) || "").toLowerCase() === "line" ? "line" : "bar";
    const xAxisLabel = typeof (spec == null ? void 0 : spec.x_field) === "string" && spec.x_field.trim() ? spec.x_field.trim() : chartType === "line" ? "Time" : "Category";
    const yAxisLabel = typeof (spec == null ? void 0 : spec.y_field) === "string" && spec.y_field.trim() ? spec.y_field.trim() : "Value";
    const values = points.map((point) => point.value);
    const minValue = Math.min(...values);
    const maxValue = Math.max(...values);
    const domainMin = Math.min(minValue, 0);
    const domainMax = Math.max(maxValue, 1);
    const domainRange = Math.max(domainMax - domainMin, 1);
    const width = 520;
    const barNeedsExtraRoom = chartType === "bar" && points.length >= 7;
    const height = chartType === "bar" ? barNeedsExtraRoom ? 292 : 276 : 252;
    const margin = {
      top: 18,
      right: 18,
      bottom: chartType === "bar" ? barNeedsExtraRoom ? 112 : 96 : 78,
      left: 58
    };
    const chartLeft = margin.left;
    const chartTop = margin.top;
    const chartWidth = width - margin.left - margin.right;
    const chartHeight = height - margin.top - margin.bottom;
    const chartRight = chartLeft + chartWidth;
    const chartBottom = chartTop + chartHeight;
    const zeroLineY = chartTop + chartHeight - (0 - domainMin) / domainRange * chartHeight;
    const gridColor = isDarkTheme ? "#374151" : "#e5e7eb";
    const axisColor = isDarkTheme ? "#6b7280" : "#cbd5e1";
    const axisTextColor = isDarkTheme ? "#9ca3af" : "#6b7280";
    const plotColor = chartType === "line" ? isDarkTheme ? "#38bdf8" : "#0284c7" : isDarkTheme ? "#22d3ee" : "#0891b2";
    const plotAccentColor = chartType === "line" ? isDarkTheme ? "#0f172a" : "#ffffff" : isDarkTheme ? "#164e63" : "#cffafe";
    const getY = (value) => chartTop + chartHeight - (value - domainMin) / domainRange * chartHeight;
    const yTickCount = 4;
    const yTicks = Array.from({ length: yTickCount + 1 }, (_, index) => {
      const value = domainMax - domainRange * index / yTickCount;
      return {
        value,
        y: getY(value)
      };
    });
    const buildXForIndex = (index) => {
      if (points.length === 1) {
        return chartLeft + chartWidth / 2;
      }
      return chartLeft + chartWidth * index / (points.length - 1);
    };
    const barSlotWidth = chartWidth / Math.max(points.length, 1);
    const barWidth = Math.max(20, Math.min(48, barSlotWidth * 0.64));
    const barLabelCharacterLimit = getDenseBarLabelCharacterLimit(barSlotWidth, points.length);
    const barLabelRotation = points.length >= 7 ? -40 : -32;
    const chartTestId = testIdPrefix || `visualization-preview-${chartType}`;
    const highlightedIndex = hoveredIndex !== null ? hoveredIndex : selectedIndex;
    const selectedPoint = Number.isInteger(selectedIndex) && selectedIndex >= 0 && selectedIndex < points.length ? points[selectedIndex] : null;
    const sourceQueryPreview = typeof sourceQuery === "string" ? sourceQuery.trim() : "";
    const hasSplunkAction = !!sourceQueryPreview && canOpenSplunk && typeof onOpenSplunk === "function";
    const highlightColor = chartType === "line" ? isDarkTheme ? "#7dd3fc" : "#0ea5e9" : isDarkTheme ? "#67e8f9" : "#06b6d4";
    const highlightSurfaceColor = chartType === "line" ? isDarkTheme ? "#082f49" : "#e0f2fe" : isDarkTheme ? "#164e63" : "#cffafe";
    const detailCardToneClass = chartType === "line" ? isDarkTheme ? "bg-gray-900 border-sky-700" : "bg-white border-sky-200" : isDarkTheme ? "bg-gray-900 border-cyan-700" : "bg-white border-cyan-200";
    const detailCardChipClass = chartType === "line" ? isDarkTheme ? "bg-sky-950 text-sky-100 border-sky-800" : "bg-sky-50 text-sky-800 border-sky-200" : isDarkTheme ? "bg-cyan-950 text-cyan-100 border-cyan-800" : "bg-cyan-50 text-cyan-800 border-cyan-200";
    const activatePoint = (index) => setHoveredIndex(index);
    const clearHoveredPoint = () => setHoveredIndex(null);
    const toggleSelectedPoint = (index) => {
      setSelectedIndex((previousIndex) => previousIndex === index ? null : index);
    };
    const closeSelectionCard = () => setSelectedIndex(null);
    const handleSelectableKeyDown = (event2, index) => {
      if (event2.key === "Enter" || event2.key === " ") {
        event2.preventDefault();
        toggleSelectedPoint(index);
      }
    };
    const getPointState = (index) => ({
      isHighlighted: highlightedIndex === index,
      isSelected: selectedIndex === index
    });
    const renderSelectionCard = () => {
      if (!selectedPoint) {
        return null;
      }
      return /* @__PURE__ */ React.createElement(
        "div",
        {
          className: "fixed inset-0 z-50 flex items-center justify-center p-4",
          style: { backgroundColor: isDarkTheme ? "rgba(2, 6, 23, 0.78)" : "rgba(15, 23, 42, 0.18)" },
          onClick: closeSelectionCard
        },
        /* @__PURE__ */ React.createElement(
          "div",
          {
            role: "dialog",
            "aria-modal": "true",
            "aria-label": "Visualization point details",
            "data-testid": `${chartTestId}-selection-card`,
            className: `w-full max-w-sm rounded-2xl border shadow-2xl ${detailCardToneClass}`,
            onClick: (event2) => event2.stopPropagation()
          },
          /* @__PURE__ */ React.createElement("div", { className: "flex items-start justify-between gap-3 px-4 pt-4" }, /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("div", { className: `text-[11px] uppercase tracking-[0.18em] ${mutedTextClass}` }, chartType === "line" ? "Selected trend point" : "Selected category"), /* @__PURE__ */ React.createElement("h3", { "data-testid": `${chartTestId}-selection-label`, className: `mt-1 text-sm font-semibold ${headingClass}` }, selectedPoint.fullLabel || selectedPoint.label)), /* @__PURE__ */ React.createElement(
            "button",
            {
              type: "button",
              "data-testid": `${chartTestId}-selection-close`,
              onClick: closeSelectionCard,
              className: `inline-flex h-8 w-8 items-center justify-center rounded-full border ${isDarkTheme ? "border-gray-600 bg-gray-800 text-gray-200 hover:bg-gray-700" : "border-gray-300 bg-gray-50 text-gray-700 hover:bg-gray-100"}`,
              "aria-label": "Close visualization details"
            },
            /* @__PURE__ */ React.createElement("i", { className: "fas fa-times" })
          )),
          /* @__PURE__ */ React.createElement("div", { className: "px-4 pb-4" }, /* @__PURE__ */ React.createElement("div", { className: "mt-4 grid grid-cols-2 gap-2 text-xs" }, /* @__PURE__ */ React.createElement("div", { className: `rounded-lg border px-3 py-2 ${detailCardChipClass}` }, /* @__PURE__ */ React.createElement("div", { className: "uppercase tracking-wide opacity-75" }, xAxisLabel), /* @__PURE__ */ React.createElement("div", { className: "mt-1 font-semibold break-words" }, selectedPoint.fullLabel || selectedPoint.label)), /* @__PURE__ */ React.createElement("div", { className: `rounded-lg border px-3 py-2 ${detailCardChipClass}` }, /* @__PURE__ */ React.createElement("div", { className: "uppercase tracking-wide opacity-75" }, yAxisLabel), /* @__PURE__ */ React.createElement("div", { className: "mt-1 font-semibold" }, formatVisualizationNumber(selectedPoint.value)))), /* @__PURE__ */ React.createElement("div", { className: `mt-4 rounded-xl border px-3 py-3 text-xs ${isDarkTheme ? "bg-gray-950 border-gray-700 text-gray-200" : "bg-gray-50 border-gray-200 text-gray-700"}` }, /* @__PURE__ */ React.createElement("div", { className: "uppercase tracking-[0.16em] opacity-75" }, "Preview Context"), /* @__PURE__ */ React.createElement("div", { className: "mt-2" }, (spec == null ? void 0 : spec.title) || "Visualization Preview"), /* @__PURE__ */ React.createElement("div", { className: `mt-1 ${subtextClass}` }, (spec == null ? void 0 : spec.summary_text) || "Generated from chartable query results.")), sourceQueryPreview ? /* @__PURE__ */ React.createElement("div", { className: `mt-4 rounded-xl border px-3 py-3 text-xs ${isDarkTheme ? "bg-gray-950 border-gray-700 text-gray-200" : "bg-gray-50 border-gray-200 text-gray-700"}` }, /* @__PURE__ */ React.createElement("div", { className: "uppercase tracking-[0.16em] opacity-75" }, "Source SPL"), /* @__PURE__ */ React.createElement("pre", { className: "mt-2 max-h-24 overflow-auto whitespace-pre-wrap break-all font-mono text-[11px]" }, sourceQueryPreview)) : /* @__PURE__ */ React.createElement("div", { className: `mt-4 rounded-xl border px-3 py-3 text-xs ${isDarkTheme ? "bg-gray-950 border-gray-700 text-gray-400" : "bg-gray-50 border-gray-200 text-gray-500"}` }, "No source SPL query was attached to this visualization preview."), /* @__PURE__ */ React.createElement("div", { className: "mt-4 flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between" }, sourceQueryPreview ? renderSplQueryActionButtons(sourceQueryPreview, {
            originKind: "visualization_preview",
            originLabel: (spec == null ? void 0 : spec.title) || "Visualization Preview",
            sourceLabel: (spec == null ? void 0 : spec.title) || "Visualization Preview",
            contextExcerpt: (spec == null ? void 0 : spec.summary_text) || (spec == null ? void 0 : spec.title) || "",
            className: "sm:justify-start"
          }) : /* @__PURE__ */ React.createElement("div", { className: `text-xs ${mutedTextClass}` }, "SPL actions appear when a source query is attached."), /* @__PURE__ */ React.createElement(
            "button",
            {
              type: "button",
              onClick: closeSelectionCard,
              className: `px-3 py-2 rounded-lg text-xs font-semibold border ${isDarkTheme ? "border-gray-600 bg-gray-800 text-gray-100 hover:bg-gray-700" : "border-gray-300 bg-white text-gray-700 hover:bg-gray-50"}`
            },
            "Close"
          )))
        )
      );
    };
    if (chartType === "line") {
      const polylinePoints = points.map((point, index) => {
        const x = buildXForIndex(index);
        const y = getY(point.value);
        return `${x},${y}`;
      }).join(" ");
      const xTickStep = points.length > 6 ? 2 : 1;
      return /* @__PURE__ */ React.createElement("div", { "data-testid": `${chartTestId}-root`, className: `relative mt-2 rounded-lg border p-3 ${isDarkTheme ? "bg-gray-900 border-gray-700" : "bg-white border-gray-200"}` }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-wrap items-start justify-between gap-2 mb-3" }, /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("div", { className: `text-sm font-semibold ${headingClass}` }, (spec == null ? void 0 : spec.title) || "Trend Preview"), /* @__PURE__ */ React.createElement("div", { className: `text-xs ${subtextClass}` }, (spec == null ? void 0 : spec.summary_text) || "Generated from chartable query results.")), /* @__PURE__ */ React.createElement("div", { className: "flex flex-wrap gap-2 text-[11px]" }, /* @__PURE__ */ React.createElement("span", { className: `inline-flex items-center rounded-full px-2 py-0.5 border ${isDarkTheme ? "bg-sky-900 text-sky-100 border-sky-700" : "bg-sky-100 text-sky-800 border-sky-300"}` }, "line"), (spec == null ? void 0 : spec.y_field) && /* @__PURE__ */ React.createElement("span", { className: `inline-flex items-center rounded-full px-2 py-0.5 border ${isDarkTheme ? "bg-gray-800 text-gray-200 border-gray-600" : "bg-gray-50 text-gray-700 border-gray-300"}` }, spec.y_field))), /* @__PURE__ */ React.createElement("div", { className: "flex flex-wrap items-center gap-2 mb-3 text-[11px]" }, /* @__PURE__ */ React.createElement("span", { className: `inline-flex items-center gap-2 rounded-full px-2.5 py-1 border ${isDarkTheme ? "bg-sky-950 text-sky-100 border-sky-800" : "bg-sky-50 text-sky-800 border-sky-200"}` }, /* @__PURE__ */ React.createElement("span", { className: "inline-block h-2.5 w-2.5 rounded-full", style: { backgroundColor: plotColor } }), /* @__PURE__ */ React.createElement("span", { className: "font-medium" }, yAxisLabel)), /* @__PURE__ */ React.createElement("span", { className: `inline-flex items-center rounded-full px-2.5 py-1 border ${isDarkTheme ? "bg-gray-800 text-gray-200 border-gray-600" : "bg-gray-50 text-gray-700 border-gray-300"}` }, "X-axis: ", xAxisLabel), /* @__PURE__ */ React.createElement("span", { className: `inline-flex items-center rounded-full px-2.5 py-1 border ${isDarkTheme ? "bg-gray-800 text-gray-200 border-gray-600" : "bg-gray-50 text-gray-700 border-gray-300"}` }, "Y-axis: ", yAxisLabel)), /* @__PURE__ */ React.createElement("svg", { "data-testid": `${chartTestId}-svg`, viewBox: `0 0 ${width} ${height}`, className: "w-full h-52 overflow-visible" }, yTicks.map((tick, index) => /* @__PURE__ */ React.createElement("g", { key: `line-tick-${index}` }, /* @__PURE__ */ React.createElement(
        "line",
        {
          x1: chartLeft,
          y1: tick.y,
          x2: chartRight,
          y2: tick.y,
          stroke: gridColor,
          strokeDasharray: "4 4",
          strokeWidth: "1"
        }
      ), /* @__PURE__ */ React.createElement(
        "text",
        {
          x: chartLeft - 10,
          y: tick.y + 4,
          textAnchor: "end",
          fill: axisTextColor,
          fontSize: "10"
        },
        formatVisualizationNumber(tick.value)
      ))), /* @__PURE__ */ React.createElement("line", { x1: chartLeft, y1: chartTop, x2: chartLeft, y2: chartBottom, stroke: axisColor, strokeWidth: "1.5" }), /* @__PURE__ */ React.createElement("line", { x1: chartLeft, y1: zeroLineY, x2: chartRight, y2: zeroLineY, stroke: axisColor, strokeWidth: "1.5" }), /* @__PURE__ */ React.createElement("text", { x: chartLeft, y: chartTop - 6, fill: axisTextColor, fontSize: "11", fontWeight: "600" }, yAxisLabel), /* @__PURE__ */ React.createElement(
        "polyline",
        {
          fill: "none",
          stroke: plotColor,
          strokeWidth: "3",
          strokeLinejoin: "round",
          strokeLinecap: "round",
          points: polylinePoints
        }
      ), points.map((point, index) => {
        const { isHighlighted, isSelected } = getPointState(index);
        const x = buildXForIndex(index);
        const y = getY(point.value);
        return /* @__PURE__ */ React.createElement("g", { key: `${point.fullLabel || point.label}-${index}` }, /* @__PURE__ */ React.createElement("title", null, `${point.fullLabel || point.label}: ${formatVisualizationNumber(point.value)}`), isHighlighted && /* @__PURE__ */ React.createElement("circle", { cx: x, cy: y, r: isSelected ? 11 : 9, fill: highlightSurfaceColor, opacity: "0.78", pointerEvents: "none" }), /* @__PURE__ */ React.createElement(
          "circle",
          {
            "data-testid": `${chartTestId}-point-target`,
            cx: x,
            cy: y,
            r: "11",
            fill: "transparent",
            tabIndex: "0",
            focusable: "true",
            role: "button",
            "aria-label": `Inspect ${point.fullLabel || point.label}`,
            className: "cursor-pointer",
            onMouseEnter: () => activatePoint(index),
            onMouseLeave: clearHoveredPoint,
            onFocus: () => activatePoint(index),
            onBlur: clearHoveredPoint,
            onClick: () => toggleSelectedPoint(index),
            onKeyDown: (event2) => handleSelectableKeyDown(event2, index)
          }
        ), /* @__PURE__ */ React.createElement(
          "circle",
          {
            "data-testid": `${chartTestId}-point`,
            "data-highlighted": isHighlighted ? "true" : "false",
            "data-selected": isSelected ? "true" : "false",
            cx: x,
            cy: y,
            r: isSelected ? 5.5 : isHighlighted ? 5 : 4,
            fill: isHighlighted ? highlightSurfaceColor : plotAccentColor,
            stroke: isHighlighted ? highlightColor : plotColor,
            strokeWidth: isHighlighted ? "3" : "2",
            pointerEvents: "none"
          }
        ));
      }), points.map((point, index) => {
        if (index % xTickStep !== 0 && index !== points.length - 1) {
          return null;
        }
        const { isHighlighted, isSelected } = getPointState(index);
        const x = buildXForIndex(index);
        return /* @__PURE__ */ React.createElement("g", { key: `${point.fullLabel || point.label}-axis-${index}` }, /* @__PURE__ */ React.createElement("line", { x1: x, y1: chartBottom, x2: x, y2: chartBottom + 5, stroke: axisColor, strokeWidth: "1" }), /* @__PURE__ */ React.createElement(
          "text",
          {
            "data-testid": `${chartTestId}-axis-label`,
            x,
            y: chartBottom + 20,
            textAnchor: "middle",
            fill: isHighlighted ? highlightColor : axisTextColor,
            fontSize: "10",
            fontWeight: isSelected ? "700" : isHighlighted ? "600" : "400"
          },
          point.label
        ));
      })), /* @__PURE__ */ React.createElement("div", { className: "grid grid-cols-2 sm:grid-cols-4 gap-2 mt-3" }, points.map((point, index) => {
        const { isHighlighted, isSelected } = getPointState(index);
        const boxClass = isHighlighted ? chartType === "line" ? isDarkTheme ? "bg-sky-950 border-sky-500" : "bg-sky-50 border-sky-300" : isDarkTheme ? "bg-cyan-950 border-cyan-500" : "bg-cyan-50 border-cyan-300" : isDarkTheme ? "bg-gray-950 border-gray-700" : "bg-gray-50 border-gray-200";
        return /* @__PURE__ */ React.createElement(
          "button",
          {
            key: `${point.fullLabel || point.label}-${index}`,
            type: "button",
            "data-testid": `${chartTestId}-data-box`,
            "data-highlighted": isHighlighted ? "true" : "false",
            "data-selected": isSelected ? "true" : "false",
            onMouseEnter: () => activatePoint(index),
            onMouseLeave: clearHoveredPoint,
            onFocus: () => activatePoint(index),
            onBlur: clearHoveredPoint,
            onClick: () => toggleSelectedPoint(index),
            className: `rounded border px-2 py-1 text-left transition-colors ${boxClass}`,
            title: point.fullLabel || point.label,
            "aria-label": `Inspect ${point.fullLabel || point.label}`
          },
          /* @__PURE__ */ React.createElement("div", { className: `text-[10px] uppercase tracking-wide ${mutedTextClass}` }, truncateVisualizationLabel(point.fullLabel || point.label, 18)),
          /* @__PURE__ */ React.createElement("div", { className: `text-xs font-semibold ${headingClass}` }, formatVisualizationNumber(point.value))
        );
      })), renderSelectionCard());
    }
    return /* @__PURE__ */ React.createElement("div", { "data-testid": `${chartTestId}-root`, className: `relative mt-2 rounded-lg border p-3 ${isDarkTheme ? "bg-gray-900 border-gray-700" : "bg-white border-gray-200"}` }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-wrap items-start justify-between gap-2 mb-3" }, /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("div", { className: `text-sm font-semibold ${headingClass}` }, (spec == null ? void 0 : spec.title) || "Breakdown Preview"), /* @__PURE__ */ React.createElement("div", { className: `text-xs ${subtextClass}` }, (spec == null ? void 0 : spec.summary_text) || "Generated from chartable query results.")), /* @__PURE__ */ React.createElement("div", { className: "flex flex-wrap gap-2 text-[11px]" }, /* @__PURE__ */ React.createElement("span", { className: `inline-flex items-center rounded-full px-2 py-0.5 border ${isDarkTheme ? "bg-cyan-900 text-cyan-100 border-cyan-700" : "bg-cyan-100 text-cyan-800 border-cyan-300"}` }, "bar"), (spec == null ? void 0 : spec.y_field) && /* @__PURE__ */ React.createElement("span", { className: `inline-flex items-center rounded-full px-2 py-0.5 border ${isDarkTheme ? "bg-gray-800 text-gray-200 border-gray-600" : "bg-gray-50 text-gray-700 border-gray-300"}` }, spec.y_field))), /* @__PURE__ */ React.createElement("div", { className: "flex flex-wrap items-center gap-2 mb-3 text-[11px]" }, /* @__PURE__ */ React.createElement("span", { className: `inline-flex items-center gap-2 rounded-full px-2.5 py-1 border ${isDarkTheme ? "bg-cyan-950 text-cyan-100 border-cyan-800" : "bg-cyan-50 text-cyan-800 border-cyan-200"}` }, /* @__PURE__ */ React.createElement("span", { className: "inline-block h-2.5 w-2.5 rounded-sm", style: { backgroundColor: plotColor } }), /* @__PURE__ */ React.createElement("span", { className: "font-medium" }, yAxisLabel)), /* @__PURE__ */ React.createElement("span", { className: `inline-flex items-center rounded-full px-2.5 py-1 border ${isDarkTheme ? "bg-gray-800 text-gray-200 border-gray-600" : "bg-gray-50 text-gray-700 border-gray-300"}` }, "X-axis: ", xAxisLabel), /* @__PURE__ */ React.createElement("span", { className: `inline-flex items-center rounded-full px-2.5 py-1 border ${isDarkTheme ? "bg-gray-800 text-gray-200 border-gray-600" : "bg-gray-50 text-gray-700 border-gray-300"}` }, "Y-axis: ", yAxisLabel)), /* @__PURE__ */ React.createElement("svg", { "data-testid": `${chartTestId}-svg`, viewBox: `0 0 ${width} ${height}`, className: "w-full h-52 overflow-visible" }, yTicks.map((tick, index) => /* @__PURE__ */ React.createElement("g", { key: `bar-tick-${index}` }, /* @__PURE__ */ React.createElement(
      "line",
      {
        x1: chartLeft,
        y1: tick.y,
        x2: chartRight,
        y2: tick.y,
        stroke: gridColor,
        strokeDasharray: "4 4",
        strokeWidth: "1"
      }
    ), /* @__PURE__ */ React.createElement(
      "text",
      {
        x: chartLeft - 10,
        y: tick.y + 4,
        textAnchor: "end",
        fill: axisTextColor,
        fontSize: "10"
      },
      formatVisualizationNumber(tick.value)
    ))), /* @__PURE__ */ React.createElement("line", { x1: chartLeft, y1: chartTop, x2: chartLeft, y2: chartBottom, stroke: axisColor, strokeWidth: "1.5" }), /* @__PURE__ */ React.createElement("line", { x1: chartLeft, y1: zeroLineY, x2: chartRight, y2: zeroLineY, stroke: axisColor, strokeWidth: "1.5" }), /* @__PURE__ */ React.createElement("text", { x: chartLeft, y: chartTop - 6, fill: axisTextColor, fontSize: "11", fontWeight: "600" }, yAxisLabel), points.map((point, index) => {
      const { isHighlighted, isSelected } = getPointState(index);
      const rawLabel = point.fullLabel || point.label;
      const displayLabel = truncateVisualizationLabel(rawLabel, barLabelCharacterLimit);
      const x = chartLeft + barSlotWidth * index + (barSlotWidth - barWidth) / 2;
      const valueY = getY(point.value);
      const barHeight = Math.max(Math.abs(zeroLineY - valueY), 2);
      const barY = point.value >= 0 ? valueY : zeroLineY;
      const valueLabelY = point.value >= 0 ? Math.max(barY - 6, chartTop + 10) : Math.min(barY + barHeight + 12, chartBottom - 4);
      return /* @__PURE__ */ React.createElement(
        "g",
        {
          key: `${point.fullLabel || point.label}-${index}`,
          tabIndex: "0",
          focusable: "true",
          role: "button",
          "aria-label": `Inspect ${rawLabel}`,
          className: "cursor-pointer",
          onMouseEnter: () => activatePoint(index),
          onMouseLeave: clearHoveredPoint,
          onFocus: () => activatePoint(index),
          onBlur: clearHoveredPoint,
          onClick: () => toggleSelectedPoint(index),
          onKeyDown: (event2) => handleSelectableKeyDown(event2, index)
        },
        /* @__PURE__ */ React.createElement("title", null, `${rawLabel}: ${formatVisualizationNumber(point.value)}`),
        /* @__PURE__ */ React.createElement(
          "rect",
          {
            "data-testid": `${chartTestId}-rect`,
            "data-highlighted": isHighlighted ? "true" : "false",
            "data-selected": isSelected ? "true" : "false",
            x,
            y: barY,
            width: barWidth,
            height: barHeight,
            rx: "4",
            fill: isHighlighted ? highlightColor : plotColor,
            stroke: isSelected ? highlightSurfaceColor : "transparent",
            strokeWidth: isSelected ? "2" : "0"
          }
        ),
        /* @__PURE__ */ React.createElement("text", { x: x + barWidth / 2, y: valueLabelY, textAnchor: "middle", fill: isHighlighted ? highlightColor : axisTextColor, fontSize: "10", fontWeight: isSelected ? "700" : isHighlighted ? "600" : "400" }, formatVisualizationNumber(point.value)),
        /* @__PURE__ */ React.createElement(
          "text",
          {
            "data-testid": `${chartTestId}-axis-label`,
            "data-full-label": rawLabel,
            "data-truncated": displayLabel !== rawLabel ? "true" : "false",
            "aria-label": rawLabel,
            transform: `translate(${x + barWidth / 2} ${chartBottom + 28}) rotate(${barLabelRotation})`,
            textAnchor: "end",
            fill: isHighlighted ? highlightColor : axisTextColor,
            fontSize: "9",
            fontWeight: isSelected ? "700" : isHighlighted ? "600" : "400"
          },
          displayLabel
        )
      );
    })), /* @__PURE__ */ React.createElement("div", { className: "grid grid-cols-2 sm:grid-cols-4 gap-2 mt-3" }, points.map((point, index) => {
      const { isHighlighted, isSelected } = getPointState(index);
      const boxClass = isHighlighted ? isDarkTheme ? "bg-cyan-950 border-cyan-500" : "bg-cyan-50 border-cyan-300" : isDarkTheme ? "bg-gray-950 border-gray-700" : "bg-gray-50 border-gray-200";
      return /* @__PURE__ */ React.createElement(
        "button",
        {
          key: `${point.fullLabel || point.label}-${index}`,
          type: "button",
          "data-testid": `${chartTestId}-data-box`,
          "data-highlighted": isHighlighted ? "true" : "false",
          "data-selected": isSelected ? "true" : "false",
          onMouseEnter: () => activatePoint(index),
          onMouseLeave: clearHoveredPoint,
          onFocus: () => activatePoint(index),
          onBlur: clearHoveredPoint,
          onClick: () => toggleSelectedPoint(index),
          className: `rounded border px-2 py-1 text-left transition-colors ${boxClass}`,
          title: point.fullLabel || point.label,
          "aria-label": `Inspect ${point.fullLabel || point.label}`
        },
        /* @__PURE__ */ React.createElement("div", { className: `text-[10px] uppercase tracking-wide ${mutedTextClass}` }, truncateVisualizationLabel(point.fullLabel || point.label, 18)),
        /* @__PURE__ */ React.createElement("div", { className: `text-xs font-semibold ${headingClass}` }, formatVisualizationNumber(point.value))
      );
    })), renderSelectionCard());
  }
  function VisualizationRegressionHarness() {
    const regressionTheme = visualizationSearchParams.get("theme") === "dark" ? "dark" : "light";
    const isDarkTheme = regressionTheme === "dark";
    const headingClass = isDarkTheme ? "text-gray-100" : "text-gray-900";
    const subtextClass = isDarkTheme ? "text-gray-300" : "text-gray-600";
    const mutedTextClass = isDarkTheme ? "text-gray-300" : "text-gray-600";
    const regressionSplQuery = "search index=_internal | chart count by sourcetype";
    const openRegressionSplunkSearch = () => {
    };
    const denseBarSpec = {
      chart_type: "bar",
      title: "Dense Category Stress Test",
      summary_text: "Regression fixture for bar visibility and dense x-axis label readability.",
      x_field: "sourcetype",
      y_field: "event_count",
      points: [
        { label: "WinEventLog:Security:AuthenticationFailures-West", full_label: "WinEventLog:Security:AuthenticationFailures-West", value: 428461 },
        { label: "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational-HighVolume", full_label: "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational-HighVolume", value: 391208 },
        { label: "aws:cloudtrail:management-events-production", full_label: "aws:cloudtrail:management-events-production", value: 284932 },
        { label: "azure:sentinel:incidents:priority-one-escalations", full_label: "azure:sentinel:incidents:priority-one-escalations", value: 251447 },
        { label: "pan:traffic:internet-edge:critical-blocks", full_label: "pan:traffic:internet-edge:critical-blocks", value: 198764 },
        { label: "zeek:conn:long-duration-external-sessions", full_label: "zeek:conn:long-duration-external-sessions", value: 173025 },
        { label: "crowdstrike:fdr:identity-protection-detections", full_label: "crowdstrike:fdr:identity-protection-detections", value: 152981 },
        { label: "okta:system:policy-evaluation-anomalies", full_label: "okta:system:policy-evaluation-anomalies", value: 129604 }
      ]
    };
    const lineSpec = {
      chart_type: "line",
      title: "Trend Stability Fixture",
      summary_text: "Companion fixture to confirm line preview geometry remains intact.",
      x_field: "_time",
      y_field: "count",
      points: [
        { label: "14:00", full_label: "2026-04-19 14:00", value: 42 },
        { label: "15:00", full_label: "2026-04-19 15:00", value: 57 },
        { label: "16:00", full_label: "2026-04-19 16:00", value: 39 },
        { label: "17:00", full_label: "2026-04-19 17:00", value: 61 },
        { label: "18:00", full_label: "2026-04-19 18:00", value: 48 },
        { label: "19:00", full_label: "2026-04-19 19:00", value: 52 },
        { label: "20:00", full_label: "2026-04-19 20:00", value: 67 },
        { label: "21:00", full_label: "2026-04-19 21:00", value: 58 }
      ]
    };
    return /* @__PURE__ */ React.createElement("div", { "data-theme": regressionTheme, "data-testid": "visualization-regression-root", className: isDarkTheme ? "min-h-screen bg-gray-950 text-gray-100" : "min-h-screen bg-gray-100 text-gray-900" }, /* @__PURE__ */ React.createElement("div", { className: "max-w-6xl mx-auto px-6 py-8" }, /* @__PURE__ */ React.createElement("div", { className: `rounded-2xl border p-6 shadow-sm ${isDarkTheme ? "bg-gray-900 border-gray-700" : "bg-white border-gray-200"}` }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-col gap-2 mb-6" }, /* @__PURE__ */ React.createElement("div", { className: "text-xs font-semibold uppercase tracking-[0.2em] text-cyan-600" }, "Browser Regression Harness"), /* @__PURE__ */ React.createElement("h1", { className: `text-2xl font-bold ${headingClass}` }, "Visualization Preview Layout"), /* @__PURE__ */ React.createElement("p", { className: `text-sm ${subtextClass}` }, "Deterministic frontend fixture for catching collapsed bars, missing SVG geometry, and unreadable dense category labels.")), /* @__PURE__ */ React.createElement("div", { className: "grid grid-cols-1 gap-6" }, /* @__PURE__ */ React.createElement(
      VisualizationPreviewCard,
      {
        spec: denseBarSpec,
        isDarkTheme,
        headingClass,
        subtextClass,
        mutedTextClass,
        testIdPrefix: "visualization-regression-bar",
        sourceQuery: regressionSplQuery,
        canOpenSplunk: true,
        onOpenSplunk: openRegressionSplunkSearch
      }
    ), /* @__PURE__ */ React.createElement(
      VisualizationPreviewCard,
      {
        spec: lineSpec,
        isDarkTheme,
        headingClass,
        subtextClass,
        mutedTextClass,
        testIdPrefix: "visualization-regression-line",
        sourceQuery: regressionSplQuery,
        canOpenSplunk: true,
        onOpenSplunk: openRegressionSplunkSearch
      }
    )))));
  }
  function App() {
    var _a, _b, _c, _d, _e, _f, _g, _h, _i, _j, _k, _l, _m, _n, _o, _p, _q, _r, _s, _t, _u, _v, _w, _x, _y, _z, _A, _B, _C, _D, _E, _F, _G, _H, _I, _J, _K, _L, _M, _N, _O, _P, _Q, _R, _S, _T, _U, _V, _W, _X, _Y, _Z, __, _$, _aa, _ba, _ca, _da, _ea, _fa, _ga, _ha, _ia, _ja, _ka, _la, _ma, _na, _oa, _pa, _qa, _ra, _sa, _ta, _ua, _va, _wa, _xa, _ya, _za, _Aa, _Ba, _Ca, _Da, _Ea, _Fa, _Ga, _Ha, _Ia, _Ja, _Ka, _La, _Ma, _Na, _Oa, _Pa, _Qa, _Ra, _Sa, _Ta, _Ua, _Va, _Wa, _Xa, _ob, _pb, _qb, _rb, _sb, _tb, _ub, _vb, _wb, _xb, _yb;
    const THEME_PREFERENCE_KEY = "dt4sms_theme_preference";
    const OPERATOR_VOICE_PREFERENCE_KEY = "dt4sms_operator_voice";
    const OPERATOR_VOICE_OPTIONS = [
      { value: "direct", label: "Direct Ops", description: "Short, operational language focused on the next move." },
      { value: "evidence", label: "Evidence-led", description: "Validation-first language focused on proof and verification." },
      { value: "executive", label: "Executive Brief", description: "Outcome-led language focused on risk, impact, and investment." }
    ];
    const initialChatState = useRef(loadPersistedChatState()).current || {};
    const initialWelcomeSplashDismissed = useRef(loadWelcomeSplashDismissed()).current;
    const [isConnected, setIsConnected] = useState(false);
    const [discoveryStatus, setDiscoveryStatus] = useState("idle");
    const [messages, setMessages] = useState([]);
    const [progress, setProgress] = useState({ percentage: 0, description: "" });
    const [discoveryLastUpdatedAt, setDiscoveryLastUpdatedAt] = useState(null);
    const [discoveryCompletedAt, setDiscoveryCompletedAt] = useState(null);
    const [discoveryResultTimestamp, setDiscoveryResultTimestamp] = useState(null);
    const [discoverySessionId, setDiscoverySessionId] = useState(null);
    const [discoveryReportCount, setDiscoveryReportCount] = useState(0);
    const [discoveryErrorMessage, setDiscoveryErrorMessage] = useState("");
    const [discoveryPhasePlan, setDiscoveryPhasePlan] = useState([]);
    const [discoveryCurrentPhaseTitle, setDiscoveryCurrentPhaseTitle] = useState("");
    const [discoveryLastRunOutcome, setDiscoveryLastRunOutcome] = useState(null);
    const [discoveryActionDialog, setDiscoveryActionDialog] = useState(null);
    const [reports, setReports] = useState([]);
    const [sessionCatalog, setSessionCatalog] = useState([]);
    const [discoveryDashboard, setDiscoveryDashboard] = useState(null);
    const [v2Intelligence, setV2Intelligence] = useState(null);
    const [showAllIntelligencePatterns, setShowAllIntelligencePatterns] = useState(false);
    const [isAuthEnableInfoModalOpen, setIsAuthEnableInfoModalOpen] = useState(false);
    const [hasReviewedAuthEnableInfo, setHasReviewedAuthEnableInfo] = useState(false);
    const [pendingAuthEnableReview, setPendingAuthEnableReview] = useState(false);
    const [v2Artifacts, setV2Artifacts] = useState({ has_data: false, artifacts: [], count: 0 });
    const [workflowTab, setWorkflowTab] = useState("admin");
    const [compareSelection, setCompareSelection] = useState({ current: "latest", baseline: "previous" });
    const [discoveryCompare, setDiscoveryCompare] = useState(null);
    const [runbookPayload, setRunbookPayload] = useState(null);
    const [selectedReport, setSelectedReport] = useState(null);
    const [reportContent, setReportContent] = useState(null);
    const [isReportFullViewOpen, setIsReportFullViewOpen] = useState(false);
    const [expandedSessions, setExpandedSessions] = useState({});
    const [expandedYears, setExpandedYears] = useState({});
    const [expandedMonths, setExpandedMonths] = useState({});
    const [expandedDays, setExpandedDays] = useState({});
    const [isChatOpen, setIsChatOpen] = useState(false);
    const [isChatFullscreen, setIsChatFullscreen] = useState(false);
    const [chatMessages, setChatMessages] = useState(() => Array.isArray(initialChatState.chatMessages) ? initialChatState.chatMessages : []);
    const [chatInput, setChatInput] = useState("");
    const [isTyping, setIsTyping] = useState(false);
    const [chatStatus, setChatStatus] = useState("");
    const [isChatSettingsOpen, setIsChatSettingsOpen] = useState(false);
    const [chatSettings, setChatSettings] = useState(null);
    const [serverConversationHistory, setServerConversationHistory] = useState(() => Array.isArray(initialChatState.serverConversationHistory) ? initialChatState.serverConversationHistory : null);
    const [chatSessionId, setChatSessionId] = useState(() => {
      const persistedId = typeof initialChatState.chatSessionId === "string" ? initialChatState.chatSessionId.trim() : "";
      return persistedId || generateChatSessionId();
    });
    const [workspaceTab, setWorkspaceTab] = useState("mission");
    const [lastPrimaryWorkspaceTab, setLastPrimaryWorkspaceTab] = useState("mission");
    const [capabilitiesView, setCapabilitiesView] = useState("overview");
    const [connectionInfo, setConnectionInfo] = useState(null);
    const [discoveryStartTime, setDiscoveryStartTime] = useState(null);
    const [elapsedTime, setElapsedTime] = useState(0);
    const [isSummaryModalOpen, setIsSummaryModalOpen] = useState(false);
    const [isSummaryFullscreen, setIsSummaryFullscreen] = useState(false);
    const [summaryActionDialog, setSummaryActionDialog] = useState(null);
    const [summaryData, setSummaryData] = useState(null);
    const [isLoadingSummary, setIsLoadingSummary] = useState(false);
    const [currentSessionId, setCurrentSessionId] = useState(null);
    const [activeTab, setActiveTab] = useState("summary");
    const [queryFilter, setQueryFilter] = useState("all");
    const [queryFocus, setQueryFocus] = useState(null);
    const [taskFilter, setTaskFilter] = useState("all");
    const [riskFocus, setRiskFocus] = useState(null);
    const [showAllUnknownData, setShowAllUnknownData] = useState(false);
    const [summaryProgress, setSummaryProgress] = useState({
      stage: "idle",
      progress: 0,
      message: "Not started"
    });
    const [summaryInfographicCapability, setSummaryInfographicCapability] = useState({
      status: "idle",
      available: false,
      checkedSession: null,
      checkedProvider: null,
      canGenerate: false,
      hasExisting: false,
      existingArtifact: null,
      reason: ""
    });
    const [isGeneratingSummaryInfographic, setIsGeneratingSummaryInfographic] = useState(false);
    const [isAbortingSummary, setIsAbortingSummary] = useState(false);
    const [isSettingsOpen, setIsSettingsOpen] = useState(false);
    const [activeSettingsTab, setActiveSettingsTab] = useState("connections");
    const [config, setConfig] = useState(null);
    const [authStatus, setAuthStatus] = useState(null);
    const [securityUsers, setSecurityUsers] = useState([]);
    const [securityUserDrafts, setSecurityUserDrafts] = useState({});
    const [securityUsersState, setSecurityUsersState] = useState({ loading: false, error: "" });
    const [isSecurityUserComposerOpen, setIsSecurityUserComposerOpen] = useState(false);
    const [securityUserComposer, setSecurityUserComposer] = useState({
      username: "",
      password: "",
      role: "analyst",
      is_enabled: true,
      require_password_reset: true,
      mcp_config_name: ""
    });
    const [securityTokens, setSecurityTokens] = useState([]);
    const [securityTokensState, setSecurityTokensState] = useState({ loading: false, error: "" });
    const [isSecurityTokenComposerOpen, setIsSecurityTokenComposerOpen] = useState(false);
    const [securityTokenComposer, setSecurityTokenComposer] = useState({
      name: "",
      token_type: "external_api",
      scopes: ["rag:search", "rag:assets:read"],
      owner_user_id: "",
      expires_in_days: 30
    });
    const [securityTokenReveal, setSecurityTokenReveal] = useState(null);
    const [selectedProvider, setSelectedProvider] = useState("openai");
    const [isCredentialModalOpen, setIsCredentialModalOpen] = useState(false);
    const [isConnectionModalOpen, setIsConnectionModalOpen] = useState(false);
    const [connectionModalPosition, setConnectionModalPosition] = useState({ top: 72, left: 16, pointerLeft: 28 });
    const [credentialName, setCredentialName] = useState("");
    const [savedCredentials, setSavedCredentials] = useState({});
    const [loadedCredentialName, setLoadedCredentialName] = useState(null);
    const [isUpdateMode, setIsUpdateMode] = useState(false);
    const [isLoadingCredential, setIsLoadingCredential] = useState(false);
    const [apiKeyPlaceholder, setApiKeyPlaceholder] = useState("Enter API key");
    const [showConfigForm, setShowConfigForm] = useState(false);
    const [availableModels, setAvailableModels] = useState([]);
    const [isLoadingModels, setIsLoadingModels] = useState(false);
    const [selectedModel, setSelectedModel] = useState("");
    const SPL_LIBRARY_ASSET_TYPE = "spl_query_library";
    const defaultRagAssetDraft = {
      title: "",
      asset_type: "reference_document",
      source_label: "",
      description: "",
      tags: "",
      content: ""
    };
    const [ragAssetDraft, setRagAssetDraft] = useState(() => ({ ...defaultRagAssetDraft }));
    const [ragAssetUploadFile, setRagAssetUploadFile] = useState(null);
    const [capabilitiesData, setCapabilitiesData] = useState({
      status: "idle",
      summary: { total: 0, installed: 0, enabled: 0, ready: 0, restart_required: 0 },
      capabilities: {},
      error: ""
    });
    const [capabilityDrafts, setCapabilityDrafts] = useState({});
    const [capabilityActionState, setCapabilityActionState] = useState({});
    const [capabilityNotice, setCapabilityNotice] = useState(null);
    const [selectedCapabilityDetailName, setSelectedCapabilityDetailName] = useState(null);
    const [deeplinkDrafts, setDeeplinkDrafts] = useState({
      splunk_deeplink_tools: {
        query: "search index=_internal | head 20",
        earliest: "-24h",
        latest: "now",
        app: "search"
      }
    });
    const [deeplinkBuildResults, setDeeplinkBuildResults] = useState({});
    const [exportBuildState, setExportBuildState] = useState({
      status: "idle",
      bundle: null,
      error: ""
    });
    const [ragAssetWorkspace, setRagAssetWorkspace] = useState({
      status: "idle",
      summary: {
        asset_count: 0,
        asset_type_counts: {},
        asset_dir: "",
        checked_in_asset_count: 0,
        checked_out_asset_count: 0,
        library_status_counts: { checked_in: 0, checked_out: 0 }
      },
      assets: [],
      contextPreview: null,
      detailAssetId: null,
      assetDetail: null,
      detailStatus: "idle",
      detailError: "",
      error: ""
    });
    const [ragContextQuery, setRagContextQuery] = useState("");
    const [ragContextLimit, setRagContextLimit] = useState(4);
    const [ragLibraryFilter, setRagLibraryFilter] = useState("all");
    const [headerHeight, setHeaderHeight] = useState(88);
    const [savedMCPConfigs, setSavedMCPConfigs] = useState({});
    const [loadedMCPConfigName, setLoadedMCPConfigName] = useState(null);
    const [isMCPSaveModalOpen, setIsMCPSaveModalOpen] = useState(false);
    const [mcpConfigName, setMCPConfigName] = useState("");
    const [mcpConfigDescription, setMCPConfigDescription] = useState("");
    const [showMCPConfigForm, setShowMCPConfigForm] = useState(false);
    const [mcpTokenPlaceholder, setMCPTokenPlaceholder] = useState("Enter token");
    const [showSuggestedQueries, setShowSuggestedQueries] = useState(false);
    const [isWelcomeSplashOpen, setIsWelcomeSplashOpen] = useState(() => !initialWelcomeSplashDismissed);
    const [hasDismissedWelcomeSplash, setHasDismissedWelcomeSplash] = useState(() => initialWelcomeSplashDismissed);
    const [welcomeSplashDoNotShowAgain, setWelcomeSplashDoNotShowAgain] = useState(() => initialWelcomeSplashDismissed);
    const [themePreference, setThemePreference] = useState(() => {
      try {
        const savedTheme = localStorage.getItem(THEME_PREFERENCE_KEY);
        if (savedTheme === "light" || savedTheme === "dark" || savedTheme === "system") {
          return savedTheme;
        }
      } catch (error) {
        console.error("Failed to read theme preference:", error);
      }
      return "system";
    });
    const [operatorVoice, setOperatorVoice] = useState(() => {
      try {
        const savedVoice = localStorage.getItem(OPERATOR_VOICE_PREFERENCE_KEY);
        if (OPERATOR_VOICE_OPTIONS.some((option) => option.value === savedVoice)) {
          return savedVoice;
        }
      } catch (error) {
        console.error("Failed to read operator voice preference:", error);
      }
      return "direct";
    });
    const [resolvedTheme, setResolvedTheme] = useState("light");
    useEffect(() => {
      var _a2;
      if ((_a2 = config == null ? void 0 : config.security) == null ? void 0 : _a2.auth_enabled) {
        setHasReviewedAuthEnableInfo(true);
      }
    }, [(_a = config == null ? void 0 : config.security) == null ? void 0 : _a.auth_enabled]);
    useEffect(() => {
      if (isWelcomeSplashOpen) {
        setWelcomeSplashDoNotShowAgain(hasDismissedWelcomeSplash);
      }
    }, [isWelcomeSplashOpen, hasDismissedWelcomeSplash]);
    const securityConfig = (config == null ? void 0 : config.security) || {};
    const oidcStatus = ((_b = authStatus == null ? void 0 : authStatus.auth_provider_status) == null ? void 0 : _b.oidc) || null;
    const oidcCanEnableAuth = !!(oidcStatus == null ? void 0 : oidcStatus.can_enable_auth);
    const authProviderSelection = securityConfig.auth_provider || "local_password";
    const authEnableGateActive = !securityConfig.auth_enabled && !hasReviewedAuthEnableInfo;
    const isMissionTab = workspaceTab === "mission";
    const isIntelligenceTab = workspaceTab === "intelligence";
    const isArtifactsTab = workspaceTab === "artifacts";
    const isCapabilitiesTab = workspaceTab === "capabilities";
    const isChatTab = isChatFullscreen && workspaceTab === "chat";
    const isSummaryTab = isSummaryFullscreen && workspaceTab === "summary-workspace";
    const operatorVoiceDefinition = OPERATOR_VOICE_OPTIONS.find((option) => option.value === operatorVoice) || OPERATOR_VOICE_OPTIONS[0];
    const isCapabilitiesOverview = isCapabilitiesTab && capabilitiesView === "overview";
    const isCapabilitiesRagView = isCapabilitiesTab && capabilitiesView === "rag";
    const isDarkTheme = resolvedTheme === "dark";
    const normalizedSelectedModel = (selectedModel || ((_c = config == null ? void 0 : config.llm) == null ? void 0 : _c.model) || "").trim().toLowerCase();
    const isOpenAIImageModelSelected = selectedProvider === "openai" && normalizedSelectedModel.startsWith("gpt-image-");
    const panelClass = isDarkTheme ? "bg-gray-800 border-gray-700" : "bg-white border-gray-200";
    const panelMutedClass = isDarkTheme ? "bg-gray-700 border-gray-600" : "bg-gray-50 border-gray-200";
    const headingClass = isDarkTheme ? "text-gray-100" : "text-gray-900";
    const subtextClass = isDarkTheme ? "text-gray-300" : "text-gray-600";
    const mutedTextClass = isDarkTheme ? "text-gray-300" : "text-gray-600";
    const workspaceShellWidthClass = "max-w-[1800px]";
    const hasSelectedReport = Boolean(selectedReport && reportContent);
    const selectedMissionReportRecord = (Array.isArray(reports) ? reports : []).find((report) => report.name === selectedReport) || null;
    const selectedArtifactRecord = (Array.isArray(v2Artifacts == null ? void 0 : v2Artifacts.artifacts) ? v2Artifacts.artifacts : []).find((artifact) => artifact.name === selectedReport) || null;
    const selectedWorkspaceReportRecord = selectedArtifactRecord || selectedMissionReportRecord || null;
    const isMissionDiscoveryActive = discoveryStatus === "starting" || discoveryStatus === "running";
    const discoveryHasFocusedReport = isArtifactsTab && !!selectedMissionReportRecord && hasSelectedReport;
    const showWorkspaceRail = false;
    const workspaceShellClass = showWorkspaceRail ? "grid grid-cols-1 gap-6 lg:grid-cols-[minmax(0,1fr)_280px] xl:grid-cols-[minmax(0,1fr)_320px] 2xl:grid-cols-[minmax(0,1fr)_360px]" : "grid grid-cols-1 gap-6";
    const workspaceMainClass = "min-w-0";
    const workspaceRailClass = showWorkspaceRail ? "min-w-0 lg:sticky lg:top-24 lg:self-start" : "min-w-0";
    const workspaceRailPanelClass = showWorkspaceRail ? "lg:flex lg:max-h-[calc(100vh-8.5rem)] lg:flex-col" : "";
    const workspaceRailListClass = showWorkspaceRail ? "lg:flex-1 lg:overflow-y-auto" : "";
    const discoveryActivityShellClass = discoveryHasFocusedReport ? isMissionDiscoveryActive ? "grid grid-cols-1 gap-6 2xl:grid-cols-[minmax(0,1.26fr)_minmax(380px,0.92fr)]" : "grid grid-cols-1 gap-6 2xl:grid-cols-[minmax(0,0.92fr)_minmax(420px,1.14fr)]" : "space-y-6";
    const discoveryWorkspaceSplitClass = "grid grid-cols-1 gap-6 lg:grid-cols-3";
    const windowedChatDialogStyle = {
      height: "min(860px, calc(100dvh - 3rem))",
      maxHeight: "calc(100dvh - 3rem)"
    };
    const windowedSummaryDialogStyle = {
      height: "min(1040px, calc(100dvh - 3rem))",
      maxHeight: "calc(100dvh - 3rem)"
    };
    const capabilityOverlayTopOffset = Math.max(headerHeight, 0);
    const capabilityDetailOverlayStyle = {
      top: `${capabilityOverlayTopOffset}px`
    };
    const windowedCapabilityDetailDialogStyle = {
      maxHeight: `calc(100dvh - ${capabilityOverlayTopOffset}px - 1.5rem)`
    };
    const fullscreenChatConversationStyle = isChatTab ? {
      maxWidth: "min(96%, 112rem)",
      marginLeft: "auto",
      marginRight: "auto"
    } : void 0;
    const getChatBubbleStyle = (messageType) => {
      if (!isChatTab) {
        return void 0;
      }
      if (messageType === "user") {
        return { maxWidth: "min(72%, 60rem)" };
      }
      return { maxWidth: "100%" };
    };
    const capabilityList = Object.values((capabilitiesData == null ? void 0 : capabilitiesData.capabilities) || {});
    const genericCapabilityList = capabilityList.filter((capability) => capability.name !== "rag_chromadb");
    const deeplinkCapability = ((_d = capabilitiesData == null ? void 0 : capabilitiesData.capabilities) == null ? void 0 : _d.splunk_deeplink_tools) || null;
    const exportCapability = ((_e = capabilitiesData == null ? void 0 : capabilitiesData.capabilities) == null ? void 0 : _e.export_tools) || null;
    const ragCapability = ((_f = capabilitiesData == null ? void 0 : capabilitiesData.capabilities) == null ? void 0 : _f.rag_chromadb) || null;
    const selectedCapabilityDetail = selectedCapabilityDetailName ? ((_g = capabilitiesData == null ? void 0 : capabilitiesData.capabilities) == null ? void 0 : _g[selectedCapabilityDetailName]) || null : null;
    const ragIndexSummary = (ragCapability == null ? void 0 : ragCapability.index_summary) && typeof ragCapability.index_summary === "object" ? ragCapability.index_summary : null;
    const ragIndexedDocumentCount = Number((ragIndexSummary == null ? void 0 : ragIndexSummary.document_count) || 0);
    const ragKnowledgeAssetSummary = (ragCapability == null ? void 0 : ragCapability.knowledge_asset_summary) && typeof (ragCapability == null ? void 0 : ragCapability.knowledge_asset_summary) === "object" ? ragCapability.knowledge_asset_summary : null;
    const ragIndexSourceTypes = (ragIndexSummary == null ? void 0 : ragIndexSummary.source_type_counts) && typeof ragIndexSummary.source_type_counts === "object" ? Object.entries(ragIndexSummary.source_type_counts) : [];
    const ragKnowledgeAssetTypeCounts = Object.entries(((_h = ragAssetWorkspace.summary) == null ? void 0 : _h.asset_type_counts) || (ragKnowledgeAssetSummary == null ? void 0 : ragKnowledgeAssetSummary.asset_type_counts) || {});
    const ragDisplayedAssets = Array.isArray(ragAssetWorkspace.assets) ? ragAssetWorkspace.assets : [];
    const ragDisplayedAssetCount = (_k = (_j = (_i = ragAssetWorkspace.summary) == null ? void 0 : _i.asset_count) != null ? _j : ragKnowledgeAssetSummary == null ? void 0 : ragKnowledgeAssetSummary.asset_count) != null ? _k : 0;
    const ragDisplayedAssetDir = ((_l = ragAssetWorkspace.summary) == null ? void 0 : _l.asset_dir) || (ragKnowledgeAssetSummary == null ? void 0 : ragKnowledgeAssetSummary.asset_dir) || "output/rag/assets";
    const ragSplLibraryAssetCount = ragDisplayedAssets.filter((asset) => String((asset == null ? void 0 : asset.asset_type) || "").toLowerCase() === SPL_LIBRARY_ASSET_TYPE).length;
    const ragLibraryStatusCounts = ((_m = ragAssetWorkspace.summary) == null ? void 0 : _m.library_status_counts) && typeof ragAssetWorkspace.summary.library_status_counts === "object" ? ragAssetWorkspace.summary.library_status_counts : (ragKnowledgeAssetSummary == null ? void 0 : ragKnowledgeAssetSummary.library_status_counts) && typeof ragKnowledgeAssetSummary.library_status_counts === "object" ? ragKnowledgeAssetSummary.library_status_counts : { checked_in: 0, checked_out: 0 };
    const ragCheckedInAssetCount = (_p = (_o = (_n = ragAssetWorkspace.summary) == null ? void 0 : _n.checked_in_asset_count) != null ? _o : ragKnowledgeAssetSummary == null ? void 0 : ragKnowledgeAssetSummary.checked_in_asset_count) != null ? _p : ragDisplayedAssets.filter((asset) => String((asset == null ? void 0 : asset.library_status) || "checked_in").toLowerCase() !== "checked_out").length;
    const ragCheckedOutAssetCount = (_s = (_r = (_q = ragAssetWorkspace.summary) == null ? void 0 : _q.checked_out_asset_count) != null ? _r : ragKnowledgeAssetSummary == null ? void 0 : ragKnowledgeAssetSummary.checked_out_asset_count) != null ? _s : ragDisplayedAssets.filter((asset) => String((asset == null ? void 0 : asset.library_status) || "").toLowerCase() === "checked_out").length;
    const ragLibraryAssets = ragDisplayedAssets.filter((asset) => {
      const libraryStatus = String((asset == null ? void 0 : asset.library_status) || "checked_in").toLowerCase();
      if (ragLibraryFilter === "spl_library") {
        return String((asset == null ? void 0 : asset.asset_type) || "").toLowerCase() === SPL_LIBRARY_ASSET_TYPE;
      }
      if (ragLibraryFilter === "checked_in") {
        return libraryStatus !== "checked_out";
      }
      if (ragLibraryFilter === "checked_out") {
        return libraryStatus === "checked_out";
      }
      return true;
    });
    const ragLibraryAssetCount = ragLibraryAssets.length;
    const ragActionInProgress = (capabilityActionState == null ? void 0 : capabilityActionState.rag_chromadb) || "";
    const isRagBusy = !!ragActionInProgress;
    const ragStatusLabel = (ragCapability == null ? void 0 : ragCapability.health_status) || "unknown";
    const canInstallRag = !!(ragCapability == null ? void 0 : ragCapability.runtime_available) && !(ragCapability == null ? void 0 : ragCapability.installed);
    const canEnableRag = !!(ragCapability == null ? void 0 : ragCapability.installed) && !(ragCapability == null ? void 0 : ragCapability.enabled) && !(ragCapability == null ? void 0 : ragCapability.restart_required);
    const canDisableRag = !!(ragCapability == null ? void 0 : ragCapability.installed) && !!(ragCapability == null ? void 0 : ragCapability.enabled);
    const canTestRag = !!(ragCapability == null ? void 0 : ragCapability.installed);
    const canReindexRag = !!(ragCapability == null ? void 0 : ragCapability.installed) && !(ragCapability == null ? void 0 : ragCapability.restart_required);
    const canUseSplunkDeeplinks = !!(deeplinkCapability == null ? void 0 : deeplinkCapability.installed) && !!(deeplinkCapability == null ? void 0 : deeplinkCapability.enabled) && !(deeplinkCapability == null ? void 0 : deeplinkCapability.restart_required) && String((deeplinkCapability == null ? void 0 : deeplinkCapability.health_status) || "").toLowerCase() === "ready";
    const canUseExportTools = !!(exportCapability == null ? void 0 : exportCapability.installed) && !!(exportCapability == null ? void 0 : exportCapability.enabled) && !(exportCapability == null ? void 0 : exportCapability.restart_required) && String((exportCapability == null ? void 0 : exportCapability.health_status) || "").toLowerCase() === "ready";
    const parseMissionSessionDate = (value) => {
      if (!value) {
        return null;
      }
      if (value instanceof Date && !Number.isNaN(value.getTime())) {
        return value;
      }
      const rawValue = String(value || "").trim();
      if (!rawValue) {
        return null;
      }
      const parsedValue = new Date(rawValue);
      if (!Number.isNaN(parsedValue.getTime())) {
        return parsedValue;
      }
      if (/^\d{8}_\d{6}$/.test(rawValue)) {
        const datePart = rawValue.slice(0, 8);
        const timePart = rawValue.slice(9);
        const normalizedValue = `${datePart.slice(0, 4)}-${datePart.slice(4, 6)}-${datePart.slice(6, 8)}T${timePart.slice(0, 2)}:${timePart.slice(2, 4)}:${timePart.slice(4, 6)}`;
        const timestampValue = new Date(normalizedValue);
        if (!Number.isNaN(timestampValue.getTime())) {
          return timestampValue;
        }
      }
      return null;
    };
    const formatMissionDateTime = (value, fallback = "Unknown") => {
      const parsedValue = parseMissionSessionDate(value);
      return parsedValue ? parsedValue.toLocaleString() : fallback;
    };
    const formatMissionSessionSelectionLabel = (value) => {
      const normalizedValue = String(value || "").trim();
      if (!normalizedValue || normalizedValue === "latest") {
        return "Latest session";
      }
      if (normalizedValue === "previous") {
        return "Previous session";
      }
      return formatMissionDateTime(normalizedValue, normalizedValue);
    };
    const formatDiscoveryRuntimeDuration = (value, fallback = "Unknown") => {
      const numericValue = Number(value);
      if (!Number.isFinite(numericValue) || numericValue < 0) {
        return fallback;
      }
      const totalSeconds = Math.round(numericValue);
      const hours = Math.floor(totalSeconds / 3600);
      const mins = Math.floor(totalSeconds % 3600 / 60);
      const secs = totalSeconds % 60;
      if (hours > 0) {
        return `${hours}h ${mins.toString().padStart(2, "0")}m`;
      }
      return `${mins}:${secs.toString().padStart(2, "0")}`;
    };
    const normalizeDiscoveryStatusValue = (value) => {
      const normalizedValue = String(value || "").trim().toLowerCase();
      return ["idle", "starting", "running", "completed", "error", "aborted"].includes(normalizedValue) ? normalizedValue : "idle";
    };
    const formatMissionMetricValue = (value, fallback = "0") => {
      if (value === null || value === void 0 || value === "") {
        return fallback;
      }
      const numericValue = Number(value);
      if (Number.isFinite(numericValue)) {
        return numericValue.toLocaleString();
      }
      return String(value);
    };
    const formatMissionTrendValue = (value) => {
      const numericValue = Number(value);
      if (!Number.isFinite(numericValue) || numericValue === 0) {
        return "No change";
      }
      return `${numericValue > 0 ? "+" : ""}${numericValue.toLocaleString()}`;
    };
    const getMissionFreshnessMeta = (value) => {
      const parsedValue = parseMissionSessionDate(value);
      if (!parsedValue) {
        return {
          label: "Snapshot age unavailable",
          ageLabel: "age unavailable",
          ageHours: null,
          badgeClass: isDarkTheme ? "bg-gray-900 text-gray-200 border border-gray-700" : "bg-gray-100 text-gray-700 border border-gray-200",
          summary: "DT4SMS is showing the latest saved mission snapshot, but the recorded capture time is unavailable."
        };
      }
      const ageHours = Math.max(0, Math.floor((Date.now() - parsedValue.getTime()) / 36e5));
      const ageDays = Math.floor(ageHours / 24);
      const ageLabel = ageDays >= 1 ? `${ageDays} day${ageDays === 1 ? "" : "s"} old` : `${ageHours} hour${ageHours === 1 ? "" : "s"} old`;
      if (ageHours >= 72) {
        return {
          label: "Stale mission snapshot",
          ageLabel,
          ageHours,
          badgeClass: isDarkTheme ? "bg-amber-950 text-amber-100 border border-amber-700" : "bg-amber-50 text-amber-800 border border-amber-200",
          summary: `The latest discovery session is ${ageLabel}. Re-run discovery before relying on this mission surface for current operational decisions.`
        };
      }
      if (ageHours >= 24) {
        return {
          label: "Aging mission snapshot",
          ageLabel,
          ageHours,
          badgeClass: isDarkTheme ? "bg-blue-950 text-blue-100 border border-blue-700" : "bg-blue-50 text-blue-800 border border-blue-200",
          summary: `The latest discovery session is ${ageLabel}. The mission view is still useful, but a refresh would tighten the action picture.`
        };
      }
      return {
        label: "Fresh mission snapshot",
        ageLabel,
        ageHours,
        badgeClass: isDarkTheme ? "bg-emerald-950 text-emerald-100 border border-emerald-700" : "bg-emerald-50 text-emerald-800 border border-emerald-200",
        summary: `The latest discovery session is ${ageLabel}. This mission view is current enough to drive immediate action planning.`
      };
    };
    const discoveryStatusNormalized = normalizeDiscoveryStatusValue(discoveryStatus);
    const discoveryProgressPercent = Math.round(Math.max(0, Math.min(100, Number((progress == null ? void 0 : progress.percentage) || 0))));
    const discoveryEtaMethodLabel = String((progress == null ? void 0 : progress.eta_method) || "").trim() === "stage_calibrated" ? "Stage-calibrated ETA" : "ETA";
    const discoveryEtaLabel = (progress == null ? void 0 : progress.eta_seconds) != null ? formatDiscoveryRuntimeDuration(progress.eta_seconds, "Calculating") : isMissionDiscoveryActive ? "Calibrating" : "Not active";
    const discoveryUpdatedLabel = discoveryLastUpdatedAt ? formatMissionDateTime(discoveryLastUpdatedAt, "Awaiting update") : isMissionDiscoveryActive ? "Live updates pending" : "No recent run";
    const discoveryCompletedLabel = discoveryCompletedAt ? formatMissionDateTime(discoveryCompletedAt, "Not completed yet") : discoveryStatusNormalized === "completed" ? "Completed now" : "Not completed yet";
    const discoveryResultSessionLabel = discoveryResultTimestamp ? formatMissionSessionSelectionLabel(discoveryResultTimestamp) : "No completed session";
    const discoveryPhaseEntries = Array.isArray(discoveryPhasePlan) ? discoveryPhasePlan : [];
    const discoveryActivePhase = discoveryPhaseEntries.find((phase) => phase.status === "active") || null;
    const discoveryCompletedPhaseCount = discoveryPhaseEntries.filter((phase) => phase.status === "completed").length;
    const discoveryAllStagesComplete = discoveryPhaseEntries.length > 0 && discoveryPhaseEntries.every((phase) => String((phase == null ? void 0 : phase.status) || "pending").trim().toLowerCase() === "completed");
    const discoverySummarySessionTimestamp = discoveryResultTimestamp || (discoveryLastRunOutcome == null ? void 0 : discoveryLastRunOutcome.result_timestamp) || null;
    const discoverySummarySession = discoverySummarySessionTimestamp ? sessionCatalog.find((session) => (session == null ? void 0 : session.timestamp) === discoverySummarySessionTimestamp) || {
      timestamp: discoverySummarySessionTimestamp,
      hasSummary: false
    } : null;
    const isDiscoverySummaryReady = discoveryStatusNormalized === "completed" && discoveryAllStagesComplete && !!discoverySummarySessionTimestamp;
    const discoveryPhaseLeadTitle = (discoveryActivePhase == null ? void 0 : discoveryActivePhase.title) || discoveryCurrentPhaseTitle || (discoveryLastRunOutcome == null ? void 0 : discoveryLastRunOutcome.phase_title) || "Awaiting next run";
    const discoveryStatusMeta = (() => {
      switch (discoveryStatusNormalized) {
        case "starting":
          return {
            label: "Starting discovery",
            shortValue: "Starting",
            summary: "Discovery is preparing the runtime. You can move to another workspace and use the header monitor to jump back here.",
            monitorLabel: "Header live",
            bannerTitle: "Discovery startup is underway",
            statusBadgeClass: isDarkTheme ? "bg-amber-950 text-amber-100 border border-amber-700" : "bg-amber-50 text-amber-800 border border-amber-200",
            headerChipClass: isDarkTheme ? "bg-amber-950/60 border-amber-700 text-amber-100" : "bg-amber-50 border-amber-200 text-amber-900",
            tonePanelClass: isDarkTheme ? "bg-amber-950/40 border-amber-700" : "bg-amber-50 border-amber-200",
            toneTextClass: isDarkTheme ? "text-amber-100" : "text-amber-900",
            dotClass: "bg-amber-500",
            progressTrackClass: isDarkTheme ? "bg-amber-950/70" : "bg-white/80",
            progressFillClass: "bg-amber-500"
          };
        case "running":
          return {
            label: "Discovery running",
            shortValue: "Running",
            summary: "Discovery is streaming live progress. Leave this workspace if needed; the header monitor will stay active until the run completes.",
            monitorLabel: "Header live",
            bannerTitle: "Discovery is actively collecting and packaging outputs",
            statusBadgeClass: isDarkTheme ? "bg-indigo-950 text-indigo-100 border border-indigo-700" : "bg-indigo-50 text-indigo-800 border border-indigo-200",
            headerChipClass: isDarkTheme ? "bg-indigo-950/60 border-indigo-700 text-indigo-100" : "bg-indigo-50 border-indigo-200 text-indigo-900",
            tonePanelClass: isDarkTheme ? "bg-indigo-950/50 border-indigo-700" : "bg-indigo-50 border-indigo-200",
            toneTextClass: isDarkTheme ? "text-indigo-100" : "text-indigo-950",
            dotClass: "bg-indigo-500",
            progressTrackClass: isDarkTheme ? "bg-indigo-950/70" : "bg-white/80",
            progressFillClass: "bg-indigo-600"
          };
        case "completed":
          return {
            label: "Discovery complete",
            shortValue: "Done",
            summary: "Discovery finished successfully and the outputs are ready for review. The header monitor now marks the last run outcome until you start another run.",
            monitorLabel: "Outcome pinned",
            bannerTitle: "Discovery outputs are ready for review",
            statusBadgeClass: isDarkTheme ? "bg-emerald-950 text-emerald-100 border border-emerald-700" : "bg-emerald-50 text-emerald-800 border border-emerald-200",
            headerChipClass: isDarkTheme ? "bg-emerald-950/60 border-emerald-700 text-emerald-100" : "bg-emerald-50 border-emerald-200 text-emerald-900",
            tonePanelClass: isDarkTheme ? "bg-emerald-950/45 border-emerald-700" : "bg-emerald-50 border-emerald-200",
            toneTextClass: isDarkTheme ? "text-emerald-100" : "text-emerald-900",
            dotClass: "bg-emerald-500",
            progressTrackClass: isDarkTheme ? "bg-emerald-950/70" : "bg-white/80",
            progressFillClass: "bg-emerald-600"
          };
        case "error":
          return {
            label: "Discovery issue",
            shortValue: "Issue",
            summary: "Discovery ended with an error. Review the live log, correct the blocking issue, and then retry the run.",
            monitorLabel: "Needs attention",
            bannerTitle: "Discovery stopped on an error",
            statusBadgeClass: isDarkTheme ? "bg-rose-950 text-rose-100 border border-rose-700" : "bg-rose-50 text-rose-800 border border-rose-200",
            headerChipClass: isDarkTheme ? "bg-rose-950/60 border-rose-700 text-rose-100" : "bg-rose-50 border-rose-200 text-rose-900",
            tonePanelClass: isDarkTheme ? "bg-rose-950/45 border-rose-700" : "bg-rose-50 border-rose-200",
            toneTextClass: isDarkTheme ? "text-rose-100" : "text-rose-900",
            dotClass: "bg-rose-500",
            progressTrackClass: isDarkTheme ? "bg-rose-950/70" : "bg-white/80",
            progressFillClass: "bg-rose-600"
          };
        case "aborted":
          return {
            label: "Discovery stopped",
            shortValue: "Stopped",
            summary: "Discovery was stopped by the operator. Review the partial log context or start a fresh run when you are ready.",
            monitorLabel: "Stopped",
            bannerTitle: "Discovery was stopped before completion",
            statusBadgeClass: isDarkTheme ? "bg-orange-950 text-orange-100 border border-orange-700" : "bg-orange-50 text-orange-800 border border-orange-200",
            headerChipClass: isDarkTheme ? "bg-orange-950/60 border-orange-700 text-orange-100" : "bg-orange-50 border-orange-200 text-orange-900",
            tonePanelClass: isDarkTheme ? "bg-orange-950/45 border-orange-700" : "bg-orange-50 border-orange-200",
            toneTextClass: isDarkTheme ? "text-orange-100" : "text-orange-900",
            dotClass: "bg-orange-500",
            progressTrackClass: isDarkTheme ? "bg-orange-950/70" : "bg-white/80",
            progressFillClass: "bg-orange-600"
          };
        case "idle":
        default:
          return {
            label: "Discovery ready",
            shortValue: "Ready",
            summary: "Discovery is ready to run. Start from here and the header monitor will stay visible across the workspace while the pipeline is active.",
            monitorLabel: "Standby",
            bannerTitle: "Discovery control center is ready",
            statusBadgeClass: isDarkTheme ? "bg-gray-900 text-gray-100 border border-gray-700" : "bg-gray-50 text-gray-800 border border-gray-200",
            headerChipClass: isDarkTheme ? "bg-gray-800 border-gray-600 text-gray-100" : "bg-white border-gray-300 text-gray-900",
            tonePanelClass: isDarkTheme ? "bg-gray-900 border-gray-700" : "bg-gray-50 border-gray-200",
            toneTextClass: isDarkTheme ? "text-gray-100" : "text-gray-900",
            dotClass: "bg-gray-400",
            progressTrackClass: isDarkTheme ? "bg-gray-800" : "bg-white",
            progressFillClass: "bg-slate-500"
          };
      }
    })();
    const discoveryHeaderChipLabel = isMissionDiscoveryActive ? `Discovery ${Math.max(discoveryProgressPercent, 1)}%` : `Discovery ${discoveryStatusMeta.shortValue}`;
    const discoveryNarrative = (() => {
      if (isMissionDiscoveryActive) {
        return discoveryActivePhase ? `${discoveryActivePhase.label} is active. ${progress.description || discoveryActivePhase.description || "Streaming live discovery activity across the pipeline."}` : progress.description || "Streaming live discovery activity across the pipeline.";
      }
      if (discoveryStatusNormalized === "completed") {
        return discoveryReportCount > 0 ? `${discoveryReportCount} output artifact(s) are ready for ${discoveryResultSessionLabel}.` : "Discovery completed successfully and outputs are ready for review.";
      }
      if (discoveryStatusNormalized === "error") {
        return discoveryErrorMessage || "Discovery failed before outputs were fully assembled.";
      }
      if (discoveryStatusNormalized === "aborted") {
        return "Discovery was stopped before completion. Review the current log or start a fresh run.";
      }
      return "Start a run here, then move across Mission, Intelligence, or Context while the header monitor keeps the live state visible.";
    })();
    const missionDiscoveryMonitorCard = (() => {
      if (isMissionDiscoveryActive) {
        return {
          title: `${(discoveryActivePhase == null ? void 0 : discoveryActivePhase.label) || "Discovery"} is active`,
          summary: progress.description || "Discovery is live. Use the ledger to see the active stage without reading the full log.",
          detail: `${discoveryEtaMethodLabel}: ${discoveryEtaLabel}`,
          meta: `${discoveryProgressPercent}% complete • Last update ${discoveryUpdatedLabel}`,
          ctaLabel: "Open Discovery"
        };
      }
      if (discoveryLastRunOutcome) {
        const outcomeTimestamp = discoveryLastRunOutcome.completed_at || discoveryLastRunOutcome.result_timestamp || discoveryCompletedAt;
        return {
          title: discoveryLastRunOutcome.title || "Last discovery outcome",
          summary: discoveryLastRunOutcome.summary || "The latest discovery outcome is pinned here for operator handoff.",
          detail: outcomeTimestamp ? `Recorded ${formatMissionDateTime(outcomeTimestamp, "at the latest checkpoint")}` : `Phase anchor: ${discoveryLastRunOutcome.phase_title || discoveryPhaseLeadTitle}`,
          meta: discoveryLastRunOutcome.report_count > 0 ? `${discoveryLastRunOutcome.report_count} output artifact(s) available` : discoveryLastRunOutcome.error || `Phase anchor: ${discoveryLastRunOutcome.phase_title || discoveryPhaseLeadTitle}`,
          ctaLabel: "Review Discovery"
        };
      }
      return {
        title: "No recent runtime handoff",
        summary: "Run discovery to pin the live outcome here so Mission and Discovery share the same operator handoff state.",
        detail: "This card updates from the shared runtime monitor, not from the historical session log.",
        meta: "Use the Discovery control center to start the next run.",
        ctaLabel: "Open Discovery"
      };
    })();
    const selectedPackageSessionLabel = formatMissionSessionSelectionLabel(compareSelection.current);
    const activePackageBundle = exportBuildState.bundle || (exportCapability == null ? void 0 : exportCapability.latest_bundle) || null;
    const hasFreshPackageBuild = !!exportBuildState.bundle;
    const packageCardTitle = hasFreshPackageBuild ? "Current Report Package" : "Last Built Report Package";
    const downloadPackageLabel = hasFreshPackageBuild ? "Download Package" : "Download Last Package";
    const packagePersonaLabel = workflowTab ? `${workflowTab.charAt(0).toUpperCase()}${workflowTab.slice(1)}` : "Persona";
    const packageTargetLabel = `${selectedPackageSessionLabel} / ${packagePersonaLabel} persona / ${operatorVoiceDefinition.label} voice`;
    const canUseRagContextPreview = !!(ragCapability == null ? void 0 : ragCapability.installed) && !!(ragCapability == null ? void 0 : ragCapability.enabled) && !(ragCapability == null ? void 0 : ragCapability.restart_required) && String((ragCapability == null ? void 0 : ragCapability.health_status) || "").toLowerCase() === "ready" && ragIndexedDocumentCount > 0;
    const activeDetailPreviewTrace = (() => {
      var _a2, _b2, _c2;
      const detailAssetId = ((_b2 = (_a2 = ragAssetWorkspace.assetDetail) == null ? void 0 : _a2.asset) == null ? void 0 : _b2.asset_id) || ragAssetWorkspace.detailAssetId;
      if (!detailAssetId) {
        return { matchedChunkIds: [] };
      }
      const matchedAssets = Array.isArray((_c2 = ragAssetWorkspace.contextPreview) == null ? void 0 : _c2.matched_assets) ? ragAssetWorkspace.contextPreview.matched_assets : [];
      const matchedAsset = matchedAssets.find((asset) => (asset == null ? void 0 : asset.asset_id) === detailAssetId);
      const matchedChunkIds = Array.isArray(matchedAsset == null ? void 0 : matchedAsset.matched_chunk_ids) ? matchedAsset.matched_chunk_ids.filter(Boolean) : Array.isArray(matchedAsset == null ? void 0 : matchedAsset.matched_chunks) ? matchedAsset.matched_chunks.map((chunk) => chunk == null ? void 0 : chunk.document_id).filter(Boolean) : [];
      return { matchedChunkIds };
    })();
    const v2Blueprint = (v2Intelligence == null ? void 0 : v2Intelligence.blueprint) || null;
    const v2Overview = (v2Blueprint == null ? void 0 : v2Blueprint.overview) || {};
    const v2CapabilityGraph = (v2Blueprint == null ? void 0 : v2Blueprint.capability_graph) || {};
    const v2CoverageGaps = Array.isArray(v2Blueprint == null ? void 0 : v2Blueprint.coverage_gaps) ? v2Blueprint.coverage_gaps : [];
    const v2FindingLedger = Array.isArray(v2Blueprint == null ? void 0 : v2Blueprint.finding_ledger) ? v2Blueprint.finding_ledger : [];
    const v2UseCases = Array.isArray(v2Blueprint == null ? void 0 : v2Blueprint.suggested_use_cases) ? v2Blueprint.suggested_use_cases : [];
    const getNormalizedLine = (value, fallback = "") => {
      const normalized = String(value || "").replace(/\s+/g, " ").trim();
      return normalized || fallback;
    };
    const formatIntelligencePatternLabel = (value, fallback = "Pattern") => {
      const cleaned = getNormalizedLine(value);
      if (!cleaned) {
        return fallback;
      }
      if (!/[_-]/.test(cleaned)) {
        return cleaned;
      }
      return cleaned.split(/[_-]+/).map((part) => {
        const normalized = part.toLowerCase();
        if (normalized === "llm") return "LLM";
        if (normalized === "mcp") return "MCP";
        if (normalized === "rag") return "RAG";
        return normalized.charAt(0).toUpperCase() + normalized.slice(1);
      }).join(" ");
    };
    const getIntelligencePatternEyebrowLabel = (pattern, idx) => {
      const tokenSource = getNormalizedLine((pattern == null ? void 0 : pattern.category) || (pattern == null ? void 0 : pattern.title));
      const normalizedTokens = tokenSource.toLowerCase();
      if (normalizedTokens.includes("volume") || normalizedTokens.includes("distribution")) {
        return "Volume profile";
      }
      if (normalizedTokens.includes("index")) {
        return "Index posture";
      }
      if (normalizedTokens.includes("source")) {
        return "Source mix";
      }
      if (normalizedTokens.includes("temporal") || normalizedTokens.includes("time")) {
        return "Time pattern";
      }
      if (normalizedTokens.includes("quality")) {
        return "Quality signal";
      }
      if (normalizedTokens.includes("security")) {
        return "Security signal";
      }
      const categoryLabel = formatIntelligencePatternLabel(pattern == null ? void 0 : pattern.category, "");
      if (categoryLabel) {
        return categoryLabel;
      }
      return `Pattern ${idx + 1}`;
    };
    const normalizeIntelligencePatternComparisonText = (value) => getNormalizedLine(value).toLowerCase().replace(/[_-]+/g, " ").replace(/[^a-z0-9 ]+/g, " ").replace(/\s+/g, " ").trim();
    const getDistinctIntelligencePatternEvidence = (pattern) => {
      const comparisonSources = [pattern == null ? void 0 : pattern.title, pattern == null ? void 0 : pattern.description, pattern == null ? void 0 : pattern.signal].map((item) => normalizeIntelligencePatternComparisonText(item)).filter(Boolean);
      const evidenceItems = Array.isArray(pattern == null ? void 0 : pattern.evidence) ? pattern.evidence : [];
      const seenEvidence = /* @__PURE__ */ new Set();
      return evidenceItems.map((item) => getNormalizedLine(item)).filter(Boolean).filter((item) => {
        const normalizedEvidence = normalizeIntelligencePatternComparisonText(item);
        if (!normalizedEvidence || seenEvidence.has(normalizedEvidence)) {
          return false;
        }
        seenEvidence.add(normalizedEvidence);
        return !comparisonSources.some((source) => source === normalizedEvidence || source.includes(normalizedEvidence) || normalizedEvidence.includes(source));
      });
    };
    const formatOperatorPriorityLabel = (value) => {
      const normalized = getNormalizedLine(value, "medium").toLowerCase();
      return normalized.charAt(0).toUpperCase() + normalized.slice(1);
    };
    const getOperatorPriorityClasses = (value) => {
      switch (String(value || "").trim().toLowerCase()) {
        case "high":
        case "critical":
          return isDarkTheme ? "bg-rose-950 border-rose-800 text-rose-100" : "bg-rose-50 border-rose-200 text-rose-800";
        case "low":
          return isDarkTheme ? "bg-sky-950 border-sky-800 text-sky-100" : "bg-sky-50 border-sky-200 text-sky-800";
        case "medium":
        default:
          return isDarkTheme ? "bg-amber-950 border-amber-800 text-amber-100" : "bg-amber-50 border-amber-200 text-amber-800";
      }
    };
    const buildOperatorVoiceAdminCard = (action, voice) => {
      const title = getNormalizedLine(action == null ? void 0 : action.title, "Admin control follow-up");
      const why = getNormalizedLine(action == null ? void 0 : action.why, "This control path needs a concrete owner and implementation sequence.");
      const nextStep = getNormalizedLine(action == null ? void 0 : action.next_step, "Review the full runbook for sequencing.");
      const effort = getNormalizedLine(action == null ? void 0 : action.effort, "unknown");
      switch (voice) {
        case "evidence":
          return {
            title,
            summary: why,
            meta: `Evidence path: ${nextStep}`,
            badge: `Validation effort: ${effort}`
          };
        case "executive":
          return {
            title,
            summary: `Risk if ignored: ${why}`,
            meta: `Leadership ask: ${nextStep}`,
            badge: `Investment shape: ${effort}`
          };
        case "direct":
        default:
          return {
            title,
            summary: why,
            meta: `Next move: ${nextStep}`,
            badge: `Effort lane: ${effort}`
          };
      }
    };
    const buildOperatorVoiceAnalystCard = (track, voice) => {
      const title = getNormalizedLine(track == null ? void 0 : track.title, "Investigation track");
      const question = getNormalizedLine(track == null ? void 0 : track.question, "Define the detection hypothesis and validate it against current telemetry.");
      const successMetric = getNormalizedLine(track == null ? void 0 : track.success_metric, "Define a measurable validation path in the runbook.");
      switch (voice) {
        case "evidence":
          return {
            title,
            summary: question,
            meta: `Validation signal: ${successMetric}`
          };
        case "executive":
          return {
            title,
            summary: `If confirmed: ${question}`,
            meta: `Why it matters: ${successMetric}`
          };
        case "direct":
        default:
          return {
            title,
            summary: `Test now: ${question}`,
            meta: `Success signal: ${successMetric}`
          };
      }
    };
    const buildOperatorVoiceExecutiveItem = (item, voice, idx, type = "theme") => {
      const summary = getNormalizedLine(item, "No executive framing was captured.");
      if (voice === "evidence") {
        return {
          title: type === "theme" ? `Evidence Theme ${idx + 1}` : `90-Day Validation ${idx + 1}`,
          summary,
          meta: type === "theme" ? "Use this to justify telemetry and control investment." : "Use this to set measurable leadership checkpoints."
        };
      }
      if (voice === "executive") {
        return {
          title: type === "theme" ? `Board Theme ${idx + 1}` : `Quarter Priority ${idx + 1}`,
          summary,
          meta: type === "theme" ? "Frame this as business exposure and resilience upside." : "Carry this into the next planning cycle with an accountable owner."
        };
      }
      return {
        title: type === "theme" ? `Value Lever ${idx + 1}` : `90-Day Move ${idx + 1}`,
        summary,
        meta: type === "theme" ? "Use this to align the next operator handoff." : "Turn this into a scheduled operating move."
      };
    };
    const summarizeFindingEntry = (entry) => {
      const findings = Array.isArray(entry == null ? void 0 : entry.findings) ? entry.findings.filter(Boolean) : [];
      return getNormalizedLine(findings[0], "Review the ledger entry for the full signal chain.");
    };
    const latestMissionSession = (discoveryDashboard == null ? void 0 : discoveryDashboard.latest) || null;
    const missionOverview = (latestMissionSession == null ? void 0 : latestMissionSession.overview) || {};
    const missionStats = (latestMissionSession == null ? void 0 : latestMissionSession.stats) || {};
    const missionFreshness = getMissionFreshnessMeta((latestMissionSession == null ? void 0 : latestMissionSession.created_at) || (latestMissionSession == null ? void 0 : latestMissionSession.timestamp));
    const missionHasPreviousSession = !!(discoveryDashboard == null ? void 0 : discoveryDashboard.previous);
    const missionReportCount = Array.isArray(latestMissionSession == null ? void 0 : latestMissionSession.report_paths) ? latestMissionSession.report_paths.length : 0;
    const missionAdminActions = Array.isArray((_u = (_t = latestMissionSession == null ? void 0 : latestMissionSession.personas) == null ? void 0 : _t.admin) == null ? void 0 : _u.actions) ? latestMissionSession.personas.admin.actions : [];
    const missionAnalystTracks = Array.isArray((_w = (_v = latestMissionSession == null ? void 0 : latestMissionSession.personas) == null ? void 0 : _v.analyst) == null ? void 0 : _w.hypotheses) ? latestMissionSession.personas.analyst.hypotheses : [];
    const missionExecutiveThemes = Array.isArray((_y = (_x = latestMissionSession == null ? void 0 : latestMissionSession.personas) == null ? void 0 : _x.executive) == null ? void 0 : _y.business_value_themes) ? latestMissionSession.personas.executive.business_value_themes : [];
    const missionExecutiveFocus = Array.isArray((_A = (_z = latestMissionSession == null ? void 0 : latestMissionSession.personas) == null ? void 0 : _z.executive) == null ? void 0 : _A.next_90_day_focus) ? latestMissionSession.personas.executive.next_90_day_focus : [];
    const missionExecutiveHeadline = ((_C = (_B = latestMissionSession == null ? void 0 : latestMissionSession.personas) == null ? void 0 : _B.executive) == null ? void 0 : _C.headline) || `Readiness sits at ${formatMissionMetricValue((_D = discoveryDashboard == null ? void 0 : discoveryDashboard.kpis) == null ? void 0 : _D.readiness_score)} / 100 with ${formatMissionMetricValue((_E = discoveryDashboard == null ? void 0 : discoveryDashboard.kpis) == null ? void 0 : _E.recommendation_count)} recommendation(s) queued for follow-up.`;
    const missionWhyNow = missionFreshness.ageHours == null ? "Mission view is running from the latest saved discovery snapshot available in DT4SMS." : missionFreshness.ageHours >= 72 ? `This mission snapshot is ${missionFreshness.ageLabel}. Re-run discovery before treating these counts and action queues as current.` : `This mission snapshot is ${missionFreshness.ageLabel} and ready to drive immediate operator, analyst, and executive follow-up.`;
    const missionSummaryCards = [
      {
        label: "Hosts Observed",
        value: formatMissionMetricValue(missionOverview.total_hosts),
        detail: `${formatMissionMetricValue(missionOverview.total_sources, "0")} sources mapped in the latest snapshot.`,
        shellClass: isDarkTheme ? "bg-blue-950 border-blue-800" : "bg-blue-50 border-blue-200",
        labelClass: isDarkTheme ? "text-blue-200" : "text-blue-800",
        valueClass: isDarkTheme ? "text-blue-50" : "text-blue-950"
      },
      {
        label: "Data Volume (24h)",
        value: missionOverview.data_volume_24h || "Unknown",
        detail: missionOverview.splunk_version ? `Splunk ${missionOverview.splunk_version}${missionOverview.license_state ? ` • License ${missionOverview.license_state}` : ""}` : "Splunk version and license state were not captured.",
        shellClass: isDarkTheme ? "bg-emerald-950 border-emerald-800" : "bg-emerald-50 border-emerald-200",
        labelClass: isDarkTheme ? "text-emerald-200" : "text-emerald-800",
        valueClass: isDarkTheme ? "text-emerald-50" : "text-emerald-950"
      },
      {
        label: "Action Pressure",
        value: formatMissionMetricValue(missionStats.recommendation_count || ((_F = discoveryDashboard == null ? void 0 : discoveryDashboard.kpis) == null ? void 0 : _F.recommendation_count)),
        detail: `${formatMissionMetricValue(missionStats.suggested_use_case_count, "0")} suggested use case(s) and ${formatMissionMetricValue(missionAdminActions.length, "0")} admin queue item(s).`,
        shellClass: isDarkTheme ? "bg-amber-950 border-amber-800" : "bg-amber-50 border-amber-200",
        labelClass: isDarkTheme ? "text-amber-200" : "text-amber-900",
        valueClass: isDarkTheme ? "text-amber-50" : "text-amber-950"
      },
      {
        label: "Evidence Bundle",
        value: formatMissionMetricValue(missionStats.discovery_steps),
        detail: `${formatMissionMetricValue(missionReportCount, "0")} report artifact(s) and ${formatMissionMetricValue((_G = discoveryDashboard == null ? void 0 : discoveryDashboard.kpis) == null ? void 0 : _G.tool_count)} MCP tool(s) in scope.`,
        shellClass: isDarkTheme ? "bg-purple-950 border-purple-800" : "bg-purple-50 border-purple-200",
        labelClass: isDarkTheme ? "text-purple-200" : "text-purple-800",
        valueClass: isDarkTheme ? "text-purple-50" : "text-purple-950"
      }
    ];
    const missionChangeCards = [
      {
        label: "Readiness Shift",
        value: formatMissionTrendValue((_H = discoveryDashboard == null ? void 0 : discoveryDashboard.trends) == null ? void 0 : _H.readiness_delta),
        detail: "Score movement versus the previous discovery run.",
        shellClass: isDarkTheme ? "bg-indigo-950 border-indigo-800" : "bg-indigo-50 border-indigo-200",
        labelClass: isDarkTheme ? "text-indigo-200" : "text-indigo-800",
        valueClass: isDarkTheme ? "text-indigo-50" : "text-indigo-950"
      },
      {
        label: "Index Drift",
        value: formatMissionTrendValue((_I = discoveryDashboard == null ? void 0 : discoveryDashboard.trends) == null ? void 0 : _I.indexes_delta),
        detail: "New or removed indexes since the previous run.",
        shellClass: isDarkTheme ? "bg-blue-950 border-blue-800" : "bg-blue-50 border-blue-200",
        labelClass: isDarkTheme ? "text-blue-200" : "text-blue-800",
        valueClass: isDarkTheme ? "text-blue-50" : "text-blue-950"
      },
      {
        label: "Sourcetype Drift",
        value: formatMissionTrendValue((_J = discoveryDashboard == null ? void 0 : discoveryDashboard.trends) == null ? void 0 : _J.sourcetypes_delta),
        detail: "Telemetry coverage movement across sourcetypes.",
        shellClass: isDarkTheme ? "bg-emerald-950 border-emerald-800" : "bg-emerald-50 border-emerald-200",
        labelClass: isDarkTheme ? "text-emerald-200" : "text-emerald-800",
        valueClass: isDarkTheme ? "text-emerald-50" : "text-emerald-950"
      },
      {
        label: "Recommendation Load",
        value: formatMissionTrendValue((_K = discoveryDashboard == null ? void 0 : discoveryDashboard.trends) == null ? void 0 : _K.recommendations_delta),
        detail: "Change in recommended follow-up work since the last run.",
        shellClass: isDarkTheme ? "bg-amber-950 border-amber-800" : "bg-amber-50 border-amber-200",
        labelClass: isDarkTheme ? "text-amber-200" : "text-amber-900",
        valueClass: isDarkTheme ? "text-amber-50" : "text-amber-950"
      }
    ];
    const missionAdminVoiceCards = missionAdminActions.slice(0, 3).map((action) => buildOperatorVoiceAdminCard(action, operatorVoice));
    const missionAnalystVoiceCards = missionAnalystTracks.slice(0, 3).map((track) => buildOperatorVoiceAnalystCard(track, operatorVoice));
    const missionExecutiveSourceItems = missionExecutiveThemes.length > 0 ? missionExecutiveThemes : missionExecutiveFocus;
    const missionExecutiveVoiceCards = missionExecutiveSourceItems.slice(0, 3).map((item, idx) => buildOperatorVoiceExecutiveItem(item, operatorVoice, idx, missionExecutiveThemes.length > 0 ? "theme" : "focus"));
    const missionRunbookAdminCards = missionAdminActions.slice(0, 6).map((action) => buildOperatorVoiceAdminCard(action, operatorVoice));
    const missionRunbookAnalystCards = missionAnalystTracks.slice(0, 6).map((track) => buildOperatorVoiceAnalystCard(track, operatorVoice));
    const missionRunbookExecutiveCards = missionExecutiveSourceItems.slice(0, 6).map((item, idx) => buildOperatorVoiceExecutiveItem(item, operatorVoice, idx, missionExecutiveThemes.length > 0 ? "theme" : "focus"));
    const intelligenceGapCount = v2CoverageGaps.length;
    const intelligenceFindingCount = v2FindingLedger.length;
    const intelligenceUseCaseCount = v2UseCases.length;
    const intelligenceTopGap = v2CoverageGaps[0] || null;
    const intelligenceTopUseCase = v2UseCases[0] || null;
    const intelligenceTopFinding = v2FindingLedger[0] || null;
    const intelligenceNotablePatterns = Array.isArray(v2Intelligence == null ? void 0 : v2Intelligence.notable_patterns) ? v2Intelligence.notable_patterns.filter((pattern) => pattern && typeof pattern === "object") : [];
    const intelligencePatternDisplayLimit = 3;
    const hasExpandableIntelligencePatterns = intelligenceNotablePatterns.length > intelligencePatternDisplayLimit;
    const visibleIntelligenceNotablePatterns = showAllIntelligencePatterns ? intelligenceNotablePatterns : intelligenceNotablePatterns.slice(0, intelligencePatternDisplayLimit);
    const intelligenceExecutiveSourceItems = v2UseCases.map((item) => getNormalizedLine(item == null ? void 0 : item.business_value)).filter(Boolean);
    const intelligenceExecutivePatternItems = intelligenceNotablePatterns.map((pattern) => getNormalizedLine((pattern == null ? void 0 : pattern.description) || (pattern == null ? void 0 : pattern.signal) || (pattern == null ? void 0 : pattern.title))).filter(Boolean);
    const intelligenceHeadline = (() => {
      if (operatorVoice === "evidence") {
        return `${formatMissionMetricValue(intelligenceGapCount)} coverage gap(s), ${formatMissionMetricValue(intelligenceUseCaseCount)} usable investigations, and ${formatMissionMetricValue(intelligenceFindingCount)} evidence entries are ready for verification.`;
      }
      if (operatorVoice === "executive") {
        return `${formatMissionMetricValue(intelligenceGapCount)} intelligence gap(s) and ${formatMissionMetricValue(intelligenceUseCaseCount)} activation paths now shape the next telemetry and control investment conversation.`;
      }
      return `${formatMissionMetricValue(intelligenceGapCount)} high-value gap(s) and ${formatMissionMetricValue(intelligenceUseCaseCount)} investigation path(s) are ready for immediate action.`;
    })();
    const intelligenceWhyNow = (() => {
      if (operatorVoice === "evidence") {
        return `Use the blueprint to verify blind spots, confirm the highest-signal findings, and decide which suggested use cases deserve analyst time first. ${missionFreshness.summary}`;
      }
      if (operatorVoice === "executive") {
        return `Use the blueprint to decide which telemetry gaps create the largest exposure and which use cases deserve funded follow-up. ${missionFreshness.summary}`;
      }
      return `Use the blueprint to call the next telemetry fix, the next investigation, and the next leadership handoff without digging through the raw discovery output first. ${missionFreshness.summary}`;
    })();
    const intelligenceSummaryCards = [
      {
        label: "Coverage Gaps",
        value: formatMissionMetricValue(intelligenceGapCount),
        detail: (intelligenceTopGap == null ? void 0 : intelligenceTopGap.gap) ? `Top gap: ${intelligenceTopGap.gap}` : "No high-priority gaps were recorded in this blueprint.",
        shellClass: isDarkTheme ? "bg-rose-950 border-rose-800" : "bg-rose-50 border-rose-200",
        labelClass: isDarkTheme ? "text-rose-200" : "text-rose-800",
        valueClass: isDarkTheme ? "text-rose-50" : "text-rose-950"
      },
      {
        label: "Investigation Paths",
        value: formatMissionMetricValue(intelligenceUseCaseCount),
        detail: (intelligenceTopUseCase == null ? void 0 : intelligenceTopUseCase.title) ? `Lead use case: ${intelligenceTopUseCase.title}` : "No use cases were generated from the current blueprint.",
        shellClass: isDarkTheme ? "bg-indigo-950 border-indigo-800" : "bg-indigo-50 border-indigo-200",
        labelClass: isDarkTheme ? "text-indigo-200" : "text-indigo-800",
        valueClass: isDarkTheme ? "text-indigo-50" : "text-indigo-950"
      },
      {
        label: "Evidence Logged",
        value: formatMissionMetricValue(intelligenceFindingCount),
        detail: (intelligenceTopFinding == null ? void 0 : intelligenceTopFinding.title) ? `First signal: ${intelligenceTopFinding.title}` : "No evidence ledger entries were captured.",
        shellClass: isDarkTheme ? "bg-emerald-950 border-emerald-800" : "bg-emerald-50 border-emerald-200",
        labelClass: isDarkTheme ? "text-emerald-200" : "text-emerald-800",
        valueClass: isDarkTheme ? "text-emerald-50" : "text-emerald-950"
      },
      {
        label: "Operational Surface",
        value: formatMissionMetricValue(v2Overview.total_hosts),
        detail: `${formatMissionMetricValue(v2Overview.total_indexes)} indexes, ${formatMissionMetricValue(v2Overview.total_sourcetypes)} sourcetypes, ${formatMissionMetricValue(v2Overview.total_sources)} sources.`,
        shellClass: isDarkTheme ? "bg-blue-950 border-blue-800" : "bg-blue-50 border-blue-200",
        labelClass: isDarkTheme ? "text-blue-200" : "text-blue-800",
        valueClass: isDarkTheme ? "text-blue-50" : "text-blue-950"
      }
    ];
    const intelligencePriorityBoard = [
      {
        label: "Top Coverage Gap",
        detail: (intelligenceTopGap == null ? void 0 : intelligenceTopGap.why_it_matters) || "No major gap narrative was captured in the current blueprint.",
        badge: formatOperatorPriorityLabel(intelligenceTopGap == null ? void 0 : intelligenceTopGap.priority),
        badgeClass: getOperatorPriorityClasses(intelligenceTopGap == null ? void 0 : intelligenceTopGap.priority)
      },
      {
        label: "Top Investigation",
        detail: (intelligenceTopUseCase == null ? void 0 : intelligenceTopUseCase.description) || (intelligenceTopUseCase == null ? void 0 : intelligenceTopUseCase.scenario) || "No suggested investigation was generated in the current blueprint.",
        badge: (intelligenceTopUseCase == null ? void 0 : intelligenceTopUseCase.implementation_complexity) ? `Complexity ${intelligenceTopUseCase.implementation_complexity}` : "Complexity unknown",
        badgeClass: getOperatorPriorityClasses((intelligenceTopUseCase == null ? void 0 : intelligenceTopUseCase.implementation_complexity) === "high" ? "high" : "medium")
      },
      {
        label: "Latest Signal",
        detail: summarizeFindingEntry(intelligenceTopFinding),
        badge: (intelligenceTopFinding == null ? void 0 : intelligenceTopFinding.timestamp) ? formatMissionDateTime(intelligenceTopFinding.timestamp, "Captured") : "Captured in ledger",
        badgeClass: isDarkTheme ? "bg-gray-900 border-gray-700 text-gray-200" : "bg-gray-100 border-gray-300 text-gray-700"
      }
    ];
    const intelligenceAdminBriefs = v2CoverageGaps.slice(0, 3).map((gap) => buildOperatorVoiceAdminCard({
      title: (gap == null ? void 0 : gap.gap) || "Coverage gap",
      why: (gap == null ? void 0 : gap.why_it_matters) || "This telemetry blind spot needs a concrete control plan.",
      effort: (gap == null ? void 0 : gap.priority) || "medium",
      next_step: `Close the blind spot for ${(gap == null ? void 0 : gap.gap) || "this telemetry surface"} and validate it in the next discovery run.`
    }, operatorVoice));
    const intelligenceAnalystBriefs = v2UseCases.slice(0, 3).map((useCase) => buildOperatorVoiceAnalystCard({
      title: (useCase == null ? void 0 : useCase.title) || (useCase == null ? void 0 : useCase.name) || "Suggested investigation",
      question: (useCase == null ? void 0 : useCase.description) || (useCase == null ? void 0 : useCase.scenario) || "Define the investigation hypothesis for this use case.",
      success_metric: Array.isArray(useCase == null ? void 0 : useCase.success_metrics) && useCase.success_metrics[0] || (useCase == null ? void 0 : useCase.business_value) || "Prove measurable detection or response uplift."
    }, operatorVoice));
    const intelligenceExecutiveBriefs = (intelligenceExecutiveSourceItems.length > 0 ? intelligenceExecutiveSourceItems : intelligenceExecutivePatternItems).slice(0, 3).map((item, idx) => buildOperatorVoiceExecutiveItem(item, operatorVoice, idx, intelligenceExecutiveSourceItems.length > 0 ? "theme" : "focus"));
    const summaryStageOrder = {
      idle: 0,
      queued: 1,
      loading: 1,
      loading_reports: 1,
      generating_queries: 2,
      identifying_unknowns: 2,
      ai_analysis: 2,
      generating_summary: 3,
      creating_summary: 3,
      generating_tasks: 4,
      finalizing: 5,
      saving: 5,
      complete: 6,
      error: 0,
      interrupted: 0,
      aborted: 0
    };
    const summaryStageNormalized = String((summaryProgress == null ? void 0 : summaryProgress.stage) || "idle").trim().toLowerCase() || "idle";
    const summaryTerminalStages = ["complete", "error", "interrupted", "aborted"];
    const currentSummaryStep = summaryStageOrder[summaryStageNormalized] || 0;
    const isSummaryStepDone = (step) => summaryStageNormalized === "complete" || currentSummaryStep > step;
    const isSummaryStepActive = (step) => summaryStageNormalized !== "complete" && currentSummaryStep === step;
    const summaryWorkerPid = Number.isFinite(Number(summaryProgress == null ? void 0 : summaryProgress.worker_pid)) && Number(summaryProgress == null ? void 0 : summaryProgress.worker_pid) > 0 ? Number(summaryProgress.worker_pid) : null;
    const isSummaryWorkerActive = !!summaryWorkerPid && !summaryTerminalStages.includes(summaryStageNormalized);
    const normalizeSummaryProgressPayload = (payload, fallback = {}) => {
      const source = payload && typeof payload === "object" ? payload : fallback;
      return {
        ...source,
        stage: String((source == null ? void 0 : source.stage) || "idle").trim().toLowerCase() || "idle",
        progress: Math.max(0, Math.min(100, Number((source == null ? void 0 : source.progress) || 0))),
        message: String((source == null ? void 0 : source.message) || "Not started").trim() || "Not started",
        worker_pid: Number.isFinite(Number(source == null ? void 0 : source.worker_pid)) && Number(source == null ? void 0 : source.worker_pid) > 0 ? Number(source.worker_pid) : null,
        execution_mode: String((source == null ? void 0 : source.execution_mode) || "").trim().toLowerCase() || null
      };
    };
    const suggestedChatQueries = [
      "Give me a narrative overview of what our Splunk environment appears to prioritize operationally.",
      "What story do the current data sources tell about platform usage, reliability, and potential blind spots?",
      "If you were onboarding a new security lead, what should they review first and why?",
      "Describe likely risk trends we should monitor weekly, and how to validate whether they are improving.",
      "Identify where data quality issues could silently undermine detections or reporting confidence.",
      "Propose a practical 30-day hardening plan with quick wins, medium-term tasks, and measurable outcomes.",
      "Suggest a recursive analysis loop we can run each week to catch drift, anomalies, and hidden failure modes.",
      "Translate the discovery output into executive-ready priorities with business impact and verification steps."
    ];
    const handleSettingsChange = () => {
    };
    const handleApiKeyChange = () => {
      setApiKeyPlaceholder("Enter API key");
      handleSettingsChange();
    };
    const SECURITY_ROLE_OPTIONS = ["admin", "analyst", "viewer"];
    const SECURITY_TOKEN_SCOPE_OPTIONS = {
      external_api: [
        {
          value: "rag:search",
          label: "RAG Search",
          description: "Allow read-only RAG search and context retrieval."
        },
        {
          value: "rag:assets:read",
          label: "RAG Asset Read",
          description: "Allow index summary, asset listing, and asset detail reads."
        }
      ],
      inbound_mcp: [
        {
          value: "mcp:tools:read",
          label: "MCP Tool Read",
          description: "Allow read-only inbound MCP tool discovery and execution."
        }
      ]
    };
    const SETTINGS_MODAL_TABS = [
      { id: "connections", label: "Connections", icon: "fa-plug" },
      { id: "users", label: "Users", icon: "fa-users" },
      { id: "access", label: "MCP/API & Tokens", icon: "fa-key" }
    ];
    const escapeSettingsToastHtml = (value) => String(value || "").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");
    const getDefaultSecurityScopes = (tokenType) => {
      if (tokenType === "inbound_mcp") {
        return ["mcp:tools:read"];
      }
      return ["rag:search", "rag:assets:read"];
    };
    const buildSecurityUserDraft = (user) => ({
      role: (user == null ? void 0 : user.role) || "analyst",
      is_enabled: (user == null ? void 0 : user.is_enabled) !== false,
      require_password_reset: !!(user == null ? void 0 : user.require_password_reset),
      mcp_config_name: (user == null ? void 0 : user.mcp_config_name) || "",
      new_password: ""
    });
    const showSettingsToast = (title, message, tone = "success") => {
      const toneClasses = {
        success: "bg-green-600 text-white",
        error: "bg-red-600 text-white",
        warning: "bg-gradient-to-r from-amber-400 to-yellow-400 text-gray-900 border-2 border-amber-600",
        info: "bg-blue-600 text-white"
      };
      const toneIcons = {
        success: "fa-check-circle",
        error: "fa-times-circle",
        warning: "fa-exclamation-triangle",
        info: "fa-info-circle"
      };
      const toast = document.createElement("div");
      toast.className = `fixed top-6 right-6 ${toneClasses[tone] || toneClasses.info} px-6 py-4 rounded-xl shadow-2xl z-50`;
      toast.innerHTML = `
                    <div class="flex items-center gap-3">
                        <i class="fas ${toneIcons[tone] || toneIcons.info} text-2xl"></i>
                        <div>
                            <p class="font-bold text-base">${escapeSettingsToastHtml(title)}</p>
                            <p class="text-sm opacity-90">${escapeSettingsToastHtml(message)}</p>
                        </div>
                    </div>
                `;
      document.body.appendChild(toast);
      setTimeout(() => {
        toast.style.opacity = "0";
        toast.style.transition = "opacity 0.3s";
        setTimeout(() => toast.remove(), 300);
      }, 3600);
    };
    const resetSecurityUserComposer = () => {
      setSecurityUserComposer({
        username: "",
        password: "",
        role: "analyst",
        is_enabled: true,
        require_password_reset: true,
        mcp_config_name: ""
      });
    };
    const resetSecurityTokenComposer = (tokenType = "external_api") => {
      setSecurityTokenComposer({
        name: "",
        token_type: tokenType,
        scopes: getDefaultSecurityScopes(tokenType),
        owner_user_id: "",
        expires_in_days: 30
      });
    };
    const handleKeyActivate = (event2, callback) => {
      if (event2.key === "Enter" || event2.key === " ") {
        event2.preventDefault();
        callback();
      }
    };
    const handleDialogKeyDown = (event2, onClose) => {
      if (event2.key === "Escape") {
        event2.preventDefault();
        onClose();
      }
    };
    useEffect(() => {
      if (!isLoadingSummary || !currentSessionId) return;
      const interval = setInterval(async () => {
        try {
          const response = await fetch(`/summarize-progress/${currentSessionId}`);
          const progress2 = await response.json();
          setSummaryProgress((prev) => {
            if (!progress2 || typeof progress2 !== "object") {
              return prev;
            }
            const normalizedProgress = normalizeSummaryProgressPayload(progress2, prev);
            const monotonicProgress = Math.max((prev == null ? void 0 : prev.progress) || 0, (normalizedProgress == null ? void 0 : normalizedProgress.progress) || 0);
            return {
              ...normalizedProgress,
              progress: monotonicProgress
            };
          });
        } catch (error) {
          console.error("Progress check failed:", error);
        }
      }, 500);
      return () => clearInterval(interval);
    }, [isLoadingSummary, currentSessionId]);
    useEffect(() => {
      var _a2;
      const provider = normalizeProvider(((_a2 = config == null ? void 0 : config.llm) == null ? void 0 : _a2.provider) || "openai");
      if (!isSummaryModalOpen || activeTab !== "summary" || !summaryData || !currentSessionId) {
        return;
      }
      if (summaryInfographicCapability.status === "checking" || summaryInfographicCapability.checkedSession === currentSessionId && summaryInfographicCapability.checkedProvider === provider) {
        return;
      }
      let cancelled = false;
      setSummaryInfographicCapability({
        status: "checking",
        available: false,
        checkedSession: currentSessionId,
        checkedProvider: provider,
        canGenerate: false,
        hasExisting: false,
        existingArtifact: null,
        reason: ""
      });
      (async () => {
        try {
          const response = await fetch(`/api/summary/infographic-capability?timestamp=${encodeURIComponent(currentSessionId)}`);
          const result = await response.json();
          if (cancelled) {
            return;
          }
          setSummaryInfographicCapability({
            status: (result == null ? void 0 : result.available) ? "supported" : "unsupported",
            available: !!(result == null ? void 0 : result.available),
            checkedSession: currentSessionId,
            checkedProvider: provider,
            canGenerate: !!(result == null ? void 0 : result.can_generate),
            hasExisting: !!(result == null ? void 0 : result.has_existing),
            existingArtifact: (result == null ? void 0 : result.existing_artifact) && typeof result.existing_artifact === "object" ? result.existing_artifact : null,
            reason: typeof (result == null ? void 0 : result.reason) === "string" ? result.reason : ""
          });
        } catch (error) {
          if (cancelled) {
            return;
          }
          console.error("Failed to check summary infographic capability:", error);
          setSummaryInfographicCapability({
            status: "error",
            available: false,
            checkedSession: currentSessionId,
            checkedProvider: provider,
            canGenerate: false,
            hasExisting: false,
            existingArtifact: null,
            reason: (error == null ? void 0 : error.message) || "Capability probe failed"
          });
        }
      })();
      return () => {
        cancelled = true;
      };
    }, [
      activeTab,
      (_L = config == null ? void 0 : config.llm) == null ? void 0 : _L.provider,
      currentSessionId,
      isSummaryModalOpen,
      summaryData
    ]);
    const [taskProgress, setTaskProgress] = useState(() => {
      const saved = localStorage.getItem("splunk_task_progress");
      return saved ? JSON.parse(saved) : {};
    });
    useEffect(() => {
      localStorage.setItem("splunk_task_progress", JSON.stringify(taskProgress));
    }, [taskProgress]);
    useEffect(() => {
      try {
        localStorage.setItem(THEME_PREFERENCE_KEY, themePreference);
      } catch (error) {
        console.error("Failed to persist theme preference:", error);
      }
    }, [themePreference]);
    useEffect(() => {
      try {
        localStorage.setItem(OPERATOR_VOICE_PREFERENCE_KEY, operatorVoice);
      } catch (error) {
        console.error("Failed to persist operator voice preference:", error);
      }
    }, [operatorVoice]);
    useEffect(() => {
      const mediaQuery = window.matchMedia("(prefers-color-scheme: dark)");
      const updateResolvedTheme = () => {
        const nextTheme = themePreference === "system" ? mediaQuery.matches ? "dark" : "light" : themePreference;
        setResolvedTheme(nextTheme);
      };
      updateResolvedTheme();
      if (themePreference === "system") {
        const handleMediaChange = () => updateResolvedTheme();
        if (mediaQuery.addEventListener) {
          mediaQuery.addEventListener("change", handleMediaChange);
        } else {
          mediaQuery.addListener(handleMediaChange);
        }
        return () => {
          if (mediaQuery.removeEventListener) {
            mediaQuery.removeEventListener("change", handleMediaChange);
          } else {
            mediaQuery.removeListener(handleMediaChange);
          }
        };
      }
    }, [themePreference]);
    useEffect(() => {
      document.documentElement.setAttribute("data-theme", resolvedTheme);
    }, [resolvedTheme]);
    const syncWelcomeSplashPreference = (dismissed) => {
      const shouldDismiss = !!dismissed;
      setHasDismissedWelcomeSplash(shouldDismiss);
      persistWelcomeSplashDismissed(shouldDismiss);
    };
    const closeWelcomeSplash = () => {
      syncWelcomeSplashPreference(welcomeSplashDoNotShowAgain);
      setIsWelcomeSplashOpen(false);
    };
    const previewWelcomeSplash = () => {
      setIsWelcomeSplashOpen(true);
    };
    const resetWelcomeSplashPreference = () => {
      syncWelcomeSplashPreference(false);
      setWelcomeSplashDoNotShowAgain(false);
    };
    const toggleStepCompletion = (sessionId, taskIndex, stepNumber) => {
      setTaskProgress((prev) => {
        var _a2, _b2, _c2;
        const key = `${sessionId}_task${taskIndex}`;
        const current = prev[key] || { completedSteps: [], status: "not-started" };
        const completedSteps = new Set(current.completedSteps);
        if (completedSteps.has(stepNumber)) {
          completedSteps.delete(stepNumber);
        } else {
          completedSteps.add(stepNumber);
        }
        const totalSteps = ((_c2 = (_b2 = (_a2 = summaryData == null ? void 0 : summaryData.admin_tasks) == null ? void 0 : _a2[taskIndex]) == null ? void 0 : _b2.steps) == null ? void 0 : _c2.length) || 0;
        const status = completedSteps.size === 0 ? "not-started" : completedSteps.size === totalSteps ? "completed" : "in-progress";
        return {
          ...prev,
          [key]: {
            completedSteps: Array.from(completedSteps),
            status,
            lastUpdated: (/* @__PURE__ */ new Date()).toISOString()
          }
        };
      });
    };
    const getTaskProgress = (sessionId, taskIndex) => {
      const key = `${sessionId}_task${taskIndex}`;
      return taskProgress[key] || { completedSteps: [], status: "not-started" };
    };
    const getTaskCompletionPercentage = (sessionId, taskIndex, totalSteps) => {
      const progress2 = getTaskProgress(sessionId, taskIndex);
      if (totalSteps === 0) return 0;
      return Math.round(progress2.completedSteps.length / totalSteps * 100);
    };
    const [verificationResults, setVerificationResults] = useState({});
    const [verificationHistory, setVerificationHistory] = useState({});
    const [verifyingTask, setVerifyingTask] = useState(null);
    const [loadingRemediation, setLoadingRemediation] = useState(null);
    const [remediationData, setRemediationData] = useState({});
    const [showHistory, setShowHistory] = useState(null);
    const getRemediation = async (sessionId, taskIndex, task, verificationResult) => {
      setLoadingRemediation(taskIndex);
      try {
        const response = await fetch("/get-remediation", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            session_id: sessionId,
            task_index: taskIndex,
            task,
            verification_result: verificationResult
          })
        });
        const result = await response.json();
        setRemediationData((prev) => ({
          ...prev,
          [`${sessionId}_task${taskIndex}`]: result
        }));
      } catch (error) {
        console.error("Failed to get remediation:", error);
      } finally {
        setLoadingRemediation(null);
      }
    };
    const loadVerificationHistory = async (sessionId, taskIndex) => {
      try {
        const response = await fetch(`/verification-history/${sessionId}/${taskIndex}`);
        const result = await response.json();
        setVerificationHistory((prev) => ({
          ...prev,
          [`${sessionId}_task${taskIndex}`]: result
        }));
      } catch (error) {
        console.error("Failed to load verification history:", error);
      }
    };
    const runVerification = async (sessionId, taskIndex, task) => {
      setVerifyingTask(taskIndex);
      try {
        const response = await fetch("/verify-task", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            session_id: sessionId,
            task_index: taskIndex,
            verification_spl: task.verification_spl,
            expected_outcome: task.expected_outcome
          })
        });
        const result = await response.json();
        setVerificationResults((prev) => ({
          ...prev,
          [`${sessionId}_task${taskIndex}`]: result
        }));
      } catch (error) {
        console.error("Verification failed:", error);
        setVerificationResults((prev) => ({
          ...prev,
          [`${sessionId}_task${taskIndex}`]: {
            status: "error",
            message: `Failed to run verification: ${error.message}`,
            results: null
          }
        }));
      } finally {
        setVerifyingTask(null);
      }
    };
    const getVerificationResult = (sessionId, taskIndex) => {
      return verificationResults[`${sessionId}_task${taskIndex}`];
    };
    const [discoveryLogHeight, setDiscoveryLogHeight] = useState(480);
    const [reportViewerHeight, setReportViewerHeight] = useState(560);
    const [isResizingLog, setIsResizingLog] = useState(false);
    const [isResizingReport, setIsResizingReport] = useState(false);
    const wsRef = useRef(null);
    const headerRef = useRef(null);
    const discoveryLogContainerRef = useRef(null);
    const messagesEndRef = useRef(null);
    const chatEndRef = useRef(null);
    const chatInputRef = useRef(null);
    const ragAssetFileInputRef = useRef(null);
    const summaryRequestAbortRef = useRef(null);
    const scrollDiscoveryLogToBottom = (behavior = "smooth") => {
      const container = discoveryLogContainerRef.current;
      if (!container) {
        return;
      }
      if (container.scrollHeight <= container.clientHeight) {
        return;
      }
      if (typeof container.scrollTo === "function") {
        container.scrollTo({ top: container.scrollHeight, behavior });
        return;
      }
      container.scrollTop = container.scrollHeight;
    };
    useEffect(() => {
      scrollDiscoveryLogToBottom(messages.length > 1 ? "smooth" : "auto");
    }, [messages]);
    useEffect(() => {
      const updateHeaderHeight = () => {
        var _a2, _b2;
        const nextHeight = Math.ceil(((_b2 = (_a2 = headerRef.current) == null ? void 0 : _a2.getBoundingClientRect) == null ? void 0 : _b2.call(_a2).height) || 88);
        setHeaderHeight(nextHeight > 0 ? nextHeight : 88);
      };
      updateHeaderHeight();
      window.addEventListener("resize", updateHeaderHeight);
      return () => window.removeEventListener("resize", updateHeaderHeight);
    }, []);
    useEffect(() => {
      if (workspaceTab !== "chat" && workspaceTab !== "summary-workspace") {
        setLastPrimaryWorkspaceTab(workspaceTab);
      }
    }, [workspaceTab]);
    useEffect(() => {
      if (isChatOpen || isChatTab) {
        setTimeout(() => {
          var _a2, _b2;
          (_a2 = chatEndRef.current) == null ? void 0 : _a2.scrollIntoView({ behavior: "auto", block: "end" });
          (_b2 = chatInputRef.current) == null ? void 0 : _b2.focus();
        }, 100);
      }
    }, [isChatOpen, isChatTab]);
    useEffect(() => {
      savePersistedChatState({
        chatSessionId,
        chatMessages: compactPersistedChatMessages(chatMessages),
        serverConversationHistory: compactPersistedConversationHistory(serverConversationHistory)
      });
    }, [chatSessionId, chatMessages, serverConversationHistory]);
    useEffect(() => {
      connectWebSocket();
      loadDiscoveryStatus();
      loadReports();
      loadDiscoveryDashboard();
      loadV2Intelligence();
      loadV2Artifacts();
      loadCapabilities();
      loadDiscoveryCompare("latest", "previous");
      loadRunbookPayload("latest", "admin");
      loadConfig();
      loadCapabilities();
      return () => {
        if (wsRef.current) {
          wsRef.current.close();
        }
      };
    }, []);
    useEffect(() => {
      if (discoveryDashboard && discoveryDashboard.has_data) {
        loadRunbookPayload(compareSelection.current, workflowTab);
      }
    }, [workflowTab]);
    useEffect(() => {
      if (isIntelligenceTab) {
        loadV2Intelligence();
      }
      if (isArtifactsTab) {
        loadDiscoveryStatus();
        loadReports();
        loadV2Artifacts();
      }
      if (isCapabilitiesTab) {
        loadCapabilities();
      }
    }, [workspaceTab]);
    useEffect(() => {
      if (!isCapabilitiesTab) {
        setSelectedCapabilityDetailName(null);
      }
    }, [isCapabilitiesTab]);
    useEffect(() => {
      if (discoveryStatus === "running" && discoveryStartTime) {
        const interval = setInterval(() => {
          const elapsed = Math.floor((Date.now() - discoveryStartTime) / 1e3);
          setElapsedTime(elapsed);
        }, 1e3);
        return () => clearInterval(interval);
      } else if (discoveryStatus !== "running") {
        setElapsedTime(0);
      }
    }, [discoveryStatus, discoveryStartTime]);
    useEffect(() => {
      const discoveryStatusPollIntervalMs = discoveryStatus === "starting" || discoveryStatus === "running" ? 1e3 : 5e3;
      const interval = setInterval(() => {
        loadDiscoveryStatus();
      }, discoveryStatusPollIntervalMs);
      return () => clearInterval(interval);
    }, [discoveryStatus]);
    const connectWebSocket = () => {
      const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
      const wsUrl = `${protocol}//${window.location.host}/ws`;
      wsRef.current = new WebSocket(wsUrl);
      wsRef.current.onopen = () => {
        setIsConnected(true);
        loadDiscoveryStatus();
        addMessage("system", "Connected to discovery engine");
      };
      wsRef.current.onmessage = (event2) => {
        const message = JSON.parse(event2.data);
        handleWebSocketMessage(message);
      };
      wsRef.current.onclose = () => {
        setIsConnected(false);
        setTimeout(connectWebSocket, 3e3);
      };
    };
    const handleWebSocketMessage = (message) => {
      var _a2, _b2, _c2, _d2, _e2, _f2, _g2, _h2, _i2, _j2, _k2, _l2, _m2;
      switch (message.type) {
        case "discovery_status":
          applyDiscoveryRuntimeSnapshot(message.data);
          break;
        case "banner":
          addMessage("banner", message.data);
          break;
        case "phase":
          addMessage("phase", message.data);
          break;
        case "success":
        case "error":
        case "warning":
        case "info":
          if (message.type === "error" && String(((_a2 = message == null ? void 0 : message.data) == null ? void 0 : _a2.type) || "").trim().toLowerCase() === "fatal_error") {
            setDiscoveryStatus("error");
            setDiscoveryErrorMessage(String(((_b2 = message == null ? void 0 : message.data) == null ? void 0 : _b2.message) || "Discovery failed.").trim());
            setDiscoveryLastUpdatedAt(message.timestamp || (/* @__PURE__ */ new Date()).toISOString());
            setDiscoveryCompletedAt(message.timestamp || (/* @__PURE__ */ new Date()).toISOString());
          }
          if (message.type === "warning") {
            const warningType = String(((_c2 = message == null ? void 0 : message.data) == null ? void 0 : _c2.type) || "").trim().toLowerCase();
            const warningMessage = String(((_d2 = message == null ? void 0 : message.data) == null ? void 0 : _d2.message) || "").trim().toLowerCase();
            if (warningType === "user_abort" || warningMessage.includes("aborted")) {
              setDiscoveryStatus("aborted");
              setDiscoveryErrorMessage("Discovery aborted by user");
              setDiscoveryLastUpdatedAt(message.timestamp || (/* @__PURE__ */ new Date()).toISOString());
              setDiscoveryCompletedAt(message.timestamp || (/* @__PURE__ */ new Date()).toISOString());
            }
          }
          addMessage(message.type, message.data);
          break;
        case "progress": {
          const nextProgress = {
            percentage: Math.max(0, Math.min(100, Number(((_e2 = message == null ? void 0 : message.data) == null ? void 0 : _e2.percentage) || 0))),
            current_step: Math.max(0, Number(((_f2 = message == null ? void 0 : message.data) == null ? void 0 : _f2.current_step) || 0)),
            total_steps: Math.max(0, Number(((_g2 = message == null ? void 0 : message.data) == null ? void 0 : _g2.total_steps) || 0)),
            description: String(((_h2 = message == null ? void 0 : message.data) == null ? void 0 : _h2.description) || "").trim(),
            eta_seconds: ((_i2 = message == null ? void 0 : message.data) == null ? void 0 : _i2.eta_seconds) == null || ((_j2 = message == null ? void 0 : message.data) == null ? void 0 : _j2.eta_seconds) === "" ? null : Number(message.data.eta_seconds),
            eta_method: String(((_k2 = message == null ? void 0 : message.data) == null ? void 0 : _k2.eta_method) || "").trim() || null
          };
          setProgress(nextProgress);
          setDiscoveryStatus("running");
          setDiscoveryLastUpdatedAt(message.timestamp || (/* @__PURE__ */ new Date()).toISOString());
          setDiscoveryCompletedAt(null);
          setDiscoveryErrorMessage("");
          if (!discoveryStartTime) {
            setDiscoveryStartTime(Date.now());
          }
          break;
        }
        case "overview":
          addMessage("overview", message.data);
          break;
        case "classification":
          addMessage("classification", message.data);
          break;
        case "recommendations":
          addMessage("recommendations", message.data);
          break;
        case "use_cases":
          addMessage("use_cases", message.data);
          break;
        case "completion":
          addMessage("completion", message.data);
          setProgress({ percentage: 100, description: "Discovery completed. Finalizing UI..." });
          setDiscoveryStatus("completed");
          setDiscoveryLastUpdatedAt(message.timestamp || (/* @__PURE__ */ new Date()).toISOString());
          setDiscoveryCompletedAt(message.timestamp || (/* @__PURE__ */ new Date()).toISOString());
          setDiscoveryResultTimestamp(((_l2 = message == null ? void 0 : message.data) == null ? void 0 : _l2.timestamp) || null);
          setDiscoveryReportCount(Number(((_m2 = message == null ? void 0 : message.data) == null ? void 0 : _m2.report_count) || 0));
          setDiscoveryErrorMessage("");
          setDiscoveryStartTime(null);
          setElapsedTime(0);
          loadReports();
          loadDiscoveryDashboard();
          loadV2Intelligence();
          loadV2Artifacts();
          loadDiscoveryCompare("latest", "previous");
          loadRunbookPayload("latest", workflowTab);
          break;
        case "rate_limit":
          addMessage("rate_limit", message.data);
          break;
      }
    };
    const addMessage = (type, data) => {
      setMessages((prev) => [...prev, {
        id: Date.now() + Math.random(),
        type,
        data,
        timestamp: (/* @__PURE__ */ new Date()).toISOString()
      }]);
    };
    const applyDiscoveryRuntimeSnapshot = (snapshot = {}) => {
      var _a2;
      const normalizedStatus = normalizeDiscoveryStatusValue(snapshot == null ? void 0 : snapshot.status);
      const snapshotProgress = (snapshot == null ? void 0 : snapshot.progress) && typeof snapshot.progress === "object" ? snapshot.progress : {};
      const nextProgress = {
        percentage: Math.max(0, Math.min(100, Number(snapshotProgress.percentage || 0))),
        current_step: Math.max(0, Number(snapshotProgress.current_step || 0)),
        total_steps: Math.max(0, Number(snapshotProgress.total_steps || 0)),
        description: String(snapshotProgress.description || "").trim(),
        eta_seconds: snapshotProgress.eta_seconds == null || snapshotProgress.eta_seconds === "" ? null : Number(snapshotProgress.eta_seconds),
        eta_method: String(snapshotProgress.eta_method || "").trim() || null
      };
      const parsedStartedAt = parseMissionSessionDate(snapshot == null ? void 0 : snapshot.started_at);
      const nextPhasePlan = Array.isArray(snapshot == null ? void 0 : snapshot.phase_plan) ? snapshot.phase_plan.map((phase, index) => ({
        key: String((phase == null ? void 0 : phase.key) || `phase-${index}`),
        label: String((phase == null ? void 0 : phase.label) || (phase == null ? void 0 : phase.title) || `Stage ${index + 1}`),
        title: String((phase == null ? void 0 : phase.title) || (phase == null ? void 0 : phase.label) || `Stage ${index + 1}`),
        description: String((phase == null ? void 0 : phase.description) || "").trim(),
        status: String((phase == null ? void 0 : phase.status) || "pending").trim().toLowerCase() || "pending",
        started_at: (phase == null ? void 0 : phase.started_at) || null,
        completed_at: (phase == null ? void 0 : phase.completed_at) || null,
        last_detail: String((phase == null ? void 0 : phase.last_detail) || "").trim(),
        progress_percent: Number.isFinite(Number(phase == null ? void 0 : phase.progress_percent)) ? Number(phase.progress_percent) : 0
      })) : [];
      const nextLastRunOutcome = (snapshot == null ? void 0 : snapshot.last_run_outcome) && typeof snapshot.last_run_outcome === "object" ? {
        status: normalizeDiscoveryStatusValue(snapshot.last_run_outcome.status),
        title: String(snapshot.last_run_outcome.title || "").trim(),
        summary: String(snapshot.last_run_outcome.summary || "").trim(),
        completed_at: snapshot.last_run_outcome.completed_at || null,
        result_timestamp: snapshot.last_run_outcome.result_timestamp || null,
        report_count: Number.isFinite(Number(snapshot.last_run_outcome.report_count)) ? Number(snapshot.last_run_outcome.report_count) : 0,
        phase_title: String(snapshot.last_run_outcome.phase_title || "").trim(),
        error: String(snapshot.last_run_outcome.error || "").trim()
      } : null;
      const nextActivityLog = Array.isArray(snapshot == null ? void 0 : snapshot.activity_log) ? snapshot.activity_log.map((entry, index) => {
        const entryData = (entry == null ? void 0 : entry.data) && typeof entry.data === "object" && entry.data !== null ? entry.data : { message: String((entry == null ? void 0 : entry.data) || "").trim() };
        return {
          id: String((entry == null ? void 0 : entry.id) || `${(entry == null ? void 0 : entry.timestamp) || "discovery"}-${index}`),
          type: String((entry == null ? void 0 : entry.type) || "info").trim().toLowerCase() || "info",
          data: entryData,
          timestamp: (entry == null ? void 0 : entry.timestamp) || (/* @__PURE__ */ new Date()).toISOString()
        };
      }) : [];
      setDiscoveryStatus(normalizedStatus);
      setProgress(nextProgress);
      setDiscoveryStartTime(parsedStartedAt ? parsedStartedAt.getTime() : null);
      setDiscoveryLastUpdatedAt((snapshot == null ? void 0 : snapshot.updated_at) || null);
      setDiscoveryCompletedAt((snapshot == null ? void 0 : snapshot.completed_at) || null);
      setDiscoveryResultTimestamp((snapshot == null ? void 0 : snapshot.result_timestamp) || null);
      setDiscoverySessionId((_a2 = snapshot == null ? void 0 : snapshot.session_id) != null ? _a2 : null);
      setDiscoveryReportCount(Number.isFinite(Number(snapshot == null ? void 0 : snapshot.report_count)) ? Number(snapshot.report_count) : 0);
      setDiscoveryErrorMessage(String((snapshot == null ? void 0 : snapshot.error) || "").trim());
      setDiscoveryPhasePlan(nextPhasePlan);
      setDiscoveryCurrentPhaseTitle(String((snapshot == null ? void 0 : snapshot.current_phase_title) || "").trim());
      setDiscoveryLastRunOutcome(nextLastRunOutcome);
      setMessages(nextActivityLog);
      if (normalizedStatus === "idle" && !parsedStartedAt) {
        setElapsedTime(0);
      }
    };
    const loadDiscoveryStatus = async () => {
      try {
        const response = await fetch("/api/discovery/status");
        if (!response.ok) {
          throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }
        const result = await response.json();
        applyDiscoveryRuntimeSnapshot(result);
      } catch (error) {
        console.error("Failed to load discovery status:", error);
      }
    };
    const closeDiscoveryActionDialog = () => {
      setDiscoveryActionDialog(null);
    };
    const executeDiscoveryStart = async () => {
      var _a2;
      setDiscoveryStatus("starting");
      setMessages([]);
      setProgress({ percentage: 0, current_step: 0, total_steps: 0, description: "Initializing...", eta_seconds: null, eta_method: "stage_calibrated" });
      setDiscoveryStartTime(Date.now());
      setDiscoveryLastUpdatedAt((/* @__PURE__ */ new Date()).toISOString());
      setDiscoveryCompletedAt(null);
      setDiscoveryResultTimestamp(null);
      setDiscoverySessionId(null);
      setDiscoveryReportCount(0);
      setDiscoveryErrorMessage("");
      setDiscoveryPhasePlan([]);
      setDiscoveryCurrentPhaseTitle("");
      setDiscoveryLastRunOutcome(null);
      setElapsedTime(0);
      try {
        const response = await fetch("/start-discovery", { method: "POST" });
        const result = await response.json();
        if (result.error) {
          addMessage("error", { message: result.error });
          setDiscoveryStatus("error");
          setDiscoveryErrorMessage(String(result.error || "Discovery failed to start."));
          setDiscoveryCompletedAt((/* @__PURE__ */ new Date()).toISOString());
          setDiscoveryStartTime(null);
        } else {
          if (result == null ? void 0 : result.discovery) {
            applyDiscoveryRuntimeSnapshot(result.discovery);
          } else {
            setDiscoveryStatus("running");
            setDiscoverySessionId((_a2 = result == null ? void 0 : result.session_id) != null ? _a2 : null);
          }
        }
      } catch (error) {
        addMessage("error", { message: `Failed to start discovery: ${error.message}` });
        setDiscoveryStatus("error");
        setDiscoveryErrorMessage(String((error == null ? void 0 : error.message) || "Discovery failed to start."));
        setDiscoveryCompletedAt((/* @__PURE__ */ new Date()).toISOString());
        setDiscoveryStartTime(null);
      }
    };
    const startDiscovery = async () => {
      var _a2, _b2, _c2;
      const endpointUrl = ((_b2 = (_a2 = config == null ? void 0 : config.llm) == null ? void 0 : _a2.endpoint_url) == null ? void 0 : _b2.toLowerCase()) || "";
      const credentialName2 = ((_c2 = config == null ? void 0 : config.active_credential_name) == null ? void 0 : _c2.toLowerCase()) || "";
      const isLocalLLM = endpointUrl.includes("localhost") || endpointUrl.includes("127.0.0.1") || endpointUrl.includes(":8000") || // Common vLLM port
      endpointUrl.includes(":11434") || // Common Ollama port
      credentialName2.includes("local") || credentialName2.includes("vllm") || credentialName2.includes("ollama");
      if (isLocalLLM) {
        setDiscoveryActionDialog({
          action: "start",
          tone: "amber",
          icon: "fa-microchip",
          eyebrow: "Local model runtime",
          title: "Run discovery with the current local LLM?",
          summary: "This discovery run is pointed at a local model. Runtime will usually be slower than a hosted provider, especially during evidence synthesis and packaging.",
          details: [
            "Expect multi-minute runtime depending on model size and local hardware.",
            "The header monitor and Discovery control center stay live while the pipeline runs.",
            "You can stop the run at any time from the Discovery workspace."
          ],
          confirmLabel: "Continue Discovery",
          cancelLabel: "Stay Here"
        });
        return;
      }
      await executeDiscoveryStart();
    };
    const executeDiscoveryAbort = async () => {
      try {
        const response = await fetch("/abort-discovery", { method: "POST" });
        const result = await response.json();
        if (result.error) {
          addMessage("error", { message: result.error });
        } else {
          addMessage("warning", { message: "⚠️ Discovery aborted by user" });
          if (result == null ? void 0 : result.discovery) {
            applyDiscoveryRuntimeSnapshot(result.discovery);
          } else {
            setDiscoveryStatus("aborted");
            setDiscoveryErrorMessage("Discovery aborted by user");
            setDiscoveryCompletedAt((/* @__PURE__ */ new Date()).toISOString());
            setDiscoveryStartTime(null);
            setElapsedTime(0);
          }
        }
      } catch (error) {
        addMessage("error", { message: `Failed to abort discovery: ${error.message}` });
      }
    };
    const abortDiscovery = async () => {
      setDiscoveryActionDialog({
        action: "abort",
        tone: "rose",
        icon: "fa-stop-circle",
        eyebrow: "Stop active pipeline",
        title: "Abort the current discovery run?",
        summary: "This stops the active pipeline and preserves the partial runtime ledger so the operator can review what finished before the stop.",
        details: [
          "The current discovery session will be marked as stopped.",
          "Mission and Discovery will keep the last run outcome visible after the abort.",
          "No additional discovery artifacts will be produced for the interrupted run."
        ],
        confirmLabel: "Abort Discovery",
        cancelLabel: "Keep Running"
      });
    };
    const confirmDiscoveryAction = async () => {
      const pendingAction = discoveryActionDialog == null ? void 0 : discoveryActionDialog.action;
      closeDiscoveryActionDialog();
      if (pendingAction === "start") {
        await executeDiscoveryStart();
      } else if (pendingAction === "abort") {
        await executeDiscoveryAbort();
      }
    };
    const formatElapsedTime = (seconds) => {
      const mins = Math.floor(seconds / 60);
      const secs = seconds % 60;
      return `${mins}:${secs.toString().padStart(2, "0")}`;
    };
    const loadReports = async () => {
      try {
        const response = await fetch("/reports");
        if (!response.ok) {
          throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }
        const result = await response.json();
        console.log("Loaded reports:", result);
        setReports(result.reports || []);
        setSessionCatalog(result.sessions || []);
      } catch (error) {
        console.error("Failed to load reports:", error);
        setReports([]);
        setSessionCatalog([]);
      }
    };
    const loadDiscoveryDashboard = async () => {
      try {
        const response = await fetch("/api/discovery/dashboard");
        if (!response.ok) {
          throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }
        const result = await response.json();
        setDiscoveryDashboard(result);
      } catch (error) {
        console.error("Failed to load discovery dashboard:", error);
        setDiscoveryDashboard(null);
      }
    };
    const loadV2Intelligence = async () => {
      try {
        const response = await fetch("/api/v2/intelligence");
        if (!response.ok) {
          throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }
        const result = await response.json();
        setV2Intelligence(result);
      } catch (error) {
        console.error("Failed to load discovery intelligence:", error);
        setV2Intelligence({ has_data: false, message: error.message || "Failed to load discovery intelligence." });
      }
    };
    const loadV2Artifacts = async () => {
      try {
        const response = await fetch("/api/v2/artifacts");
        if (!response.ok) {
          throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }
        const result = await response.json();
        setV2Artifacts(result);
      } catch (error) {
        console.error("Failed to load discovery artifacts:", error);
        setV2Artifacts({ has_data: false, artifacts: [], count: 0, message: error.message || "Failed to load discovery artifacts." });
      }
    };
    const refreshIntelligenceWorkspace = () => {
      loadDiscoveryDashboard();
      loadV2Intelligence();
    };
    const refreshArtifactsWorkspace = () => {
      loadDiscoveryStatus();
      loadReports();
      loadV2Artifacts();
      loadCapabilities();
    };
    const openDiscoveryWorkspace = () => {
      setWorkspaceTab("artifacts");
      refreshArtifactsWorkspace();
    };
    const loadCapabilities = async () => {
      var _a2, _b2;
      try {
        const response = await fetch("/api/capabilities");
        const result = await response.json();
        if (!response.ok) {
          throw new Error((result == null ? void 0 : result.detail) || (result == null ? void 0 : result.message) || `HTTP ${response.status}`);
        }
        setCapabilitiesData({
          status: "success",
          summary: result.summary || { total: 0, installed: 0, enabled: 0, ready: 0, restart_required: 0 },
          capabilities: result.capabilities || {},
          error: ""
        });
        const nextDrafts = {};
        Object.entries(result.capabilities || {}).forEach(([name, capability]) => {
          nextDrafts[name] = JSON.stringify((capability == null ? void 0 : capability.config) || {}, null, 2);
        });
        setCapabilityDrafts(nextDrafts);
        const deeplinkConfig = ((_b2 = (_a2 = result == null ? void 0 : result.capabilities) == null ? void 0 : _a2.splunk_deeplink_tools) == null ? void 0 : _b2.config) || {};
        setDeeplinkDrafts((prev) => {
          var _a3, _b3, _c2, _d2;
          return {
            ...prev,
            splunk_deeplink_tools: {
              query: ((_a3 = prev == null ? void 0 : prev.splunk_deeplink_tools) == null ? void 0 : _a3.query) || "search index=_internal | head 20",
              earliest: ((_b3 = prev == null ? void 0 : prev.splunk_deeplink_tools) == null ? void 0 : _b3.earliest) || deeplinkConfig.default_earliest || "-24h",
              latest: ((_c2 = prev == null ? void 0 : prev.splunk_deeplink_tools) == null ? void 0 : _c2.latest) || deeplinkConfig.default_latest || "now",
              app: ((_d2 = prev == null ? void 0 : prev.splunk_deeplink_tools) == null ? void 0 : _d2.app) || deeplinkConfig.default_app || "search"
            }
          };
        });
        loadRagAssetWorkspace({ suppressLoading: true });
      } catch (error) {
        console.error("Failed to load capabilities:", error);
        setCapabilitiesData((prev) => ({
          ...prev,
          status: "error",
          error: error.message || "Failed to load capabilities."
        }));
      }
    };
    const refreshCapabilitiesWorkspace = () => {
      loadCapabilities();
    };
    const loadRagAssetWorkspace = async (options = {}) => {
      if (!options.suppressLoading) {
        setRagAssetWorkspace((prev) => ({
          ...prev,
          status: "loading",
          error: ""
        }));
      }
      try {
        const response = await fetch("/api/capabilities/rag/assets");
        const result = await response.json();
        if (!response.ok) {
          throw new Error((result == null ? void 0 : result.detail) || (result == null ? void 0 : result.message) || `HTTP ${response.status}`);
        }
        const details = (result == null ? void 0 : result.details) || {};
        setRagAssetWorkspace((prev) => {
          const nextAssets = Array.isArray(details.assets) ? details.assets : [];
          const keepDetail = !!prev.detailAssetId && nextAssets.some((asset) => asset.asset_id === prev.detailAssetId);
          return {
            ...prev,
            status: "success",
            summary: buildRagAssetSummaryState(details, prev.summary),
            assets: nextAssets,
            detailAssetId: keepDetail ? prev.detailAssetId : null,
            assetDetail: keepDetail ? prev.assetDetail : null,
            detailStatus: keepDetail ? prev.detailStatus : "idle",
            detailError: keepDetail ? prev.detailError : "",
            error: ""
          };
        });
      } catch (error) {
        console.error("Failed to load RAG assets:", error);
        setRagAssetWorkspace((prev) => ({
          ...prev,
          status: "error",
          error: error.message || "Failed to load managed knowledge assets."
        }));
      }
    };
    const getCapabilityStatusClasses = (status) => {
      switch (String(status || "").toLowerCase()) {
        case "ready":
          return isDarkTheme ? "bg-emerald-900 text-emerald-100 border border-emerald-700" : "bg-emerald-100 text-emerald-800 border border-emerald-300";
        case "degraded":
          return isDarkTheme ? "bg-amber-900 text-amber-100 border border-amber-700" : "bg-amber-100 text-amber-900 border border-amber-300";
        case "restart-required":
          return isDarkTheme ? "bg-orange-900 text-orange-100 border border-orange-700" : "bg-orange-100 text-orange-900 border border-orange-300";
        case "disabled":
          return isDarkTheme ? "bg-slate-800 text-slate-100 border border-slate-600" : "bg-slate-100 text-slate-800 border border-slate-300";
        case "not_installed":
          return isDarkTheme ? "bg-gray-800 text-gray-200 border border-gray-600" : "bg-gray-100 text-gray-800 border border-gray-300";
        case "unavailable":
          return isDarkTheme ? "bg-fuchsia-900 text-fuchsia-100 border border-fuchsia-700" : "bg-fuchsia-100 text-fuchsia-900 border border-fuchsia-300";
        default:
          return isDarkTheme ? "bg-gray-800 text-gray-200 border border-gray-600" : "bg-gray-100 text-gray-800 border border-gray-300";
      }
    };
    const formatTokenLabel = (value) => {
      const cleaned = String(value || "").trim();
      if (!cleaned) {
        return "";
      }
      return cleaned.split(/[_-]+/).map((part) => {
        const normalized = part.toLowerCase();
        if (normalized === "rag") return "RAG";
        if (normalized === "llm") return "LLM";
        if (normalized === "mcp") return "MCP";
        return normalized.charAt(0).toUpperCase() + normalized.slice(1);
      }).join(" ");
    };
    const formatCapabilityStatusLabel = (status) => {
      switch (String(status || "").toLowerCase()) {
        case "degraded":
          return "Needs attention";
        case "not_installed":
          return "Not installed";
        case "restart-required":
          return "Restart required";
        case "unavailable":
          return "Planned";
        default:
          return formatTokenLabel(status) || "Unknown";
      }
    };
    const formatCapabilityCategoryLabel = (category) => {
      switch (String(category || "").toLowerCase()) {
        case "rag":
          return "Retrieval";
        case "tool_pack":
          return "Operator Toolset";
        case "capability":
          return "Capability";
        default:
          return formatTokenLabel(category) || "Capability";
      }
    };
    const formatCapabilityInstallMethodLabel = (method) => {
      switch (String(method || "").toLowerCase()) {
        case "internal":
          return "Built In";
        case "pip":
          return "Optional Download";
        default:
          return formatTokenLabel(method) || "Unknown";
      }
    };
    const formatCapabilityMaturityLabel = (maturity) => {
      switch (String(maturity || "").toLowerCase()) {
        case "foundation":
          return "Core";
        case "phase4":
          return "Expanded";
        case "phase5":
          return "Advanced";
        default:
          return formatTokenLabel(maturity) || "Experimental";
      }
    };
    const formatCapabilityUsageContextLabel = (usedIn) => {
      switch (String(usedIn || "").toLowerCase()) {
        case "chat_preview":
          return "Chat Response";
        case "llm_prompt":
          return "Prompt Context";
        default:
          return formatTokenLabel(usedIn) || "Capability Use";
      }
    };
    const formatCapabilitySourceTypeLabel = (sourceType) => {
      switch (String(sourceType || "").toLowerCase()) {
        case "knowledge_asset":
          return "Knowledge Asset";
        case "query_result_preview":
          return "Query Result Preview";
        case "discovery_artifact":
          return "Discovery Artifact";
        case "generated_summary":
          return "Generated Summary";
        case "runbook":
          return "Runbook";
        case "handoff":
          return "Developer Handoff";
        case "uploaded_document":
          return "Reference Document";
        case "chat_memory_derived":
          return "Conversation Memory";
        case "tool_result_snapshot":
          return "Tool Result Snapshot";
        default:
          return formatTokenLabel(sourceType) || "Artifact";
      }
    };
    const formatKnowledgeAssetTypeLabel = (assetType) => {
      switch (String(assetType || "").toLowerCase()) {
        case "spl_query_library":
          return "SPL Library Query";
        case "splunk_documentation":
          return "Splunk Documentation";
        case "monitored_system_context":
          return "Monitored System";
        case "connected_system_context":
          return "Connected System";
        case "integration_context":
          return "Integration Context";
        case "runbook_context":
          return "Runbook Context";
        case "reference_document":
          return "Reference Document";
        default:
          return formatTokenLabel(assetType) || "Knowledge Asset";
      }
    };
    const formatKnowledgeAssetImportMethodLabel = (method) => {
      switch (String(method || "").toLowerCase()) {
        case "file_upload":
          return "File Upload";
        case "text":
          return "Pasted Text";
        default:
          return formatTokenLabel(method) || "Imported";
      }
    };
    const formatKnowledgeAssetLibraryStatusLabel = (status) => {
      switch (String(status || "").toLowerCase()) {
        case "checked_out":
          return "Checked Out";
        case "checked_in":
        default:
          return "Checked In";
      }
    };
    const getKnowledgeAssetLibraryStatusClasses = (status) => {
      switch (String(status || "").toLowerCase()) {
        case "checked_out":
          return isDarkTheme ? "bg-amber-950 border-amber-800 text-amber-100" : "bg-amber-50 border-amber-200 text-amber-800";
        case "checked_in":
        default:
          return isDarkTheme ? "bg-emerald-950 border-emerald-800 text-emerald-100" : "bg-emerald-50 border-emerald-200 text-emerald-800";
      }
    };
    const buildRagAssetSummaryState = (assetSummary, fallbackSummary = {}) => {
      var _a2, _b2, _c2, _d2;
      return {
        asset_count: (assetSummary == null ? void 0 : assetSummary.asset_count) || 0,
        asset_type_counts: (assetSummary == null ? void 0 : assetSummary.asset_type_counts) || {},
        asset_dir: (assetSummary == null ? void 0 : assetSummary.asset_dir) || (fallbackSummary == null ? void 0 : fallbackSummary.asset_dir) || "",
        checked_in_asset_count: (_b2 = (_a2 = assetSummary == null ? void 0 : assetSummary.checked_in_asset_count) != null ? _a2 : fallbackSummary == null ? void 0 : fallbackSummary.checked_in_asset_count) != null ? _b2 : 0,
        checked_out_asset_count: (_d2 = (_c2 = assetSummary == null ? void 0 : assetSummary.checked_out_asset_count) != null ? _c2 : fallbackSummary == null ? void 0 : fallbackSummary.checked_out_asset_count) != null ? _d2 : 0,
        library_status_counts: (assetSummary == null ? void 0 : assetSummary.library_status_counts) || (fallbackSummary == null ? void 0 : fallbackSummary.library_status_counts) || { checked_in: 0, checked_out: 0 }
      };
    };
    const formatExportOutputLabel = (output) => {
      switch (String(output || "").toLowerCase()) {
        case "bundle_zip":
          return "ZIP Package";
        case "manifest_json":
          return "Manifest";
        case "summary_markdown":
          return "Summary Note";
        default:
          return formatTokenLabel(output) || "Export Output";
      }
    };
    const formatPackageFileLabel = (filename) => {
      const raw = String(filename || "").trim();
      if (!raw) {
        return "Unavailable";
      }
      const basename = raw.replace(/\.zip$/i, "");
      const match = basename.match(/^dt4sms_(?:export|report_package)_(\d{8})_(\d{6})_([a-z]+)(?:_(.+))?$/i);
      if (!match) {
        return formatTokenLabel(basename.replace(/bundle/gi, "package")) || raw;
      }
      const [, datePart, timePart, persona, titlePart] = match;
      const formattedTimestamp = `${datePart.slice(0, 4)}-${datePart.slice(4, 6)}-${datePart.slice(6, 8)} ${timePart.slice(0, 2)}:${timePart.slice(2, 4)}:${timePart.slice(4, 6)}`;
      const labelParts = ["Report Package", formattedTimestamp, formatTokenLabel(persona) || "Persona"];
      const normalizedTitle = String(titlePart || "").replace(/bundle/gi, "package");
      if (normalizedTitle) {
        labelParts.push(formatTokenLabel(normalizedTitle));
      }
      return labelParts.join(" - ");
    };
    const updateCapabilityDraft = (name, value) => {
      setCapabilityDrafts((prev) => ({
        ...prev,
        [name]: value
      }));
    };
    const updateDeeplinkDraft = (name, field, value) => {
      setDeeplinkDrafts((prev) => ({
        ...prev,
        [name]: {
          ...prev[name] || {},
          [field]: value
        }
      }));
    };
    const runCapabilityAction = async (name, action, payload = null) => {
      setCapabilityActionState((prev) => ({
        ...prev,
        [name]: action
      }));
      try {
        const response = await fetch(`/api/capabilities/${name}/${action}`, {
          method: "POST",
          headers: payload ? { "Content-Type": "application/json" } : void 0,
          body: payload ? JSON.stringify(payload) : void 0
        });
        const result = await response.json();
        if (!response.ok) {
          throw new Error((result == null ? void 0 : result.detail) || (result == null ? void 0 : result.message) || `${action} failed`);
        }
        setCapabilityNotice({
          type: "success",
          message: (result == null ? void 0 : result.message) || `${name} ${action} completed successfully.`
        });
        await loadCapabilities();
      } catch (error) {
        console.error(`Capability action failed (${name}/${action}):`, error);
        setCapabilityNotice({
          type: "error",
          message: `${name}: ${error.message || `${action} failed`}`
        });
      } finally {
        setCapabilityActionState((prev) => {
          const next = { ...prev };
          delete next[name];
          return next;
        });
        setTimeout(() => setCapabilityNotice(null), 3500);
      }
    };
    const buildCapabilityDeeplink = async (payload, options = {}) => {
      var _a2;
      const capabilityName = options.name || "splunk_deeplink_tools";
      const openedWindow = options.openAfterBuild ? window.open("", "_blank") : null;
      setCapabilityActionState((prev) => ({
        ...prev,
        [capabilityName]: "build"
      }));
      try {
        const response = await fetch("/api/capabilities/deeplinks/build", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload || {})
        });
        const result = await response.json();
        if (!response.ok) {
          throw new Error((result == null ? void 0 : result.detail) || (result == null ? void 0 : result.message) || "Failed to build deeplink.");
        }
        const deeplink = ((_a2 = result == null ? void 0 : result.details) == null ? void 0 : _a2.deeplink) || null;
        if (options.storeResult !== false && deeplink) {
          setDeeplinkBuildResults((prev) => ({
            ...prev,
            [capabilityName]: deeplink
          }));
        }
        if (options.openAfterBuild && (deeplink == null ? void 0 : deeplink.url)) {
          if (openedWindow && !openedWindow.closed) {
            openedWindow.location.href = deeplink.url;
          } else {
            window.open(deeplink.url, "_blank", "noopener,noreferrer");
          }
        }
        if (!options.suppressNotice) {
          setCapabilityNotice({
            type: "success",
            message: (result == null ? void 0 : result.message) || "Splunk deeplink generated."
          });
          setTimeout(() => setCapabilityNotice(null), 3500);
        }
        return deeplink;
      } catch (error) {
        if (openedWindow && !openedWindow.closed) {
          openedWindow.close();
        }
        console.error("Failed to build deeplink:", error);
        setCapabilityNotice({
          type: "error",
          message: error.message || "Failed to build deeplink."
        });
        setTimeout(() => setCapabilityNotice(null), 3500);
        return null;
      } finally {
        setCapabilityActionState((prev) => {
          const next = { ...prev };
          delete next[capabilityName];
          return next;
        });
      }
    };
    const normalizeSplunkSearchQuery = (splQuery) => {
      const query = String(splQuery || "").replace(/\s+/g, " ").trim();
      if (!query) {
        return "";
      }
      const lowered = query.toLowerCase();
      if (lowered.startsWith("search ") || query.startsWith("|")) {
        return query;
      }
      return `search ${query}`;
    };
    const getDefaultSplunkDeeplinkPayload = (overrides = {}) => {
      const capabilityConfig = (deeplinkCapability == null ? void 0 : deeplinkCapability.config) || {};
      return {
        app: String(overrides.app || (deeplinkCapability == null ? void 0 : deeplinkCapability.default_app) || capabilityConfig.default_app || "search").trim().replace(/^\/+|\/+$/g, "") || "search",
        earliest: String(overrides.earliest || capabilityConfig.default_earliest || "-24h").trim() || "-24h",
        latest: String(overrides.latest || capabilityConfig.default_latest || "now").trim() || "now"
      };
    };
    const buildSplunkSearchUrl = (splQuery, overrides = {}) => {
      if (!canUseSplunkDeeplinks) {
        return "";
      }
      const normalizedQuery = normalizeSplunkSearchQuery(splQuery);
      const baseUrl = String((deeplinkCapability == null ? void 0 : deeplinkCapability.resolved_web_base_url) || "").trim().replace(/\/+$/, "");
      const deeplinkDefaults = getDefaultSplunkDeeplinkPayload(overrides);
      const appName = deeplinkDefaults.app;
      const earliest = deeplinkDefaults.earliest;
      const latest = deeplinkDefaults.latest;
      if (!normalizedQuery || !baseUrl) {
        return "";
      }
      const params = new URLSearchParams({
        q: normalizedQuery,
        earliest,
        latest
      });
      return `${baseUrl}/en-US/app/${encodeURIComponent(appName)}/search?${params.toString()}`;
    };
    const openSplunkSearch = async (splQuery, overrides = {}) => {
      if (!splQuery || !canUseSplunkDeeplinks) {
        return;
      }
      const deeplinkPayload = {
        query: splQuery,
        ...getDefaultSplunkDeeplinkPayload(overrides)
      };
      const directUrl = buildSplunkSearchUrl(deeplinkPayload.query, deeplinkPayload);
      if (directUrl) {
        const launchedWindow = window.open(directUrl, "_blank", "noopener,noreferrer");
        if (!launchedWindow) {
          window.location.assign(directUrl);
        }
        return;
      }
      await buildCapabilityDeeplink(
        deeplinkPayload,
        {
          name: "splunk_deeplink_tools",
          openAfterBuild: true,
          suppressNotice: true,
          storeResult: false
        }
      );
    };
    const openSplunkSearchFromChat = async (splQuery) => {
      await openSplunkSearch(splQuery);
    };
    const buildSplLibraryTitle = (splQuery, options = {}) => {
      const explicitTitle = String(options.title || "").trim();
      if (explicitTitle) {
        return explicitTitle;
      }
      const singleLineQuery = normalizeSplunkSearchQuery(splQuery).replace(/\s+/g, " ").trim();
      const preview = singleLineQuery.length > 72 ? `${singleLineQuery.slice(0, 72).trim()}...` : singleLineQuery;
      return preview ? `SPL Library: ${preview}` : "SPL Library Query";
    };
    const buildSplLibraryTags = (options = {}) => {
      const rawTags = [
        "spl",
        "spl-library",
        String(options.originKind || "").trim().toLowerCase().replace(/[^a-z0-9]+/g, "-"),
        ...Array.isArray(options.tags) ? options.tags : []
      ];
      const tags = [];
      const seen = /* @__PURE__ */ new Set();
      rawTags.forEach((rawTag) => {
        const cleanedTag = String(rawTag || "").trim();
        if (!cleanedTag) {
          return;
        }
        const normalizedTag = cleanedTag.toLowerCase();
        if (seen.has(normalizedTag)) {
          return;
        }
        seen.add(normalizedTag);
        tags.push(cleanedTag);
      });
      return tags.slice(0, 12);
    };
    const buildSplLibraryPayload = (splQuery, options = {}) => {
      const trimmedQuery = String(splQuery || "").trim();
      if (!trimmedQuery) {
        return null;
      }
      const sourceLabel = String(options.sourceLabel || options.originLabel || "").trim();
      const originKind = String(options.originKind || "interface_spl_query").trim() || "interface_spl_query";
      const contextExcerpt = String(options.contextExcerpt || "").trim();
      const deeplinkDefaults = getDefaultSplunkDeeplinkPayload(options.deeplinkOptions || {});
      const singleLineQuery = normalizeSplunkSearchQuery(trimmedQuery).replace(/\s+/g, " ").trim();
      const contentLines = [
        "Saved SPL query for reuse in Splunk Web and follow-on chat workflows.",
        `Query summary: ${singleLineQuery}`
      ];
      if (sourceLabel) {
        contentLines.push(`Saved from: ${sourceLabel}.`);
      }
      contentLines.push("", "## Query", trimmedQuery);
      if (contextExcerpt) {
        contentLines.push("", "## Context", contextExcerpt.slice(0, 900));
      }
      return {
        title: buildSplLibraryTitle(trimmedQuery, options),
        content: contentLines.join("\n"),
        asset_type: SPL_LIBRARY_ASSET_TYPE,
        source_label: sourceLabel || "Interface SPL Query",
        description: String(options.description || "Saved reusable SPL query for direct Splunk launch and chat reuse.").trim(),
        tags: buildSplLibraryTags(options),
        attributes: {
          spl_query: trimmedQuery,
          app: deeplinkDefaults.app,
          earliest: deeplinkDefaults.earliest,
          latest: deeplinkDefaults.latest,
          origin_kind: originKind,
          origin_label: sourceLabel
        }
      };
    };
    const getKnowledgeAssetAttributes = (asset) => {
      return (asset == null ? void 0 : asset.attributes) && typeof asset.attributes === "object" ? asset.attributes : {};
    };
    const getKnowledgeAssetSplIntelligence = (attributes) => {
      return (attributes == null ? void 0 : attributes.spl_intelligence) && typeof attributes.spl_intelligence === "object" ? attributes.spl_intelligence : {};
    };
    const formatSplIntelligenceLabel = (value, fallback = "Unknown") => {
      const normalized = String(value || "").trim().toLowerCase();
      if (!normalized) {
        return fallback;
      }
      if (normalized === "known_good") {
        return "Known Good";
      }
      return formatTokenLabel(normalized) || fallback;
    };
    const getSplEnvironmentFitClasses = (status) => {
      switch (String(status || "").toLowerCase()) {
        case "strong":
          return isDarkTheme ? "bg-emerald-950 border-emerald-800 text-emerald-100" : "bg-emerald-50 border-emerald-200 text-emerald-800";
        case "partial":
          return isDarkTheme ? "bg-amber-950 border-amber-800 text-amber-100" : "bg-amber-50 border-amber-200 text-amber-800";
        case "weak":
        case "mismatch":
          return isDarkTheme ? "bg-rose-950 border-rose-800 text-rose-100" : "bg-rose-50 border-rose-200 text-rose-800";
        default:
          return isDarkTheme ? "bg-gray-800 border-gray-600 text-gray-200" : "bg-gray-100 border-gray-300 text-gray-700";
      }
    };
    const getSplValidationClasses = (status) => {
      switch (String(status || "").toLowerCase()) {
        case "known_good":
          return isDarkTheme ? "bg-emerald-950 border-emerald-800 text-emerald-100" : "bg-emerald-50 border-emerald-200 text-emerald-800";
        case "mixed":
          return isDarkTheme ? "bg-amber-950 border-amber-800 text-amber-100" : "bg-amber-50 border-amber-200 text-amber-800";
        case "failing":
          return isDarkTheme ? "bg-rose-950 border-rose-800 text-rose-100" : "bg-rose-50 border-rose-200 text-rose-800";
        case "unvalidated":
        default:
          return isDarkTheme ? "bg-gray-800 border-gray-600 text-gray-200" : "bg-gray-100 border-gray-300 text-gray-700";
      }
    };
    const getSplReuseTierClasses = (tier, knownGood = false) => {
      if (knownGood || String(tier || "").toLowerCase() === "known_good") {
        return isDarkTheme ? "bg-emerald-950 border-emerald-800 text-emerald-100" : "bg-emerald-50 border-emerald-200 text-emerald-800";
      }
      switch (String(tier || "").toLowerCase()) {
        case "high":
        case "preferred":
          return isDarkTheme ? "bg-sky-950 border-sky-800 text-sky-100" : "bg-sky-50 border-sky-200 text-sky-800";
        case "medium":
        case "candidate":
          return isDarkTheme ? "bg-gray-800 border-gray-600 text-gray-200" : "bg-gray-100 border-gray-300 text-gray-700";
        case "low":
          return isDarkTheme ? "bg-amber-950 border-amber-800 text-amber-100" : "bg-amber-50 border-amber-200 text-amber-800";
        default:
          return isDarkTheme ? "bg-gray-800 border-gray-600 text-gray-200" : "bg-gray-100 border-gray-300 text-gray-700";
      }
    };
    const renderSplQueryIntelligence = (attributes, options = {}) => {
      const splIntelligence = getKnowledgeAssetSplIntelligence(attributes);
      const environmentFit = splIntelligence.environment_fit && typeof splIntelligence.environment_fit === "object" ? splIntelligence.environment_fit : {};
      const validation = splIntelligence.validation && typeof splIntelligence.validation === "object" ? splIntelligence.validation : {};
      const reuse = splIntelligence.reuse && typeof splIntelligence.reuse === "object" ? splIntelligence.reuse : {};
      const fitStatus = String(environmentFit.status || "").trim().toLowerCase();
      const fitReason = String(environmentFit.reason || "").trim();
      const validationStatus = String(validation.status || "").trim().toLowerCase();
      const reuseTier = String(reuse.tier || "").trim().toLowerCase();
      const reuseGuidance = String(reuse.guidance || "").trim();
      const successCount = Number(validation.success_count || 0);
      const failureCount = Number(validation.failure_count || 0);
      const executionCount = Number(validation.execution_count || 0);
      const knownGood = Boolean(reuse.known_good) || validationStatus === "known_good";
      const testIdPrefix = typeof options.testIdPrefix === "string" ? options.testIdPrefix.trim() : "";
      const buildTestId = (suffix) => testIdPrefix ? `${testIdPrefix}-${suffix}` : void 0;
      const hasIntelligence = fitStatus || validationStatus || reuseTier || executionCount > 0 || successCount > 0 || failureCount > 0 || fitReason || reuseGuidance;
      if (!hasIntelligence) {
        return null;
      }
      return /* @__PURE__ */ React.createElement("div", { "data-testid": buildTestId("intelligence-panel"), className: "mt-3 space-y-2" }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-wrap gap-2 text-[11px]" }, fitStatus && /* @__PURE__ */ React.createElement("span", { "data-testid": buildTestId("fit-status"), className: `rounded-full px-2 py-0.5 border ${getSplEnvironmentFitClasses(fitStatus)}` }, "Environment Fit: ", formatSplIntelligenceLabel(fitStatus, "Unknown")), validationStatus && /* @__PURE__ */ React.createElement("span", { "data-testid": buildTestId("validation-status"), className: `rounded-full px-2 py-0.5 border ${getSplValidationClasses(validationStatus)}` }, "Validation: ", formatSplIntelligenceLabel(validationStatus, "Unknown")), (reuseTier || knownGood) && /* @__PURE__ */ React.createElement("span", { "data-testid": buildTestId("reuse-tier"), className: `rounded-full px-2 py-0.5 border ${getSplReuseTierClasses(reuseTier, knownGood)}` }, "Reuse: ", knownGood ? "Known Good" : formatSplIntelligenceLabel(reuseTier, "Candidate")), (executionCount > 0 || successCount > 0 || failureCount > 0) && /* @__PURE__ */ React.createElement("span", { "data-testid": buildTestId("feedback-counts"), className: `rounded-full px-2 py-0.5 border ${isDarkTheme ? "bg-gray-900 border-gray-700 text-gray-200" : "bg-white border-gray-300 text-gray-700"}` }, "Observed Runs: ", successCount, " success / ", failureCount, " failure")), (fitReason || reuseGuidance) && /* @__PURE__ */ React.createElement("div", { "data-testid": buildTestId("intelligence-notes"), className: `text-xs ${subtextClass}` }, [fitReason, reuseGuidance].filter(Boolean).join(" ")));
    };
    const importKnowledgeAssetToLibrary = async (payload, options = {}) => {
      var _a2;
      if (!payload || typeof payload !== "object") {
        return null;
      }
      const fallbackSuccessMessage = String(options.successMessage || "Knowledge asset saved to the context library.").trim();
      const fallbackErrorMessage = String(options.errorMessage || "Knowledge asset import failed.").trim();
      const logLabel = String(options.logLabel || "knowledge asset import").trim() || "knowledge asset import";
      setCapabilityActionState((prev) => ({
        ...prev,
        rag_chromadb: "import-asset"
      }));
      try {
        const response = await fetch("/api/capabilities/rag/assets/import/text", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload)
        });
        const result = await response.json();
        if (!response.ok) {
          throw new Error((result == null ? void 0 : result.detail) || (result == null ? void 0 : result.message) || fallbackErrorMessage);
        }
        const savedAsset = ((_a2 = result == null ? void 0 : result.details) == null ? void 0 : _a2.asset) || null;
        const savedAssetId = (savedAsset == null ? void 0 : savedAsset.asset_id) || null;
        setCapabilityNotice({
          type: "success",
          message: (result == null ? void 0 : result.message) || fallbackSuccessMessage
        });
        await loadCapabilities();
        if (savedAssetId && ragAssetWorkspace.detailAssetId === savedAssetId) {
          await loadRagAssetDetail(savedAssetId, { force: true });
        }
        return savedAsset;
      } catch (error) {
        console.error(`Failed during ${logLabel}:`, error);
        setCapabilityNotice({
          type: "error",
          message: (error == null ? void 0 : error.message) || fallbackErrorMessage
        });
        return null;
      } finally {
        setCapabilityActionState((prev) => {
          const next = { ...prev };
          delete next.rag_chromadb;
          return next;
        });
        setTimeout(() => setCapabilityNotice(null), 3500);
      }
    };
    const saveSplQueryToLibrary = async (splQuery, options = {}) => {
      const payload = buildSplLibraryPayload(splQuery, options);
      if (!payload) {
        return null;
      }
      return importKnowledgeAssetToLibrary(payload, {
        successMessage: "SPL query saved to the context library.",
        errorMessage: "Failed to save SPL query to the library.",
        logLabel: "save SPL query to library"
      });
    };
    const useSplQueryInChat = (splQuery, options = {}) => {
      const trimmedQuery = String(splQuery || "").trim();
      if (!trimmedQuery) {
        return;
      }
      const contextLabel = String(options.originLabel || options.sourceLabel || "saved SPL query").trim() || "saved SPL query";
      const prompt = String(options.chatPrompt || "").trim() || [
        `Help me work with this ${contextLabel}:`,
        "",
        "```spl",
        trimmedQuery,
        "```",
        "",
        "Explain it, refine it, or run it if appropriate."
      ].join("\n");
      openChatSurface();
      setChatInput(prompt);
      setTimeout(() => {
        var _a2;
        return (_a2 = chatInputRef.current) == null ? void 0 : _a2.focus();
      }, 0);
    };
    const renderSplQueryActionButtons2 = (splQuery, options = {}) => {
      const trimmedQuery = String(splQuery || "").trim();
      if (!trimmedQuery) {
        return null;
      }
      const deeplinkOptions = options.deeplinkOptions || {};
      return /* @__PURE__ */ React.createElement("div", { className: `flex flex-wrap items-center gap-2 ${options.className || ""}` }, canUseSplunkDeeplinks && /* @__PURE__ */ React.createElement(
        "button",
        {
          type: "button",
          onClick: () => openSplunkSearch(trimmedQuery, deeplinkOptions),
          className: "px-2 py-1 text-xs text-sky-200 hover:text-white bg-sky-900 hover:bg-sky-800 rounded transition-colors",
          title: "Open this search in Splunk Web"
        },
        /* @__PURE__ */ React.createElement("i", { className: "fas fa-external-link-alt mr-1" }),
        "Open in Splunk"
      ), options.allowSave !== false && /* @__PURE__ */ React.createElement(
        "button",
        {
          type: "button",
          onClick: () => saveSplQueryToLibrary(trimmedQuery, options),
          disabled: isRagBusy,
          className: `px-2 py-1 text-xs rounded transition-colors ${!isRagBusy ? "text-emerald-100 bg-emerald-700 hover:bg-emerald-800" : isDarkTheme ? "bg-gray-800 text-gray-500 cursor-not-allowed" : "bg-gray-200 text-gray-500 cursor-not-allowed"}`,
          title: "Save this query to the managed SPL library"
        },
        /* @__PURE__ */ React.createElement("i", { className: "fas fa-bookmark mr-1" }),
        ragActionInProgress === "import-asset" ? "Saving..." : "Save to Library"
      ), options.allowUseInChat !== false && /* @__PURE__ */ React.createElement(
        "button",
        {
          type: "button",
          onClick: () => useSplQueryInChat(trimmedQuery, options),
          className: "px-2 py-1 text-xs text-violet-100 hover:text-white bg-violet-700 hover:bg-violet-800 rounded transition-colors",
          title: "Bring this query into the chat workspace"
        },
        /* @__PURE__ */ React.createElement("i", { className: "fas fa-comments mr-1" }),
        "Use in Chat"
      ), options.allowCopy !== false && /* @__PURE__ */ React.createElement(
        "button",
        {
          type: "button",
          onClick: () => copyToClipboard(trimmedQuery),
          className: "px-2 py-1 text-xs text-gray-300 hover:text-white bg-gray-800 hover:bg-gray-700 rounded transition-colors",
          title: "Copy this query to the clipboard"
        },
        /* @__PURE__ */ React.createElement("i", { className: "fas fa-copy mr-1" }),
        "Copy"
      ));
    };
    const renderCapabilityReusableQueryCards = (usage) => {
      const reusableQueries = Array.isArray(usage == null ? void 0 : usage.reusable_queries) ? usage.reusable_queries.filter((candidate) => typeof (candidate == null ? void 0 : candidate.query) === "string" && candidate.query.trim()).slice(0, 3) : [];
      if (reusableQueries.length === 0) {
        return null;
      }
      return /* @__PURE__ */ React.createElement("div", { className: "space-y-2 mt-3", "data-testid": "chat-capability-reusable-query-list" }, /* @__PURE__ */ React.createElement("div", { className: `text-[11px] font-semibold uppercase tracking-[0.18em] ${mutedTextClass}` }, "Reusable SPL Candidates"), reusableQueries.map((candidate, candidateIdx) => {
        const query = String(candidate.query || "").trim();
        const reuseTier = String(candidate.reuse_tier || "").trim().toLowerCase();
        const fitStatus = String(candidate.environment_fit_status || "").trim().toLowerCase();
        const validationStatus = String(candidate.validation_status || "").trim().toLowerCase();
        const successCount = Number(candidate.success_count || 0);
        const failureCount = Number(candidate.failure_count || 0);
        const knownGood = Boolean(candidate.known_good) || validationStatus === "known_good";
        return /* @__PURE__ */ React.createElement("div", { key: `${(usage == null ? void 0 : usage.name) || "capability"}-candidate-${candidateIdx}`, "data-testid": "chat-capability-reusable-query-card", className: `rounded-lg border p-3 ${isDarkTheme ? "bg-gray-900 border-gray-700" : "bg-white border-emerald-200"}` }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-col gap-2 sm:flex-row sm:items-start sm:justify-between" }, /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("div", { className: `text-sm font-medium ${headingClass}` }, candidate.title || "Saved SPL Query"), candidate.why_reuse && /* @__PURE__ */ React.createElement("div", { className: `mt-1 text-xs ${subtextClass}` }, candidate.why_reuse)), renderSplQueryActionButtons2(query, {
          allowSave: false,
          originKind: "chat_capability_reuse",
          originLabel: candidate.title || (usage == null ? void 0 : usage.title) || "Reusable SPL candidate",
          sourceLabel: (usage == null ? void 0 : usage.title) || (usage == null ? void 0 : usage.name) || "Capability Evidence",
          contextExcerpt: candidate.why_reuse || (usage == null ? void 0 : usage.contribution) || "",
          deeplinkOptions: {
            app: candidate.app,
            earliest: candidate.earliest,
            latest: candidate.latest
          },
          className: "sm:justify-end"
        })), /* @__PURE__ */ React.createElement("div", { className: "mt-2 flex flex-wrap gap-2 text-[11px]" }, (reuseTier || knownGood) && /* @__PURE__ */ React.createElement("span", { "data-testid": "chat-capability-reusable-query-reuse-tier", className: `rounded-full px-2 py-0.5 border ${getSplReuseTierClasses(reuseTier, knownGood)}` }, "Reuse: ", knownGood ? "Known Good" : formatSplIntelligenceLabel(reuseTier, "Candidate")), fitStatus && /* @__PURE__ */ React.createElement("span", { "data-testid": "chat-capability-reusable-query-fit-status", className: `rounded-full px-2 py-0.5 border ${getSplEnvironmentFitClasses(fitStatus)}` }, "Environment Fit: ", formatSplIntelligenceLabel(fitStatus, "Unknown")), validationStatus && /* @__PURE__ */ React.createElement("span", { "data-testid": "chat-capability-reusable-query-validation-status", className: `rounded-full px-2 py-0.5 border ${getSplValidationClasses(validationStatus)}` }, "Validation: ", formatSplIntelligenceLabel(validationStatus, "Unknown")), (successCount > 0 || failureCount > 0) && /* @__PURE__ */ React.createElement("span", { "data-testid": "chat-capability-reusable-query-feedback-counts", className: `rounded-full px-2 py-0.5 border ${isDarkTheme ? "bg-gray-800 border-gray-600 text-gray-200" : "bg-gray-100 border-gray-300 text-gray-700"}` }, "Observed Runs: ", successCount, " success / ", failureCount, " failure")), /* @__PURE__ */ React.createElement("pre", { "data-testid": "chat-capability-reusable-query", className: `mt-2 max-h-32 overflow-auto rounded-lg border px-3 py-3 text-xs whitespace-pre-wrap font-mono ${isDarkTheme ? "bg-gray-950 border-gray-700 text-gray-100" : "bg-gray-50 border-gray-200 text-gray-900"}` }, query));
      }));
    };
    const extractAssistantSplQuery = (result) => {
      var _a2;
      if (typeof (result == null ? void 0 : result.spl_query) === "string" && result.spl_query.trim()) {
        return result.spl_query.trim();
      }
      const toolCalls = Array.isArray(result == null ? void 0 : result.tool_calls) ? result.tool_calls : [];
      for (let index = toolCalls.length - 1; index >= 0; index -= 1) {
        const toolCall = toolCalls[index];
        if (typeof (toolCall == null ? void 0 : toolCall.spl_query) === "string" && toolCall.spl_query.trim()) {
          return toolCall.spl_query.trim();
        }
        if (typeof ((_a2 = toolCall == null ? void 0 : toolCall.args) == null ? void 0 : _a2.query) === "string" && toolCall.args.query.trim()) {
          return toolCall.args.query.trim();
        }
      }
      return void 0;
    };
    const formatVisualizationNumber2 = (value) => {
      const numericValue = Number(value);
      if (!Number.isFinite(numericValue)) {
        return String(value != null ? value : "");
      }
      if (Math.abs(numericValue) >= 1e3) {
        return numericValue.toLocaleString();
      }
      if (Math.abs(numericValue) >= 10 || Number.isInteger(numericValue)) {
        return numericValue.toFixed(0);
      }
      return numericValue.toFixed(2).replace(/\.00$/, "");
    };
    const renderVisualizationPreview = (spec, options = {}) => /* @__PURE__ */ React.createElement(
      VisualizationPreviewCard,
      {
        spec,
        isDarkTheme,
        headingClass,
        subtextClass,
        mutedTextClass,
        sourceQuery: options.sourceQuery,
        canOpenSplunk: !!options.canOpenSplunk,
        onOpenSplunk: options.onOpenSplunk
      }
    );
    const saveCapabilityConfig = async (name) => {
      try {
        const parsed = JSON.parse(capabilityDrafts[name] || "{}");
        await runCapabilityAction(name, "config", { config: parsed });
      } catch (error) {
        setCapabilityNotice({
          type: "error",
          message: `${name}: capability config must be valid JSON before saving.`
        });
        setTimeout(() => setCapabilityNotice(null), 3500);
      }
    };
    const loadDiscoveryCompare = async (current = "latest", baseline = "previous") => {
      try {
        const params = new URLSearchParams();
        if (current) params.set("current", current);
        if (baseline) params.set("baseline", baseline);
        const response = await fetch(`/api/discovery/compare?${params.toString()}`);
        if (!response.ok) {
          throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }
        const result = await response.json();
        setDiscoveryCompare(result);
      } catch (error) {
        console.error("Failed to load discovery compare:", error);
        setDiscoveryCompare({ has_data: false, message: error.message || "Failed to load compare data." });
      }
    };
    const loadRunbookPayload = async (timestamp = "latest", persona = workflowTab, voice = operatorVoice) => {
      try {
        const params = new URLSearchParams();
        if (timestamp) params.set("timestamp", timestamp);
        if (persona) params.set("persona", persona);
        if (voice) params.set("voice", voice);
        const response = await fetch(`/api/discovery/runbook?${params.toString()}`);
        if (!response.ok) {
          throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }
        const result = await response.json();
        setRunbookPayload(result);
        return result;
      } catch (error) {
        console.error("Failed to load runbook payload:", error);
        const fallbackResult = { has_data: false, message: error.message || "Failed to load runbook." };
        setRunbookPayload(fallbackResult);
        return fallbackResult;
      }
    };
    const ensureCurrentRunbookPayload = async () => {
      var _a2;
      const requestedTimestamp = compareSelection.current || "latest";
      const currentSessionTimestamp = String(((_a2 = runbookPayload == null ? void 0 : runbookPayload.session) == null ? void 0 : _a2.timestamp) || "").trim();
      const hasMatchingTimestamp = requestedTimestamp === "latest" || currentSessionTimestamp === requestedTimestamp;
      const hasMatchingPersona = String((runbookPayload == null ? void 0 : runbookPayload.persona) || "").trim() === workflowTab;
      const hasMatchingVoice = String((runbookPayload == null ? void 0 : runbookPayload.voice) || "").trim() === operatorVoice;
      if ((runbookPayload == null ? void 0 : runbookPayload.has_data) && hasMatchingTimestamp && hasMatchingPersona && hasMatchingVoice) {
        return runbookPayload;
      }
      return loadRunbookPayload(requestedTimestamp, workflowTab, operatorVoice);
    };
    const refreshCompareSelection = () => {
      loadDiscoveryCompare(compareSelection.current, compareSelection.baseline);
    };
    const refreshRunbook = () => {
      return loadRunbookPayload(compareSelection.current, workflowTab, operatorVoice);
    };
    const downloadCapabilityExport = (filename) => {
      if (!filename) {
        return;
      }
      const link = document.createElement("a");
      link.href = `/api/capabilities/exports/download/${encodeURIComponent(filename)}`;
      link.target = "_blank";
      link.rel = "noreferrer";
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
    };
    const buildCapabilityExport = async (payload = {}, options = {}) => {
      var _a2;
      setExportBuildState({ status: "loading", bundle: null, error: "" });
      try {
        const response = await fetch("/api/capabilities/exports/build", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload)
        });
        const result = await response.json();
        if (!response.ok) {
          throw new Error((result == null ? void 0 : result.detail) || (result == null ? void 0 : result.message) || `HTTP ${response.status}`);
        }
        const exportBundle = ((_a2 = result == null ? void 0 : result.details) == null ? void 0 : _a2.export) || null;
        if (!exportBundle) {
          throw new Error("Report package details were not returned by the server.");
        }
        setExportBuildState({ status: "success", bundle: exportBundle, error: "" });
        loadReports();
        loadV2Artifacts();
        loadCapabilities();
        if (options.downloadAfterBuild && (exportBundle == null ? void 0 : exportBundle.download_name)) {
          downloadCapabilityExport(exportBundle.download_name);
        }
        return exportBundle;
      } catch (error) {
        console.error("Failed to build report package:", error);
        setExportBuildState({
          status: "error",
          bundle: null,
          error: (error == null ? void 0 : error.message) || "Failed to build report package."
        });
        return null;
      }
    };
    const clearRagAssetDraft = () => {
      setRagAssetDraft(defaultRagAssetDraft);
      setRagAssetUploadFile(null);
      if (ragAssetFileInputRef.current) {
        ragAssetFileInputRef.current.value = "";
      }
    };
    const updateRagAssetDraft = (field, value) => {
      setRagAssetDraft((prev) => ({
        ...prev,
        [field]: value
      }));
    };
    const clearRagAssetDetail = () => {
      setRagAssetWorkspace((prev) => ({
        ...prev,
        detailAssetId: null,
        assetDetail: null,
        detailStatus: "idle",
        detailError: ""
      }));
    };
    const loadRagAssetDetail = async (assetId, options = {}) => {
      var _a2, _b2;
      if (!assetId) {
        return;
      }
      const detailAlreadyOpen = ragAssetWorkspace.detailStatus === "success" && ((_b2 = (_a2 = ragAssetWorkspace.assetDetail) == null ? void 0 : _a2.asset) == null ? void 0 : _b2.asset_id) === assetId;
      if (!options.force && detailAlreadyOpen) {
        clearRagAssetDetail();
        return;
      }
      setRagAssetWorkspace((prev) => {
        var _a3, _b3;
        return {
          ...prev,
          detailAssetId: assetId,
          detailStatus: "loading",
          detailError: "",
          assetDetail: ((_b3 = (_a3 = prev.assetDetail) == null ? void 0 : _a3.asset) == null ? void 0 : _b3.asset_id) === assetId ? prev.assetDetail : null
        };
      });
      try {
        const response = await fetch(`/api/capabilities/rag/assets/${encodeURIComponent(assetId)}`);
        const result = await response.json();
        if (!response.ok) {
          throw new Error((result == null ? void 0 : result.detail) || (result == null ? void 0 : result.message) || "Knowledge asset detail could not be loaded.");
        }
        setRagAssetWorkspace((prev) => ({
          ...prev,
          detailAssetId: assetId,
          assetDetail: (result == null ? void 0 : result.details) || null,
          detailStatus: "success",
          detailError: ""
        }));
      } catch (error) {
        console.error("Failed to load knowledge asset detail:", error);
        setRagAssetWorkspace((prev) => ({
          ...prev,
          detailAssetId: assetId,
          assetDetail: null,
          detailStatus: "error",
          detailError: error.message || "Knowledge asset detail could not be loaded."
        }));
      }
    };
    const importRagKnowledgeAsset = async () => {
      var _a2;
      const usingFileUpload = !!ragAssetUploadFile;
      const trimmedTitle = String(ragAssetDraft.title || "").trim();
      const trimmedContent = String(ragAssetDraft.content || "").trim();
      if (!usingFileUpload && !trimmedTitle) {
        setCapabilityNotice({
          type: "error",
          message: "rag_chromadb: asset title is required when pasting content."
        });
        setTimeout(() => setCapabilityNotice(null), 3500);
        return;
      }
      if (!usingFileUpload && !trimmedContent) {
        setCapabilityNotice({
          type: "error",
          message: "rag_chromadb: provide pasted content or choose a supported file to import."
        });
        setTimeout(() => setCapabilityNotice(null), 3500);
        return;
      }
      setCapabilityActionState((prev) => ({
        ...prev,
        rag_chromadb: "import-asset"
      }));
      try {
        let response;
        if (usingFileUpload) {
          const formData = new FormData();
          formData.append("file", ragAssetUploadFile);
          if (trimmedTitle) {
            formData.append("title", trimmedTitle);
          }
          formData.append("asset_type", ragAssetDraft.asset_type || "reference_document");
          formData.append("source_label", ragAssetDraft.source_label || "");
          formData.append("description", ragAssetDraft.description || "");
          formData.append("tags", ragAssetDraft.tags || "");
          response = await fetch("/api/capabilities/rag/assets/import/file", {
            method: "POST",
            body: formData
          });
        } else {
          response = await fetch("/api/capabilities/rag/assets/import/text", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              title: trimmedTitle,
              content: trimmedContent,
              asset_type: ragAssetDraft.asset_type || "reference_document",
              source_label: ragAssetDraft.source_label || "",
              description: ragAssetDraft.description || "",
              tags: String(ragAssetDraft.tags || "").split(",").map((tag) => tag.trim()).filter(Boolean)
            })
          });
        }
        const result = await response.json();
        if (!response.ok) {
          throw new Error((result == null ? void 0 : result.detail) || (result == null ? void 0 : result.message) || "Knowledge asset import failed.");
        }
        const assetSummary = ((_a2 = result == null ? void 0 : result.details) == null ? void 0 : _a2.asset_summary) || {};
        setRagAssetWorkspace((prev) => ({
          ...prev,
          status: "success",
          summary: buildRagAssetSummaryState(assetSummary, prev.summary),
          assets: Array.isArray(assetSummary.assets) ? assetSummary.assets : prev.assets,
          contextPreview: null,
          detailAssetId: null,
          assetDetail: null,
          detailStatus: "idle",
          detailError: "",
          error: ""
        }));
        setCapabilityNotice({
          type: "success",
          message: (result == null ? void 0 : result.message) || "Knowledge asset imported."
        });
        clearRagAssetDraft();
        await loadCapabilities();
      } catch (error) {
        console.error("Failed to import knowledge asset:", error);
        setCapabilityNotice({
          type: "error",
          message: error.message || "Knowledge asset import failed."
        });
      } finally {
        setCapabilityActionState((prev) => {
          const next = { ...prev };
          delete next.rag_chromadb;
          return next;
        });
        setTimeout(() => setCapabilityNotice(null), 3500);
      }
    };
    const deleteRagKnowledgeAsset = async (assetId, assetTitle) => {
      var _a2;
      if (!assetId) {
        return;
      }
      const confirmed = window.confirm(`Delete knowledge asset "${assetTitle || "selected asset"}"?`);
      if (!confirmed) {
        return;
      }
      setCapabilityActionState((prev) => ({
        ...prev,
        rag_chromadb: "delete-asset"
      }));
      try {
        const response = await fetch(`/api/capabilities/rag/assets/${encodeURIComponent(assetId)}/delete`, {
          method: "POST"
        });
        const result = await response.json();
        if (!response.ok) {
          throw new Error((result == null ? void 0 : result.detail) || (result == null ? void 0 : result.message) || "Knowledge asset deletion failed.");
        }
        const assetSummary = ((_a2 = result == null ? void 0 : result.details) == null ? void 0 : _a2.asset_summary) || {};
        setRagAssetWorkspace((prev) => ({
          ...prev,
          status: "success",
          summary: buildRagAssetSummaryState(assetSummary, prev.summary),
          assets: Array.isArray(assetSummary.assets) ? assetSummary.assets : prev.assets,
          contextPreview: null,
          detailAssetId: null,
          assetDetail: null,
          detailStatus: "idle",
          detailError: "",
          error: ""
        }));
        setCapabilityNotice({
          type: "success",
          message: (result == null ? void 0 : result.message) || "Knowledge asset deleted."
        });
        await loadCapabilities();
      } catch (error) {
        console.error("Failed to delete knowledge asset:", error);
        setCapabilityNotice({
          type: "error",
          message: error.message || "Knowledge asset deletion failed."
        });
      } finally {
        setCapabilityActionState((prev) => {
          const next = { ...prev };
          delete next.rag_chromadb;
          return next;
        });
        setTimeout(() => setCapabilityNotice(null), 3500);
      }
    };
    const setRagKnowledgeAssetLibraryStatus = async (assetId, assetTitle, libraryStatus) => {
      var _a2;
      if (!assetId) {
        return;
      }
      const normalizedStatus = String(libraryStatus || "checked_in").toLowerCase() === "checked_out" ? "checked_out" : "checked_in";
      const endpoint = normalizedStatus === "checked_out" ? "check-out" : "check-in";
      const actionKey = normalizedStatus === "checked_out" ? "check-out-asset" : "check-in-asset";
      const statusLabel = normalizedStatus === "checked_out" ? "check out" : "check in";
      if (normalizedStatus === "checked_out") {
        const confirmed = window.confirm(`Check out knowledge asset "${assetTitle || "selected asset"}" from the active RAG library? It will stay stored, but retrieval previews will stop using it until it is checked back in.`);
        if (!confirmed) {
          return;
        }
      }
      setCapabilityActionState((prev) => ({
        ...prev,
        rag_chromadb: actionKey
      }));
      try {
        const response = await fetch(`/api/capabilities/rag/assets/${encodeURIComponent(assetId)}/${endpoint}`, {
          method: "POST"
        });
        const result = await response.json();
        if (!response.ok) {
          throw new Error((result == null ? void 0 : result.detail) || (result == null ? void 0 : result.message) || `Knowledge asset ${statusLabel} failed.`);
        }
        const assetSummary = ((_a2 = result == null ? void 0 : result.details) == null ? void 0 : _a2.asset_summary) || {};
        setRagAssetWorkspace((prev) => ({
          ...prev,
          status: "success",
          summary: buildRagAssetSummaryState(assetSummary, prev.summary),
          assets: Array.isArray(assetSummary.assets) ? assetSummary.assets : prev.assets,
          contextPreview: null,
          detailAssetId: null,
          assetDetail: null,
          detailStatus: "idle",
          detailError: "",
          error: ""
        }));
        setCapabilityNotice({
          type: "success",
          message: (result == null ? void 0 : result.message) || `Knowledge asset ${statusLabel} completed.`
        });
        await loadCapabilities();
      } catch (error) {
        console.error(`Failed to ${statusLabel} knowledge asset:`, error);
        setCapabilityNotice({
          type: "error",
          message: error.message || `Knowledge asset ${statusLabel} failed.`
        });
      } finally {
        setCapabilityActionState((prev) => {
          const next = { ...prev };
          delete next.rag_chromadb;
          return next;
        });
        setTimeout(() => setCapabilityNotice(null), 3500);
      }
    };
    const buildRagContextPreview = async () => {
      const trimmedQuery = String(ragContextQuery || "").trim();
      if (!trimmedQuery) {
        setCapabilityNotice({
          type: "error",
          message: "rag_chromadb: enter a context question before building a preview."
        });
        setTimeout(() => setCapabilityNotice(null), 3500);
        return;
      }
      setCapabilityActionState((prev) => ({
        ...prev,
        rag_chromadb: "build-context"
      }));
      try {
        const response = await fetch("/api/capabilities/rag/context/build", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            query: trimmedQuery,
            limit: ragContextLimit
          })
        });
        const result = await response.json();
        if (!response.ok) {
          throw new Error((result == null ? void 0 : result.detail) || (result == null ? void 0 : result.message) || "RAG context preview failed.");
        }
        setRagAssetWorkspace((prev) => ({
          ...prev,
          contextPreview: (result == null ? void 0 : result.details) || null,
          error: ""
        }));
        setCapabilityNotice({
          type: "success",
          message: (result == null ? void 0 : result.message) || "RAG context preview generated."
        });
      } catch (error) {
        console.error("Failed to build RAG context preview:", error);
        setCapabilityNotice({
          type: "error",
          message: error.message || "RAG context preview failed."
        });
      } finally {
        setCapabilityActionState((prev) => {
          const next = { ...prev };
          delete next.rag_chromadb;
          return next;
        });
        setTimeout(() => setCapabilityNotice(null), 3500);
      }
    };
    const openCapabilitiesOverview = () => {
      setWorkspaceTab("capabilities");
      setCapabilitiesView("overview");
      loadCapabilities();
    };
    const openRagCapabilitiesWorkspace = (options = {}) => {
      setWorkspaceTab("capabilities");
      setCapabilitiesView("rag");
      if (options.libraryFilter) {
        setRagLibraryFilter(options.libraryFilter);
      }
      loadCapabilities();
    };
    const openCapabilityDetail = (name) => {
      if (!name) {
        return;
      }
      setSelectedCapabilityDetailName(name);
    };
    const closeCapabilityDetail = () => {
      setSelectedCapabilityDetailName(null);
    };
    const renderCapabilityRuntimeSnapshot = (capability) => {
      var _a2, _b2, _c2, _d2, _e2, _f2, _g2, _h2, _i2, _j2, _k2, _l2, _m2, _n2;
      if (!capability) {
        return null;
      }
      if (capability.name === "rag_local") {
        return /* @__PURE__ */ React.createElement("div", { className: `rounded-xl border p-4 ${panelMutedClass}` }, /* @__PURE__ */ React.createElement("div", { className: `text-[11px] uppercase tracking-[0.18em] ${mutedTextClass}` }, "Operational Snapshot"), /* @__PURE__ */ React.createElement("div", { className: `mt-2 text-sm font-semibold ${headingClass}` }, "Local Search Profile"), /* @__PURE__ */ React.createElement("div", { className: `grid grid-cols-1 gap-3 mt-3 text-sm sm:grid-cols-2 ${subtextClass}` }, /* @__PURE__ */ React.createElement("div", null, "Source directory: ", ((_a2 = capability == null ? void 0 : capability.config) == null ? void 0 : _a2.source_dir) || "output"), /* @__PURE__ */ React.createElement("div", null, "Max files scanned: ", ((_b2 = capability == null ? void 0 : capability.config) == null ? void 0 : _b2.max_files) || 8), /* @__PURE__ */ React.createElement("div", null, "Max scan characters: ", ((_c2 = capability == null ? void 0 : capability.config) == null ? void 0 : _c2.max_scan_chars) || 12e3), /* @__PURE__ */ React.createElement("div", null, "Snippet size: ", ((_d2 = capability == null ? void 0 : capability.config) == null ? void 0 : _d2.max_block_chars) || 420)), /* @__PURE__ */ React.createElement("div", { className: `mt-3 text-xs ${mutedTextClass}` }, "Allowed file types: ", Array.isArray((_e2 = capability == null ? void 0 : capability.config) == null ? void 0 : _e2.allowed_extensions) && capability.config.allowed_extensions.length > 0 ? capability.config.allowed_extensions.join(", ") : ".md, .txt, .json"));
      }
      if (capability.name === "rag_chromadb") {
        const indexSummary = (capability == null ? void 0 : capability.index_summary) && typeof capability.index_summary === "object" ? capability.index_summary : null;
        const knowledgeAssetSummary = (capability == null ? void 0 : capability.knowledge_asset_summary) && typeof capability.knowledge_asset_summary === "object" ? capability.knowledge_asset_summary : null;
        const indexSourceTypes = (indexSummary == null ? void 0 : indexSummary.source_type_counts) && typeof indexSummary.source_type_counts === "object" ? Object.entries(indexSummary.source_type_counts) : [];
        const knowledgeAssetTypes = (knowledgeAssetSummary == null ? void 0 : knowledgeAssetSummary.asset_type_counts) && typeof knowledgeAssetSummary.asset_type_counts === "object" ? Object.entries(knowledgeAssetSummary.asset_type_counts) : [];
        return /* @__PURE__ */ React.createElement("div", { className: `rounded-xl border p-4 ${panelMutedClass}` }, /* @__PURE__ */ React.createElement("div", { className: `text-[11px] uppercase tracking-[0.18em] ${mutedTextClass}` }, "Operational Snapshot"), /* @__PURE__ */ React.createElement("div", { className: `mt-2 text-sm font-semibold ${headingClass}` }, "Indexed Retrieval Plane"), /* @__PURE__ */ React.createElement("div", { className: `grid grid-cols-1 gap-3 mt-3 text-sm sm:grid-cols-2 ${subtextClass}` }, /* @__PURE__ */ React.createElement("div", null, "Indexed documents: ", (indexSummary == null ? void 0 : indexSummary.document_count) || 0), /* @__PURE__ */ React.createElement("div", null, "Source files indexed: ", (indexSummary == null ? void 0 : indexSummary.source_file_count) || 0), /* @__PURE__ */ React.createElement("div", null, "Managed assets: ", (knowledgeAssetSummary == null ? void 0 : knowledgeAssetSummary.asset_count) || 0), /* @__PURE__ */ React.createElement("div", null, "Asset directory: ", (knowledgeAssetSummary == null ? void 0 : knowledgeAssetSummary.asset_dir) || ((_f2 = capability == null ? void 0 : capability.config) == null ? void 0 : _f2.asset_dir) || "output/rag/assets")), /* @__PURE__ */ React.createElement("div", { className: `mt-3 text-xs ${mutedTextClass}` }, "Storage directory: ", ((_g2 = capability == null ? void 0 : capability.config) == null ? void 0 : _g2.storage_dir) || "output/rag/chromadb"), (indexSummary == null ? void 0 : indexSummary.last_indexed_at) && /* @__PURE__ */ React.createElement("div", { className: `mt-1 text-xs ${mutedTextClass}` }, "Last indexed: ", new Date(indexSummary.last_indexed_at).toLocaleString()), (indexSourceTypes.length > 0 || knowledgeAssetTypes.length > 0) && /* @__PURE__ */ React.createElement("div", { className: "grid grid-cols-1 gap-3 mt-4 lg:grid-cols-2" }, /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("div", { className: `text-xs font-medium mb-2 ${headingClass}` }, "Indexed Source Mix"), /* @__PURE__ */ React.createElement("div", { className: "flex flex-wrap gap-2 text-[11px]" }, indexSourceTypes.length > 0 ? indexSourceTypes.map(([sourceType, count]) => /* @__PURE__ */ React.createElement("span", { key: sourceType, className: `rounded-full px-2 py-0.5 border ${isDarkTheme ? "bg-gray-800 text-gray-200 border-gray-600" : "bg-white text-gray-700 border-gray-300"}` }, formatCapabilitySourceTypeLabel(sourceType), ": ", count)) : /* @__PURE__ */ React.createElement("span", { className: mutedTextClass }, "No indexed source mix yet."))), /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("div", { className: `text-xs font-medium mb-2 ${headingClass}` }, "Knowledge Asset Mix"), /* @__PURE__ */ React.createElement("div", { className: "flex flex-wrap gap-2 text-[11px]" }, knowledgeAssetTypes.length > 0 ? knowledgeAssetTypes.map(([assetType, count]) => /* @__PURE__ */ React.createElement("span", { key: assetType, className: `rounded-full px-2 py-0.5 border ${isDarkTheme ? "bg-gray-800 text-gray-200 border-gray-600" : "bg-white text-gray-700 border-gray-300"}` }, formatKnowledgeAssetTypeLabel(assetType), ": ", count)) : /* @__PURE__ */ React.createElement("span", { className: mutedTextClass }, "No managed assets imported yet.")))));
      }
      if (capability.name === "splunk_deeplink_tools") {
        return /* @__PURE__ */ React.createElement("div", { className: `rounded-xl border p-4 ${panelMutedClass}` }, /* @__PURE__ */ React.createElement("div", { className: `text-[11px] uppercase tracking-[0.18em] ${mutedTextClass}` }, "Operational Snapshot"), /* @__PURE__ */ React.createElement("div", { className: `mt-2 text-sm font-semibold ${headingClass}` }, "Splunk Pivot Path"), /* @__PURE__ */ React.createElement("div", { className: `grid grid-cols-1 gap-3 mt-3 text-sm sm:grid-cols-2 ${subtextClass}` }, /* @__PURE__ */ React.createElement("div", null, "Resolved web URL: ", capability.resolved_web_base_url || "Unavailable"), /* @__PURE__ */ React.createElement("div", null, "Resolution source: ", capability.base_url_source || "unresolved"), /* @__PURE__ */ React.createElement("div", null, "Default app: ", capability.default_app || ((_h2 = capability == null ? void 0 : capability.config) == null ? void 0 : _h2.default_app) || "search"), /* @__PURE__ */ React.createElement("div", null, "Default earliest: ", ((_i2 = capability == null ? void 0 : capability.config) == null ? void 0 : _i2.default_earliest) || "-24h")), capability.sample_search_url && /* @__PURE__ */ React.createElement("div", { className: "mt-3" }, /* @__PURE__ */ React.createElement(
          "a",
          {
            href: capability.sample_search_url,
            target: "_blank",
            rel: "noreferrer",
            className: "text-sm font-medium text-sky-600 hover:text-sky-800 underline"
          },
          "Open sample search"
        )));
      }
      if (capability.name === "visualization_tools") {
        return /* @__PURE__ */ React.createElement("div", { className: `rounded-xl border p-4 ${panelMutedClass}` }, /* @__PURE__ */ React.createElement("div", { className: `text-[11px] uppercase tracking-[0.18em] ${mutedTextClass}` }, "Operational Snapshot"), /* @__PURE__ */ React.createElement("div", { className: `mt-2 text-sm font-semibold ${headingClass}` }, "Visualization Delivery"), /* @__PURE__ */ React.createElement("div", { className: `grid grid-cols-1 gap-3 mt-3 text-sm sm:grid-cols-2 ${subtextClass}` }, /* @__PURE__ */ React.createElement("div", null, "Preview enabled: ", capability.preview_enabled ? "Yes" : "No"), /* @__PURE__ */ React.createElement("div", null, "Max preview points: ", capability.max_preview_points || ((_j2 = capability == null ? void 0 : capability.config) == null ? void 0 : _j2.max_preview_points) || 8), /* @__PURE__ */ React.createElement("div", null, "Chart types: ", Array.isArray(capability.supported_chart_types) && capability.supported_chart_types.length > 0 ? capability.supported_chart_types.join(", ") : "line, bar"), /* @__PURE__ */ React.createElement("div", null, "Query shapes: ", Array.isArray(capability.supported_query_shapes) && capability.supported_query_shapes.length > 0 ? capability.supported_query_shapes.join(", ") : "time_series, aggregation")));
      }
      if (capability.name === "export_tools") {
        return /* @__PURE__ */ React.createElement("div", { className: `rounded-xl border p-4 ${panelMutedClass}` }, /* @__PURE__ */ React.createElement("div", { className: `text-[11px] uppercase tracking-[0.18em] ${mutedTextClass}` }, "Operational Snapshot"), /* @__PURE__ */ React.createElement("div", { className: `mt-2 text-sm font-semibold ${headingClass}` }, "Report Package Delivery"), /* @__PURE__ */ React.createElement("div", { className: `grid grid-cols-1 gap-3 mt-3 text-sm sm:grid-cols-2 ${subtextClass}` }, /* @__PURE__ */ React.createElement("div", null, "Source directory: ", capability.output_dir || ((_k2 = capability == null ? void 0 : capability.config) == null ? void 0 : _k2.source_dir) || "output"), /* @__PURE__ */ React.createElement("div", null, "Export directory: ", capability.export_dir || ((_l2 = capability == null ? void 0 : capability.config) == null ? void 0 : _l2.export_dir) || "output/exports"), /* @__PURE__ */ React.createElement("div", null, "Available sessions: ", capability.available_session_count || 0), /* @__PURE__ */ React.createElement("div", null, "Packages built: ", capability.bundle_count || 0)), /* @__PURE__ */ React.createElement("div", { className: `mt-3 text-xs ${mutedTextClass}` }, "Package contents: ", Array.isArray(capability.supported_outputs) && capability.supported_outputs.length > 0 ? capability.supported_outputs.map((output) => formatExportOutputLabel(output)).join(", ") : "ZIP Package, Manifest, Summary Note"), /* @__PURE__ */ React.createElement("div", { className: `mt-1 text-xs ${mutedTextClass}` }, "Max files per package: ", capability.max_bundle_files || ((_m2 = capability == null ? void 0 : capability.config) == null ? void 0 : _m2.max_bundle_files) || 12), ((_n2 = capability.latest_bundle) == null ? void 0 : _n2.name) && /* @__PURE__ */ React.createElement("div", { className: "mt-3" }, /* @__PURE__ */ React.createElement(
          "button",
          {
            type: "button",
            onClick: () => downloadCapabilityExport(capability.latest_bundle.name),
            className: "text-sm font-medium text-sky-600 hover:text-sky-800 underline"
          },
          "Download latest package: ",
          formatPackageFileLabel(capability.latest_bundle.name)
        )));
      }
      return null;
    };
    const renderCapabilityDetailModal = () => {
      if (!selectedCapabilityDetail || !isCapabilitiesTab) {
        return null;
      }
      const capability = selectedCapabilityDetail;
      const capabilitySet = Array.isArray(capability.capability_set) ? capability.capability_set.filter(Boolean) : [];
      const dependencyPackages = Array.isArray(capability.dependency_packages) ? capability.dependency_packages : [];
      const availabilityLabel = capability.runtime_available ? "Available now" : "Planned add-on";
      const restartNote = capability.restart_required ? "A restart is currently required before this capability can finish activation." : !capability.installed && capability.requires_restart_on_install ? "Installing this capability requires an application restart before it can be enabled." : "";
      return /* @__PURE__ */ React.createElement(
        "div",
        {
          className: "fixed inset-x-0 bottom-0 z-[70] overflow-y-auto bg-black/70 p-3 backdrop-blur-sm sm:p-6",
          style: capabilityDetailOverlayStyle,
          onClick: closeCapabilityDetail
        },
        /* @__PURE__ */ React.createElement("div", { className: "min-h-full w-full flex items-start justify-center" }, /* @__PURE__ */ React.createElement(
          "div",
          {
            className: `w-full max-w-5xl min-h-0 rounded-2xl border shadow-2xl flex flex-col overflow-hidden ${isDarkTheme ? "bg-gray-900 border-gray-700" : "bg-white border-gray-200"}`,
            style: windowedCapabilityDetailDialogStyle,
            role: "dialog",
            "aria-modal": "true",
            "aria-labelledby": "capability-detail-title",
            onClick: (event2) => event2.stopPropagation(),
            onKeyDown: (event2) => handleDialogKeyDown(event2, closeCapabilityDetail),
            tabIndex: -1
          },
          /* @__PURE__ */ React.createElement("div", { className: `shrink-0 flex items-start justify-between gap-4 border-b px-4 py-4 sm:px-6 sm:py-5 ${isDarkTheme ? "border-gray-700" : "border-gray-200"}` }, /* @__PURE__ */ React.createElement("div", { className: "min-w-0" }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-wrap items-center gap-2" }, /* @__PURE__ */ React.createElement("span", { className: `inline-flex items-center rounded-full px-2 py-0.5 text-[11px] font-medium ${getCapabilityStatusClasses(capability.health_status || "unknown")}` }, formatCapabilityStatusLabel(capability.health_status || "unknown")), /* @__PURE__ */ React.createElement("span", { className: `inline-flex items-center rounded-full px-2 py-0.5 text-[11px] font-medium ${isDarkTheme ? "bg-gray-800 text-gray-200 border border-gray-600" : "bg-gray-100 text-gray-700 border border-gray-300"}` }, formatCapabilityCategoryLabel(capability.category || "capability")), /* @__PURE__ */ React.createElement("span", { className: `inline-flex items-center rounded-full px-2 py-0.5 text-[11px] font-medium ${isDarkTheme ? "bg-sky-950 text-sky-100 border border-sky-800" : "bg-sky-50 text-sky-800 border border-sky-200"}` }, availabilityLabel)), /* @__PURE__ */ React.createElement("h3", { id: "capability-detail-title", className: `mt-3 text-lg font-semibold sm:text-xl ${headingClass}` }, capability.title || capability.name), /* @__PURE__ */ React.createElement("p", { className: `mt-2 text-sm ${subtextClass}` }, capability.description || "Optional capability package.")), /* @__PURE__ */ React.createElement(
            "button",
            {
              type: "button",
              onClick: closeCapabilityDetail,
              className: `inline-flex items-center gap-2 rounded-lg border px-3 py-1.5 text-sm font-medium ${isDarkTheme ? "border-gray-600 bg-gray-800 text-gray-100 hover:bg-gray-700" : "border-gray-300 bg-white text-gray-800 hover:bg-gray-50"}`
            },
            /* @__PURE__ */ React.createElement("i", { className: "fa-solid fa-xmark", "aria-hidden": "true" }),
            /* @__PURE__ */ React.createElement("span", null, "Close")
          )),
          /* @__PURE__ */ React.createElement("div", { className: "min-h-0 flex-1 overflow-y-auto px-4 py-4 sm:px-6 sm:py-5" }, /* @__PURE__ */ React.createElement("div", { className: "grid grid-cols-1 gap-4 xl:grid-cols-[minmax(0,1.15fr)_minmax(280px,0.85fr)]" }, /* @__PURE__ */ React.createElement("div", { className: "space-y-4" }, /* @__PURE__ */ React.createElement("div", { className: "grid grid-cols-1 gap-4 lg:grid-cols-2" }, /* @__PURE__ */ React.createElement("div", { className: `rounded-xl border p-4 ${panelMutedClass}` }, /* @__PURE__ */ React.createElement("div", { className: `text-[11px] uppercase tracking-[0.18em] ${mutedTextClass}` }, "Purpose"), /* @__PURE__ */ React.createElement("div", { className: `mt-2 text-sm leading-6 ${subtextClass}` }, capability.purpose || capability.description || "This capability extends DT4SMS with additional operator workflows.")), /* @__PURE__ */ React.createElement("div", { className: `rounded-xl border p-4 ${panelMutedClass}` }, /* @__PURE__ */ React.createElement("div", { className: `text-[11px] uppercase tracking-[0.18em] ${mutedTextClass}` }, "Intent"), /* @__PURE__ */ React.createElement("div", { className: `mt-2 text-sm leading-6 ${subtextClass}` }, capability.intent || "Expose an operator-facing workflow that can be installed and enabled on demand."))), /* @__PURE__ */ React.createElement("div", { className: `rounded-xl border p-4 ${panelMutedClass}` }, /* @__PURE__ */ React.createElement("div", { className: `text-[11px] uppercase tracking-[0.18em] ${mutedTextClass}` }, "Capability Set"), capabilitySet.length > 0 ? /* @__PURE__ */ React.createElement("ul", { className: `mt-3 space-y-2 text-sm ${subtextClass}` }, capabilitySet.map((item, itemIndex) => /* @__PURE__ */ React.createElement("li", { key: `${capability.name}-capability-set-${itemIndex}`, className: "flex items-start gap-2" }, /* @__PURE__ */ React.createElement("span", { className: `mt-1 h-1.5 w-1.5 rounded-full ${isDarkTheme ? "bg-sky-300" : "bg-sky-600"}` }), /* @__PURE__ */ React.createElement("span", null, item)))) : /* @__PURE__ */ React.createElement("div", { className: `mt-3 text-sm ${mutedTextClass}` }, "Capability-set details are not yet defined.")), renderCapabilityRuntimeSnapshot(capability)), /* @__PURE__ */ React.createElement("div", { className: "space-y-4" }, /* @__PURE__ */ React.createElement("div", { className: `rounded-xl border p-4 ${panelMutedClass}` }, /* @__PURE__ */ React.createElement("div", { className: `text-[11px] uppercase tracking-[0.18em] ${mutedTextClass}` }, "Current State"), /* @__PURE__ */ React.createElement("div", { className: "grid grid-cols-2 gap-3 mt-3" }, /* @__PURE__ */ React.createElement("div", { className: `rounded-lg border px-3 py-2 ${isDarkTheme ? "bg-gray-900 border-gray-700" : "bg-white border-gray-300"}` }, /* @__PURE__ */ React.createElement("div", { className: `text-[11px] uppercase tracking-wide ${mutedTextClass}` }, "Setup"), /* @__PURE__ */ React.createElement("div", { className: `mt-1 text-sm font-semibold ${headingClass}` }, formatCapabilityInstallMethodLabel(capability.install_method || "unknown"))), /* @__PURE__ */ React.createElement("div", { className: `rounded-lg border px-3 py-2 ${isDarkTheme ? "bg-gray-900 border-gray-700" : "bg-white border-gray-300"}` }, /* @__PURE__ */ React.createElement("div", { className: `text-[11px] uppercase tracking-wide ${mutedTextClass}` }, "Stage"), /* @__PURE__ */ React.createElement("div", { className: `mt-1 text-sm font-semibold ${headingClass}` }, formatCapabilityMaturityLabel(capability.maturity || "experimental"))), /* @__PURE__ */ React.createElement("div", { className: `rounded-lg border px-3 py-2 ${isDarkTheme ? "bg-gray-900 border-gray-700" : "bg-white border-gray-300"}` }, /* @__PURE__ */ React.createElement("div", { className: `text-[11px] uppercase tracking-wide ${mutedTextClass}` }, "Installed"), /* @__PURE__ */ React.createElement("div", { className: `mt-1 text-sm font-semibold ${headingClass}` }, capability.installed ? "Yes" : "No")), /* @__PURE__ */ React.createElement("div", { className: `rounded-lg border px-3 py-2 ${isDarkTheme ? "bg-gray-900 border-gray-700" : "bg-white border-gray-300"}` }, /* @__PURE__ */ React.createElement("div", { className: `text-[11px] uppercase tracking-wide ${mutedTextClass}` }, "Enabled"), /* @__PURE__ */ React.createElement("div", { className: `mt-1 text-sm font-semibold ${headingClass}` }, capability.enabled ? "Yes" : "No")))), /* @__PURE__ */ React.createElement("div", { className: `rounded-xl border p-4 ${panelMutedClass}` }, /* @__PURE__ */ React.createElement("div", { className: `text-[11px] uppercase tracking-[0.18em] ${mutedTextClass}` }, "Health"), /* @__PURE__ */ React.createElement("div", { className: "mt-3 flex flex-wrap items-center gap-2" }, /* @__PURE__ */ React.createElement("span", { className: `inline-flex items-center rounded-full px-2 py-0.5 text-[11px] font-medium ${getCapabilityStatusClasses(capability.health_status || "unknown")}` }, formatCapabilityStatusLabel(capability.health_status || "unknown")), capability.version && /* @__PURE__ */ React.createElement("span", { className: `inline-flex items-center rounded-full px-2 py-0.5 text-[11px] font-medium ${isDarkTheme ? "bg-gray-800 text-gray-200 border border-gray-600" : "bg-white text-gray-700 border border-gray-300"}` }, "Version ", capability.version)), /* @__PURE__ */ React.createElement("div", { className: `mt-3 text-sm leading-6 ${subtextClass}` }, capability.health_message || "Capability has not been tested yet."), capability.last_tested_at && /* @__PURE__ */ React.createElement("div", { className: `mt-2 text-xs ${mutedTextClass}` }, "Last checked: ", new Date(capability.last_tested_at).toLocaleString()), capability.last_error && /* @__PURE__ */ React.createElement("div", { className: `mt-3 rounded-lg border px-3 py-2 text-xs ${isDarkTheme ? "bg-red-950 border-red-800 text-red-100" : "bg-red-50 border-red-200 text-red-800"}` }, capability.last_error)), /* @__PURE__ */ React.createElement("div", { className: `rounded-xl border p-4 ${panelMutedClass}` }, /* @__PURE__ */ React.createElement("div", { className: `text-[11px] uppercase tracking-[0.18em] ${mutedTextClass}` }, "Dependencies"), dependencyPackages.length > 0 ? /* @__PURE__ */ React.createElement("div", { className: "flex flex-wrap gap-2 mt-3 text-[11px]" }, dependencyPackages.map((pkg) => /* @__PURE__ */ React.createElement("span", { key: pkg, className: `rounded-full px-2 py-0.5 border ${isDarkTheme ? "bg-gray-800 text-gray-200 border-gray-600" : "bg-white text-gray-700 border-gray-300"}` }, pkg))) : /* @__PURE__ */ React.createElement("div", { className: `mt-3 text-sm ${mutedTextClass}` }, "No additional packages are required for this capability.")), restartNote && /* @__PURE__ */ React.createElement("div", { className: `rounded-xl border px-4 py-3 text-sm ${isDarkTheme ? "bg-amber-950 border-amber-800 text-amber-100" : "bg-amber-50 border-amber-200 text-amber-800"}` }, restartNote))))
        ))
      );
    };
    const renderAuthEnableInfoModal = () => {
      if (!isSettingsOpen || !config || !isAuthEnableInfoModalOpen) {
        return null;
      }
      const authGuidePrimaryLabel = pendingAuthEnableReview && !securityConfig.auth_enabled ? "Continue to enable" : hasReviewedAuthEnableInfo ? "Close guide" : "Mark as reviewed";
      const authGuideMethods = [
        {
          eyebrow: "Method 01",
          title: "Local Password",
          shellClass: isDarkTheme ? "bg-indigo-950 border-indigo-800" : "bg-indigo-50 border-indigo-200",
          eyebrowClass: isDarkTheme ? "text-indigo-200" : "text-indigo-800",
          titleClass: isDarkTheme ? "text-indigo-50" : "text-indigo-950",
          bullets: [
            "DT4SMS stores and manages local credentials in its own security database.",
            "Bootstrap admin sign-in, forced first-login reset, user CRUD, roles, and MCP assignment all stay local to the install.",
            "Best when the deployment needs a self-contained operator model or does not yet have enterprise SSO ready."
          ]
        },
        {
          eyebrow: "Method 02",
          title: "OIDC / Enterprise SSO",
          shellClass: isDarkTheme ? "bg-sky-950 border-sky-800" : "bg-sky-50 border-sky-200",
          eyebrowClass: isDarkTheme ? "text-sky-200" : "text-sky-800",
          titleClass: isDarkTheme ? "text-sky-50" : "text-sky-950",
          bullets: [
            "DT4SMS redirects the browser through the provider authorization-code flow using issuer discovery, token exchange, userinfo, JWKS validation, and local session creation.",
            "Claims can map username, email, default role, and MCP assignment behavior into the existing DT4SMS user model.",
            "Best when identity is already centralized and the install should inherit enterprise sign-in policy instead of managing passwords locally."
          ]
        }
      ];
      const authGuideSettings = [
        ["Auth Provider", "Chooses between DT4SMS-managed local passwords and external OIDC sign-in."],
        ["Session Timeout", "Sets how long an authenticated browser session remains valid before re-authentication is required."],
        ["Minimum Password Length", "Defines the floor for local-password complexity and user password resets."],
        ["Require Reset On First Login", "Forces the bootstrap or newly provisioned local user to rotate their initial credential before normal access."],
        ["Enable External REST API", "Controls whether token-authenticated external clients can use the sanitized DT4SMS REST surface."],
        ["Enable External MCP", "Controls whether scoped bearer tokens can reach the read-only inbound MCP endpoint."],
        ["OIDC Provider Fields", "Contain issuer, client, scopes, claims, and assignment settings that shape enterprise sign-in behavior."]
      ];
      const authGuideChecklist = [
        authProviderSelection === "oidc" ? oidcCanEnableAuth ? "OIDC provider settings are present enough to start enabling the browser sign-in flow." : "OIDC still needs issuer URL, client ID, and client secret before the provider path is truly ready." : "Local password mode is ready immediately and uses DT4SMS-managed users and password-reset controls.",
        "Enabling authentication changes the app from demo mode into sign-in-required mode for normal interactive use.",
        "External REST API and inbound MCP access remain separately gated by their own toggles and scoped tokens.",
        "If you continue from this guide, the checkbox will unlock for this session and can enable immediately when requested."
      ];
      const authGuideCurrentReadiness = authProviderSelection === "oidc" ? oidcCanEnableAuth ? "Provider ready" : "Provider setup required" : "Ready now";
      return /* @__PURE__ */ React.createElement(
        "div",
        {
          className: "fixed inset-x-0 bottom-0 z-[60] overflow-y-auto bg-black/70 p-3 backdrop-blur-sm sm:p-6",
          style: { ...capabilityDetailOverlayStyle, zIndex: 60 },
          onClick: () => {
            setIsAuthEnableInfoModalOpen(false);
            setPendingAuthEnableReview(false);
          }
        },
        /* @__PURE__ */ React.createElement("div", { className: "min-h-full w-full flex items-start justify-center" }, /* @__PURE__ */ React.createElement(
          "div",
          {
            className: `w-full max-w-6xl min-h-0 rounded-2xl border shadow-2xl flex flex-col overflow-hidden ${isDarkTheme ? "bg-gray-900 border-gray-700" : "bg-white border-gray-200"}`,
            style: windowedCapabilityDetailDialogStyle,
            role: "dialog",
            "aria-modal": "true",
            "aria-labelledby": "auth-enable-info-title",
            onClick: (event2) => event2.stopPropagation(),
            onKeyDown: (event2) => handleDialogKeyDown(event2, () => {
              setIsAuthEnableInfoModalOpen(false);
              setPendingAuthEnableReview(false);
            }),
            tabIndex: -1,
            "data-testid": "auth-enable-info-modal"
          },
          /* @__PURE__ */ React.createElement("div", { className: `shrink-0 flex items-start justify-between gap-4 border-b px-4 py-4 sm:px-6 sm:py-5 ${isDarkTheme ? "border-gray-700 bg-sky-950/30" : "border-gray-200 bg-sky-50"}` }, /* @__PURE__ */ React.createElement("div", { className: "min-w-0" }, /* @__PURE__ */ React.createElement("div", { className: `text-[11px] uppercase tracking-[0.18em] ${mutedTextClass}` }, "Authentication control guide"), /* @__PURE__ */ React.createElement("h3", { id: "auth-enable-info-title", className: `mt-3 text-lg font-semibold sm:text-xl ${headingClass}` }, "Review authentication methods before enabling access control"), /* @__PURE__ */ React.createElement("p", { className: `mt-2 text-sm ${subtextClass}` }, "This guide explains how DT4SMS local sign-in, OIDC / SSO, session controls, password rules, and external access toggles behave so the install can move from demo mode to enforced sign-in intentionally.")), /* @__PURE__ */ React.createElement(
            "button",
            {
              type: "button",
              onClick: () => {
                setIsAuthEnableInfoModalOpen(false);
                setPendingAuthEnableReview(false);
              },
              className: `inline-flex items-center gap-2 rounded-lg border px-3 py-1.5 text-sm font-medium ${isDarkTheme ? "border-gray-600 bg-gray-800 text-gray-100 hover:bg-gray-700" : "border-gray-300 bg-white text-gray-800 hover:bg-gray-50"}`
            },
            /* @__PURE__ */ React.createElement("i", { className: "fa-solid fa-xmark", "aria-hidden": "true" }),
            /* @__PURE__ */ React.createElement("span", null, "Exit")
          )),
          /* @__PURE__ */ React.createElement("div", { className: "min-h-0 flex-1 overflow-y-auto px-4 py-4 sm:px-6 sm:py-5" }, /* @__PURE__ */ React.createElement("div", { className: "grid grid-cols-1 gap-4 xl:grid-cols-[minmax(0,1.1fr)_minmax(300px,0.9fr)]" }, /* @__PURE__ */ React.createElement("div", { className: "space-y-4" }, /* @__PURE__ */ React.createElement("div", { className: "grid grid-cols-1 gap-4 lg:grid-cols-2" }, authGuideMethods.map((method) => /* @__PURE__ */ React.createElement("div", { key: method.title, className: `rounded-xl border p-4 ${method.shellClass}` }, /* @__PURE__ */ React.createElement("div", { className: `text-[11px] uppercase tracking-[0.18em] ${method.eyebrowClass}` }, method.eyebrow), /* @__PURE__ */ React.createElement("div", { className: `mt-2 text-base font-semibold ${method.titleClass}` }, method.title), /* @__PURE__ */ React.createElement("ul", { className: `mt-3 space-y-2 text-sm ${subtextClass}` }, method.bullets.map((bullet, bulletIdx) => /* @__PURE__ */ React.createElement("li", { key: `${method.title}-bullet-${bulletIdx}`, className: "flex items-start gap-2" }, /* @__PURE__ */ React.createElement("span", { className: `mt-1 h-1.5 w-1.5 rounded-full ${isDarkTheme ? "bg-sky-300" : "bg-sky-600"}` }), /* @__PURE__ */ React.createElement("span", null, bullet))))))), /* @__PURE__ */ React.createElement("div", { className: `rounded-xl border p-4 ${panelMutedClass}` }, /* @__PURE__ */ React.createElement("div", { className: `text-[11px] uppercase tracking-[0.18em] ${mutedTextClass}` }, "Contained settings"), /* @__PURE__ */ React.createElement("div", { className: "grid grid-cols-1 gap-3 mt-3 sm:grid-cols-2 xl:grid-cols-3" }, authGuideSettings.map(([title, description]) => /* @__PURE__ */ React.createElement("div", { key: title, className: `rounded-lg border px-3 py-3 ${isDarkTheme ? "bg-gray-900 border-gray-700" : "bg-white border-gray-300"}` }, /* @__PURE__ */ React.createElement("div", { className: `text-sm font-semibold ${headingClass}` }, title), /* @__PURE__ */ React.createElement("div", { className: `mt-2 text-xs leading-5 ${subtextClass}` }, description))))), /* @__PURE__ */ React.createElement("div", { className: `rounded-xl border p-4 ${panelMutedClass}` }, /* @__PURE__ */ React.createElement("div", { className: `text-[11px] uppercase tracking-[0.18em] ${mutedTextClass}` }, "What changes when auth is enabled"), /* @__PURE__ */ React.createElement("div", { className: `mt-3 grid grid-cols-1 gap-3 text-sm ${subtextClass} lg:grid-cols-2` }, /* @__PURE__ */ React.createElement("div", { className: `rounded-lg border px-3 py-3 ${isDarkTheme ? "bg-gray-900 border-gray-700" : "bg-white border-gray-300"}` }, "Normal application use moves behind sign-in, and the active browser session becomes the source of role-aware access checks."), /* @__PURE__ */ React.createElement("div", { className: `rounded-lg border px-3 py-3 ${isDarkTheme ? "bg-gray-900 border-gray-700" : "bg-white border-gray-300"}` }, "Local-password mode uses DT4SMS users, password reset, token ownership, and MCP assignment directly from the install database."), /* @__PURE__ */ React.createElement("div", { className: `rounded-lg border px-3 py-3 ${isDarkTheme ? "bg-gray-900 border-gray-700" : "bg-white border-gray-300"}` }, "OIDC mode still lands in the DT4SMS authorization model, but the browser sign-in journey and identity claims come from the provider."), /* @__PURE__ */ React.createElement("div", { className: `rounded-lg border px-3 py-3 ${isDarkTheme ? "bg-gray-900 border-gray-700" : "bg-white border-gray-300"}` }, "External REST API and inbound MCP access still require their own toggles plus scoped tokens; enabling auth does not automatically expose those surfaces.")))), /* @__PURE__ */ React.createElement("div", { className: "space-y-4" }, /* @__PURE__ */ React.createElement("div", { className: `rounded-xl border p-4 ${panelMutedClass}` }, /* @__PURE__ */ React.createElement("div", { className: `text-[11px] uppercase tracking-[0.18em] ${mutedTextClass}` }, "Current readiness"), /* @__PURE__ */ React.createElement("div", { className: "mt-3 flex flex-wrap gap-2 text-[11px] font-medium" }, /* @__PURE__ */ React.createElement("span", { className: `inline-flex items-center rounded-full px-2 py-1 ${securityConfig.auth_enabled ? "bg-emerald-50 text-gray-900" : "bg-gray-100 text-gray-700"}` }, securityConfig.auth_enabled ? "auth already enabled" : "demo mode active"), /* @__PURE__ */ React.createElement("span", { className: `inline-flex items-center rounded-full px-2 py-1 ${authProviderSelection === "oidc" ? "bg-sky-50 text-gray-900" : "bg-indigo-50 text-gray-900"}` }, "provider: ", authProviderSelection), /* @__PURE__ */ React.createElement("span", { className: `inline-flex items-center rounded-full px-2 py-1 ${authGuideCurrentReadiness === "Provider ready" || authGuideCurrentReadiness === "Ready now" ? "bg-emerald-50 text-gray-900" : "bg-amber-50 text-gray-900"}` }, authGuideCurrentReadiness)), /* @__PURE__ */ React.createElement("div", { className: `mt-3 text-sm leading-6 ${subtextClass}` }, authProviderSelection === "oidc" ? "OIDC settings live in this same panel. Review issuer, client, scopes, and claim mapping before switching the install into sign-in-required mode." : "Local password mode can be enabled immediately, but the bootstrap admin reset and user lifecycle settings still shape the operational rollout.")), /* @__PURE__ */ React.createElement("div", { className: `rounded-xl border p-4 ${panelMutedClass}` }, /* @__PURE__ */ React.createElement("div", { className: `text-[11px] uppercase tracking-[0.18em] ${mutedTextClass}` }, "Before you continue"), /* @__PURE__ */ React.createElement("ul", { className: `mt-3 space-y-2 text-sm ${subtextClass}` }, authGuideChecklist.map((item, itemIdx) => /* @__PURE__ */ React.createElement("li", { key: `auth-guide-check-${itemIdx}`, className: "flex items-start gap-2" }, /* @__PURE__ */ React.createElement("span", { className: `mt-1 h-1.5 w-1.5 rounded-full ${isDarkTheme ? "bg-emerald-300" : "bg-emerald-600"}` }), /* @__PURE__ */ React.createElement("span", null, item))))), /* @__PURE__ */ React.createElement("div", { className: `rounded-xl border px-4 py-3 text-sm ${pendingAuthEnableReview && !securityConfig.auth_enabled ? isDarkTheme ? "bg-indigo-950 border-indigo-800 text-indigo-100" : "bg-indigo-50 border-indigo-200 text-indigo-900" : isDarkTheme ? "bg-gray-900 border-gray-700 text-gray-200" : "bg-gray-50 border-gray-200 text-gray-700"}` }, pendingAuthEnableReview && !securityConfig.auth_enabled ? "You opened this guide from the greyed-out authentication control. Continuing will mark the guide as reviewed and switch the auth checkbox on immediately." : "Use this guide as a reference before saving any access-control changes. Marking it reviewed removes the greyed-out gate for the auth checkbox in this session.")))),
          /* @__PURE__ */ React.createElement("div", { className: `shrink-0 flex items-center justify-end gap-3 border-t px-4 py-4 sm:px-6 ${isDarkTheme ? "border-gray-700 bg-gray-900/90" : "border-gray-200 bg-white"}` }, /* @__PURE__ */ React.createElement(
            "button",
            {
              type: "button",
              onClick: () => {
                setIsAuthEnableInfoModalOpen(false);
                setPendingAuthEnableReview(false);
              },
              className: `rounded-lg px-4 py-2 text-sm font-medium ${isDarkTheme ? "bg-gray-800 text-gray-100 border border-gray-700 hover:bg-gray-700" : "bg-white text-gray-700 border border-gray-300 hover:bg-gray-50"}`
            },
            "Exit"
          ), /* @__PURE__ */ React.createElement(
            "button",
            {
              type: "button",
              onClick: () => {
                const shouldEnableAuth = pendingAuthEnableReview && !securityConfig.auth_enabled;
                if (!hasReviewedAuthEnableInfo) {
                  setHasReviewedAuthEnableInfo(true);
                }
                setIsAuthEnableInfoModalOpen(false);
                setPendingAuthEnableReview(false);
                if (shouldEnableAuth) {
                  setConfig((current) => ({
                    ...current,
                    security: {
                      ...(current == null ? void 0 : current.security) || {},
                      auth_enabled: true
                    }
                  }));
                  handleSettingsChange();
                }
              },
              className: "rounded-lg px-4 py-2 text-sm font-medium text-white bg-indigo-600 hover:bg-indigo-700"
            },
            authGuidePrimaryLabel
          ))
        ))
      );
    };
    const renderWelcomeSplashModal = () => {
      if (!isWelcomeSplashOpen) {
        return null;
      }
      const splashCapabilityHighlights = [
        {
          eyebrow: "Discover",
          title: "Map the environment quickly",
          description: "Run discovery, capture high-signal evidence, and turn the current Splunk estate into a readable operator workspace instead of a raw data dump.",
          shellClass: isDarkTheme ? "bg-sky-950 border-sky-800" : "bg-sky-50 border-sky-200"
        },
        {
          eyebrow: "Explain",
          title: "Turn findings into operator language",
          description: "Use Mission, Intelligence, Artifacts, and Summary views to turn technical output into priorities, patterns, follow-on actions, and runbook-ready context.",
          shellClass: isDarkTheme ? "bg-emerald-950 border-emerald-800" : "bg-emerald-50 border-emerald-200"
        },
        {
          eyebrow: "Act",
          title: "Operate from one control surface",
          description: "Manage capabilities, secure access, artifact export, and optional auth workflows without leaving the app or losing the active environment context.",
          shellClass: isDarkTheme ? "bg-amber-950 border-amber-800" : "bg-amber-50 border-amber-200"
        }
      ];
      const splashWorkspaceGuide = [
        "Mission: the current operational handoff, priorities, and execution cues.",
        "Intelligence: pattern cards, evidence compression, and investigation signals.",
        "Artifacts: generated reports, summaries, packages, and durable outputs.",
        "Capabilities: optional packs for RAG, export, visualization, and Splunk deep links.",
        "Settings: connections, models, auth, and install-wide control surfaces."
      ];
      const splashGettingStarted = [
        "Start with Mission if you want the shortest path from discovery output to action.",
        "Open Intelligence when you need a cleaner explanation of recurring patterns and evidence themes.",
        "Use Capabilities and Settings when you are preparing the install for broader operator or demo use."
      ];
      return /* @__PURE__ */ React.createElement(
        "div",
        {
          className: "fixed inset-x-0 bottom-0 z-[80] overflow-hidden bg-black/86 p-3 sm:p-6",
          style: {
            ...capabilityDetailOverlayStyle,
            zIndex: 80
          },
          onClick: closeWelcomeSplash
        },
        /* @__PURE__ */ React.createElement("div", { className: "h-full w-full relative flex items-start justify-center" }, /* @__PURE__ */ React.createElement(
          "div",
          {
            "aria-hidden": "true",
            className: "pointer-events-none absolute inset-0",
            style: {
              background: isDarkTheme ? "radial-gradient(circle at 50% 18%, rgba(56, 189, 248, 0.14) 0%, rgba(15, 23, 42, 0.22) 24%, rgba(2, 6, 23, 0.72) 68%, rgba(2, 6, 23, 0.94) 100%)" : "radial-gradient(circle at 50% 18%, rgba(99, 102, 241, 0.12) 0%, rgba(255, 255, 255, 0.08) 24%, rgba(15, 23, 42, 0.44) 68%, rgba(2, 6, 23, 0.8) 100%)"
            }
          }
        ), /* @__PURE__ */ React.createElement("div", { className: "relative w-full max-w-6xl" }, /* @__PURE__ */ React.createElement(
          "div",
          {
            className: `w-full min-h-0 rounded-2xl border shadow-2xl flex flex-col overflow-hidden ${isDarkTheme ? "bg-gray-900 border-gray-700" : "bg-white border-gray-200"}`,
            style: {
              ...windowedCapabilityDetailDialogStyle,
              boxShadow: isDarkTheme ? "0 38px 120px rgba(2, 6, 23, 0.86), 0 0 0 1px rgba(56, 189, 248, 0.12)" : "0 34px 100px rgba(15, 23, 42, 0.28), 0 0 0 1px rgba(99, 102, 241, 0.12)"
            },
            role: "dialog",
            "aria-modal": "true",
            "aria-labelledby": "welcome-splash-title",
            onClick: (event2) => event2.stopPropagation(),
            onKeyDown: (event2) => handleDialogKeyDown(event2, closeWelcomeSplash),
            tabIndex: -1,
            "data-testid": "welcome-splash-modal"
          },
          /* @__PURE__ */ React.createElement("div", { className: `shrink-0 border-b px-4 py-4 sm:px-6 sm:py-5 ${isDarkTheme ? "border-gray-700 bg-gradient-to-r from-sky-950 via-slate-900 to-indigo-950" : "border-gray-200 bg-gradient-to-r from-sky-50 via-white to-indigo-50"}` }, /* @__PURE__ */ React.createElement("div", { className: "grid grid-cols-1 gap-4 xl:grid-cols-[minmax(0,1.15fr)_300px] xl:items-start" }, /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("div", { className: `text-[11px] uppercase tracking-[0.18em] ${mutedTextClass}` }, "First-run welcome"), /* @__PURE__ */ React.createElement("h2", { id: "welcome-splash-title", className: `mt-3 text-2xl font-semibold sm:text-3xl ${headingClass}` }, "Welcome to DT4SMS"), /* @__PURE__ */ React.createElement("p", { className: `mt-3 text-sm leading-6 sm:text-base ${subtextClass}` }, "DT4SMS turns Splunk discovery, investigation, reporting, and operator handoff into one guided workspace. It helps teams move from raw environment evidence to readable priorities, explainable patterns, capability-driven enhancements, and secure operational follow-through.")), /* @__PURE__ */ React.createElement("div", { className: `rounded-xl border p-4 ${isDarkTheme ? "bg-gray-950/70 border-gray-700" : "bg-white/80 border-gray-200"}` }, /* @__PURE__ */ React.createElement("div", { className: `text-[11px] uppercase tracking-[0.18em] ${mutedTextClass}` }, "Best first clicks"), /* @__PURE__ */ React.createElement("ul", { className: `mt-3 space-y-2 text-sm ${subtextClass}` }, splashGettingStarted.map((item, itemIdx) => /* @__PURE__ */ React.createElement("li", { key: `welcome-start-${itemIdx}`, className: "flex items-start gap-2" }, /* @__PURE__ */ React.createElement("span", { className: `mt-1 h-1.5 w-1.5 rounded-full ${isDarkTheme ? "bg-sky-300" : "bg-sky-600"}` }), /* @__PURE__ */ React.createElement("span", null, item))))))),
          /* @__PURE__ */ React.createElement("div", { className: "min-h-0 flex-1 overflow-y-auto px-4 py-4 sm:px-6 sm:py-5" }, /* @__PURE__ */ React.createElement("div", { className: "grid grid-cols-1 gap-4 xl:grid-cols-[minmax(0,1.05fr)_minmax(300px,0.95fr)]" }, /* @__PURE__ */ React.createElement("div", { className: "space-y-4" }, /* @__PURE__ */ React.createElement("div", { className: "grid grid-cols-1 gap-4 lg:grid-cols-3" }, splashCapabilityHighlights.map((item) => /* @__PURE__ */ React.createElement("div", { key: item.title, className: `rounded-xl border p-4 ${item.shellClass}` }, /* @__PURE__ */ React.createElement("div", { className: `text-[11px] uppercase tracking-[0.18em] ${mutedTextClass}` }, item.eyebrow), /* @__PURE__ */ React.createElement("div", { className: `mt-2 text-base font-semibold ${headingClass}` }, item.title), /* @__PURE__ */ React.createElement("div", { className: `mt-3 text-sm leading-6 ${subtextClass}` }, item.description)))), /* @__PURE__ */ React.createElement("div", { className: `rounded-xl border p-4 ${panelMutedClass}` }, /* @__PURE__ */ React.createElement("div", { className: `text-[11px] uppercase tracking-[0.18em] ${mutedTextClass}` }, "What you will find inside"), /* @__PURE__ */ React.createElement("div", { className: "grid grid-cols-1 gap-3 mt-3 lg:grid-cols-2" }, splashWorkspaceGuide.map((item, itemIdx) => /* @__PURE__ */ React.createElement("div", { key: `welcome-workspace-${itemIdx}`, className: `rounded-lg border px-3 py-3 text-sm ${isDarkTheme ? "bg-gray-900 border-gray-700 text-gray-200" : "bg-white border-gray-300 text-gray-700"}` }, item))))), /* @__PURE__ */ React.createElement("div", { className: "space-y-4" }, /* @__PURE__ */ React.createElement("div", { className: `rounded-xl border p-4 ${panelMutedClass}` }, /* @__PURE__ */ React.createElement("div", { className: `text-[11px] uppercase tracking-[0.18em] ${mutedTextClass}` }, "Why teams use it"), /* @__PURE__ */ React.createElement("div", { className: `mt-3 space-y-3 text-sm ${subtextClass}` }, /* @__PURE__ */ React.createElement("div", { className: `rounded-lg border px-3 py-3 ${isDarkTheme ? "bg-gray-900 border-gray-700" : "bg-white border-gray-300"}` }, "Keep discovery outputs, summaries, artifacts, and optional capability evidence in one operator-facing place."), /* @__PURE__ */ React.createElement("div", { className: `rounded-lg border px-3 py-3 ${isDarkTheme ? "bg-gray-900 border-gray-700" : "bg-white border-gray-300"}` }, "Move between demo mode and secured mode without changing the core operating surface."), /* @__PURE__ */ React.createElement("div", { className: `rounded-lg border px-3 py-3 ${isDarkTheme ? "bg-gray-900 border-gray-700" : "bg-white border-gray-300"}` }, "Explain what matters now, not just what exists technically, so operators can act faster with less translation overhead."))), /* @__PURE__ */ React.createElement("div", { className: `rounded-xl border px-4 py-3 text-sm ${isDarkTheme ? "bg-indigo-950 border-indigo-800 text-indigo-100" : "bg-indigo-50 border-indigo-200 text-indigo-900"}` }, "This preference is stored only in this browser. Settings can reset it later for demos, onboarding, or repeated walkthroughs.")))),
          /* @__PURE__ */ React.createElement("div", { className: `shrink-0 border-t px-4 py-4 sm:px-6 ${isDarkTheme ? "border-gray-700 bg-gray-900/90" : "border-gray-200 bg-white"}` }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-col gap-3 md:flex-row md:items-center md:justify-between" }, /* @__PURE__ */ React.createElement("label", { className: `inline-flex items-start gap-3 text-sm ${subtextClass}` }, /* @__PURE__ */ React.createElement(
            "input",
            {
              type: "checkbox",
              "data-testid": "welcome-splash-dismiss-checkbox",
              checked: welcomeSplashDoNotShowAgain,
              onChange: (event2) => setWelcomeSplashDoNotShowAgain(event2.target.checked),
              className: "mt-1 h-4 w-4 rounded border-gray-300"
            }
          ), /* @__PURE__ */ React.createElement("span", null, "Don't show this again on this browser.")), /* @__PURE__ */ React.createElement("div", { className: "flex flex-col-reverse gap-2 sm:flex-row sm:justify-end" }, /* @__PURE__ */ React.createElement(
            "button",
            {
              type: "button",
              onClick: closeWelcomeSplash,
              className: `rounded-lg px-4 py-2 text-sm font-medium ${isDarkTheme ? "bg-gray-800 text-gray-100 border border-gray-700 hover:bg-gray-700" : "bg-white text-gray-700 border border-gray-300 hover:bg-gray-50"}`
            },
            "Dismiss for now"
          ), /* @__PURE__ */ React.createElement(
            "button",
            {
              type: "button",
              onClick: closeWelcomeSplash,
              className: "rounded-lg px-4 py-2 text-sm font-medium text-white bg-indigo-600 hover:bg-indigo-700"
            },
            "Enter Workspace"
          ))))
        )))
      );
    };
    const renderRagOverviewCard = () => {
      const lastIndexedLabel = (ragIndexSummary == null ? void 0 : ragIndexSummary.last_indexed_at) ? new Date(ragIndexSummary.last_indexed_at).toLocaleString() : "Not indexed yet";
      return /* @__PURE__ */ React.createElement("div", { className: `rounded-xl border p-5 ${isDarkTheme ? "bg-gradient-to-br from-slate-900 via-sky-950 to-indigo-950 border-sky-800" : "bg-gradient-to-br from-sky-50 via-white to-indigo-50 border-sky-200"}` }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-col xl:flex-row xl:items-start xl:justify-between gap-4" }, /* @__PURE__ */ React.createElement("div", { className: "max-w-3xl" }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-wrap items-center gap-2 mb-2" }, /* @__PURE__ */ React.createElement("span", { className: `inline-flex items-center rounded-full px-2.5 py-1 text-[11px] font-medium ${getCapabilityStatusClasses(ragStatusLabel)}` }, formatCapabilityStatusLabel(ragStatusLabel)), /* @__PURE__ */ React.createElement("span", { className: `inline-flex items-center rounded-full px-2.5 py-1 text-[11px] font-medium border ${isDarkTheme ? "bg-sky-950 text-sky-100 border-sky-800" : "bg-white text-sky-800 border-sky-200"}` }, "Focused Workspace")), /* @__PURE__ */ React.createElement("h3", { className: `text-xl font-semibold ${headingClass}` }, (ragCapability == null ? void 0 : ragCapability.title) || "Indexed Artifact Search"), /* @__PURE__ */ React.createElement("p", { className: `mt-2 text-sm ${subtextClass}` }, (ragCapability == null ? void 0 : ragCapability.description) || "Indexed artifact search plus managed knowledge assets for context-rich retrieval.", " ", "The retrieval workflow now lives on its own dedicated workspace so the overview can stay focused on install, health, and control tasks."), /* @__PURE__ */ React.createElement("div", { className: `mt-3 text-xs ${mutedTextClass}` }, "Managed asset directory: ", ragDisplayedAssetDir)), /* @__PURE__ */ React.createElement("div", { className: "flex flex-wrap gap-2" }, /* @__PURE__ */ React.createElement(
        "button",
        {
          type: "button",
          onClick: () => openCapabilityDetail("rag_chromadb"),
          "aria-label": "View details for Indexed Artifact Search",
          title: "View details",
          className: `inline-flex h-10 w-10 items-center justify-center rounded-full border ${isDarkTheme ? "border-sky-700 bg-slate-950 text-sky-100 hover:bg-slate-900" : "border-sky-300 bg-white text-sky-700 hover:bg-sky-50"}`
        },
        /* @__PURE__ */ React.createElement("i", { className: "fa-solid fa-circle-info text-sm", "aria-hidden": "true" })
      ), /* @__PURE__ */ React.createElement(
        "button",
        {
          type: "button",
          onClick: openRagCapabilitiesWorkspace,
          className: "px-3 py-1.5 rounded text-sm font-medium bg-sky-600 hover:bg-sky-700 text-white"
        },
        "Open RAG Workspace"
      ), canReindexRag && /* @__PURE__ */ React.createElement(
        "button",
        {
          type: "button",
          onClick: () => runCapabilityAction("rag_chromadb", "reindex"),
          disabled: isRagBusy,
          className: `px-3 py-1.5 rounded text-sm font-medium ${!isRagBusy ? "bg-violet-600 hover:bg-violet-700 text-white" : isDarkTheme ? "bg-gray-800 text-gray-500 cursor-not-allowed" : "bg-gray-200 text-gray-500 cursor-not-allowed"}`
        },
        ragActionInProgress === "reindex" ? "Reindexing..." : "Reindex"
      ))), /* @__PURE__ */ React.createElement("div", { className: "grid grid-cols-2 xl:grid-cols-4 gap-3 mt-5" }, /* @__PURE__ */ React.createElement("div", { className: `rounded-lg p-3 border ${isDarkTheme ? "bg-gray-900 border-gray-700" : "bg-white border-gray-200"}` }, /* @__PURE__ */ React.createElement("div", { className: `text-[11px] uppercase tracking-wide ${mutedTextClass}` }, "Indexed Documents"), /* @__PURE__ */ React.createElement("div", { className: `text-2xl font-semibold mt-1 ${headingClass}` }, ragIndexedDocumentCount)), /* @__PURE__ */ React.createElement("div", { className: `rounded-lg p-3 border ${isDarkTheme ? "bg-gray-900 border-gray-700" : "bg-white border-gray-200"}` }, /* @__PURE__ */ React.createElement("div", { className: `text-[11px] uppercase tracking-wide ${mutedTextClass}` }, "Source Files"), /* @__PURE__ */ React.createElement("div", { className: `text-2xl font-semibold mt-1 ${headingClass}` }, (ragIndexSummary == null ? void 0 : ragIndexSummary.source_file_count) || 0)), /* @__PURE__ */ React.createElement("div", { className: `rounded-lg p-3 border ${isDarkTheme ? "bg-gray-900 border-gray-700" : "bg-white border-gray-200"}` }, /* @__PURE__ */ React.createElement("div", { className: `text-[11px] uppercase tracking-wide ${mutedTextClass}` }, "Managed Assets"), /* @__PURE__ */ React.createElement("div", { className: `text-2xl font-semibold mt-1 ${headingClass}` }, ragDisplayedAssetCount)), /* @__PURE__ */ React.createElement("div", { className: `rounded-lg p-3 border ${isDarkTheme ? "bg-gray-900 border-gray-700" : "bg-white border-gray-200"}` }, /* @__PURE__ */ React.createElement("div", { className: `text-[11px] uppercase tracking-wide ${mutedTextClass}` }, "Preview Ready"), /* @__PURE__ */ React.createElement("div", { className: `text-sm font-semibold mt-2 ${headingClass}` }, canUseRagContextPreview ? "Yes" : "Not yet"), /* @__PURE__ */ React.createElement("div", { className: `mt-1 text-[11px] ${mutedTextClass}` }, "Last indexed: ", lastIndexedLabel))), (ragIndexSourceTypes.length > 0 || ragKnowledgeAssetTypeCounts.length > 0) && /* @__PURE__ */ React.createElement("div", { className: "grid grid-cols-1 xl:grid-cols-2 gap-3 mt-4" }, /* @__PURE__ */ React.createElement("div", { className: `rounded-lg border px-3 py-3 ${panelMutedClass}` }, /* @__PURE__ */ React.createElement("div", { className: `text-xs font-medium mb-2 ${headingClass}` }, "Indexed Source Mix"), /* @__PURE__ */ React.createElement("div", { className: "flex flex-wrap gap-2 text-[11px]" }, ragIndexSourceTypes.length > 0 ? ragIndexSourceTypes.map(([sourceType, count]) => /* @__PURE__ */ React.createElement("span", { key: sourceType, className: `rounded-full px-2 py-0.5 border ${isDarkTheme ? "bg-gray-800 text-gray-200 border-gray-600" : "bg-white text-gray-700 border-gray-300"}` }, formatCapabilitySourceTypeLabel(sourceType), ": ", count)) : /* @__PURE__ */ React.createElement("span", { className: mutedTextClass }, "No indexed source mix yet."))), /* @__PURE__ */ React.createElement("div", { className: `rounded-lg border px-3 py-3 ${panelMutedClass}` }, /* @__PURE__ */ React.createElement("div", { className: `text-xs font-medium mb-2 ${headingClass}` }, "Managed Asset Mix"), /* @__PURE__ */ React.createElement("div", { className: "flex flex-wrap gap-2 text-[11px]" }, ragKnowledgeAssetTypeCounts.length > 0 ? ragKnowledgeAssetTypeCounts.map(([assetType, count]) => /* @__PURE__ */ React.createElement("span", { key: assetType, className: `rounded-full px-2 py-0.5 border ${isDarkTheme ? "bg-gray-800 text-gray-200 border-gray-600" : "bg-white text-gray-700 border-gray-300"}` }, formatKnowledgeAssetTypeLabel(assetType), ": ", count)) : /* @__PURE__ */ React.createElement("span", { className: mutedTextClass }, "No managed assets imported yet.")))));
    };
    const renderRagWorkspaceView = () => {
      var _a2, _b2, _c2, _d2, _e2, _f2, _g2, _h2;
      if (!ragCapability) {
        return /* @__PURE__ */ React.createElement("div", { "data-testid": "context-library-detail-panel", className: `rounded-lg shadow-sm p-6 border ${panelClass}` }, /* @__PURE__ */ React.createElement("h3", { className: `text-lg font-semibold ${headingClass}` }, "RAG Workspace"), /* @__PURE__ */ React.createElement("p", { className: `mt-2 text-sm ${subtextClass}` }, "The dedicated retrieval workspace is unavailable because the `rag_chromadb` capability was not returned by the capabilities API."));
      }
      return /* @__PURE__ */ React.createElement(React.Fragment, null, /* @__PURE__ */ React.createElement("div", { className: `rounded-lg shadow-sm p-6 border ${panelClass}` }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-col xl:flex-row xl:items-start xl:justify-between gap-4" }, /* @__PURE__ */ React.createElement("div", { className: "max-w-4xl" }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-wrap items-center gap-2 mb-2" }, /* @__PURE__ */ React.createElement("span", { className: `inline-flex items-center rounded-full px-2 py-0.5 text-[11px] font-medium ${getCapabilityStatusClasses(ragStatusLabel)}` }, formatCapabilityStatusLabel(ragStatusLabel)), /* @__PURE__ */ React.createElement("span", { className: `inline-flex items-center rounded-full px-2 py-0.5 text-[11px] font-medium ${isDarkTheme ? "bg-gray-800 text-gray-200 border border-gray-600" : "bg-gray-100 text-gray-700 border border-gray-300"}` }, formatCapabilityCategoryLabel(ragCapability.category || "retrieval")), /* @__PURE__ */ React.createElement("span", { className: `inline-flex items-center rounded-full px-2 py-0.5 text-[11px] font-medium ${isDarkTheme ? "bg-sky-950 text-sky-100 border border-sky-800" : "bg-sky-50 text-sky-800 border border-sky-200"}` }, "Dedicated Workspace")), /* @__PURE__ */ React.createElement("h3", { className: `text-xl font-semibold ${headingClass}` }, ragCapability.title || "Indexed Artifact Search"), /* @__PURE__ */ React.createElement("p", { className: `mt-2 text-sm ${subtextClass}` }, ragCapability.description || "Indexed artifact search plus managed knowledge assets for context-rich retrieval.")), /* @__PURE__ */ React.createElement("div", { className: `rounded-lg border px-3 py-3 min-w-[240px] ${panelMutedClass}` }, /* @__PURE__ */ React.createElement("div", { className: `text-xs font-medium ${headingClass}` }, "Health"), /* @__PURE__ */ React.createElement("div", { className: `mt-2 text-sm ${subtextClass}` }, ragCapability.health_message || "Capability has not been tested yet."), ragCapability.last_tested_at && /* @__PURE__ */ React.createElement("div", { className: `mt-2 text-[11px] ${mutedTextClass}` }, "Last checked: ", new Date(ragCapability.last_tested_at).toLocaleString()), ragCapability.version && /* @__PURE__ */ React.createElement("div", { className: `mt-1 text-[11px] ${mutedTextClass}` }, "Version: ", ragCapability.version))), /* @__PURE__ */ React.createElement("div", { className: "grid grid-cols-2 xl:grid-cols-4 gap-3 mt-5" }, /* @__PURE__ */ React.createElement("div", { className: `${isDarkTheme ? "bg-indigo-900 border border-indigo-700" : "bg-indigo-50"} rounded-lg p-3` }, /* @__PURE__ */ React.createElement("div", { className: `${isDarkTheme ? "text-indigo-200" : "text-indigo-700"} text-xs uppercase tracking-wide` }, "Documents Indexed"), /* @__PURE__ */ React.createElement("div", { className: `${isDarkTheme ? "text-indigo-100" : "text-indigo-900"} text-2xl font-semibold` }, ragIndexedDocumentCount)), /* @__PURE__ */ React.createElement("div", { className: `${isDarkTheme ? "bg-blue-900 border border-blue-700" : "bg-blue-50"} rounded-lg p-3` }, /* @__PURE__ */ React.createElement("div", { className: `${isDarkTheme ? "text-blue-200" : "text-blue-700"} text-xs uppercase tracking-wide` }, "Source Files"), /* @__PURE__ */ React.createElement("div", { className: `${isDarkTheme ? "text-blue-100" : "text-blue-900"} text-2xl font-semibold` }, (ragIndexSummary == null ? void 0 : ragIndexSummary.source_file_count) || 0)), /* @__PURE__ */ React.createElement("div", { className: `${isDarkTheme ? "bg-emerald-900 border border-emerald-700" : "bg-emerald-50"} rounded-lg p-3` }, /* @__PURE__ */ React.createElement("div", { className: `${isDarkTheme ? "text-emerald-200" : "text-emerald-700"} text-xs uppercase tracking-wide` }, "Managed Assets"), /* @__PURE__ */ React.createElement("div", { className: `${isDarkTheme ? "text-emerald-100" : "text-emerald-900"} text-2xl font-semibold` }, ragDisplayedAssetCount)), /* @__PURE__ */ React.createElement("div", { className: `${isDarkTheme ? "bg-violet-900 border border-violet-700" : "bg-violet-50"} rounded-lg p-3` }, /* @__PURE__ */ React.createElement("div", { className: `${isDarkTheme ? "text-violet-200" : "text-violet-700"} text-xs uppercase tracking-wide` }, "Preview Ready"), /* @__PURE__ */ React.createElement("div", { className: `${isDarkTheme ? "text-violet-100" : "text-violet-900"} text-sm font-semibold mt-2` }, canUseRagContextPreview ? "Indexed retrieval ready" : "Install, enable, and reindex first"))), /* @__PURE__ */ React.createElement("div", { className: "grid grid-cols-1 xl:grid-cols-2 gap-3 mt-4" }, /* @__PURE__ */ React.createElement("div", { className: `rounded-lg border px-3 py-3 ${panelMutedClass}` }, /* @__PURE__ */ React.createElement("div", { className: `text-xs font-medium mb-1 ${headingClass}` }, "Index Status"), /* @__PURE__ */ React.createElement("div", { className: `text-xs ${subtextClass}` }, "Last indexed: ", (ragIndexSummary == null ? void 0 : ragIndexSummary.last_indexed_at) ? new Date(ragIndexSummary.last_indexed_at).toLocaleString() : "Not indexed yet."), Array.isArray(ragIndexSummary == null ? void 0 : ragIndexSummary.sample_sources) && ragIndexSummary.sample_sources.length > 0 && /* @__PURE__ */ React.createElement("div", { className: `mt-2 text-[11px] ${mutedTextClass}` }, "Sample sources: ", ragIndexSummary.sample_sources.join(", "))), /* @__PURE__ */ React.createElement("div", { className: `rounded-lg border px-3 py-3 ${panelMutedClass}` }, /* @__PURE__ */ React.createElement("div", { className: `text-xs font-medium mb-1 ${headingClass}` }, "Knowledge Asset Plane"), /* @__PURE__ */ React.createElement("div", { className: `text-xs ${subtextClass}` }, "Managed asset directory: ", ragDisplayedAssetDir), /* @__PURE__ */ React.createElement("div", { className: `mt-1 text-xs ${subtextClass}` }, "Checked in: ", ragCheckedInAssetCount, ". Checked out: ", ragCheckedOutAssetCount, "."), /* @__PURE__ */ React.createElement("div", { className: `mt-1 text-xs ${subtextClass}` }, canUseRagContextPreview ? "Checked-in assets are ready for indexed context previews." : "Asset import works now; preview and chat retrieval unlock once indexed retrieval is ready."))), (Array.isArray(ragCapability.dependency_packages) && ragCapability.dependency_packages.length > 0 || ragIndexSourceTypes.length > 0 || ragKnowledgeAssetTypeCounts.length > 0) && /* @__PURE__ */ React.createElement("div", { className: "space-y-3 mt-4" }, Array.isArray(ragCapability.dependency_packages) && ragCapability.dependency_packages.length > 0 && /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("div", { className: `text-xs font-medium mb-1 ${headingClass}` }, "Dependencies"), /* @__PURE__ */ React.createElement("div", { className: "flex flex-wrap gap-2 text-[11px]" }, ragCapability.dependency_packages.map((pkg) => /* @__PURE__ */ React.createElement("span", { key: pkg, className: `rounded-full px-2 py-0.5 border ${isDarkTheme ? "bg-gray-800 text-gray-200 border-gray-600" : "bg-gray-50 text-gray-700 border-gray-300"}` }, pkg)))), ragIndexSourceTypes.length > 0 && /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("div", { className: `text-xs font-medium mb-1 ${headingClass}` }, "Indexed Source Mix"), /* @__PURE__ */ React.createElement("div", { className: "flex flex-wrap gap-2 text-[11px]" }, ragIndexSourceTypes.map(([sourceType, count]) => /* @__PURE__ */ React.createElement("span", { key: sourceType, className: `rounded-full px-2 py-0.5 border ${isDarkTheme ? "bg-gray-800 text-gray-200 border-gray-600" : "bg-gray-50 text-gray-700 border-gray-300"}` }, formatCapabilitySourceTypeLabel(sourceType), ": ", count)))), ragKnowledgeAssetTypeCounts.length > 0 && /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("div", { className: `text-xs font-medium mb-1 ${headingClass}` }, "Managed Asset Mix"), /* @__PURE__ */ React.createElement("div", { className: "flex flex-wrap gap-2 text-[11px]" }, ragKnowledgeAssetTypeCounts.map(([assetType, count]) => /* @__PURE__ */ React.createElement("span", { key: assetType, className: `rounded-full px-2 py-0.5 border ${isDarkTheme ? "bg-gray-800 text-gray-200 border-gray-600" : "bg-gray-50 text-gray-700 border-gray-300"}` }, formatKnowledgeAssetTypeLabel(assetType), ": ", count))))), /* @__PURE__ */ React.createElement("div", { className: "flex flex-wrap gap-2 mt-5" }, /* @__PURE__ */ React.createElement(
        "button",
        {
          type: "button",
          onClick: openCapabilitiesOverview,
          className: `px-3 py-1.5 rounded text-sm font-medium ${isDarkTheme ? "bg-gray-700 hover:bg-gray-600 text-white" : "bg-gray-100 hover:bg-gray-200 text-gray-800 border border-gray-300"}`
        },
        "Back to Overview"
      ), /* @__PURE__ */ React.createElement(
        "button",
        {
          type: "button",
          onClick: () => runCapabilityAction("rag_chromadb", "install"),
          disabled: !canInstallRag || isRagBusy,
          className: `px-3 py-1.5 rounded text-sm font-medium ${canInstallRag && !isRagBusy ? "bg-indigo-600 hover:bg-indigo-700 text-white" : isDarkTheme ? "bg-gray-800 text-gray-500 cursor-not-allowed" : "bg-gray-200 text-gray-500 cursor-not-allowed"}`
        },
        ragActionInProgress === "install" ? "Installing..." : ragCapability.installed ? "Installed" : ragCapability.runtime_available ? "Install" : "Planned"
      ), /* @__PURE__ */ React.createElement(
        "button",
        {
          type: "button",
          onClick: () => runCapabilityAction("rag_chromadb", "enable"),
          disabled: !canEnableRag || isRagBusy,
          className: `px-3 py-1.5 rounded text-sm font-medium ${canEnableRag && !isRagBusy ? "bg-emerald-600 hover:bg-emerald-700 text-white" : isDarkTheme ? "bg-gray-800 text-gray-500 cursor-not-allowed" : "bg-gray-200 text-gray-500 cursor-not-allowed"}`
        },
        ragActionInProgress === "enable" ? "Enabling..." : "Enable"
      ), /* @__PURE__ */ React.createElement(
        "button",
        {
          type: "button",
          onClick: () => runCapabilityAction("rag_chromadb", "disable"),
          disabled: !canDisableRag || isRagBusy,
          className: `px-3 py-1.5 rounded text-sm font-medium ${canDisableRag && !isRagBusy ? "bg-rose-600 hover:bg-rose-700 text-white" : isDarkTheme ? "bg-gray-800 text-gray-500 cursor-not-allowed" : "bg-gray-200 text-gray-500 cursor-not-allowed"}`
        },
        ragActionInProgress === "disable" ? "Disabling..." : "Disable"
      ), /* @__PURE__ */ React.createElement(
        "button",
        {
          type: "button",
          onClick: () => runCapabilityAction("rag_chromadb", "test"),
          disabled: !canTestRag || isRagBusy,
          className: `px-3 py-1.5 rounded text-sm font-medium ${canTestRag && !isRagBusy ? "bg-amber-600 hover:bg-amber-700 text-white" : isDarkTheme ? "bg-gray-800 text-gray-500 cursor-not-allowed" : "bg-gray-200 text-gray-500 cursor-not-allowed"}`
        },
        ragActionInProgress === "test" ? "Testing..." : "Test"
      ), /* @__PURE__ */ React.createElement(
        "button",
        {
          type: "button",
          onClick: () => runCapabilityAction("rag_chromadb", "reindex"),
          disabled: !canReindexRag || isRagBusy,
          className: `px-3 py-1.5 rounded text-sm font-medium ${canReindexRag && !isRagBusy ? "bg-violet-600 hover:bg-violet-700 text-white" : isDarkTheme ? "bg-gray-800 text-gray-500 cursor-not-allowed" : "bg-gray-200 text-gray-500 cursor-not-allowed"}`
        },
        ragActionInProgress === "reindex" ? "Reindexing..." : "Reindex"
      ))), /* @__PURE__ */ React.createElement("div", { className: "grid grid-cols-1 xl:grid-cols-2 gap-6" }, /* @__PURE__ */ React.createElement("div", { className: "space-y-6" }, /* @__PURE__ */ React.createElement("div", { className: `rounded-lg shadow-sm p-6 border ${panelClass}` }, /* @__PURE__ */ React.createElement("div", { className: `text-sm font-semibold mb-2 ${headingClass}` }, "Import Knowledge Asset"), /* @__PURE__ */ React.createElement("p", { className: `text-xs mb-3 ${subtextClass}` }, "Bring in documentation, environment notes, and runbook context that indexed retrieval should be able to assemble into operator-ready answers. New imports land in the library checked in by default."), /* @__PURE__ */ React.createElement("div", { className: "grid grid-cols-1 sm:grid-cols-2 gap-2 mb-2" }, /* @__PURE__ */ React.createElement(
        "input",
        {
          value: ragAssetDraft.title || "",
          onChange: (event2) => updateRagAssetDraft("title", event2.target.value),
          placeholder: "Asset title",
          className: `rounded-lg border px-3 py-2 text-xs ${isDarkTheme ? "bg-gray-900 border-gray-700 text-gray-100" : "bg-white border-gray-300 text-gray-900"}`
        }
      ), /* @__PURE__ */ React.createElement(
        "select",
        {
          value: ragAssetDraft.asset_type || "reference_document",
          onChange: (event2) => updateRagAssetDraft("asset_type", event2.target.value),
          className: `rounded-lg border px-3 py-2 text-xs ${isDarkTheme ? "bg-gray-900 border-gray-700 text-gray-100" : "bg-white border-gray-300 text-gray-900"}`
        },
        /* @__PURE__ */ React.createElement("option", { value: SPL_LIBRARY_ASSET_TYPE }, "SPL Library Query"),
        /* @__PURE__ */ React.createElement("option", { value: "reference_document" }, "Reference Document"),
        /* @__PURE__ */ React.createElement("option", { value: "splunk_documentation" }, "Splunk Documentation"),
        /* @__PURE__ */ React.createElement("option", { value: "monitored_system_context" }, "Monitored System Context"),
        /* @__PURE__ */ React.createElement("option", { value: "connected_system_context" }, "Connected System Context"),
        /* @__PURE__ */ React.createElement("option", { value: "integration_context" }, "Integration Context"),
        /* @__PURE__ */ React.createElement("option", { value: "runbook_context" }, "Runbook Context")
      ), /* @__PURE__ */ React.createElement(
        "input",
        {
          value: ragAssetDraft.source_label || "",
          onChange: (event2) => updateRagAssetDraft("source_label", event2.target.value),
          placeholder: "Source label, system, or owner",
          className: `rounded-lg border px-3 py-2 text-xs ${isDarkTheme ? "bg-gray-900 border-gray-700 text-gray-100" : "bg-white border-gray-300 text-gray-900"}`
        }
      ), /* @__PURE__ */ React.createElement(
        "input",
        {
          value: ragAssetDraft.tags || "",
          onChange: (event2) => updateRagAssetDraft("tags", event2.target.value),
          placeholder: "Tags, comma separated",
          className: `rounded-lg border px-3 py-2 text-xs ${isDarkTheme ? "bg-gray-900 border-gray-700 text-gray-100" : "bg-white border-gray-300 text-gray-900"}`
        }
      )), /* @__PURE__ */ React.createElement(
        "textarea",
        {
          value: ragAssetDraft.description || "",
          onChange: (event2) => updateRagAssetDraft("description", event2.target.value),
          rows: 2,
          placeholder: "Why this asset matters to retrieval and what it should help answer",
          className: `w-full rounded-lg border px-3 py-2 text-xs mb-2 ${isDarkTheme ? "bg-gray-900 border-gray-700 text-gray-100" : "bg-white border-gray-300 text-gray-900"}`
        }
      ), /* @__PURE__ */ React.createElement(
        "textarea",
        {
          value: ragAssetDraft.content || "",
          onChange: (event2) => updateRagAssetDraft("content", event2.target.value),
          rows: 8,
          placeholder: "Paste documentation, system context, runbook notes, integration details, or other retrieval content here",
          className: `w-full rounded-lg border px-3 py-2 text-xs font-mono ${isDarkTheme ? "bg-gray-900 border-gray-700 text-gray-100" : "bg-white border-gray-300 text-gray-900"}`
        }
      ), /* @__PURE__ */ React.createElement("div", { className: "mt-2" }, /* @__PURE__ */ React.createElement("label", { className: `block text-xs font-medium mb-1 ${headingClass}` }, "Upload a supported asset instead"), /* @__PURE__ */ React.createElement(
        "input",
        {
          ref: ragAssetFileInputRef,
          type: "file",
          accept: ".md,.txt,.json,.log,.csv,.pdf,.docx",
          onChange: (event2) => {
            var _a3;
            return setRagAssetUploadFile(((_a3 = event2.target.files) == null ? void 0 : _a3[0]) || null);
          },
          className: `block w-full text-xs ${subtextClass}`
        }
      ), ragAssetUploadFile && /* @__PURE__ */ React.createElement("div", { className: `mt-1 ${mutedTextClass}` }, "Selected file: ", ragAssetUploadFile.name)), /* @__PURE__ */ React.createElement("div", { className: "flex flex-wrap gap-2 mt-3" }, /* @__PURE__ */ React.createElement(
        "button",
        {
          type: "button",
          onClick: importRagKnowledgeAsset,
          disabled: isRagBusy,
          className: `px-3 py-1.5 rounded text-sm font-medium ${!isRagBusy ? "bg-cyan-700 hover:bg-cyan-800 text-white" : isDarkTheme ? "bg-gray-800 text-gray-500 cursor-not-allowed" : "bg-gray-200 text-gray-500 cursor-not-allowed"}`
        },
        ragActionInProgress === "import-asset" ? "Importing..." : ragAssetUploadFile ? "Upload Asset" : "Import Asset"
      ), /* @__PURE__ */ React.createElement(
        "button",
        {
          type: "button",
          onClick: clearRagAssetDraft,
          disabled: isRagBusy,
          className: `px-3 py-1.5 rounded text-sm font-medium ${!isRagBusy ? "bg-slate-700 hover:bg-slate-800 text-white" : isDarkTheme ? "bg-gray-800 text-gray-500 cursor-not-allowed" : "bg-gray-200 text-gray-500 cursor-not-allowed"}`
        },
        "Reset Draft"
      )), /* @__PURE__ */ React.createElement("div", { className: `mt-2 text-xs ${mutedTextClass}` }, "Paste content or upload `.md`, `.txt`, `.json`, `.log`, `.csv`, `.pdf`, or `.docx`. If a file is selected, file import takes precedence over pasted content. Imported assets stay in the library until you remove them."))), /* @__PURE__ */ React.createElement("div", { className: "space-y-6" }, /* @__PURE__ */ React.createElement("div", { className: `rounded-lg shadow-sm p-6 border ${panelClass}` }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-col sm:flex-row sm:items-start sm:justify-between gap-2 mb-2" }, /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("div", { className: `text-sm font-semibold ${headingClass}` }, "Build Context Preview"), /* @__PURE__ */ React.createElement("div", { className: `text-xs ${subtextClass}` }, "Preview the exact indexed context retrieval can assemble from the managed asset plane.")), /* @__PURE__ */ React.createElement("div", { className: `text-[11px] rounded-lg px-2 py-1 border ${canUseRagContextPreview ? isDarkTheme ? "bg-sky-950 border-sky-800 text-sky-100" : "bg-sky-50 border-sky-200 text-sky-800" : isDarkTheme ? "bg-gray-900 border-gray-700 text-gray-300" : "bg-white border-gray-300 text-gray-600"}` }, canUseRagContextPreview ? "Indexed asset search is ready." : "Indexed asset search is unavailable until rag_chromadb is installed, enabled, and reindexed.")), /* @__PURE__ */ React.createElement("div", { className: "grid grid-cols-1 sm:grid-cols-[minmax(0,1fr)_140px] gap-2" }, /* @__PURE__ */ React.createElement(
        "input",
        {
          value: ragContextQuery || "",
          onChange: (event2) => setRagContextQuery(event2.target.value),
          placeholder: "What should the assistant know about our Splunk indexer cluster dependencies?",
          className: `rounded-lg border px-3 py-2 text-xs ${isDarkTheme ? "bg-gray-900 border-gray-700 text-gray-100" : "bg-white border-gray-300 text-gray-900"}`
        }
      ), /* @__PURE__ */ React.createElement(
        "select",
        {
          value: ragContextLimit,
          onChange: (event2) => setRagContextLimit(Number(event2.target.value) || 4),
          className: `rounded-lg border px-3 py-2 text-xs ${isDarkTheme ? "bg-gray-900 border-gray-700 text-gray-100" : "bg-white border-gray-300 text-gray-900"}`
        },
        /* @__PURE__ */ React.createElement("option", { value: 2 }, "2 chunks"),
        /* @__PURE__ */ React.createElement("option", { value: 3 }, "3 chunks"),
        /* @__PURE__ */ React.createElement("option", { value: 4 }, "4 chunks"),
        /* @__PURE__ */ React.createElement("option", { value: 5 }, "5 chunks"),
        /* @__PURE__ */ React.createElement("option", { value: 6 }, "6 chunks")
      )), /* @__PURE__ */ React.createElement("div", { className: "flex flex-wrap gap-2 mt-3" }, /* @__PURE__ */ React.createElement(
        "button",
        {
          type: "button",
          onClick: buildRagContextPreview,
          disabled: !canUseRagContextPreview || isRagBusy,
          className: `px-3 py-1.5 rounded text-sm font-medium ${canUseRagContextPreview && !isRagBusy ? "bg-violet-600 hover:bg-violet-700 text-white" : isDarkTheme ? "bg-gray-800 text-gray-500 cursor-not-allowed" : "bg-gray-200 text-gray-500 cursor-not-allowed"}`
        },
        ragActionInProgress === "build-context" ? "Building Preview..." : "Build Preview"
      ), /* @__PURE__ */ React.createElement(
        "button",
        {
          type: "button",
          onClick: () => setRagAssetWorkspace((prev) => ({ ...prev, contextPreview: null })),
          disabled: !ragAssetWorkspace.contextPreview || isRagBusy,
          className: `px-3 py-1.5 rounded text-sm font-medium ${ragAssetWorkspace.contextPreview && !isRagBusy ? "bg-slate-700 hover:bg-slate-800 text-white" : isDarkTheme ? "bg-gray-800 text-gray-500 cursor-not-allowed" : "bg-gray-200 text-gray-500 cursor-not-allowed"}`
        },
        "Clear Preview"
      ), /* @__PURE__ */ React.createElement(
        "button",
        {
          type: "button",
          onClick: () => loadRagAssetWorkspace(),
          disabled: isRagBusy,
          className: `px-3 py-1.5 rounded text-sm font-medium ${!isRagBusy ? "bg-indigo-600 hover:bg-indigo-700 text-white" : isDarkTheme ? "bg-gray-800 text-gray-500 cursor-not-allowed" : "bg-gray-200 text-gray-500 cursor-not-allowed"}`
        },
        ragAssetWorkspace.status === "loading" ? "Refreshing..." : "Refresh Assets"
      )), ((_a2 = ragAssetWorkspace.contextPreview) == null ? void 0 : _a2.message) && /* @__PURE__ */ React.createElement("div", { className: `mt-3 text-xs rounded-lg border px-3 py-2 ${panelMutedClass} ${subtextClass}` }, ragAssetWorkspace.contextPreview.message), ((_b2 = ragAssetWorkspace.contextPreview) == null ? void 0 : _b2.operator_brief) && /* @__PURE__ */ React.createElement("div", { className: `mt-3 rounded-lg border px-3 py-3 ${isDarkTheme ? "bg-gray-900 border-gray-700" : "bg-white border-gray-300"}` }, /* @__PURE__ */ React.createElement("div", { className: `text-sm font-medium mb-2 ${headingClass}` }, "Operator Context Brief"), /* @__PURE__ */ React.createElement("pre", { className: `text-xs whitespace-pre-wrap font-mono ${isDarkTheme ? "text-gray-100" : "text-gray-900"}` }, ragAssetWorkspace.contextPreview.operator_brief)), Array.isArray((_c2 = ragAssetWorkspace.contextPreview) == null ? void 0 : _c2.matched_assets) && ragAssetWorkspace.contextPreview.matched_assets.length > 0 && /* @__PURE__ */ React.createElement("div", { className: "space-y-2 mt-3" }, ragAssetWorkspace.contextPreview.matched_assets.map((asset) => /* @__PURE__ */ React.createElement("div", { key: asset.asset_id || `${asset.title}-${asset.asset_type}`, className: `rounded-lg border px-3 py-3 text-xs ${isDarkTheme ? "bg-gray-900 border-gray-700 text-gray-100" : "bg-white border-gray-300 text-gray-800"}` }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-col sm:flex-row sm:items-start sm:justify-between gap-2" }, /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("div", { className: "flex flex-wrap items-center gap-2" }, /* @__PURE__ */ React.createElement("span", { className: `font-medium ${headingClass}` }, asset.title || "Matched asset"), /* @__PURE__ */ React.createElement("span", { className: `rounded-full px-2 py-0.5 border text-[11px] ${isDarkTheme ? "bg-sky-950 border-sky-800 text-sky-100" : "bg-sky-50 border-sky-200 text-sky-800"}` }, formatKnowledgeAssetTypeLabel(asset.asset_type))), asset.source_label && /* @__PURE__ */ React.createElement("div", { className: `mt-1 ${mutedTextClass}` }, "Source: ", asset.source_label)), /* @__PURE__ */ React.createElement("div", { className: "flex flex-wrap items-center gap-2" }, asset.match_score != null && /* @__PURE__ */ React.createElement("span", { className: `rounded-full px-2 py-0.5 border text-[11px] ${isDarkTheme ? "bg-violet-950 border-violet-800 text-violet-100" : "bg-violet-50 border-violet-200 text-violet-800"}` }, "score ", asset.match_score), asset.asset_id && /* @__PURE__ */ React.createElement(
        "button",
        {
          type: "button",
          onClick: () => loadRagAssetDetail(asset.asset_id, { force: true }),
          disabled: ragAssetWorkspace.detailStatus === "loading",
          className: `px-2.5 py-1 rounded text-[11px] font-medium ${ragAssetWorkspace.detailStatus !== "loading" ? "bg-slate-700 hover:bg-slate-800 text-white" : isDarkTheme ? "bg-gray-800 text-gray-500 cursor-not-allowed" : "bg-gray-200 text-gray-500 cursor-not-allowed"}`
        },
        ragAssetWorkspace.detailStatus === "loading" && ragAssetWorkspace.detailAssetId === asset.asset_id ? "Loading Detail..." : "Inspect Asset"
      ))), asset.why_matched && /* @__PURE__ */ React.createElement("div", { className: `mt-2 ${subtextClass}` }, asset.why_matched), asset.best_excerpt && /* @__PURE__ */ React.createElement("div", { className: `mt-2 ${subtextClass}` }, asset.best_excerpt), Array.isArray(asset.matched_chunks) && asset.matched_chunks.length > 0 && /* @__PURE__ */ React.createElement("div", { className: "flex flex-wrap gap-2 mt-2 text-[11px]" }, asset.matched_chunks.slice(0, 4).map((matchedChunk, matchedChunkIndex) => /* @__PURE__ */ React.createElement(
        "span",
        {
          key: `${asset.asset_id || asset.title}-${matchedChunk.document_id || matchedChunkIndex}`,
          className: `rounded-full px-2 py-0.5 border ${isDarkTheme ? "bg-emerald-950 border-emerald-800 text-emerald-100" : "bg-emerald-50 border-emerald-200 text-emerald-800"}`
        },
        matchedChunk.section || `Matched chunk ${matchedChunkIndex + 1}`,
        matchedChunk.score != null ? ` · ${matchedChunk.score}` : ""
      ))), Array.isArray(asset.focus_terms) && asset.focus_terms.length > 0 && /* @__PURE__ */ React.createElement("div", { className: "flex flex-wrap gap-2 mt-2 text-[11px]" }, asset.focus_terms.slice(0, 8).map((term) => /* @__PURE__ */ React.createElement("span", { key: `${asset.asset_id || asset.title}-${term}`, className: `rounded-full px-2 py-0.5 border ${isDarkTheme ? "bg-gray-800 border-gray-600 text-gray-200" : "bg-gray-100 border-gray-300 text-gray-700"}` }, term))), Array.isArray(asset.key_points) && asset.key_points.length > 0 && /* @__PURE__ */ React.createElement("ul", { className: `mt-2 list-disc pl-4 space-y-1 ${subtextClass}` }, asset.key_points.slice(0, 2).map((point, pointIndex) => /* @__PURE__ */ React.createElement("li", { key: `${asset.asset_id || asset.title}-${pointIndex}` }, point)))))), ((_d2 = ragAssetWorkspace.contextPreview) == null ? void 0 : _d2.context_text) && /* @__PURE__ */ React.createElement("pre", { className: `mt-3 rounded-lg border px-3 py-3 text-xs whitespace-pre-wrap font-mono ${isDarkTheme ? "bg-gray-900 border-gray-700 text-gray-100" : "bg-white border-gray-300 text-gray-900"}` }, ragAssetWorkspace.contextPreview.context_text), Array.isArray((_e2 = ragAssetWorkspace.contextPreview) == null ? void 0 : _e2.chunks) && ragAssetWorkspace.contextPreview.chunks.length > 0 && /* @__PURE__ */ React.createElement("div", { className: "space-y-2 mt-3" }, ragAssetWorkspace.contextPreview.chunks.map((chunk, chunkIndex) => /* @__PURE__ */ React.createElement("div", { key: `${chunk.source || "chunk"}-${chunkIndex}`, className: `rounded-lg border px-3 py-2 text-xs ${isDarkTheme ? "bg-gray-900 border-gray-700 text-gray-100" : "bg-white border-gray-300 text-gray-800"}` }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-wrap items-center gap-2 mb-1" }, /* @__PURE__ */ React.createElement("span", { className: `font-medium ${headingClass}` }, chunk.source || `Chunk ${chunkIndex + 1}`), chunk.score != null && /* @__PURE__ */ React.createElement("span", { className: `rounded-full px-2 py-0.5 border ${isDarkTheme ? "bg-violet-950 border-violet-800 text-violet-100" : "bg-violet-50 border-violet-200 text-violet-800"}` }, "score ", chunk.score)), /* @__PURE__ */ React.createElement("div", { className: subtextClass }, chunk.snippet || "No snippet returned."))))), (ragAssetWorkspace.detailAssetId || ragAssetWorkspace.assetDetail) && /* @__PURE__ */ React.createElement("div", { className: `rounded-lg shadow-sm p-6 border ${panelClass}` }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-col sm:flex-row sm:items-start sm:justify-between gap-2 mb-3" }, /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("div", { className: `text-sm font-semibold ${headingClass}` }, "Knowledge Asset Detail"), /* @__PURE__ */ React.createElement("div", { className: `text-xs ${subtextClass}` }, "Inspect the stored asset sections and the chunk splits the indexer uses for retrieval.")), /* @__PURE__ */ React.createElement(
        "button",
        {
          type: "button",
          onClick: clearRagAssetDetail,
          className: `px-3 py-1.5 rounded text-sm font-medium ${isDarkTheme ? "bg-gray-700 hover:bg-gray-600 text-white" : "bg-gray-100 hover:bg-gray-200 text-gray-800 border border-gray-300"}`
        },
        "Close Detail"
      )), ragAssetWorkspace.detailStatus === "loading" ? /* @__PURE__ */ React.createElement("div", { className: `text-xs rounded-lg border px-3 py-3 ${panelMutedClass} ${subtextClass}` }, "Loading managed knowledge asset detail.") : ragAssetWorkspace.detailStatus === "error" ? /* @__PURE__ */ React.createElement("div", { className: `text-xs rounded-lg border px-3 py-3 ${isDarkTheme ? "bg-red-950 border-red-800 text-red-100" : "bg-red-50 border-red-200 text-red-800"}` }, ragAssetWorkspace.detailError || "Knowledge asset detail could not be loaded.") : ((_f2 = ragAssetWorkspace.assetDetail) == null ? void 0 : _f2.asset) ? /* @__PURE__ */ React.createElement(React.Fragment, null, /* @__PURE__ */ React.createElement("div", { className: `rounded-lg border px-3 py-3 mb-3 ${isDarkTheme ? "bg-gray-900 border-gray-700" : "bg-white border-gray-300"}` }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-col sm:flex-row sm:items-start sm:justify-between gap-2" }, /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("div", { className: "flex flex-wrap items-center gap-2" }, /* @__PURE__ */ React.createElement("span", { className: `text-sm font-medium ${headingClass}` }, ragAssetWorkspace.assetDetail.asset.title || "Knowledge Asset"), /* @__PURE__ */ React.createElement("span", { className: `rounded-full px-2 py-0.5 border text-[11px] ${isDarkTheme ? "bg-sky-950 border-sky-800 text-sky-100" : "bg-sky-50 border-sky-200 text-sky-800"}` }, formatKnowledgeAssetTypeLabel(ragAssetWorkspace.assetDetail.asset.asset_type))), ragAssetWorkspace.assetDetail.asset.source_label && /* @__PURE__ */ React.createElement("div", { className: `mt-1 text-xs ${mutedTextClass}` }, "Source: ", ragAssetWorkspace.assetDetail.asset.source_label)), /* @__PURE__ */ React.createElement("div", { className: `text-xs ${mutedTextClass}` }, "Stored as: ", ragAssetWorkspace.assetDetail.stored_path || ragAssetWorkspace.assetDetail.asset.content_path || "managed asset")), /* @__PURE__ */ React.createElement("div", { className: "grid grid-cols-2 sm:grid-cols-4 gap-2 mt-3 text-[11px]" }, /* @__PURE__ */ React.createElement("div", { className: mutedTextClass }, "Stored sections: ", Array.isArray(ragAssetWorkspace.assetDetail.stored_sections) ? ragAssetWorkspace.assetDetail.stored_sections.length : 0), /* @__PURE__ */ React.createElement("div", { className: mutedTextClass }, "Chunk sections: ", ragAssetWorkspace.assetDetail.chunk_count || 0), /* @__PURE__ */ React.createElement("div", { className: mutedTextClass }, "Context characters: ", ragAssetWorkspace.assetDetail.context_character_count || 0), /* @__PURE__ */ React.createElement("div", { className: mutedTextClass }, "Imported: ", ragAssetWorkspace.assetDetail.asset.created_at ? new Date(ragAssetWorkspace.assetDetail.asset.created_at).toLocaleString() : "Unknown"))), (() => {
        const detailAttributes = getKnowledgeAssetAttributes(ragAssetWorkspace.assetDetail.asset);
        const detailSplQuery = String(detailAttributes.spl_query || "").trim();
        if (!detailSplQuery) {
          return null;
        }
        return /* @__PURE__ */ React.createElement("div", { "data-testid": "context-library-detail-spl-query", className: `rounded-lg border px-3 py-3 mb-3 ${isDarkTheme ? "bg-gray-900 border-gray-700" : "bg-white border-gray-300"}` }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-col gap-2 sm:flex-row sm:items-start sm:justify-between" }, /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("div", { className: `text-sm font-medium ${headingClass}` }, "Saved SPL Query"), /* @__PURE__ */ React.createElement("div", { className: `mt-1 text-xs ${subtextClass}` }, "Run this query in Splunk Web, reuse it in chat, or keep it parked in the context library.")), renderSplQueryActionButtons2(detailSplQuery, {
          allowSave: false,
          originKind: "spl_library_asset",
          originLabel: ragAssetWorkspace.assetDetail.asset.title || "Saved SPL Library Query",
          sourceLabel: ragAssetWorkspace.assetDetail.asset.source_label || ragAssetWorkspace.assetDetail.asset.title || "SPL Library Query",
          contextExcerpt: ragAssetWorkspace.assetDetail.asset.summary || ragAssetWorkspace.assetDetail.asset.preview || "",
          deeplinkOptions: {
            app: detailAttributes.app,
            earliest: detailAttributes.earliest,
            latest: detailAttributes.latest
          },
          className: "sm:justify-end"
        })), /* @__PURE__ */ React.createElement("pre", { className: `mt-3 max-h-40 overflow-auto rounded-lg border px-3 py-3 text-xs whitespace-pre-wrap font-mono ${isDarkTheme ? "bg-gray-950 border-gray-700 text-gray-100" : "bg-gray-50 border-gray-200 text-gray-900"}` }, detailSplQuery), renderSplQueryIntelligence(detailAttributes, { testIdPrefix: "context-library-detail-spl" }));
      })(), /* @__PURE__ */ React.createElement("div", { className: "grid grid-cols-1 2xl:grid-cols-2 gap-3" }, /* @__PURE__ */ React.createElement("div", { className: `rounded-lg border px-3 py-3 ${isDarkTheme ? "bg-gray-900 border-gray-700" : "bg-white border-gray-300"}` }, /* @__PURE__ */ React.createElement("div", { className: `text-sm font-medium mb-2 ${headingClass}` }, "Stored Sections"), /* @__PURE__ */ React.createElement("div", { className: "space-y-2 max-h-96 overflow-y-auto pr-1" }, Array.isArray(ragAssetWorkspace.assetDetail.stored_sections) && ragAssetWorkspace.assetDetail.stored_sections.length > 0 ? ragAssetWorkspace.assetDetail.stored_sections.map((section, sectionIndex) => /* @__PURE__ */ React.createElement("details", { key: `${section.title || "section"}-${sectionIndex}`, open: section.title !== "Context", className: `rounded border px-3 py-2 ${isDarkTheme ? "border-gray-700 bg-gray-950" : "border-gray-200 bg-gray-50"}` }, /* @__PURE__ */ React.createElement("summary", { className: `cursor-pointer text-xs font-medium ${headingClass}` }, section.title || `Section ${sectionIndex + 1}`, " (", section.character_count || 0, " chars)"), Array.isArray(section.items) && section.items.length > 0 ? /* @__PURE__ */ React.createElement("ul", { className: `mt-2 list-disc pl-4 space-y-1 text-xs ${subtextClass}` }, section.items.map((item, itemIndex) => /* @__PURE__ */ React.createElement("li", { key: `${section.title || "section"}-${itemIndex}` }, item))) : /* @__PURE__ */ React.createElement("pre", { className: `mt-2 text-xs whitespace-pre-wrap font-mono ${subtextClass}` }, section.content || "No section content available."))) : /* @__PURE__ */ React.createElement("div", { className: `text-xs rounded-lg border px-3 py-3 ${panelMutedClass} ${mutedTextClass}` }, "No stored sections were available for this asset."))), /* @__PURE__ */ React.createElement("div", { className: `rounded-lg border px-3 py-3 ${isDarkTheme ? "bg-gray-900 border-gray-700" : "bg-white border-gray-300"}` }, /* @__PURE__ */ React.createElement("div", { className: `text-sm font-medium mb-2 ${headingClass}` }, "Chunk Browser"), /* @__PURE__ */ React.createElement("div", { className: `text-xs mb-2 ${subtextClass}` }, "These are the current chunk splits generated from the asset file by the indexing logic."), activeDetailPreviewTrace.matchedChunkIds.length > 0 && /* @__PURE__ */ React.createElement("div", { className: `text-xs rounded-lg border px-3 py-2 mb-2 ${isDarkTheme ? "bg-sky-950 border-sky-800 text-sky-100" : "bg-sky-50 border-sky-200 text-sky-800"}` }, "Current preview matched ", activeDetailPreviewTrace.matchedChunkIds.length, " chunk-browser section(s) for this asset. Highlighted below."), /* @__PURE__ */ React.createElement("div", { className: "space-y-2 max-h-96 overflow-y-auto pr-1" }, Array.isArray(ragAssetWorkspace.assetDetail.chunk_sections) && ragAssetWorkspace.assetDetail.chunk_sections.length > 0 ? ragAssetWorkspace.assetDetail.chunk_sections.map((section, sectionIndex) => {
        const isPreviewMatched = activeDetailPreviewTrace.matchedChunkIds.includes(section.document_id);
        return /* @__PURE__ */ React.createElement("details", { key: section.document_id || `${section.section || "chunk"}-${sectionIndex}`, open: isPreviewMatched || sectionIndex === 0, className: `rounded border px-3 py-2 ${isPreviewMatched ? isDarkTheme ? "border-sky-700 bg-sky-950/40" : "border-sky-300 bg-sky-50" : isDarkTheme ? "border-gray-700 bg-gray-950" : "border-gray-200 bg-gray-50"}` }, /* @__PURE__ */ React.createElement("summary", { className: `cursor-pointer text-xs font-medium ${headingClass}` }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-wrap items-center gap-2" }, /* @__PURE__ */ React.createElement("span", null, section.section || `Chunk ${sectionIndex + 1}`, " (", section.character_count || 0, " chars)"), isPreviewMatched && /* @__PURE__ */ React.createElement("span", { className: `rounded-full px-2 py-0.5 border text-[11px] ${isDarkTheme ? "bg-sky-900 border-sky-700 text-sky-100" : "bg-sky-100 border-sky-300 text-sky-800"}` }, "Matched in Preview"))), /* @__PURE__ */ React.createElement("pre", { className: `mt-2 text-xs whitespace-pre-wrap font-mono ${subtextClass}` }, section.content || "No chunk content available."));
      }) : /* @__PURE__ */ React.createElement("div", { className: `text-xs rounded-lg border px-3 py-3 ${panelMutedClass} ${mutedTextClass}` }, "No chunk-browser sections were produced for this asset."))))) : null), /* @__PURE__ */ React.createElement("div", { className: `rounded-lg shadow-sm p-6 border ${panelClass}` }, /* @__PURE__ */ React.createElement("details", { className: `rounded-lg border ${isDarkTheme ? "border-gray-700 bg-gray-950" : "border-gray-200 bg-gray-50"}` }, /* @__PURE__ */ React.createElement("summary", { className: `cursor-pointer px-3 py-2 text-sm font-medium ${headingClass}` }, "Inspect Configuration"), /* @__PURE__ */ React.createElement("div", { className: "px-3 py-3" }, /* @__PURE__ */ React.createElement(
        "textarea",
        {
          value: capabilityDrafts.rag_chromadb || "{}",
          onChange: (event2) => updateCapabilityDraft("rag_chromadb", event2.target.value),
          rows: 10,
          className: `w-full rounded-lg border px-3 py-2 text-xs font-mono ${isDarkTheme ? "bg-gray-900 border-gray-700 text-gray-100" : "bg-white border-gray-300 text-gray-900"}`
        }
      ), /* @__PURE__ */ React.createElement("div", { className: `mt-2 text-xs ${mutedTextClass}` }, "Install the capability, restart the app if prompted, then enable and reindex it before using it in chat or indexed context previews."), /* @__PURE__ */ React.createElement("div", { className: "flex flex-wrap gap-2 mt-3" }, /* @__PURE__ */ React.createElement(
        "button",
        {
          type: "button",
          onClick: () => saveCapabilityConfig("rag_chromadb"),
          disabled: isRagBusy,
          className: `px-3 py-1.5 rounded text-sm font-medium ${!isRagBusy ? "bg-slate-700 hover:bg-slate-800 text-white" : isDarkTheme ? "bg-gray-800 text-gray-500 cursor-not-allowed" : "bg-gray-200 text-gray-500 cursor-not-allowed"}`
        },
        ragActionInProgress === "config" ? "Saving..." : "Save Config"
      ))))))), /* @__PURE__ */ React.createElement("div", { className: `rounded-lg shadow-sm p-6 border ${panelClass} mt-6` }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-col lg:flex-row lg:items-start lg:justify-between gap-3 mb-3" }, /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("div", { className: `text-sm font-semibold ${headingClass}` }, "Knowledge Asset Library"), /* @__PURE__ */ React.createElement("div", { className: `text-xs ${subtextClass}` }, "Imports land here checked in by default. Check assets out to keep them stored but remove them from active RAG circulation until you check them back in.")), /* @__PURE__ */ React.createElement("div", { className: "grid grid-cols-3 gap-2 min-w-[280px] text-[11px]" }, /* @__PURE__ */ React.createElement("div", { className: `rounded-lg border px-3 py-2 ${panelMutedClass}` }, /* @__PURE__ */ React.createElement("div", { className: mutedTextClass }, "Total"), /* @__PURE__ */ React.createElement("div", { className: `mt-1 font-semibold ${headingClass}` }, ragDisplayedAssetCount)), /* @__PURE__ */ React.createElement("div", { className: `rounded-lg border px-3 py-2 ${panelMutedClass}` }, /* @__PURE__ */ React.createElement("div", { className: mutedTextClass }, "Checked In"), /* @__PURE__ */ React.createElement("div", { className: `mt-1 font-semibold ${headingClass}` }, ragCheckedInAssetCount)), /* @__PURE__ */ React.createElement("div", { className: `rounded-lg border px-3 py-2 ${panelMutedClass}` }, /* @__PURE__ */ React.createElement("div", { className: mutedTextClass }, "Checked Out"), /* @__PURE__ */ React.createElement("div", { className: `mt-1 font-semibold ${headingClass}` }, ragCheckedOutAssetCount)))), /* @__PURE__ */ React.createElement("div", { className: "flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2 mb-3" }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-wrap gap-2" }, [
        { key: "all", label: `All (${ragDisplayedAssetCount})` },
        { key: "spl_library", label: `SPL Library (${ragSplLibraryAssetCount})` },
        { key: "checked_in", label: `Checked In (${(_g2 = ragLibraryStatusCounts == null ? void 0 : ragLibraryStatusCounts.checked_in) != null ? _g2 : ragCheckedInAssetCount})` },
        { key: "checked_out", label: `Checked Out (${(_h2 = ragLibraryStatusCounts == null ? void 0 : ragLibraryStatusCounts.checked_out) != null ? _h2 : ragCheckedOutAssetCount})` }
      ].map((filterOption) => {
        const isActive = ragLibraryFilter === filterOption.key;
        return /* @__PURE__ */ React.createElement(
          "button",
          {
            key: filterOption.key,
            "data-testid": `context-library-filter-${filterOption.key}`,
            type: "button",
            onClick: () => setRagLibraryFilter(filterOption.key),
            className: `px-3 py-1.5 rounded text-xs font-medium border ${isActive ? isDarkTheme ? "bg-sky-950 border-sky-800 text-sky-100" : "bg-sky-50 border-sky-200 text-sky-800" : isDarkTheme ? "bg-gray-900 border-gray-700 text-gray-200 hover:bg-gray-800" : "bg-white border-gray-300 text-gray-700 hover:bg-gray-50"}`
          },
          filterOption.label
        );
      })), /* @__PURE__ */ React.createElement("div", { className: `text-xs ${mutedTextClass}` }, ragLibraryAssetCount, " item(s) shown")), ragAssetWorkspace.status === "loading" ? /* @__PURE__ */ React.createElement("div", { className: `text-xs rounded-lg border px-3 py-3 ${panelMutedClass} ${subtextClass}` }, "Loading managed knowledge assets.") : ragAssetWorkspace.status === "error" ? /* @__PURE__ */ React.createElement("div", { className: `text-xs rounded-lg border px-3 py-2 ${isDarkTheme ? "bg-red-950 border-red-800 text-red-100" : "bg-red-50 border-red-200 text-red-800"}` }, ragAssetWorkspace.error || "Failed to load managed knowledge assets.") : ragLibraryAssets.length === 0 ? /* @__PURE__ */ React.createElement("div", { className: `text-xs rounded-lg border px-3 py-3 ${panelMutedClass} ${mutedTextClass}` }, ragLibraryFilter === "spl_library" ? "No SPL library queries have been saved into the context workspace yet." : ragLibraryFilter === "checked_in" ? "No checked-in knowledge assets are currently in active library circulation." : ragLibraryFilter === "checked_out" ? "No knowledge assets are currently checked out of circulation." : "No managed knowledge assets have been imported yet.") : /* @__PURE__ */ React.createElement("div", { className: "space-y-2 max-h-[42rem] overflow-y-auto pr-1" }, ragLibraryAssets.map((asset) => {
        var _a3, _b3, _c3, _d3;
        const assetLibraryStatus = String(asset.library_status || "checked_in").toLowerCase();
        const isAssetCheckedOut = assetLibraryStatus === "checked_out";
        const libraryActionKey = isAssetCheckedOut ? "check-in-asset" : "check-out-asset";
        const assetAttributes = getKnowledgeAssetAttributes(asset);
        const savedSplQuery = String(assetAttributes.spl_query || "").trim();
        const isSplLibraryOnlyView = ragLibraryFilter === "spl_library" && Boolean(savedSplQuery);
        const splIntelligenceSummary = renderSplQueryIntelligence(assetAttributes, {
          testIdPrefix: isSplLibraryOnlyView ? "context-library-spl" : ""
        });
        const splQueryActionOptions = {
          allowSave: false,
          originKind: "spl_library_asset",
          originLabel: asset.title || "Saved SPL Library Query",
          sourceLabel: asset.source_label || asset.title || "SPL Library Query",
          contextExcerpt: asset.summary || asset.preview || "",
          deeplinkOptions: {
            app: assetAttributes.app,
            earliest: assetAttributes.earliest,
            latest: assetAttributes.latest
          },
          className: "sm:justify-end"
        };
        return /* @__PURE__ */ React.createElement("div", { key: asset.asset_id || asset.content_path || asset.title, "data-testid": savedSplQuery ? "context-library-spl-asset-card" : "context-library-asset-card", className: `rounded-lg border px-3 py-3 ${isDarkTheme ? "bg-gray-900 border-gray-700" : "bg-white border-gray-300"}` }, isSplLibraryOnlyView ? /* @__PURE__ */ React.createElement("div", { className: "space-y-3" }, /* @__PURE__ */ React.createElement("div", { "data-testid": "context-library-spl-query-card", className: `rounded-lg border px-3 py-3 ${isDarkTheme ? "bg-gray-950 border-gray-700" : "bg-gray-50 border-gray-200"}` }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-col gap-2 sm:flex-row sm:items-start sm:justify-between" }, /* @__PURE__ */ React.createElement("div", { className: `text-[11px] font-semibold uppercase tracking-wide ${mutedTextClass}` }, "Saved SPL Query"), renderSplQueryActionButtons2(savedSplQuery, splQueryActionOptions)), /* @__PURE__ */ React.createElement("pre", { "data-testid": "context-library-spl-only-query", className: `mt-2 max-h-[26rem] overflow-auto rounded-lg border px-3 py-3 text-xs whitespace-pre-wrap font-mono ${isDarkTheme ? "bg-gray-900 border-gray-700 text-gray-100" : "bg-white border-gray-300 text-gray-900"}` }, savedSplQuery), splIntelligenceSummary), /* @__PURE__ */ React.createElement("div", { className: "flex flex-wrap gap-2" }, /* @__PURE__ */ React.createElement(
          "button",
          {
            type: "button",
            "data-testid": "context-library-view-spl-details",
            onClick: () => loadRagAssetDetail(asset.asset_id),
            disabled: ragAssetWorkspace.detailStatus === "loading" || !asset.asset_id,
            className: `px-3 py-1.5 rounded text-sm font-medium ${ragAssetWorkspace.detailStatus !== "loading" && asset.asset_id ? "bg-slate-700 hover:bg-slate-800 text-white" : isDarkTheme ? "bg-gray-800 text-gray-500 cursor-not-allowed" : "bg-gray-200 text-gray-500 cursor-not-allowed"}`
          },
          ragAssetWorkspace.detailStatus === "loading" && ragAssetWorkspace.detailAssetId === asset.asset_id ? "Loading Detail..." : ((_b3 = (_a3 = ragAssetWorkspace.assetDetail) == null ? void 0 : _a3.asset) == null ? void 0 : _b3.asset_id) === asset.asset_id ? "Hide Details" : "View Details"
        ), /* @__PURE__ */ React.createElement(
          "button",
          {
            type: "button",
            onClick: () => setRagKnowledgeAssetLibraryStatus(asset.asset_id, asset.title, isAssetCheckedOut ? "checked_in" : "checked_out"),
            disabled: isRagBusy || !asset.asset_id,
            className: `px-3 py-1.5 rounded text-sm font-medium ${!isRagBusy && asset.asset_id ? isAssetCheckedOut ? "bg-emerald-600 hover:bg-emerald-700 text-white" : "bg-amber-600 hover:bg-amber-700 text-white" : isDarkTheme ? "bg-gray-800 text-gray-500 cursor-not-allowed" : "bg-gray-200 text-gray-500 cursor-not-allowed"}`
          },
          ragActionInProgress === libraryActionKey ? isAssetCheckedOut ? "Checking In..." : "Checking Out..." : isAssetCheckedOut ? "Check In" : "Check Out"
        ), /* @__PURE__ */ React.createElement(
          "button",
          {
            type: "button",
            onClick: () => deleteRagKnowledgeAsset(asset.asset_id, asset.title),
            disabled: isRagBusy,
            className: `px-3 py-1.5 rounded text-sm font-medium ${!isRagBusy ? "bg-rose-600 hover:bg-rose-700 text-white" : isDarkTheme ? "bg-gray-800 text-gray-500 cursor-not-allowed" : "bg-gray-200 text-gray-500 cursor-not-allowed"}`
          },
          ragActionInProgress === "delete-asset" ? "Removing..." : "Remove"
        )), isAssetCheckedOut && /* @__PURE__ */ React.createElement("div", { className: `text-xs rounded-lg border px-3 py-2 ${isDarkTheme ? "bg-amber-950 border-amber-800 text-amber-100" : "bg-amber-50 border-amber-200 text-amber-800"}` }, "Checked out of active circulation. Retrieval previews and chat RAG will ignore this asset until it is checked back in.")) : /* @__PURE__ */ React.createElement(React.Fragment, null, /* @__PURE__ */ React.createElement("div", { className: "flex flex-col sm:flex-row sm:items-start sm:justify-between gap-2" }, /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("div", { className: "flex flex-wrap items-center gap-2" }, /* @__PURE__ */ React.createElement("div", { className: `text-sm font-medium ${headingClass}` }, asset.title || "Knowledge Asset"), /* @__PURE__ */ React.createElement("span", { className: `rounded-full px-2 py-0.5 border text-[11px] ${isDarkTheme ? "bg-sky-950 border-sky-800 text-sky-100" : "bg-sky-50 border-sky-200 text-sky-800"}` }, formatKnowledgeAssetTypeLabel(asset.asset_type)), /* @__PURE__ */ React.createElement("span", { className: `rounded-full px-2 py-0.5 border text-[11px] ${isDarkTheme ? "bg-gray-800 border-gray-600 text-gray-200" : "bg-gray-100 border-gray-300 text-gray-700"}` }, formatKnowledgeAssetImportMethodLabel(asset.import_method)), /* @__PURE__ */ React.createElement("span", { className: `rounded-full px-2 py-0.5 border text-[11px] ${getKnowledgeAssetLibraryStatusClasses(assetLibraryStatus)}` }, formatKnowledgeAssetLibraryStatusLabel(assetLibraryStatus))), asset.source_label && /* @__PURE__ */ React.createElement("div", { className: `mt-1 text-xs ${mutedTextClass}` }, "Source: ", asset.source_label)), /* @__PURE__ */ React.createElement("div", { className: "flex flex-wrap gap-2" }, /* @__PURE__ */ React.createElement(
          "button",
          {
            type: "button",
            "data-testid": savedSplQuery ? "context-library-view-spl-details" : void 0,
            onClick: () => loadRagAssetDetail(asset.asset_id),
            disabled: ragAssetWorkspace.detailStatus === "loading" || !asset.asset_id,
            className: `px-3 py-1.5 rounded text-sm font-medium ${ragAssetWorkspace.detailStatus !== "loading" && asset.asset_id ? "bg-slate-700 hover:bg-slate-800 text-white" : isDarkTheme ? "bg-gray-800 text-gray-500 cursor-not-allowed" : "bg-gray-200 text-gray-500 cursor-not-allowed"}`
          },
          ragAssetWorkspace.detailStatus === "loading" && ragAssetWorkspace.detailAssetId === asset.asset_id ? "Loading Detail..." : ((_d3 = (_c3 = ragAssetWorkspace.assetDetail) == null ? void 0 : _c3.asset) == null ? void 0 : _d3.asset_id) === asset.asset_id ? "Hide Details" : "View Details"
        ), /* @__PURE__ */ React.createElement(
          "button",
          {
            type: "button",
            onClick: () => setRagKnowledgeAssetLibraryStatus(asset.asset_id, asset.title, isAssetCheckedOut ? "checked_in" : "checked_out"),
            disabled: isRagBusy || !asset.asset_id,
            className: `px-3 py-1.5 rounded text-sm font-medium ${!isRagBusy && asset.asset_id ? isAssetCheckedOut ? "bg-emerald-600 hover:bg-emerald-700 text-white" : "bg-amber-600 hover:bg-amber-700 text-white" : isDarkTheme ? "bg-gray-800 text-gray-500 cursor-not-allowed" : "bg-gray-200 text-gray-500 cursor-not-allowed"}`
          },
          ragActionInProgress === libraryActionKey ? isAssetCheckedOut ? "Checking In..." : "Checking Out..." : isAssetCheckedOut ? "Check In" : "Check Out"
        ), /* @__PURE__ */ React.createElement(
          "button",
          {
            type: "button",
            onClick: () => deleteRagKnowledgeAsset(asset.asset_id, asset.title),
            disabled: isRagBusy,
            className: `px-3 py-1.5 rounded text-sm font-medium ${!isRagBusy ? "bg-rose-600 hover:bg-rose-700 text-white" : isDarkTheme ? "bg-gray-800 text-gray-500 cursor-not-allowed" : "bg-gray-200 text-gray-500 cursor-not-allowed"}`
          },
          ragActionInProgress === "delete-asset" ? "Removing..." : "Remove"
        ))), /* @__PURE__ */ React.createElement("div", { className: `mt-2 text-xs ${subtextClass}` }, asset.summary || asset.preview || "No summary available."), savedSplQuery && /* @__PURE__ */ React.createElement("div", { "data-testid": "context-library-spl-query-card", className: `mt-3 rounded-lg border px-3 py-3 ${isDarkTheme ? "bg-gray-950 border-gray-700" : "bg-gray-50 border-gray-200"}` }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-col gap-2 sm:flex-row sm:items-start sm:justify-between" }, /* @__PURE__ */ React.createElement("div", { className: `text-[11px] font-semibold uppercase tracking-wide ${mutedTextClass}` }, "Saved SPL Query"), renderSplQueryActionButtons2(savedSplQuery, splQueryActionOptions)), /* @__PURE__ */ React.createElement("pre", { className: `mt-2 max-h-32 overflow-auto rounded-lg border px-3 py-3 text-xs whitespace-pre-wrap font-mono ${isDarkTheme ? "bg-gray-900 border-gray-700 text-gray-100" : "bg-white border-gray-300 text-gray-900"}` }, savedSplQuery), splIntelligenceSummary), isAssetCheckedOut && /* @__PURE__ */ React.createElement("div", { className: `mt-2 text-xs rounded-lg border px-3 py-2 ${isDarkTheme ? "bg-amber-950 border-amber-800 text-amber-100" : "bg-amber-50 border-amber-200 text-amber-800"}` }, "Checked out of active circulation. Retrieval previews and chat RAG will ignore this asset until it is checked back in."), asset.description && /* @__PURE__ */ React.createElement("div", { className: `mt-2 text-xs ${mutedTextClass}` }, "Purpose: ", asset.description), Array.isArray(asset.tags) && asset.tags.length > 0 && /* @__PURE__ */ React.createElement("div", { className: "flex flex-wrap gap-2 mt-2 text-[11px]" }, asset.tags.map((tag) => /* @__PURE__ */ React.createElement("span", { key: `${asset.asset_id || asset.title}-${tag}`, className: `rounded-full px-2 py-0.5 border ${isDarkTheme ? "bg-gray-800 border-gray-600 text-gray-200" : "bg-gray-100 border-gray-300 text-gray-700"}` }, tag))), Array.isArray(asset.focus_terms) && asset.focus_terms.length > 0 && /* @__PURE__ */ React.createElement("div", { className: "flex flex-wrap gap-2 mt-2 text-[11px]" }, asset.focus_terms.slice(0, 8).map((term) => /* @__PURE__ */ React.createElement("span", { key: `${asset.asset_id || asset.title}-focus-${term}`, className: `rounded-full px-2 py-0.5 border ${isDarkTheme ? "bg-sky-950 border-sky-800 text-sky-100" : "bg-sky-50 border-sky-200 text-sky-800"}` }, term))), Array.isArray(asset.key_points) && asset.key_points.length > 0 && /* @__PURE__ */ React.createElement("ul", { className: `mt-2 list-disc pl-4 space-y-1 text-xs ${subtextClass}` }, asset.key_points.slice(0, 2).map((point, pointIndex) => /* @__PURE__ */ React.createElement("li", { key: `${asset.asset_id || asset.title}-point-${pointIndex}` }, point))), Array.isArray(asset.usage_guidance) && asset.usage_guidance.length > 0 && /* @__PURE__ */ React.createElement("div", { className: `mt-2 text-xs ${mutedTextClass}` }, "Best used for: ", asset.usage_guidance[0]), /* @__PURE__ */ React.createElement("div", { className: "grid grid-cols-2 gap-2 mt-3 text-[11px]" }, /* @__PURE__ */ React.createElement("div", { className: mutedTextClass }, "Words: ", asset.word_count || 0), /* @__PURE__ */ React.createElement("div", { className: mutedTextClass }, "Characters: ", asset.text_char_count || 0), /* @__PURE__ */ React.createElement("div", { className: mutedTextClass }, "Imported: ", asset.created_at ? new Date(asset.created_at).toLocaleString() : "Unknown"), /* @__PURE__ */ React.createElement("div", { className: mutedTextClass }, "Last checked in: ", asset.last_checked_in_at ? new Date(asset.last_checked_in_at).toLocaleString() : "Not recorded")), asset.checked_out_at ? /* @__PURE__ */ React.createElement("div", { className: `mt-1 text-[11px] ${mutedTextClass}` }, "Checked out: ", new Date(asset.checked_out_at).toLocaleString()) : /* @__PURE__ */ React.createElement("div", { className: `mt-1 text-[11px] ${mutedTextClass}` }, "Available for preview and chat retrieval while checked in."), /* @__PURE__ */ React.createElement("div", { className: `mt-1 text-[11px] ${mutedTextClass}` }, "Stored as: ", asset.content_path || "managed asset")));
      }))));
    };
    const loadConnectionInfo = async () => {
      try {
        const response = await fetch("/connection-info");
        const result = await response.json();
        setConnectionInfo(result);
      } catch (error) {
        console.error("Failed to load connection info:", error);
      }
    };
    const openSettings = async () => {
      await loadConfig();
      setActiveSettingsTab("connections");
      setIsSettingsOpen(true);
      setTimeout(() => {
        loadCredentials();
        loadMCPConfigs();
        loadSecurityControlPlane();
      }, 100);
    };
    const closeSettings = () => {
      setActiveSettingsTab("connections");
      setIsSettingsOpen(false);
    };
    const loadConfig = async () => {
      try {
        const response = await fetch("/api/config");
        const data = await response.json();
        setConfig(data);
        setSelectedProvider(normalizeProvider(data.llm.provider || "openai"));
        setSelectedModel(data.llm.model || "");
        setApiKeyPlaceholder(data.llm.api_key === "***" ? "(Already Configured)" : "Enter API key");
        setMCPTokenPlaceholder(data.mcp.token === "***" ? "(Already Configured)" : "Enter token");
        if (data.active_mcp_config_name) {
          setLoadedMCPConfigName(data.active_mcp_config_name);
        }
      } catch (error) {
        console.error("Failed to load config:", error);
      }
    };
    const loadAuthStatus = async () => {
      try {
        const response = await fetch("/api/auth/status");
        const data = await response.json();
        if (!response.ok) {
          throw new Error(data.detail || "Failed to load auth status");
        }
        setAuthStatus(data);
      } catch (error) {
        console.error("Failed to load auth status:", error);
        setAuthStatus(null);
      }
    };
    const loadSecurityUsers = async () => {
      setSecurityUsersState({ loading: true, error: "" });
      try {
        const response = await fetch("/api/security/users");
        const data = await response.json();
        if (!response.ok) {
          throw new Error(data.detail || "Failed to load users");
        }
        const users = Array.isArray(data.users) ? data.users : [];
        setSecurityUsers(users);
        setSecurityUserDrafts(users.reduce((drafts, user) => {
          drafts[user.id] = buildSecurityUserDraft(user);
          return drafts;
        }, {}));
        setSecurityUsersState({ loading: false, error: "" });
      } catch (error) {
        console.error("Failed to load security users:", error);
        setSecurityUsers([]);
        setSecurityUserDrafts({});
        setSecurityUsersState({ loading: false, error: error.message });
      }
    };
    const loadSecurityTokens = async () => {
      setSecurityTokensState({ loading: true, error: "" });
      try {
        const response = await fetch("/api/security/tokens");
        const data = await response.json();
        if (!response.ok) {
          throw new Error(data.detail || "Failed to load tokens");
        }
        setSecurityTokens(Array.isArray(data.tokens) ? data.tokens : []);
        setSecurityTokensState({ loading: false, error: "" });
      } catch (error) {
        console.error("Failed to load security tokens:", error);
        setSecurityTokens([]);
        setSecurityTokensState({ loading: false, error: error.message });
      }
    };
    const loadSecurityControlPlane = async () => {
      await loadAuthStatus();
      await Promise.all([loadSecurityUsers(), loadSecurityTokens()]);
    };
    const updateSecurityUserDraft = (userId, field, value) => {
      setSecurityUserDrafts((current) => ({
        ...current,
        [userId]: {
          ...current[userId] || buildSecurityUserDraft(securityUsers.find((user) => user.id === userId) || {}),
          [field]: value
        }
      }));
    };
    const saveSecurityUser = async (user) => {
      const draft = securityUserDrafts[user.id] || buildSecurityUserDraft(user);
      const payload = {
        role: draft.role,
        is_enabled: !!draft.is_enabled,
        require_password_reset: !!draft.require_password_reset,
        mcp_config_name: draft.mcp_config_name ? draft.mcp_config_name : null
      };
      if (draft.new_password && String(draft.new_password).trim()) {
        payload.new_password = String(draft.new_password).trim();
      }
      try {
        const response = await fetch(`/api/security/users/${user.id}`, {
          method: "PATCH",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload)
        });
        const result = await response.json();
        if (!response.ok) {
          throw new Error(result.detail || "Failed to update user");
        }
        showSettingsToast("User updated", `${result.user.username} was updated successfully.`, "success");
        await loadSecurityUsers();
        await loadAuthStatus();
      } catch (error) {
        alert(`Failed to update user: ${error.message}`);
      }
    };
    const createSecurityUser = async () => {
      const username = String(securityUserComposer.username || "").trim();
      const password = String(securityUserComposer.password || "");
      if (!username || !password) {
        alert("Please provide a username and password.");
        return;
      }
      try {
        const response = await fetch("/api/security/users", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            username,
            password,
            role: securityUserComposer.role,
            is_enabled: !!securityUserComposer.is_enabled,
            require_password_reset: !!securityUserComposer.require_password_reset,
            mcp_config_name: securityUserComposer.mcp_config_name ? securityUserComposer.mcp_config_name : null
          })
        });
        const result = await response.json();
        if (!response.ok) {
          throw new Error(result.detail || "Failed to create user");
        }
        showSettingsToast("User created", `${result.user.username} is ready for assignment and login.`, "success");
        resetSecurityUserComposer();
        setIsSecurityUserComposerOpen(false);
        await loadSecurityUsers();
      } catch (error) {
        alert(`Failed to create user: ${error.message}`);
      }
    };
    const deleteSecurityUser = async (user) => {
      const confirmed = window.confirm(`Delete user '${user.username}'?

This action cannot be undone.`);
      if (!confirmed) {
        return;
      }
      try {
        const response = await fetch(`/api/security/users/${user.id}`, { method: "DELETE" });
        const result = await response.json();
        if (!response.ok) {
          throw new Error(result.detail || "Failed to delete user");
        }
        showSettingsToast("User deleted", `${user.username} was removed from the local user store.`, "warning");
        await loadSecurityUsers();
        await loadAuthStatus();
      } catch (error) {
        alert(`Failed to delete user: ${error.message}`);
      }
    };
    const toggleSecurityTokenComposerScope = (scope) => {
      setSecurityTokenComposer((current) => {
        const currentScopes = Array.isArray(current.scopes) ? current.scopes : [];
        const nextScopes = currentScopes.includes(scope) ? currentScopes.filter((entry) => entry !== scope) : [...currentScopes, scope];
        return {
          ...current,
          scopes: nextScopes
        };
      });
    };
    const createSecurityToken = async () => {
      const name = String(securityTokenComposer.name || "").trim();
      const scopes = Array.isArray(securityTokenComposer.scopes) ? securityTokenComposer.scopes : [];
      if (!name) {
        alert("Please provide a token name.");
        return;
      }
      if (scopes.length === 0) {
        alert("Select at least one scope for the token.");
        return;
      }
      const expiresInDays = Number.parseInt(securityTokenComposer.expires_in_days, 10);
      const ownerUserId = Number.parseInt(securityTokenComposer.owner_user_id, 10);
      try {
        const response = await fetch("/api/security/tokens", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            name,
            token_type: securityTokenComposer.token_type,
            scopes,
            owner_user_id: Number.isFinite(ownerUserId) ? ownerUserId : void 0,
            expires_in_days: Number.isFinite(expiresInDays) ? expiresInDays : void 0
          })
        });
        const result = await response.json();
        if (!response.ok) {
          throw new Error(result.detail || "Failed to create token");
        }
        setSecurityTokenReveal({
          access_token: result.access_token,
          token: result.token
        });
        showSettingsToast("Token issued", `${result.token.name} was created and revealed once.`, "success");
        resetSecurityTokenComposer(securityTokenComposer.token_type);
        setIsSecurityTokenComposerOpen(false);
        await loadSecurityTokens();
      } catch (error) {
        alert(`Failed to create token: ${error.message}`);
      }
    };
    const revokeSecurityToken = async (token) => {
      const confirmed = window.confirm(`Revoke token '${token.name}'?

Clients using this token will stop working immediately.`);
      if (!confirmed) {
        return;
      }
      try {
        const response = await fetch(`/api/security/tokens/${token.id}/revoke`, { method: "POST" });
        const result = await response.json();
        if (!response.ok) {
          throw new Error(result.detail || "Failed to revoke token");
        }
        showSettingsToast("Token revoked", `${token.name} can no longer be used.`, "warning");
        await loadSecurityTokens();
      } catch (error) {
        alert(`Failed to revoke token: ${error.message}`);
      }
    };
    const removeSecurityToken = async (token) => {
      var _a2;
      const confirmed = window.confirm(`Remove token '${token.name}'?

This permanently deletes the token record from DT4SMS.`);
      if (!confirmed) {
        return;
      }
      try {
        const response = await fetch(`/api/security/tokens/${token.id}`, { method: "DELETE" });
        const result = await response.json();
        if (!response.ok) {
          throw new Error(result.detail || "Failed to remove token");
        }
        if (((_a2 = securityTokenReveal == null ? void 0 : securityTokenReveal.token) == null ? void 0 : _a2.id) === token.id) {
          setSecurityTokenReveal(null);
        }
        showSettingsToast("Token removed", `${token.name} was deleted from the token inventory.`, "warning");
        await loadSecurityTokens();
      } catch (error) {
        alert(`Failed to remove token: ${error.message}`);
      }
    };
    const copySecurityTokenReveal = async () => {
      if (!(securityTokenReveal == null ? void 0 : securityTokenReveal.access_token)) {
        return;
      }
      try {
        await navigator.clipboard.writeText(securityTokenReveal.access_token);
        showSettingsToast("Token copied", "The plaintext token is now in your clipboard.", "info");
      } catch (error) {
        alert(`Failed to copy token: ${error.message}`);
      }
    };
    const loadCredentials = async () => {
      try {
        const response = await fetch("/api/credentials");
        const credentials = await response.json();
        setSavedCredentials(credentials);
        const credList2 = document.getElementById("credentials-list");
        if (!credList2) return;
        if (Object.keys(credentials).length === 0) {
          credList2.innerHTML = `
                            <div class="text-center py-12 bg-white rounded-lg border-2 border-dashed border-gray-300">
                                <i class="fas fa-plug text-purple-300 text-5xl mb-4"></i>
                                <p class="text-base font-bold text-gray-700 mb-2">No Connections Yet</p>
                                <p class="text-sm text-gray-500 mb-4">Get started by creating your first AI model connection</p>
                                <p class="text-xs text-gray-400 italic">Click "Create New Connection" above</p>
                            </div>
                        `;
          return;
        }
        const activeCredName = config == null ? void 0 : config.active_credential_name;
        const credArray = Object.values(credentials).sort((a, b) => {
          if (a.name === activeCredName) return -1;
          if (b.name === activeCredName) return 1;
          return 0;
        });
        credList2.innerHTML = credArray.map((cred) => {
          const provider = normalizeProvider(cred.provider);
          const providerIcon = provider === "openai" ? "fa-openai" : provider === "azure" ? "fa-cloud" : provider === "anthropic" ? "fa-robot" : provider === "gemini" ? "fa-gem" : provider === "custom" ? "fa-server" : "fa-brain";
          const providerColor = provider === "openai" ? "text-green-600" : provider === "azure" ? "text-blue-600" : provider === "anthropic" ? "text-orange-600" : provider === "gemini" ? "text-indigo-600" : "text-purple-600";
          const isActive = cred.name === activeCredName;
          return `
                            <div class="group bg-white rounded-lg p-4 border-2 ${isActive ? "border-amber-500 shadow-lg" : "border-gray-200 hover:border-purple-400"} hover:shadow-lg transition-all">
                                <div class="flex items-start justify-between gap-4">
                                    <div class="flex-1 min-w-0">
                                        <div class="flex items-center gap-2 mb-2">
                                            <i class="fab ${providerIcon} ${providerColor} text-lg"></i>
                                            <h5 class="text-base font-bold text-gray-900 truncate">${cred.name}</h5>
                                            ${isActive ? '<span class="ml-2 px-2 py-0.5 bg-amber-500 text-gray-900 text-xs font-bold rounded-full uppercase">Active</span>' : ""}
                                        </div>
                                        <div class="text-sm text-gray-600 space-y-1.5 pl-1">
                                            <div class="flex items-center gap-2">
                                                <i class="fas fa-cog w-4 text-gray-400"></i>
                                                <span><span class="font-semibold text-gray-700">Provider:</span> ${cred.provider}</span>
                                            </div>
                                            <div class="flex items-center gap-2">
                                                <i class="fas fa-brain w-4 text-gray-400"></i>
                                                <span><span class="font-semibold text-gray-700">Model:</span> ${cred.model}</span>
                                            </div>
                                            ${cred.endpoint_url ? `
                                            <div class="flex items-center gap-2">
                                                <i class="fas fa-link w-4 text-gray-400"></i>
                                                <span class="truncate"><span class="font-semibold text-gray-700">Endpoint:</span> <code class="text-xs bg-gray-100 px-1 rounded">${cred.endpoint_url}</code></span>
                                            </div>` : ""}
                                            <div class="flex items-center gap-2">
                                                <i class="fas fa-sliders-h w-4 text-gray-400"></i>
                                                <span><span class="font-semibold text-gray-700">Settings:</span> ${cred.max_tokens} tokens, ${cred.temperature} temp</span>
                                            </div>
                                        </div>
                                    </div>
                                    <div class="flex flex-col gap-2 shrink-0">
                                        <button
                                            onclick="loadCredentialIntoSettings('${cred.name.replace(/'/g, "'")}')"
                                            class="px-4 py-2 bg-blue-600 hover:bg-blue-700 active:bg-blue-800 text-white rounded-lg text-sm font-semibold shadow-md hover:shadow-lg transition-all transform hover:scale-105"
                                            title="Load this credential into the settings form above"
                                        >
                                            <i class="fas fa-download mr-2"></i>Load
                                        </button>
                                        <button
                                            onclick="deleteCredential('${cred.name.replace(/'/g, "'")}')"
                                            class="px-4 py-2 bg-red-600 hover:bg-red-700 active:bg-red-800 text-white rounded-lg text-sm font-semibold shadow-md hover:shadow-lg transition-all transform hover:scale-105"
                                            title="Permanently delete this saved credential"
                                        >
                                            <i class="fas fa-trash-alt mr-2"></i>Delete
                                        </button>
                                    </div>
                                </div>
                            </div>
                        `;
        }).join("");
      } catch (error) {
        console.error("Failed to load credentials:", error);
        const credList2 = document.getElementById("credentials-list");
        if (credList2) {
          credList2.innerHTML = `
                            <div class="text-center py-10">
                                <i class="fas fa-exclamation-triangle text-red-400 text-4xl mb-4"></i>
                                <p class="text-base font-semibold text-red-700">Failed to load credentials</p>
                                <p class="text-sm text-gray-600 mt-2">${error.message}</p>
                            </div>
                        `;
        }
      }
    };
    window.loadCredentialIntoSettings = async (name) => {
      try {
        setIsLoadingCredential(true);
        const credList2 = document.getElementById("credentials-list");
        let originalHTML2 = "";
        if (credList2) {
          originalHTML2 = credList2.innerHTML;
          credList2.innerHTML = `
                            <div class="text-center py-10">
                                <i class="fas fa-spinner fa-spin text-purple-600 text-4xl mb-4"></i>
                                <p class="text-base font-semibold text-gray-700">Loading credential...</p>
                                <p class="text-sm text-gray-500 mt-2">${name}</p>
                            </div>
                        `;
        }
        const response = await fetch(`/api/credentials/${name}/load`, { method: "POST" });
        const result = await response.json();
        if (response.ok) {
          const newConfig = result.config;
          setConfig(newConfig);
          setSelectedProvider(normalizeProvider(newConfig.llm.provider));
          setLoadedCredentialName(name);
          setApiKeyPlaceholder("(Already Configured)");
          setShowConfigForm(true);
          setSelectedModel(newConfig.llm.model);
          setAvailableModels([]);
          setTimeout(() => {
            const normalizedProvider = normalizeProvider(newConfig.llm.provider);
            const providerInput = document.getElementById("llm-provider");
            if (providerInput) {
              providerInput.value = normalizedProvider;
            }
            const modelInput = document.getElementById("llm-model");
            if (modelInput) {
              modelInput.value = newConfig.llm.model;
            }
            const maxTokensInput = document.getElementById("llm-max-tokens");
            if (maxTokensInput) {
              maxTokensInput.value = newConfig.llm.max_tokens;
            }
            const temperatureInput = document.getElementById("llm-temperature");
            if (temperatureInput) {
              temperatureInput.value = newConfig.llm.temperature;
            }
            const apiKeyInput = document.getElementById("llm-api-key");
            if (apiKeyInput) {
              apiKeyInput.value = "";
            }
            if (newConfig.llm.endpoint_url && document.getElementById("llm-endpoint-url")) {
              document.getElementById("llm-endpoint-url").value = newConfig.llm.endpoint_url;
            }
          }, 50);
          await loadConfig();
          await loadCredentials();
          setIsLoadingCredential(false);
        } else {
          if (credList2) {
            credList2.innerHTML = originalHTML2;
          }
          setIsLoadingCredential(false);
          alert(`Failed to load credential: ${result.detail}`);
        }
      } catch (error) {
        if (credList) {
          credList.innerHTML = originalHTML;
        }
        setIsLoadingCredential(false);
        alert(`Error loading credential: ${error.message}`);
        await loadCredentials();
      }
    };
    window.deleteCredential = async (name) => {
      const confirmed = confirm(`⚠️ Delete Credential

Are you sure you want to delete '${name}'?

This action cannot be undone.`);
      if (!confirmed) return;
      try {
        const response = await fetch(`/api/credentials/${name}`, { method: "DELETE" });
        if (response.ok) {
          await loadCredentials();
          const successDiv = document.createElement("div");
          successDiv.className = "fixed top-6 right-6 bg-red-600 text-white px-6 py-4 rounded-xl shadow-2xl z-50";
          successDiv.innerHTML = `
                            <div class="flex items-center gap-3">
                                <i class="fas fa-trash-alt text-2xl"></i>
                                <div>
                                    <p class="font-bold text-base">Credential Deleted</p>
                                    <p class="text-sm opacity-90">${name}</p>
                                </div>
                            </div>
                        `;
          document.body.appendChild(successDiv);
          setTimeout(() => {
            successDiv.style.opacity = "0";
            successDiv.style.transition = "opacity 0.3s";
            setTimeout(() => successDiv.remove(), 300);
          }, 2500);
        } else {
          const error = await response.json();
          alert(`Failed to delete: ${error.detail}`);
        }
      } catch (error) {
        alert(`Error: ${error.message}`);
      }
    };
    const loadMCPConfigs = async () => {
      try {
        const response = await fetch("/api/mcp-configs");
        const mcpConfigs = await response.json();
        setSavedMCPConfigs(mcpConfigs);
        const mcpList = document.getElementById("mcp-configs-list");
        if (!mcpList) return;
        if (Object.keys(mcpConfigs).length === 0) {
          mcpList.innerHTML = `
                            <div class="text-center py-12 bg-white rounded-lg border-2 border-dashed border-gray-300">
                                <i class="fas fa-server text-green-300 text-5xl mb-4"></i>
                                <p class="text-base font-bold text-gray-700 mb-2">No Saved Configurations</p>
                                <p class="text-sm text-gray-500 mb-4">Save your current MCP server settings for quick access</p>
                                <p class="text-xs text-gray-400 italic">Click "Save Current Config" above</p>
                            </div>
                        `;
          return;
        }
        const activeMCPName = config == null ? void 0 : config.active_mcp_config_name;
        const mcpArray = Object.values(mcpConfigs).sort((a, b) => {
          if (a.name === activeMCPName) return -1;
          if (b.name === activeMCPName) return 1;
          return a.name.localeCompare(b.name);
        });
        mcpList.innerHTML = mcpArray.map((mcp) => `
                        <div class="group bg-white rounded-lg p-4 border-2 ${mcp.name === activeMCPName ? "border-green-400 shadow-lg" : "border-gray-200"} hover:border-green-400 hover:shadow-lg transition-all">
                            <div class="flex items-start justify-between gap-4">
                                <div class="flex-1 min-w-0">
                                    <div class="flex items-center gap-2 mb-2">
                                        <i class="fas fa-server text-green-600 text-lg"></i>
                                        <h5 class="text-base font-bold text-gray-900 truncate">${mcp.name}</h5>
                                        ${mcp.name === activeMCPName ? '<span class="px-2 py-0.5 bg-green-100 text-green-700 text-xs font-bold rounded-full">ACTIVE</span>' : ""}
                                    </div>
                                    ${mcp.description ? `<p class="text-sm text-gray-600 mb-2 pl-1">${mcp.description}</p>` : ""}
                                    <div class="text-sm text-gray-600 space-y-1.5 pl-1">
                                        <div class="flex items-center gap-2">
                                            <i class="fas fa-link w-4 text-gray-400"></i>
                                            <span><span class="font-semibold text-gray-700">URL:</span> ${mcp.url}</span>
                                        </div>
                                        <div class="flex items-center gap-2">
                                            <i class="fas fa-shield-alt w-4 text-gray-400"></i>
                                            <span><span class="font-semibold text-gray-700">SSL:</span> ${mcp.verify_ssl ? "Enabled" : "Disabled"}</span>
                                        </div>
                                    </div>
                                </div>
                                <div class="flex flex-col gap-2 shrink-0">
                                    <button
                                        onclick="testMCPConfig('${mcp.name}')"
                                        class="px-4 py-2 bg-indigo-600 hover:bg-indigo-700 active:bg-indigo-800 text-white rounded-lg text-sm font-semibold shadow-md hover:shadow-lg transition-all transform hover:scale-105"
                                        title="Test connection to this MCP server"
                                    >
                                        <i class="fas fa-network-wired mr-2"></i>Test
                                    </button>
                                    <button
                                        onclick="loadMCPConfigIntoSettings('${mcp.name}')"
                                        class="px-4 py-2 bg-blue-600 hover:bg-blue-700 active:bg-blue-800 text-white rounded-lg text-sm font-semibold shadow-md hover:shadow-lg transition-all transform hover:scale-105"
                                        title="Load this configuration into active settings"
                                    >
                                        <i class="fas fa-download mr-2"></i>Load
                                    </button>
                                    <button
                                        onclick="deleteMCPConfig('${mcp.name}')"
                                        class="px-4 py-2 bg-red-600 hover:bg-red-700 active:bg-red-800 text-white rounded-lg text-sm font-semibold shadow-md hover:shadow-lg transition-all transform hover:scale-105"
                                        title="Permanently delete this saved configuration"
                                    >
                                        <i class="fas fa-trash-alt mr-2"></i>Delete
                                    </button>
                                </div>
                            </div>
                        </div>
                    `).join("");
      } catch (error) {
        console.error("Failed to load MCP configs:", error);
        const mcpList = document.getElementById("mcp-configs-list");
        if (mcpList) {
          mcpList.innerHTML = `
                            <div class="text-center py-10">
                                <i class="fas fa-exclamation-triangle text-red-400 text-4xl mb-4"></i>
                                <p class="text-base font-semibold text-red-700">Failed to load MCP configurations</p>
                                <p class="text-sm text-gray-600 mt-2">${error.message}</p>
                            </div>
                        `;
        }
      }
    };
    window.loadMCPConfigIntoSettings = async (name) => {
      try {
        const mcpList = document.getElementById("mcp-configs-list");
        const originalHTML2 = mcpList.innerHTML;
        mcpList.innerHTML = `
                        <div class="text-center py-10">
                            <i class="fas fa-spinner fa-spin text-green-600 text-4xl mb-4"></i>
                            <p class="text-base font-semibold text-gray-700">Loading configuration...</p>
                            <p class="text-sm text-gray-500 mt-2">${name}</p>
                        </div>
                    `;
        const response = await fetch(`/api/mcp-configs/${name}/load`, { method: "POST" });
        if (response.ok) {
          const result = await response.json();
          const newConfig = result.config;
          setConfig(newConfig);
          setLoadedMCPConfigName(name);
          setShowMCPConfigForm(true);
          setMCPTokenPlaceholder("(Already Configured)");
          setTimeout(() => {
            const mcpUrlInput = document.getElementById("mcp-url");
            const mcpTokenInput = document.getElementById("mcp-token");
            if (mcpUrlInput) mcpUrlInput.value = newConfig.mcp.url;
            if (mcpTokenInput) mcpTokenInput.value = "";
          }, 50);
          await loadConfig();
          await loadMCPConfigs();
          const successDiv = document.createElement("div");
          successDiv.className = "fixed top-6 right-6 bg-green-600 text-white px-6 py-4 rounded-xl shadow-2xl z-50 animate-bounce";
          successDiv.innerHTML = `
                            <div class="flex items-center gap-3">
                                <i class="fas fa-check-circle text-2xl"></i>
                                <div>
                                    <p class="font-bold text-base">Configuration Loaded!</p>
                                    <p class="text-sm opacity-90">${name}</p>
                                </div>
                            </div>
                        `;
          document.body.appendChild(successDiv);
          setTimeout(() => {
            successDiv.style.animation = "none";
            successDiv.style.opacity = "0";
            successDiv.style.transition = "opacity 0.3s";
            setTimeout(() => successDiv.remove(), 300);
          }, 2500);
        } else {
          mcpList.innerHTML = originalHTML2;
          const result = await response.json();
          alert(`Failed to load configuration: ${result.detail}`);
        }
      } catch (error) {
        alert(`Error loading configuration: ${error.message}`);
        await loadMCPConfigs();
      }
    };
    window.deleteMCPConfig = async (name) => {
      const confirmed = confirm(`⚠️ Delete MCP Configuration

Are you sure you want to delete '${name}'?

This action cannot be undone.`);
      if (!confirmed) return;
      try {
        const response = await fetch(`/api/mcp-configs/${name}`, { method: "DELETE" });
        if (response.ok) {
          await loadMCPConfigs();
          const successDiv = document.createElement("div");
          successDiv.className = "fixed top-6 right-6 bg-red-600 text-white px-6 py-4 rounded-xl shadow-2xl z-50";
          successDiv.innerHTML = `
                            <div class="flex items-center gap-3">
                                <i class="fas fa-trash-alt text-2xl"></i>
                                <div>
                                    <p class="font-bold text-base">Configuration Deleted</p>
                                    <p class="text-sm opacity-90">${name}</p>
                                </div>
                            </div>
                        `;
          document.body.appendChild(successDiv);
          setTimeout(() => {
            successDiv.style.opacity = "0";
            successDiv.style.transition = "opacity 0.3s";
            setTimeout(() => successDiv.remove(), 300);
          }, 2500);
        } else {
          const error = await response.json();
          alert(`Failed to delete: ${error.detail}`);
        }
      } catch (error) {
        alert(`Error: ${error.message}`);
      }
    };
    window.testMCPConfig = async (name) => {
      const mcpList = document.getElementById("mcp-configs-list");
      const originalHTML2 = mcpList.innerHTML;
      try {
        const testingDiv = document.createElement("div");
        testingDiv.className = "fixed top-6 right-6 bg-blue-600 text-white px-6 py-4 rounded-xl shadow-2xl z-50";
        testingDiv.innerHTML = `
                        <div class="flex items-center gap-3">
                            <i class="fas fa-spinner fa-spin text-2xl"></i>
                            <div>
                                <p class="font-bold text-base">Testing Connection...</p>
                                <p class="text-sm opacity-90">${name}</p>
                            </div>
                        </div>
                    `;
        document.body.appendChild(testingDiv);
        const response = await fetch(`/api/mcp-configs/${name}/test`, { method: "POST" });
        const result = await response.json();
        testingDiv.remove();
        const resultDiv = document.createElement("div");
        let bgColor = "bg-green-600";
        let icon = "fa-check-circle";
        if (result.status === "error") {
          bgColor = "bg-red-600";
          icon = "fa-times-circle";
        } else if (result.status === "warning") {
          bgColor = "bg-yellow-600";
          icon = "fa-exclamation-triangle";
        }
        resultDiv.className = `fixed top-6 right-6 ${bgColor} text-white px-6 py-4 rounded-xl shadow-2xl z-50`;
        resultDiv.innerHTML = `
                        <div class="flex items-center gap-3">
                            <i class="fas ${icon} text-2xl"></i>
                            <div>
                                <p class="font-bold text-base">${result.status === "success" ? "Connection Successful!" : result.status === "warning" ? "Connection Warning" : "Connection Failed"}</p>
                                <p class="text-sm opacity-90">${result.message}</p>
                            </div>
                        </div>
                    `;
        document.body.appendChild(resultDiv);
        setTimeout(() => {
          resultDiv.style.opacity = "0";
          resultDiv.style.transition = "opacity 0.3s";
          setTimeout(() => resultDiv.remove(), 300);
        }, 4e3);
      } catch (error) {
        const errorDiv = document.createElement("div");
        errorDiv.className = "fixed top-6 right-6 bg-red-600 text-white px-6 py-4 rounded-xl shadow-2xl z-50";
        errorDiv.innerHTML = `
                        <div class="flex items-center gap-3">
                            <i class="fas fa-times-circle text-2xl"></i>
                            <div>
                                <p class="font-bold text-base">Test Failed</p>
                                <p class="text-sm opacity-90">${error.message}</p>
                            </div>
                        </div>
                    `;
        document.body.appendChild(errorDiv);
        setTimeout(() => {
          errorDiv.style.opacity = "0";
          errorDiv.style.transition = "opacity 0.3s";
          setTimeout(() => errorDiv.remove(), 300);
        }, 4e3);
      }
    };
    const saveSettings = async (settings) => {
      try {
        const response = await fetch("/api/config", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(settings)
        });
        if (response.ok) {
          alert("Settings saved successfully!");
          closeSettings();
          await loadConfig();
        } else {
          const error = await response.json();
          alert(`Failed to save settings: ${error.detail || "Unknown error"}`);
        }
      } catch (error) {
        alert(`Error: ${error.message}`);
      }
    };
    const renderSecurityAccessSettings = () => {
      var _a2, _b2;
      if (!config) {
        return null;
      }
      if (activeSettingsTab === "connections") {
        return null;
      }
      const securityConfig2 = config.security || {};
      const currentUser = (authStatus == null ? void 0 : authStatus.user) || null;
      const availableMCPAssignments = Array.from(/* @__PURE__ */ new Set([
        ...Object.keys(savedMCPConfigs || {}),
        ...Object.keys(config.saved_mcp_configs || {})
      ])).sort();
      const tokenScopeOptions = SECURITY_TOKEN_SCOPE_OPTIONS[securityTokenComposer.token_type] || [];
      const oidcConfig = securityConfig2.oidc || {};
      const oidcImplemented = (oidcStatus == null ? void 0 : oidcStatus.implemented) !== false;
      const oidcScopesValue = Array.isArray(oidcConfig.scopes) && oidcConfig.scopes.length ? oidcConfig.scopes.join(", ") : "openid, profile, email";
      const showOidcPanel = securityConfig2.auth_provider === "oidc" || !!(oidcStatus == null ? void 0 : oidcStatus.configured);
      const openAuthEnableInfoModal = (options = {}) => {
        setPendingAuthEnableReview(!!options.requestEnable);
        setIsAuthEnableInfoModalOpen(true);
      };
      const handleAuthEnableToggle = () => {
        if (securityConfig2.auth_enabled) {
          setConfig((current) => ({
            ...current,
            security: {
              ...(current == null ? void 0 : current.security) || {},
              auth_enabled: false
            }
          }));
          handleSettingsChange();
          return;
        }
        if (authEnableGateActive) {
          openAuthEnableInfoModal({ requestEnable: true });
          return;
        }
        setConfig((current) => ({
          ...current,
          security: {
            ...(current == null ? void 0 : current.security) || {},
            auth_enabled: true
          }
        }));
        handleSettingsChange();
      };
      const updateOidcConfig = (field, value) => {
        setConfig((current) => ({
          ...current,
          security: {
            ...(current == null ? void 0 : current.security) || {},
            oidc: {
              ...(current == null ? void 0 : current.security) && current.security.oidc || {},
              [field]: value
            }
          }
        }));
        handleSettingsChange();
      };
      return /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("div", { className: `rounded-lg p-6 border-2 ${isDarkTheme ? "bg-gray-800 border-indigo-700" : "bg-gradient-to-r from-purple-50 to-indigo-50 border-purple-200"}` }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between mb-5" }, /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("h3", { className: "text-lg font-semibold text-gray-900 mb-2" }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-user-shield mr-2 text-indigo-600" }), "Security & Access"), /* @__PURE__ */ React.createElement("p", { className: "text-sm text-gray-600" }, activeSettingsTab === "users" ? "Manage local users, role assignments, and default MCP connections." : "Configure optional auth, external surfaces, and token-based access for the validated REST and MCP endpoints.")), /* @__PURE__ */ React.createElement("div", { className: `rounded-lg border px-4 py-3 text-xs ${isDarkTheme ? "bg-gray-900 border-gray-700 text-gray-300" : "bg-white border-gray-200 text-gray-600"}` }, /* @__PURE__ */ React.createElement("div", { className: "font-semibold text-gray-900" }, "Control state"), /* @__PURE__ */ React.createElement("div", { className: "mt-1" }, "Auth: ", securityConfig2.auth_enabled ? "enabled" : "demo mode"), /* @__PURE__ */ React.createElement("div", null, "External API: ", securityConfig2.external_api_enabled ? "enabled" : "disabled"), /* @__PURE__ */ React.createElement("div", null, "Inbound MCP: ", securityConfig2.external_mcp_enabled ? "enabled" : "disabled"))), activeSettingsTab === "access" && /* @__PURE__ */ React.createElement("div", { className: "grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-4 mb-6" }, /* @__PURE__ */ React.createElement("div", { className: `rounded-lg border p-4 ${isDarkTheme ? "bg-gray-900 border-gray-700" : "bg-white border-gray-200"}` }, /* @__PURE__ */ React.createElement("div", { className: "text-xs uppercase tracking-[0.2em] text-gray-500" }, "Mode"), /* @__PURE__ */ React.createElement("div", { className: "mt-2 text-xl font-bold text-gray-900" }, securityConfig2.auth_enabled ? "Secured" : "Demo"), /* @__PURE__ */ React.createElement("div", { className: "mt-1 text-xs text-gray-500" }, securityConfig2.auth_enabled ? "Signed-in access enforced" : "No login required")), /* @__PURE__ */ React.createElement("div", { className: `rounded-lg border p-4 ${isDarkTheme ? "bg-gray-900 border-gray-700" : "bg-white border-gray-200"}` }, /* @__PURE__ */ React.createElement("div", { className: "text-xs uppercase tracking-[0.2em] text-gray-500" }, "Current Session"), /* @__PURE__ */ React.createElement("div", { className: "mt-2 text-xl font-bold text-gray-900" }, (authStatus == null ? void 0 : authStatus.authenticated) ? (currentUser == null ? void 0 : currentUser.username) || "Authenticated" : "Anonymous"), /* @__PURE__ */ React.createElement("div", { className: "mt-1 text-xs text-gray-500" }, (authStatus == null ? void 0 : authStatus.authenticated) ? `${(currentUser == null ? void 0 : currentUser.role) || "unknown"} access` : "No active local session")), /* @__PURE__ */ React.createElement("div", { className: `rounded-lg border p-4 ${isDarkTheme ? "bg-gray-900 border-gray-700" : "bg-white border-gray-200"}` }, /* @__PURE__ */ React.createElement("div", { className: "text-xs uppercase tracking-[0.2em] text-gray-500" }, "Users"), /* @__PURE__ */ React.createElement("div", { className: "mt-2 text-xl font-bold text-gray-900" }, securityUsers.length), /* @__PURE__ */ React.createElement("div", { className: "mt-1 text-xs text-gray-500" }, "Local identities in `security.db`")), /* @__PURE__ */ React.createElement("div", { className: `rounded-lg border p-4 ${isDarkTheme ? "bg-gray-900 border-gray-700" : "bg-white border-gray-200"}` }, /* @__PURE__ */ React.createElement("div", { className: "text-xs uppercase tracking-[0.2em] text-gray-500" }, "Tokens"), /* @__PURE__ */ React.createElement("div", { className: "mt-2 text-xl font-bold text-gray-900" }, securityTokens.length), /* @__PURE__ */ React.createElement("div", { className: "mt-1 text-xs text-gray-500" }, "Scoped external consumer credentials"))), activeSettingsTab === "access" && /* @__PURE__ */ React.createElement("div", { className: `rounded-xl border p-5 ${isDarkTheme ? "bg-gray-900 border-gray-700" : "bg-white border-gray-200"}` }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-col gap-2 md:flex-row md:items-start md:justify-between mb-4" }, /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("h4", { className: "text-base font-semibold text-gray-900" }, "Install-wide Security Controls"), /* @__PURE__ */ React.createElement("p", { className: "text-xs text-gray-500 mt-1" }, "These fields save through the main settings action at the bottom of the modal.")), /* @__PURE__ */ React.createElement("div", { className: `rounded-lg px-3 py-2 text-xs ${isDarkTheme ? "bg-gray-950 border border-gray-700 text-gray-300" : "bg-gray-50 border border-gray-200 text-gray-600"}` }, "Session timeout: ", securityConfig2.session_timeout_minutes || 480, " min")), /* @__PURE__ */ React.createElement("div", { className: "grid gap-4 xl:grid-cols-2" }, /* @__PURE__ */ React.createElement("div", { className: `flex items-start justify-between gap-4 rounded-lg border px-4 py-3 ${isDarkTheme ? "bg-gray-950 border-gray-700" : "bg-gray-50 border-gray-200"}` }, /* @__PURE__ */ React.createElement("div", { className: "min-w-0" }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-wrap items-center gap-2" }, /* @__PURE__ */ React.createElement("div", { className: "text-sm font-semibold text-gray-900" }, "Enable Authentication"), /* @__PURE__ */ React.createElement(
        "button",
        {
          type: "button",
          "data-testid": "settings-auth-enable-info-button",
          onClick: () => openAuthEnableInfoModal({ requestEnable: false }),
          className: `inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-[11px] font-medium ${isDarkTheme ? "bg-gray-900 border-gray-700 text-sky-100 hover:bg-gray-800" : "bg-white border-gray-300 text-sky-700 hover:bg-sky-50"}`
        },
        /* @__PURE__ */ React.createElement("i", { className: "fas fa-circle-info", "aria-hidden": "true" }),
        /* @__PURE__ */ React.createElement("span", null, "Info")
      )), /* @__PURE__ */ React.createElement("div", { className: "mt-1 text-xs text-gray-500" }, "Require login before normal application use."), authEnableGateActive && /* @__PURE__ */ React.createElement("div", { className: `mt-2 text-[11px] ${isDarkTheme ? "text-amber-200" : "text-amber-700"}` }, "Review the authentication guide before enabling this control.")), /* @__PURE__ */ React.createElement(
        "button",
        {
          type: "button",
          "data-testid": "settings-auth-enable-toggle",
          "aria-pressed": !!securityConfig2.auth_enabled,
          "aria-label": securityConfig2.auth_enabled ? "Disable authentication" : authEnableGateActive ? "Review the authentication guide before enabling authentication" : "Enable authentication",
          onClick: handleAuthEnableToggle,
          className: `mt-1 inline-flex h-6 w-6 flex-shrink-0 items-center justify-center rounded border transition ${securityConfig2.auth_enabled ? "bg-indigo-600 border-indigo-600 text-white hover:bg-indigo-700" : authEnableGateActive ? isDarkTheme ? "bg-gray-800 border-gray-600 text-gray-400 hover:bg-gray-700" : "bg-gray-200 border-gray-300 text-gray-400 hover:bg-gray-300" : isDarkTheme ? "bg-gray-950 border-gray-500 text-transparent hover:border-indigo-400" : "bg-white border-gray-300 text-transparent hover:border-indigo-400"}`
        },
        securityConfig2.auth_enabled ? /* @__PURE__ */ React.createElement("i", { className: "fas fa-check text-[11px]", "aria-hidden": "true" }) : authEnableGateActive ? /* @__PURE__ */ React.createElement("i", { className: "fas fa-lock text-[11px]", "aria-hidden": "true" }) : /* @__PURE__ */ React.createElement("span", { className: "h-2 w-2 rounded-sm bg-transparent", "aria-hidden": "true" })
      )), /* @__PURE__ */ React.createElement("label", { className: `flex items-start justify-between gap-4 rounded-lg border px-4 py-3 ${isDarkTheme ? "bg-gray-950 border-gray-700" : "bg-gray-50 border-gray-200"}` }, /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("div", { className: "text-sm font-semibold text-gray-900" }, "Require Reset On First Login"), /* @__PURE__ */ React.createElement("div", { className: "mt-1 text-xs text-gray-500" }, "Force the bootstrap or newly provisioned user to rotate the initial password.")), /* @__PURE__ */ React.createElement(
        "input",
        {
          type: "checkbox",
          checked: !!securityConfig2.require_password_reset_on_first_login,
          onChange: (event2) => {
            setConfig((current) => ({
              ...current,
              security: {
                ...(current == null ? void 0 : current.security) || {},
                require_password_reset_on_first_login: event2.target.checked
              }
            }));
            handleSettingsChange();
          },
          className: "mt-1 h-4 w-4"
        }
      )), /* @__PURE__ */ React.createElement("label", { className: `flex items-start justify-between gap-4 rounded-lg border px-4 py-3 ${isDarkTheme ? "bg-gray-950 border-gray-700" : "bg-gray-50 border-gray-200"}` }, /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("div", { className: "text-sm font-semibold text-gray-900" }, "Enable External REST API"), /* @__PURE__ */ React.createElement("div", { className: "mt-1 text-xs text-gray-500" }, "Expose the sanitized `/api/external/rag/*` surface to token-authenticated clients.")), /* @__PURE__ */ React.createElement(
        "input",
        {
          type: "checkbox",
          checked: !!securityConfig2.external_api_enabled,
          onChange: (event2) => {
            setConfig((current) => ({
              ...current,
              security: {
                ...(current == null ? void 0 : current.security) || {},
                external_api_enabled: event2.target.checked
              }
            }));
            handleSettingsChange();
          },
          className: "mt-1 h-4 w-4"
        }
      )), /* @__PURE__ */ React.createElement("label", { className: `flex items-start justify-between gap-4 rounded-lg border px-4 py-3 ${isDarkTheme ? "bg-gray-950 border-gray-700" : "bg-gray-50 border-gray-200"}` }, /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("div", { className: "text-sm font-semibold text-gray-900" }, "Enable External MCP"), /* @__PURE__ */ React.createElement("div", { className: "mt-1 text-xs text-gray-500" }, "Expose the read-only inbound MCP endpoint for scoped bearer tokens.")), /* @__PURE__ */ React.createElement(
        "input",
        {
          type: "checkbox",
          checked: !!securityConfig2.external_mcp_enabled,
          onChange: (event2) => {
            setConfig((current) => ({
              ...current,
              security: {
                ...(current == null ? void 0 : current.security) || {},
                external_mcp_enabled: event2.target.checked
              }
            }));
            handleSettingsChange();
          },
          className: "mt-1 h-4 w-4"
        }
      ))), /* @__PURE__ */ React.createElement("div", { className: "grid gap-4 md:grid-cols-3 mt-4" }, /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("label", { className: "block text-sm font-medium text-gray-700 mb-1" }, "Auth Provider"), /* @__PURE__ */ React.createElement(
        "select",
        {
          value: securityConfig2.auth_provider || "local_password",
          onChange: (event2) => {
            const nextProvider = event2.target.value;
            setConfig((current) => {
              var _a3;
              return {
                ...current,
                security: {
                  ...(current == null ? void 0 : current.security) || {},
                  auth_provider: nextProvider,
                  auth_enabled: !!((_a3 = current == null ? void 0 : current.security) == null ? void 0 : _a3.auth_enabled)
                }
              };
            });
            handleSettingsChange();
          },
          className: "w-full px-3 py-2 border border-gray-300 rounded-md"
        },
        /* @__PURE__ */ React.createElement("option", { value: "local_password" }, "local_password"),
        /* @__PURE__ */ React.createElement("option", { value: "oidc" }, "oidc")
      ), /* @__PURE__ */ React.createElement("div", { className: "mt-1 text-xs text-gray-500" }, authProviderSelection === "oidc" ? oidcCanEnableAuth ? "OIDC sign-in is implemented and ready to enable with the current provider settings." : "OIDC sign-in is implemented. Add issuer URL, client ID, and client secret before enabling auth." : "Local password auth is implemented today. Switch to OIDC when your provider settings are ready.")), /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("label", { className: "block text-sm font-medium text-gray-700 mb-1" }, "Session Timeout (minutes)"), /* @__PURE__ */ React.createElement(
        "input",
        {
          type: "number",
          min: "15",
          value: (_a2 = securityConfig2.session_timeout_minutes) != null ? _a2 : 480,
          onChange: (event2) => {
            const nextValue = Number.parseInt(event2.target.value, 10);
            setConfig((current) => ({
              ...current,
              security: {
                ...(current == null ? void 0 : current.security) || {},
                session_timeout_minutes: Number.isFinite(nextValue) ? nextValue : 0
              }
            }));
            handleSettingsChange();
          },
          className: "w-full px-3 py-2 border border-gray-300 rounded-md"
        }
      )), /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("label", { className: "block text-sm font-medium text-gray-700 mb-1" }, "Minimum Password Length"), /* @__PURE__ */ React.createElement(
        "input",
        {
          type: "number",
          min: "8",
          value: (_b2 = securityConfig2.password_min_length) != null ? _b2 : 12,
          onChange: (event2) => {
            const nextValue = Number.parseInt(event2.target.value, 10);
            setConfig((current) => ({
              ...current,
              security: {
                ...(current == null ? void 0 : current.security) || {},
                password_min_length: Number.isFinite(nextValue) ? nextValue : 0
              }
            }));
            handleSettingsChange();
          },
          className: "w-full px-3 py-2 border border-gray-300 rounded-md"
        }
      ))), showOidcPanel && /* @__PURE__ */ React.createElement("div", { className: `mt-4 rounded-xl border p-4 ${isDarkTheme ? "bg-gray-950 border-gray-700" : "bg-gray-50 border-gray-200"}` }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between mb-4" }, /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("h5", { className: "text-sm font-semibold text-gray-900" }, "OIDC Provider"), /* @__PURE__ */ React.createElement("p", { className: "mt-1 text-xs text-gray-500" }, "Configure the live OIDC flow here. The backend can enable OIDC as soon as issuer URL, client ID, and client secret are set.")), /* @__PURE__ */ React.createElement("div", { className: "flex flex-wrap gap-2 text-[11px] font-medium" }, /* @__PURE__ */ React.createElement("span", { className: `inline-flex items-center rounded-full px-2 py-1 ${(oidcStatus == null ? void 0 : oidcStatus.configured) ? "bg-blue-50 text-gray-900" : "bg-gray-100 text-gray-700"}` }, (oidcStatus == null ? void 0 : oidcStatus.configured) ? "configured" : "not configured"), /* @__PURE__ */ React.createElement("span", { className: `inline-flex items-center rounded-full px-2 py-1 ${oidcCanEnableAuth ? "bg-emerald-50 text-gray-900" : "bg-amber-50 text-gray-900"}` }, oidcCanEnableAuth ? "ready to enable auth" : "setup required"), /* @__PURE__ */ React.createElement("span", { className: `inline-flex items-center rounded-full px-2 py-1 ${oidcImplemented ? "bg-indigo-50 text-gray-900" : "bg-gray-100 text-gray-700"}` }, oidcImplemented ? "provider flow live" : "provider unavailable"))), /* @__PURE__ */ React.createElement("div", { className: "grid gap-3 md:grid-cols-2 xl:grid-cols-3" }, /* @__PURE__ */ React.createElement("div", { className: "xl:col-span-2" }, /* @__PURE__ */ React.createElement("label", { className: "block text-sm font-medium text-gray-700 mb-1" }, "Issuer URL"), /* @__PURE__ */ React.createElement(
        "input",
        {
          type: "text",
          value: oidcConfig.issuer_url || "",
          onChange: (event2) => updateOidcConfig("issuer_url", event2.target.value),
          className: "w-full px-3 py-2 border border-gray-300 rounded-md",
          placeholder: "https://idp.example.com/application/o/dt4sms/"
        }
      )), /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("label", { className: "block text-sm font-medium text-gray-700 mb-1" }, "Audience"), /* @__PURE__ */ React.createElement(
        "input",
        {
          type: "text",
          value: oidcConfig.audience || "",
          onChange: (event2) => updateOidcConfig("audience", event2.target.value),
          className: "w-full px-3 py-2 border border-gray-300 rounded-md",
          placeholder: "optional audience"
        }
      )), /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("label", { className: "block text-sm font-medium text-gray-700 mb-1" }, "Client ID"), /* @__PURE__ */ React.createElement(
        "input",
        {
          type: "text",
          value: oidcConfig.client_id || "",
          onChange: (event2) => updateOidcConfig("client_id", event2.target.value),
          className: "w-full px-3 py-2 border border-gray-300 rounded-md",
          placeholder: "dt4sms-client"
        }
      )), /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("label", { className: "block text-sm font-medium text-gray-700 mb-1" }, "Client Secret"), /* @__PURE__ */ React.createElement(
        "input",
        {
          type: "password",
          value: oidcConfig.client_secret || "",
          onChange: (event2) => updateOidcConfig("client_secret", event2.target.value),
          className: "w-full px-3 py-2 border border-gray-300 rounded-md",
          placeholder: (oidcStatus == null ? void 0 : oidcStatus.client_secret_configured) ? "*** keeps the current secret" : "OIDC client secret"
        }
      )), /* @__PURE__ */ React.createElement("div", { className: "md:col-span-2 xl:col-span-1" }, /* @__PURE__ */ React.createElement("label", { className: "block text-sm font-medium text-gray-700 mb-1" }, "Scopes"), /* @__PURE__ */ React.createElement(
        "input",
        {
          type: "text",
          value: oidcScopesValue,
          onChange: (event2) => updateOidcConfig("scopes", event2.target.value.split(",").map((value) => value.trim()).filter(Boolean)),
          className: "w-full px-3 py-2 border border-gray-300 rounded-md",
          placeholder: "openid, profile, email"
        }
      )), /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("label", { className: "block text-sm font-medium text-gray-700 mb-1" }, "Username Claim"), /* @__PURE__ */ React.createElement(
        "input",
        {
          type: "text",
          value: oidcConfig.username_claim || "preferred_username",
          onChange: (event2) => updateOidcConfig("username_claim", event2.target.value),
          className: "w-full px-3 py-2 border border-gray-300 rounded-md"
        }
      )), /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("label", { className: "block text-sm font-medium text-gray-700 mb-1" }, "Email Claim"), /* @__PURE__ */ React.createElement(
        "input",
        {
          type: "text",
          value: oidcConfig.email_claim || "email",
          onChange: (event2) => updateOidcConfig("email_claim", event2.target.value),
          className: "w-full px-3 py-2 border border-gray-300 rounded-md"
        }
      )), /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("label", { className: "block text-sm font-medium text-gray-700 mb-1" }, "Role Claim"), /* @__PURE__ */ React.createElement(
        "input",
        {
          type: "text",
          value: oidcConfig.role_claim || "roles",
          onChange: (event2) => updateOidcConfig("role_claim", event2.target.value),
          className: "w-full px-3 py-2 border border-gray-300 rounded-md"
        }
      )), /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("label", { className: "block text-sm font-medium text-gray-700 mb-1" }, "Default Role"), /* @__PURE__ */ React.createElement(
        "select",
        {
          value: oidcConfig.default_role || "viewer",
          onChange: (event2) => updateOidcConfig("default_role", event2.target.value),
          className: "w-full px-3 py-2 border border-gray-300 rounded-md"
        },
        SECURITY_ROLE_OPTIONS.map((role) => /* @__PURE__ */ React.createElement("option", { key: `oidc-default-role-${role}`, value: role }, role))
      )), /* @__PURE__ */ React.createElement("div", { className: "md:col-span-2 xl:col-span-2" }, /* @__PURE__ */ React.createElement("label", { className: "block text-sm font-medium text-gray-700 mb-1" }, "MCP Assignment Claim"), /* @__PURE__ */ React.createElement(
        "input",
        {
          type: "text",
          value: oidcConfig.mcp_assignment_claim || "",
          onChange: (event2) => updateOidcConfig("mcp_assignment_claim", event2.target.value),
          className: "w-full px-3 py-2 border border-gray-300 rounded-md",
          placeholder: "optional claim for default MCP assignment"
        }
      )))), /* @__PURE__ */ React.createElement("div", { className: `mt-4 rounded-lg px-4 py-3 text-xs ${isDarkTheme ? "bg-gray-950 border border-gray-700 text-gray-300" : "bg-gray-50 border border-gray-200 text-gray-600"}` }, authProviderSelection === "oidc" ? oidcCanEnableAuth ? "OIDC sign-in is ready. Save the configuration, enable auth, and validate role or MCP claim mapping from the live sign-in flow." : "OIDC sign-in is implemented, but issuer URL, client ID, and client secret must be set before auth can be enabled." : securityConfig2.auth_enabled ? "When auth is enabled, complete the bootstrap admin sign-in and password rotation before handing the app to other users." : "Demo mode stays available until you save an auth-enabled configuration. Users and tokens can still be prepared ahead of time.")), activeSettingsTab === "users" && /* @__PURE__ */ React.createElement("div", { className: `mt-6 rounded-xl border p-5 ${isDarkTheme ? "bg-gray-900 border-gray-700" : "bg-white border-gray-200"}` }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-col gap-3 md:flex-row md:items-start md:justify-between mb-4" }, /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("h4", { className: "text-base font-semibold text-gray-900" }, "Local Users"), /* @__PURE__ */ React.createElement("p", { className: "text-xs text-gray-500 mt-1" }, "Create, disable, assign MCP connections, and force password reset state for local users.")), /* @__PURE__ */ React.createElement(
        "button",
        {
          type: "button",
          onClick: () => {
            setIsSecurityUserComposerOpen((current) => !current);
            if (isSecurityUserComposerOpen) {
              resetSecurityUserComposer();
            }
          },
          className: "px-4 py-2 bg-indigo-600 hover:bg-indigo-700 text-white rounded-lg text-sm font-medium"
        },
        /* @__PURE__ */ React.createElement("i", { className: `fas ${isSecurityUserComposerOpen ? "fa-minus-circle" : "fa-user-plus"} mr-2` }),
        isSecurityUserComposerOpen ? "Close User Form" : "Create User"
      )), isSecurityUserComposerOpen && /* @__PURE__ */ React.createElement("div", { className: `rounded-xl border p-4 mb-4 ${isDarkTheme ? "bg-gray-950 border-gray-700" : "bg-gray-50 border-gray-200"}` }, /* @__PURE__ */ React.createElement("div", { className: "grid gap-3 md:grid-cols-2 xl:grid-cols-3" }, /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("label", { className: "block text-sm font-medium text-gray-700 mb-1" }, "Username"), /* @__PURE__ */ React.createElement(
        "input",
        {
          type: "text",
          value: securityUserComposer.username,
          onChange: (event2) => setSecurityUserComposer((current) => ({ ...current, username: event2.target.value })),
          className: "w-full px-3 py-2 border border-gray-300 rounded-md",
          placeholder: "analyst1"
        }
      )), /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("label", { className: "block text-sm font-medium text-gray-700 mb-1" }, "Initial Password"), /* @__PURE__ */ React.createElement(
        "input",
        {
          type: "password",
          value: securityUserComposer.password,
          onChange: (event2) => setSecurityUserComposer((current) => ({ ...current, password: event2.target.value })),
          className: "w-full px-3 py-2 border border-gray-300 rounded-md",
          placeholder: `At least ${securityConfig2.password_min_length || 12} characters`
        }
      )), /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("label", { className: "block text-sm font-medium text-gray-700 mb-1" }, "Role"), /* @__PURE__ */ React.createElement(
        "select",
        {
          value: securityUserComposer.role,
          onChange: (event2) => setSecurityUserComposer((current) => ({ ...current, role: event2.target.value })),
          className: "w-full px-3 py-2 border border-gray-300 rounded-md"
        },
        SECURITY_ROLE_OPTIONS.map((role) => /* @__PURE__ */ React.createElement("option", { key: `security-role-create-${role}`, value: role }, role))
      )), /* @__PURE__ */ React.createElement("div", { className: "md:col-span-2 xl:col-span-1" }, /* @__PURE__ */ React.createElement("label", { className: "block text-sm font-medium text-gray-700 mb-1" }, "Assigned MCP Connection"), /* @__PURE__ */ React.createElement(
        "select",
        {
          value: securityUserComposer.mcp_config_name,
          onChange: (event2) => setSecurityUserComposer((current) => ({ ...current, mcp_config_name: event2.target.value })),
          className: "w-full px-3 py-2 border border-gray-300 rounded-md"
        },
        /* @__PURE__ */ React.createElement("option", { value: "" }, "No default assignment"),
        availableMCPAssignments.map((name) => /* @__PURE__ */ React.createElement("option", { key: `security-user-create-mcp-${name}`, value: name }, name))
      )), /* @__PURE__ */ React.createElement("label", { className: `flex items-center gap-3 rounded-lg border px-3 py-2 ${isDarkTheme ? "bg-gray-900 border-gray-700" : "bg-white border-gray-200"}` }, /* @__PURE__ */ React.createElement(
        "input",
        {
          type: "checkbox",
          checked: !!securityUserComposer.is_enabled,
          onChange: (event2) => setSecurityUserComposer((current) => ({ ...current, is_enabled: event2.target.checked })),
          className: "h-4 w-4"
        }
      ), /* @__PURE__ */ React.createElement("span", { className: "text-sm text-gray-700" }, "User enabled")), /* @__PURE__ */ React.createElement("label", { className: `flex items-center gap-3 rounded-lg border px-3 py-2 ${isDarkTheme ? "bg-gray-900 border-gray-700" : "bg-white border-gray-200"}` }, /* @__PURE__ */ React.createElement(
        "input",
        {
          type: "checkbox",
          checked: !!securityUserComposer.require_password_reset,
          onChange: (event2) => setSecurityUserComposer((current) => ({ ...current, require_password_reset: event2.target.checked })),
          className: "h-4 w-4"
        }
      ), /* @__PURE__ */ React.createElement("span", { className: "text-sm text-gray-700" }, "Force reset on first login"))), /* @__PURE__ */ React.createElement("div", { className: "mt-4 flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between" }, /* @__PURE__ */ React.createElement("div", { className: "text-xs text-gray-500" }, "Create the user first, then refine assignments and reset state below if needed."), /* @__PURE__ */ React.createElement("div", { className: "flex gap-2" }, /* @__PURE__ */ React.createElement(
        "button",
        {
          type: "button",
          onClick: () => {
            resetSecurityUserComposer();
            setIsSecurityUserComposerOpen(false);
          },
          className: `px-4 py-2 rounded-lg text-sm font-medium border ${isDarkTheme ? "bg-gray-900 border-gray-700 text-gray-100 hover:bg-gray-800" : "bg-white border-gray-300 text-gray-700 hover:bg-gray-50"}`
        },
        "Cancel"
      ), /* @__PURE__ */ React.createElement(
        "button",
        {
          type: "button",
          onClick: createSecurityUser,
          className: "px-4 py-2 bg-indigo-600 hover:bg-indigo-700 text-white rounded-lg text-sm font-medium"
        },
        /* @__PURE__ */ React.createElement("i", { className: "fas fa-user-plus mr-2" }),
        "Create User"
      )))), securityUsersState.loading ? /* @__PURE__ */ React.createElement("div", { className: "flex items-center justify-center py-10 text-sm text-gray-500" }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-spinner fa-spin mr-2" }), "Loading local users...") : securityUsersState.error ? /* @__PURE__ */ React.createElement("div", { className: `rounded-lg border px-4 py-4 text-sm ${isDarkTheme ? "bg-gray-950 border-gray-700 text-red-300" : "bg-red-50 border-red-200 text-red-700"}` }, securityUsersState.error) : securityUsers.length === 0 ? /* @__PURE__ */ React.createElement("div", { className: `rounded-lg border px-4 py-8 text-center text-sm ${isDarkTheme ? "bg-gray-950 border-gray-700 text-gray-400" : "bg-gray-50 border-gray-200 text-gray-600"}` }, "No local users have been created yet.") : /* @__PURE__ */ React.createElement("div", { className: "space-y-3 max-h-[30rem] overflow-y-auto pr-1" }, securityUsers.map((user) => {
        const draft = securityUserDrafts[user.id] || buildSecurityUserDraft(user);
        const isCurrentUser = currentUser && Number(currentUser.id) === Number(user.id);
        return /* @__PURE__ */ React.createElement("div", { key: `security-user-${user.id}`, className: `rounded-xl border p-4 ${isDarkTheme ? "bg-gray-950 border-gray-700" : "bg-gray-50 border-gray-200"}` }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between" }, /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("div", { className: "flex flex-wrap items-center gap-2" }, /* @__PURE__ */ React.createElement("h5", { className: "text-base font-semibold text-gray-900" }, user.username), /* @__PURE__ */ React.createElement("span", { className: `inline-flex items-center rounded-full px-2 py-0.5 text-[11px] font-semibold ${user.is_enabled ? "bg-emerald-50 text-gray-900" : "bg-amber-50 text-gray-900"}` }, user.is_enabled ? "enabled" : "disabled"), draft.require_password_reset && /* @__PURE__ */ React.createElement("span", { className: "inline-flex items-center rounded-full px-2 py-0.5 text-[11px] font-semibold bg-amber-50 text-gray-900" }, "reset required"), isCurrentUser && /* @__PURE__ */ React.createElement("span", { className: "inline-flex items-center rounded-full px-2 py-0.5 text-[11px] font-semibold bg-gray-100 text-gray-900" }, "current session")), /* @__PURE__ */ React.createElement("div", { className: "mt-2 text-xs text-gray-500" }, "Role: ", user.role || "unknown", " · ", "MCP assignment: ", user.mcp_config_name || "none", " · ", "Last login: ", user.last_login_at ? new Date(user.last_login_at).toLocaleString() : "never")), /* @__PURE__ */ React.createElement(
          "button",
          {
            type: "button",
            onClick: () => deleteSecurityUser(user),
            className: "px-3 py-2 bg-red-600 hover:bg-red-700 text-white rounded-lg text-sm font-medium"
          },
          /* @__PURE__ */ React.createElement("i", { className: "fas fa-trash-alt mr-2" }),
          "Delete"
        )), /* @__PURE__ */ React.createElement("div", { className: "grid gap-3 md:grid-cols-2 mt-4" }, /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("label", { className: "block text-sm font-medium text-gray-700 mb-1" }, "Role"), /* @__PURE__ */ React.createElement(
          "select",
          {
            value: draft.role,
            onChange: (event2) => updateSecurityUserDraft(user.id, "role", event2.target.value),
            className: "w-full px-3 py-2 border border-gray-300 rounded-md"
          },
          SECURITY_ROLE_OPTIONS.map((role) => /* @__PURE__ */ React.createElement("option", { key: `security-role-edit-${user.id}-${role}`, value: role }, role))
        )), /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("label", { className: "block text-sm font-medium text-gray-700 mb-1" }, "Assigned MCP Connection"), /* @__PURE__ */ React.createElement(
          "select",
          {
            value: draft.mcp_config_name,
            onChange: (event2) => updateSecurityUserDraft(user.id, "mcp_config_name", event2.target.value),
            className: "w-full px-3 py-2 border border-gray-300 rounded-md"
          },
          /* @__PURE__ */ React.createElement("option", { value: "" }, "No default assignment"),
          availableMCPAssignments.map((name) => /* @__PURE__ */ React.createElement("option", { key: `security-user-mcp-${user.id}-${name}`, value: name }, name))
        )), /* @__PURE__ */ React.createElement("label", { className: `flex items-center gap-3 rounded-lg border px-3 py-2 ${isDarkTheme ? "bg-gray-900 border-gray-700" : "bg-white border-gray-200"}` }, /* @__PURE__ */ React.createElement(
          "input",
          {
            type: "checkbox",
            checked: !!draft.is_enabled,
            onChange: (event2) => updateSecurityUserDraft(user.id, "is_enabled", event2.target.checked),
            className: "h-4 w-4"
          }
        ), /* @__PURE__ */ React.createElement("span", { className: "text-sm text-gray-700" }, "User enabled")), /* @__PURE__ */ React.createElement("label", { className: `flex items-center gap-3 rounded-lg border px-3 py-2 ${isDarkTheme ? "bg-gray-900 border-gray-700" : "bg-white border-gray-200"}` }, /* @__PURE__ */ React.createElement(
          "input",
          {
            type: "checkbox",
            checked: !!draft.require_password_reset,
            onChange: (event2) => updateSecurityUserDraft(user.id, "require_password_reset", event2.target.checked),
            className: "h-4 w-4"
          }
        ), /* @__PURE__ */ React.createElement("span", { className: "text-sm text-gray-700" }, "Force password reset on next login")), /* @__PURE__ */ React.createElement("div", { className: "md:col-span-2" }, /* @__PURE__ */ React.createElement("label", { className: "block text-sm font-medium text-gray-700 mb-1" }, "Set New Password (optional)"), /* @__PURE__ */ React.createElement(
          "input",
          {
            type: "password",
            value: draft.new_password,
            onChange: (event2) => updateSecurityUserDraft(user.id, "new_password", event2.target.value),
            className: "w-full px-3 py-2 border border-gray-300 rounded-md",
            placeholder: `Leave blank to keep the current password. Minimum ${securityConfig2.password_min_length || 12} characters.`
          }
        ))), /* @__PURE__ */ React.createElement("div", { className: "mt-4 flex justify-end" }, /* @__PURE__ */ React.createElement(
          "button",
          {
            type: "button",
            onClick: () => saveSecurityUser(user),
            className: "px-4 py-2 bg-indigo-600 hover:bg-indigo-700 text-white rounded-lg text-sm font-medium"
          },
          /* @__PURE__ */ React.createElement("i", { className: "fas fa-save mr-2" }),
          "Save Changes"
        )));
      }))), activeSettingsTab === "access" && /* @__PURE__ */ React.createElement("div", { className: `mt-6 rounded-xl border p-5 ${isDarkTheme ? "bg-gray-900 border-gray-700" : "bg-white border-gray-200"}` }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-col gap-3 md:flex-row md:items-start md:justify-between mb-4" }, /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("h4", { className: "text-base font-semibold text-gray-900" }, "Access Tokens"), /* @__PURE__ */ React.createElement("p", { className: "text-xs text-gray-500 mt-1" }, "Issue, review, and revoke scoped external REST and inbound MCP credentials.")), /* @__PURE__ */ React.createElement(
        "button",
        {
          type: "button",
          onClick: () => {
            setIsSecurityTokenComposerOpen((current) => !current);
            if (isSecurityTokenComposerOpen) {
              resetSecurityTokenComposer();
            }
          },
          className: "px-4 py-2 bg-indigo-600 hover:bg-indigo-700 text-white rounded-lg text-sm font-medium"
        },
        /* @__PURE__ */ React.createElement("i", { className: `fas ${isSecurityTokenComposerOpen ? "fa-minus-circle" : "fa-key"} mr-2` }),
        isSecurityTokenComposerOpen ? "Close Token Form" : "Create Token"
      )), securityTokenReveal && /* @__PURE__ */ React.createElement("div", { className: `rounded-xl border p-4 mb-4 ${isDarkTheme ? "bg-gray-950 border-gray-700" : "bg-amber-50 border-gray-200"}` }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-col gap-3 md:flex-row md:items-start md:justify-between" }, /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("div", { className: "text-sm font-semibold text-gray-900" }, "One-time token reveal"), /* @__PURE__ */ React.createElement("div", { className: "mt-1 text-xs text-gray-500" }, "Copy this token now. DT4SMS will not return the plaintext token again after you leave this panel.")), /* @__PURE__ */ React.createElement("div", { className: "flex gap-2" }, /* @__PURE__ */ React.createElement(
        "button",
        {
          type: "button",
          onClick: copySecurityTokenReveal,
          className: "px-3 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg text-sm font-medium"
        },
        /* @__PURE__ */ React.createElement("i", { className: "fas fa-copy mr-2" }),
        "Copy"
      ), /* @__PURE__ */ React.createElement(
        "button",
        {
          type: "button",
          onClick: () => setSecurityTokenReveal(null),
          className: `px-3 py-2 rounded-lg text-sm font-medium border ${isDarkTheme ? "bg-gray-900 border-gray-700 text-gray-100 hover:bg-gray-800" : "bg-white border-gray-300 text-gray-700 hover:bg-gray-50"}`
        },
        "Hide"
      ))), /* @__PURE__ */ React.createElement(
        "textarea",
        {
          readOnly: true,
          rows: 3,
          value: securityTokenReveal.access_token,
          className: "w-full mt-3 px-3 py-2 border border-gray-300 rounded-md font-mono text-xs"
        }
      )), isSecurityTokenComposerOpen && /* @__PURE__ */ React.createElement("div", { className: `rounded-xl border p-4 mb-4 ${isDarkTheme ? "bg-gray-950 border-gray-700" : "bg-gray-50 border-gray-200"}` }, /* @__PURE__ */ React.createElement("div", { className: "grid gap-3 md:grid-cols-2 xl:grid-cols-4" }, /* @__PURE__ */ React.createElement("div", { className: "xl:col-span-2" }, /* @__PURE__ */ React.createElement("label", { className: "block text-sm font-medium text-gray-700 mb-1" }, "Token Name"), /* @__PURE__ */ React.createElement(
        "input",
        {
          type: "text",
          value: securityTokenComposer.name,
          onChange: (event2) => setSecurityTokenComposer((current) => ({ ...current, name: event2.target.value })),
          className: "w-full px-3 py-2 border border-gray-300 rounded-md",
          placeholder: "External RAG Reader"
        }
      )), /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("label", { className: "block text-sm font-medium text-gray-700 mb-1" }, "Token Type"), /* @__PURE__ */ React.createElement(
        "select",
        {
          value: securityTokenComposer.token_type,
          onChange: (event2) => resetSecurityTokenComposer(event2.target.value),
          className: "w-full px-3 py-2 border border-gray-300 rounded-md"
        },
        /* @__PURE__ */ React.createElement("option", { value: "external_api" }, "external_api"),
        /* @__PURE__ */ React.createElement("option", { value: "inbound_mcp" }, "inbound_mcp")
      )), /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("label", { className: "block text-sm font-medium text-gray-700 mb-1" }, "Expires In (days)"), /* @__PURE__ */ React.createElement(
        "input",
        {
          type: "number",
          min: "1",
          value: securityTokenComposer.expires_in_days,
          onChange: (event2) => setSecurityTokenComposer((current) => ({ ...current, expires_in_days: event2.target.value })),
          className: "w-full px-3 py-2 border border-gray-300 rounded-md"
        }
      )), /* @__PURE__ */ React.createElement("div", { className: "md:col-span-2" }, /* @__PURE__ */ React.createElement("label", { className: "block text-sm font-medium text-gray-700 mb-1" }, "Owner (optional)"), /* @__PURE__ */ React.createElement(
        "select",
        {
          value: securityTokenComposer.owner_user_id,
          onChange: (event2) => setSecurityTokenComposer((current) => ({ ...current, owner_user_id: event2.target.value })),
          className: "w-full px-3 py-2 border border-gray-300 rounded-md"
        },
        /* @__PURE__ */ React.createElement("option", { value: "" }, "Service-managed token"),
        securityUsers.map((user) => /* @__PURE__ */ React.createElement("option", { key: `token-owner-${user.id}`, value: user.id }, user.username))
      )), /* @__PURE__ */ React.createElement("div", { className: "md:col-span-2 xl:col-span-2" }, /* @__PURE__ */ React.createElement("div", { className: "block text-sm font-medium text-gray-700 mb-1" }, "Scopes"), /* @__PURE__ */ React.createElement("div", { className: "grid gap-2" }, tokenScopeOptions.map((scopeOption) => {
        const isChecked = (securityTokenComposer.scopes || []).includes(scopeOption.value);
        return /* @__PURE__ */ React.createElement("label", { key: `token-scope-${scopeOption.value}`, className: `flex items-start gap-3 rounded-lg border px-3 py-2 ${isDarkTheme ? "bg-gray-900 border-gray-700" : "bg-white border-gray-200"}` }, /* @__PURE__ */ React.createElement(
          "input",
          {
            type: "checkbox",
            checked: isChecked,
            onChange: () => toggleSecurityTokenComposerScope(scopeOption.value),
            className: "mt-1 h-4 w-4"
          }
        ), /* @__PURE__ */ React.createElement("span", null, /* @__PURE__ */ React.createElement("span", { className: "block text-sm font-medium text-gray-800" }, scopeOption.label), /* @__PURE__ */ React.createElement("span", { className: "block text-xs text-gray-500" }, scopeOption.description)));
      })))), /* @__PURE__ */ React.createElement("div", { className: "mt-4 flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between" }, /* @__PURE__ */ React.createElement("div", { className: "text-xs text-gray-500" }, "Token type and scopes define which external surface can use the credential."), /* @__PURE__ */ React.createElement("div", { className: "flex gap-2" }, /* @__PURE__ */ React.createElement(
        "button",
        {
          type: "button",
          onClick: () => {
            resetSecurityTokenComposer();
            setIsSecurityTokenComposerOpen(false);
          },
          className: `px-4 py-2 rounded-lg text-sm font-medium border ${isDarkTheme ? "bg-gray-900 border-gray-700 text-gray-100 hover:bg-gray-800" : "bg-white border-gray-300 text-gray-700 hover:bg-gray-50"}`
        },
        "Cancel"
      ), /* @__PURE__ */ React.createElement(
        "button",
        {
          type: "button",
          onClick: createSecurityToken,
          className: "px-4 py-2 bg-indigo-600 hover:bg-indigo-700 text-white rounded-lg text-sm font-medium"
        },
        /* @__PURE__ */ React.createElement("i", { className: "fas fa-key mr-2" }),
        "Issue Token"
      )))), securityTokensState.loading ? /* @__PURE__ */ React.createElement("div", { className: "flex items-center justify-center py-10 text-sm text-gray-500" }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-spinner fa-spin mr-2" }), "Loading token inventory...") : securityTokensState.error ? /* @__PURE__ */ React.createElement("div", { className: `rounded-lg border px-4 py-4 text-sm ${isDarkTheme ? "bg-gray-950 border-gray-700 text-red-300" : "bg-red-50 border-red-200 text-red-700"}` }, securityTokensState.error) : securityTokens.length === 0 ? /* @__PURE__ */ React.createElement("div", { className: `rounded-lg border px-4 py-8 text-center text-sm ${isDarkTheme ? "bg-gray-950 border-gray-700 text-gray-400" : "bg-gray-50 border-gray-200 text-gray-600"}` }, "No scoped access tokens have been issued yet.") : /* @__PURE__ */ React.createElement("div", { className: "space-y-3 max-h-[30rem] overflow-y-auto pr-1" }, securityTokens.map((token) => {
        const isRevoked = !!token.revoked_at;
        return /* @__PURE__ */ React.createElement("div", { key: `security-token-${token.id}`, className: `rounded-xl border p-4 ${isDarkTheme ? "bg-gray-950 border-gray-700" : "bg-gray-50 border-gray-200"}` }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between" }, /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("div", { className: "flex flex-wrap items-center gap-2" }, /* @__PURE__ */ React.createElement("h5", { className: "text-base font-semibold text-gray-900" }, token.name), /* @__PURE__ */ React.createElement("span", { className: "inline-flex items-center rounded-full px-2 py-0.5 text-[11px] font-semibold bg-gray-100 text-gray-900" }, token.token_type), isRevoked && /* @__PURE__ */ React.createElement("span", { className: "inline-flex items-center rounded-full px-2 py-0.5 text-[11px] font-semibold bg-amber-50 text-gray-900" }, "revoked")), /* @__PURE__ */ React.createElement("div", { className: "mt-2 text-xs text-gray-500" }, "Prefix: ", token.token_prefix || "hidden", " · ", "Owner: ", token.owner_username || "service-managed", " · ", "Created by: ", token.created_by_username || "system")), /* @__PURE__ */ React.createElement("div", { className: "flex flex-wrap gap-2" }, !isRevoked && /* @__PURE__ */ React.createElement(
          "button",
          {
            type: "button",
            onClick: () => revokeSecurityToken(token),
            className: "px-3 py-2 bg-red-600 hover:bg-red-700 text-white rounded-lg text-sm font-medium"
          },
          /* @__PURE__ */ React.createElement("i", { className: "fas fa-ban mr-2" }),
          "Revoke"
        ), /* @__PURE__ */ React.createElement(
          "button",
          {
            type: "button",
            onClick: () => removeSecurityToken(token),
            className: `px-3 py-2 rounded-lg text-sm font-medium border ${isDarkTheme ? "bg-gray-900 border-gray-700 text-gray-100 hover:bg-gray-800" : "bg-white border-gray-300 text-gray-700 hover:bg-gray-50"}`
          },
          /* @__PURE__ */ React.createElement("i", { className: "fas fa-trash-alt mr-2" }),
          "Remove"
        ))), /* @__PURE__ */ React.createElement("div", { className: "mt-3 flex flex-wrap gap-2" }, (token.scopes || []).map((scope) => /* @__PURE__ */ React.createElement("span", { key: `token-scope-chip-${token.id}-${scope}`, className: `inline-flex items-center rounded-full px-2 py-0.5 text-[11px] font-medium ${isDarkTheme ? "bg-gray-900 border border-gray-700 text-gray-200" : "bg-white border border-gray-300 text-gray-700"}` }, scope))), /* @__PURE__ */ React.createElement("div", { className: "grid gap-2 mt-4 sm:grid-cols-2 xl:grid-cols-4 text-xs text-gray-500" }, /* @__PURE__ */ React.createElement("div", null, "Created: ", token.created_at ? new Date(token.created_at).toLocaleString() : "Unknown"), /* @__PURE__ */ React.createElement("div", null, "Expires: ", token.expires_at ? new Date(token.expires_at).toLocaleString() : "No expiry"), /* @__PURE__ */ React.createElement("div", null, "Last used: ", token.last_used_at ? new Date(token.last_used_at).toLocaleString() : "Never"), /* @__PURE__ */ React.createElement("div", null, "Use count: ", token.use_count || 0)));
      })))));
    };
    const openConnectionModal = (event2) => {
      const target = event2 == null ? void 0 : event2.currentTarget;
      const modalWidth = 320;
      const viewportPadding = 12;
      if (target && typeof target.getBoundingClientRect === "function") {
        const rect = target.getBoundingClientRect();
        const preferredLeft = rect.left + rect.width / 2 - modalWidth / 2;
        const maxLeft = Math.max(viewportPadding, window.innerWidth - modalWidth - viewportPadding);
        const clampedLeft = Math.min(Math.max(preferredLeft, viewportPadding), maxLeft);
        const anchorCenterX = rect.left + rect.width / 2;
        const pointerOffset = anchorCenterX - clampedLeft - 8;
        const pointerLeft = Math.min(Math.max(pointerOffset, 16), modalWidth - 24);
        setConnectionModalPosition({
          top: rect.bottom + 10,
          left: clampedLeft,
          pointerLeft
        });
      }
      loadConnectionInfo();
      setIsConnectionModalOpen(true);
    };
    const isSummaryArtifact = (reportName) => {
      if (!reportName || typeof reportName !== "string") return false;
      return reportName.startsWith("v2_ai_summary_") || reportName.startsWith("ai_summary_");
    };
    const isInfographicArtifact = (reportName) => {
      if (!reportName || typeof reportName !== "string") return false;
      return reportName.startsWith("summary_infographic_");
    };
    const getReportSessionTimestamp = (report) => {
      if (typeof (report == null ? void 0 : report.session_timestamp) === "string" && report.session_timestamp) {
        return report.session_timestamp;
      }
      const reportName = typeof (report == null ? void 0 : report.name) === "string" ? report.name : "";
      if (!reportName) {
        return null;
      }
      const infographicMatch = reportName.match(/^summary_infographic_([0-9]{8}_[0-9]{6})(?:_[0-9]{8}_[0-9]{6})?\.[^.]+$/);
      if (infographicMatch) {
        return infographicMatch[1];
      }
      const genericMatch = reportName.match(/([0-9]{8}_[0-9]{6})/);
      return genericMatch ? genericMatch[1] : null;
    };
    const buildReportImageSrc = (content) => {
      if ((content == null ? void 0 : content.type) !== "image") {
        return "";
      }
      if (typeof (content == null ? void 0 : content.content_base64) === "string" && content.content_base64) {
        return `data:${(content == null ? void 0 : content.mime_type) || "image/png"};base64,${content.content_base64}`;
      }
      if (typeof (content == null ? void 0 : content.image_url) === "string") {
        return content.image_url;
      }
      return "";
    };
    const groupReportsByHierarchy = (reports2) => {
      const sessions = {};
      reports2.forEach((report) => {
        const timestamp = getReportSessionTimestamp(report);
        if (timestamp) {
          if (!sessions[timestamp]) {
            sessions[timestamp] = {
              timestamp,
              displayName: formatSessionName(timestamp),
              reports: [],
              hasSummary: false,
              date: parseTimestamp(timestamp)
            };
          }
          sessions[timestamp].reports.push(report);
          if (isSummaryArtifact(report.name)) {
            sessions[timestamp].hasSummary = true;
          }
        }
      });
      const hierarchy = {};
      const today = /* @__PURE__ */ new Date();
      const currentYear = today.getFullYear();
      const currentMonth = today.getMonth();
      const currentDay = today.getDate();
      Object.values(sessions).forEach((session) => {
        const date = session.date;
        const year = date.getFullYear();
        const month = date.getMonth();
        const day = date.getDate();
        const showYear = year !== currentYear;
        const showMonth = showYear || month !== currentMonth;
        const yearKey = `year_${year}`;
        const monthKey = `${yearKey}_month_${month}`;
        const dayKey = `${monthKey}_day_${day}`;
        if (!hierarchy[yearKey]) {
          hierarchy[yearKey] = {
            type: "year",
            year,
            display: year.toString(),
            visible: showYear,
            months: {}
          };
        }
        if (!hierarchy[yearKey].months[monthKey]) {
          hierarchy[yearKey].months[monthKey] = {
            type: "month",
            month,
            display: date.toLocaleDateString("en-US", { month: "long", year: "numeric" }),
            visible: showMonth,
            days: {}
          };
        }
        if (!hierarchy[yearKey].months[monthKey].days[dayKey]) {
          const isToday = year === currentYear && month === currentMonth && day === currentDay;
          const dayName = isToday ? "Today" : date.toLocaleDateString("en-US", { weekday: "long", month: "long", day: "numeric" });
          hierarchy[yearKey].months[monthKey].days[dayKey] = {
            type: "day",
            day,
            display: dayName,
            isToday,
            sessions: []
          };
        }
        hierarchy[yearKey].months[monthKey].days[dayKey].sessions.push(session);
      });
      return hierarchy;
    };
    const parseTimestamp = (timestamp) => {
      const dateStr = timestamp.substring(0, 8);
      const timeStr = timestamp.substring(9);
      const year = parseInt(dateStr.substring(0, 4));
      const month = parseInt(dateStr.substring(4, 6)) - 1;
      const day = parseInt(dateStr.substring(6, 8));
      const hour = parseInt(timeStr.substring(0, 2));
      const minute = parseInt(timeStr.substring(2, 4));
      return new Date(year, month, day, hour, minute);
    };
    const groupReportsBySession = (reports2) => {
      const sessions = {};
      reports2.forEach((report) => {
        const timestamp = getReportSessionTimestamp(report);
        if (timestamp) {
          if (!sessions[timestamp]) {
            sessions[timestamp] = {
              timestamp,
              displayName: formatSessionName(timestamp),
              reports: [],
              hasSummary: false
            };
          }
          sessions[timestamp].reports.push(report);
          if (isSummaryArtifact(report.name)) {
            sessions[timestamp].hasSummary = true;
          }
        } else {
          const sessionKey = "other";
          if (!sessions[sessionKey]) {
            sessions[sessionKey] = {
              timestamp: sessionKey,
              displayName: "Other Reports",
              reports: [],
              hasSummary: false
            };
          }
          sessions[sessionKey].reports.push(report);
        }
      });
      const sortedSessions = Object.values(sessions).sort((a, b) => {
        if (a.timestamp === "other") return 1;
        if (b.timestamp === "other") return -1;
        return b.timestamp.localeCompare(a.timestamp);
      });
      return sortedSessions;
    };
    const formatSessionName = (timestamp) => {
      const dateStr = timestamp.substring(0, 8);
      const timeStr = timestamp.substring(9);
      const year = dateStr.substring(0, 4);
      const month = dateStr.substring(4, 6);
      const day = dateStr.substring(6, 8);
      const hour = timeStr.substring(0, 2);
      const minute = timeStr.substring(2, 4);
      const date = new Date(year, month - 1, day, hour, minute);
      return date.toLocaleDateString("en-US", {
        month: "short",
        day: "numeric",
        year: "numeric",
        hour: "2-digit",
        minute: "2-digit"
      });
    };
    const formatSessionTime = (timestamp) => {
      const timeStr = timestamp.substring(9);
      const dateStr = timestamp.substring(0, 8);
      const year = dateStr.substring(0, 4);
      const month = dateStr.substring(4, 6);
      const day = dateStr.substring(6, 8);
      const hour = timeStr.substring(0, 2);
      const minute = timeStr.substring(2, 4);
      const date = new Date(year, month - 1, day, hour, minute);
      return date.toLocaleTimeString("en-US", {
        hour: "2-digit",
        minute: "2-digit"
      });
    };
    const toggleSession = (timestamp) => {
      setExpandedSessions((prev) => ({
        ...prev,
        [timestamp]: !prev[timestamp]
      }));
    };
    const toggleYear = (yearKey) => {
      setExpandedYears((prev) => ({
        ...prev,
        [yearKey]: !prev[yearKey]
      }));
    };
    const toggleMonth = (monthKey) => {
      setExpandedMonths((prev) => ({
        ...prev,
        [monthKey]: !prev[monthKey]
      }));
    };
    const toggleDay = (dayKey) => {
      setExpandedDays((prev) => ({
        ...prev,
        [dayKey]: !prev[dayKey]
      }));
    };
    useEffect(() => {
      var _a2;
      if ((isChatOpen || isChatTab) && chatMessages.length > 0) {
        (_a2 = chatEndRef.current) == null ? void 0 : _a2.scrollIntoView({ behavior: "smooth", block: "end" });
      }
    }, [chatMessages, isChatOpen, isChatTab]);
    const openChatSurface = () => {
      if (isChatFullscreen) {
        setIsChatOpen(false);
        setWorkspaceTab("chat");
        return;
      }
      setIsChatOpen(true);
    };
    const enterChatFullscreen = () => {
      setIsChatOpen(false);
      setIsChatFullscreen(true);
      setWorkspaceTab("chat");
    };
    const exitChatFullscreen = ({ reopenModal = false } = {}) => {
      const nextTab = lastPrimaryWorkspaceTab && lastPrimaryWorkspaceTab !== "chat" ? lastPrimaryWorkspaceTab : "mission";
      setIsChatFullscreen(false);
      if (workspaceTab === "chat") {
        setWorkspaceTab(nextTab);
      }
      setIsChatOpen(reopenModal);
    };
    const closeChatSurface = () => {
      if (isChatFullscreen) {
        exitChatFullscreen({ reopenModal: false });
        return;
      }
      setIsChatOpen(false);
    };
    useEffect(() => {
      if (isChatSettingsOpen && !chatSettings) {
        loadChatSettings();
      }
    }, [isChatSettingsOpen]);
    const loadChatSettings = async () => {
      try {
        const response = await fetch("/api/chat/settings");
        const data = await response.json();
        setChatSettings(data);
      } catch (error) {
        console.error("Error loading chat settings:", error);
      }
    };
    const updateSetting = async (key, value) => {
      const updatedSettings = { ...chatSettings, [key]: value };
      setChatSettings(updatedSettings);
      try {
        await fetch("/api/chat/settings", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ [key]: value })
        });
      } catch (error) {
        console.error("Error updating setting:", error);
      }
    };
    const resetChatSettings = async () => {
      try {
        const response = await fetch("/api/chat/settings/reset", {
          method: "POST"
        });
        const data = await response.json();
        setChatSettings(data.settings);
      } catch (error) {
        console.error("Error resetting settings:", error);
      }
    };
    const sendChatMessage = async (overrideMessage = null, options = {}) => {
      if (isTyping) return;
      const freshContext = Boolean(options == null ? void 0 : options.freshContext);
      const investigationMode = typeof (options == null ? void 0 : options.investigationMode) === "string" && options.investigationMode ? options.investigationMode : null;
      const chatSessionIdOverride = typeof (options == null ? void 0 : options.chatSessionIdOverride) === "string" && options.chatSessionIdOverride ? options.chatSessionIdOverride : chatSessionId;
      const resolvedOverride = typeof overrideMessage === "string" ? overrideMessage : "";
      const userMessage = (resolvedOverride || chatInput || "").trim();
      if (!userMessage) return;
      setChatInput("");
      if (freshContext) {
        setServerConversationHistory(null);
      }
      setIsTyping(true);
      setChatMessages((prev) => [...prev, {
        id: Date.now(),
        type: "user",
        content: userMessage,
        timestamp: (/* @__PURE__ */ new Date()).toISOString()
      }]);
      try {
        const historyToSend = freshContext ? [] : serverConversationHistory || chatMessages.slice(-10).map((msg) => ({
          type: msg.type,
          content: msg.content
        }));
        const response = await fetch("/chat/stream", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            message: userMessage,
            history: historyToSend,
            chat_session_id: chatSessionIdOverride,
            investigation_mode: investigationMode
          })
        });
        const reader = response.body.getReader();
        const decoder = new TextDecoder();
        let buffer = "";
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          buffer += decoder.decode(value, { stream: true });
          const lines = buffer.split("\n");
          buffer = lines.pop();
          for (const line of lines) {
            if (line.startsWith("data: ")) {
              const data = JSON.parse(line.slice(6));
              if (data.type === "status") {
                setChatStatus(data.action);
              } else if (data.type === "response") {
                const result = data.data;
                setChatStatus("");
                if (result.error) {
                  setChatMessages((prev) => [...prev, {
                    id: Date.now() + 1,
                    type: "error",
                    content: result.error,
                    timestamp: (/* @__PURE__ */ new Date()).toISOString()
                  }]);
                } else {
                  const messages2 = [];
                  if (result.discovery_age_warning) {
                    messages2.push({
                      id: Date.now() + 0.5,
                      type: "warning",
                      content: result.discovery_age_warning,
                      timestamp: (/* @__PURE__ */ new Date()).toISOString()
                    });
                  }
                  const mergedFollowOnActions = mergeAssistantFollowOnActions(
                    result.response,
                    result.follow_on_actions
                  );
                  messages2.push({
                    id: Date.now() + 1,
                    type: "assistant",
                    content: result.response,
                    timestamp: (/* @__PURE__ */ new Date()).toISOString(),
                    mcp_data: result.mcp_data,
                    tool_used: result.tool_used,
                    spl_query: extractAssistantSplQuery(result),
                    visualization_spec: result.visualization_spec,
                    spl_in_text: result.spl_in_text,
                    capability_usage: Array.isArray(result.capability_usage) ? result.capability_usage : [],
                    has_follow_on: mergedFollowOnActions.length > 0,
                    follow_on_actions: mergedFollowOnActions,
                    status_timeline: result.status_timeline,
                    iterations: result.iterations,
                    execution_time: result.execution_time
                  });
                  if (result.conversation_history) {
                    setServerConversationHistory(result.conversation_history);
                  }
                  if (result.chat_session_id) {
                    setChatSessionId(result.chat_session_id);
                  } else if (chatSessionIdOverride !== chatSessionId) {
                    setChatSessionId(chatSessionIdOverride);
                  }
                  setChatMessages((prev) => [...prev, ...messages2]);
                }
              } else if (data.type === "error") {
                setChatStatus("");
                setChatMessages((prev) => [...prev, {
                  id: Date.now() + 1,
                  type: "error",
                  content: data.error,
                  timestamp: (/* @__PURE__ */ new Date()).toISOString()
                }]);
              }
            }
          }
        }
      } catch (error) {
        console.error("Chat error:", error);
        setChatStatus("");
        setChatMessages((prev) => [...prev, {
          id: Date.now() + 1,
          type: "error",
          content: `Failed to send message: ${error.message}`,
          timestamp: (/* @__PURE__ */ new Date()).toISOString()
        }]);
      } finally {
        setIsTyping(false);
        setChatStatus("");
        setTimeout(() => {
          var _a2;
          return (_a2 = chatInputRef.current) == null ? void 0 : _a2.focus();
        }, 100);
      }
    };
    const launchChatInvestigation = async (prompt, options = {}) => {
      const resolvedPrompt = typeof prompt === "string" ? prompt.trim() : "";
      if (!resolvedPrompt || isTyping) return;
      const freshContext = (options == null ? void 0 : options.freshContext) !== false;
      const nextChatSessionId = freshContext ? generateChatSessionId() : chatSessionId;
      if (freshContext) {
        clearPersistedChatState();
        setChatMessages([]);
        setChatStatus("");
        setServerConversationHistory(null);
        setChatSessionId(nextChatSessionId);
      }
      setChatInput("");
      openChatSurface();
      if ((options == null ? void 0 : options.closeSummary) !== false) {
        closeSummaryModal();
      }
      await sendChatMessage(resolvedPrompt, {
        freshContext,
        chatSessionIdOverride: nextChatSessionId,
        investigationMode: (options == null ? void 0 : options.investigationMode) || null
      });
    };
    const useSuggestedQuery = (query) => {
      setChatInput(query);
      if (chatInputRef.current) {
        setTimeout(() => chatInputRef.current.focus(), 0);
      }
    };
    const sendSuggestedQuery = async (query) => {
      await sendChatMessage(query);
    };
    const loadReport = async (filename) => {
      try {
        const response = await fetch(`/reports/${encodeURIComponent(filename)}`);
        const result = await response.json();
        if (!response.ok) {
          throw new Error((result == null ? void 0 : result.detail) || (result == null ? void 0 : result.error) || `Failed to load report (${response.status})`);
        }
        if (result.error) {
          addMessage("error", { message: result.error });
          return;
        }
        setSelectedReport(null);
        setReportContent(null);
        setIsReportFullViewOpen(false);
        setTimeout(() => {
          setSelectedReport(filename);
          setReportContent(result);
        }, 10);
      } catch (error) {
        console.error("Error loading report:", error);
        addMessage("error", { message: `Failed to load report: ${error.message}` });
      }
    };
    const openArtifactInWorkspace = async (filename) => {
      if (!filename) {
        throw new Error("No artifact filename was returned.");
      }
      setWorkspaceTab("artifacts");
      await Promise.all([loadReports(), loadV2Artifacts()]);
      await loadReport(filename);
    };
    const closeSummaryActionDialog = () => {
      setSummaryActionDialog(null);
    };
    const cancelPendingSummaryRequest = () => {
      if (summaryRequestAbortRef.current) {
        summaryRequestAbortRef.current.abort();
        summaryRequestAbortRef.current = null;
      }
    };
    const getSummaryProgressSnapshot = async (sessionId) => {
      if (!sessionId) {
        return normalizeSummaryProgressPayload();
      }
      const response = await fetch(`/summarize-progress/${sessionId}`);
      const result = await response.json();
      if (!response.ok) {
        throw new Error((result == null ? void 0 : result.detail) || (result == null ? void 0 : result.error) || `Failed to inspect summary progress (${response.status})`);
      }
      return normalizeSummaryProgressPayload(result);
    };
    const executeSummaryOpen = async (sessionId, options = {}) => {
      if (!sessionId) {
        return;
      }
      const initialProgress = (options == null ? void 0 : options.initialProgress) && typeof options.initialProgress === "object" ? normalizeSummaryProgressPayload(options.initialProgress) : null;
      closeSummaryActionDialog();
      cancelPendingSummaryRequest();
      setActiveTab("summary");
      setQueryFilter("all");
      setQueryFocus(null);
      setTaskFilter("all");
      setRiskFocus(null);
      setShowAllUnknownData(false);
      setSummaryInfographicCapability({
        status: "idle",
        available: false,
        checkedSession: null,
        checkedProvider: null,
        canGenerate: false,
        hasExisting: false,
        existingArtifact: null,
        reason: ""
      });
      setIsGeneratingSummaryInfographic(false);
      setIsAbortingSummary(false);
      setCurrentSessionId(sessionId);
      if (isSummaryFullscreen) {
        setIsSummaryModalOpen(false);
        setWorkspaceTab("summary-workspace");
      } else {
        setIsSummaryModalOpen(true);
      }
      setIsLoadingSummary(true);
      setSummaryData(null);
      setSummaryProgress(initialProgress || {
        stage: "loading",
        progress: 10,
        message: "Loading discovery reports..."
      });
      const requestController = new AbortController();
      summaryRequestAbortRef.current = requestController;
      try {
        const response = await fetch("/summarize-session", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ timestamp: sessionId }),
          signal: requestController.signal
        });
        let result = null;
        const contentType = response.headers.get("content-type") || "";
        if (contentType.includes("application/json")) {
          result = await response.json();
        } else {
          const rawText = await response.text();
          try {
            result = JSON.parse(rawText);
          } catch {
            throw new Error(`Summarization failed (${response.status}): ${rawText.slice(0, 200) || "Non-JSON server response"}`);
          }
        }
        if (!response.ok) {
          const requestError = new Error((result == null ? void 0 : result.error) || (result == null ? void 0 : result.detail) || `Summarization failed (${response.status})`);
          requestError.status = response.status;
          throw requestError;
        }
        if (result == null ? void 0 : result.error) {
          addMessage("error", { message: result.error });
          closeSummaryModal();
          return;
        }
        setSummaryData(result);
      } catch (error) {
        if ((error == null ? void 0 : error.name) === "AbortError") {
          return;
        }
        if (Number(error == null ? void 0 : error.status) === 409) {
          addMessage("warning", { message: error.message || "Summary generation was aborted." });
          closeSummaryModal();
          return;
        }
        console.error("Error loading summary:", error);
        addMessage("error", { message: `Failed to generate summary: ${error.message}` });
        closeSummaryModal();
      } finally {
        if (summaryRequestAbortRef.current === requestController) {
          summaryRequestAbortRef.current = null;
        }
        setIsLoadingSummary(false);
      }
    };
    const confirmSummaryAction = async () => {
      const pendingSessionId = (summaryActionDialog == null ? void 0 : summaryActionDialog.sessionId) || null;
      const initialProgress = (summaryActionDialog == null ? void 0 : summaryActionDialog.initialProgress) && typeof summaryActionDialog.initialProgress === "object" ? summaryActionDialog.initialProgress : null;
      closeSummaryActionDialog();
      if (pendingSessionId) {
        await executeSummaryOpen(pendingSessionId, { initialProgress });
      }
    };
    const abortSummaryRun = async () => {
      if (!currentSessionId || isAbortingSummary || !isSummaryWorkerActive) {
        return;
      }
      setIsAbortingSummary(true);
      try {
        const response = await fetch("/abort-summary", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ timestamp: currentSessionId })
        });
        let result = null;
        const contentType = response.headers.get("content-type") || "";
        if (contentType.includes("application/json")) {
          result = await response.json();
        } else {
          result = {};
        }
        if (!response.ok) {
          throw new Error((result == null ? void 0 : result.detail) || (result == null ? void 0 : result.error) || `Summary abort failed (${response.status})`);
        }
        if (result == null ? void 0 : result.error) {
          throw new Error(result.error);
        }
        cancelPendingSummaryRequest();
        setSummaryProgress(normalizeSummaryProgressPayload(result == null ? void 0 : result.progress, {
          stage: "aborted",
          progress: summaryProgress.progress,
          message: "Summary aborted by operator."
        }));
        addMessage("warning", { message: "Summary aborted by operator." });
        closeSummaryModal();
      } catch (error) {
        console.error("Error aborting summary:", error);
        addMessage("error", { message: `Failed to abort summary: ${error.message}` });
      } finally {
        setIsAbortingSummary(false);
      }
    };
    const openSummaryModal = async (sessionId, options = {}) => {
      var _a2, _b2, _c2;
      const hasSummary = Boolean(options == null ? void 0 : options.hasSummary);
      let activeSummaryProgress = null;
      try {
        activeSummaryProgress = await getSummaryProgressSnapshot(sessionId);
      } catch (error) {
        console.error("Failed to inspect active summary worker state:", error);
      }
      const activeSummaryStage = String((activeSummaryProgress == null ? void 0 : activeSummaryProgress.stage) || "idle").trim().toLowerCase() || "idle";
      const activeSummaryWorkerPid = Number.isFinite(Number(activeSummaryProgress == null ? void 0 : activeSummaryProgress.worker_pid)) && Number(activeSummaryProgress == null ? void 0 : activeSummaryProgress.worker_pid) > 0 ? Number(activeSummaryProgress.worker_pid) : null;
      const hasActiveSummaryWorker = !!activeSummaryWorkerPid && !summaryTerminalStages.includes(activeSummaryStage);
      if (hasActiveSummaryWorker) {
        setSummaryActionDialog({
          sessionId,
          initialProgress: activeSummaryProgress,
          tone: "amber",
          icon: "fa-rotate-right",
          eyebrow: "Summary worker active",
          title: "Reconnect to the running summary worker?",
          summary: "DT4SMS already has a durable background summary worker running for this session. Rejoin it to keep the live stage monitor open or stay here and resume later.",
          details: [
            `${(activeSummaryProgress == null ? void 0 : activeSummaryProgress.message) || "The summary worker is still running."}`,
            `Worker PID ${activeSummaryWorkerPid} stays active even if you close the summary workspace again.`,
            "Use the loading workspace Abort Summary control if you need to stop the worker after reconnecting."
          ],
          confirmLabel: "Resume Summary",
          cancelLabel: "Stay Here"
        });
        return;
      }
      const endpointUrl = ((_b2 = (_a2 = config == null ? void 0 : config.llm) == null ? void 0 : _a2.endpoint_url) == null ? void 0 : _b2.toLowerCase()) || "";
      const credentialName2 = ((_c2 = config == null ? void 0 : config.active_credential_name) == null ? void 0 : _c2.toLowerCase()) || "";
      const isLocalLLM = endpointUrl.includes("localhost") || endpointUrl.includes("127.0.0.1") || endpointUrl.includes(":8000") || // Common vLLM port
      endpointUrl.includes(":11434") || // Common Ollama port
      credentialName2.includes("local") || credentialName2.includes("vllm") || credentialName2.includes("ollama");
      if (!hasSummary && isLocalLLM) {
        setSummaryActionDialog({
          sessionId,
          tone: "amber",
          icon: "fa-microchip",
          eyebrow: "Local model runtime",
          title: "Generate summary with the current local LLM?",
          summary: "This session does not have a saved summary yet, so DT4SMS will run the full summarization workflow against the current local model.",
          details: [
            "Expect a multi-minute runtime while the app extracts findings, generates SPL, and builds the operator summary.",
            "The summary workspace will stay live with stage-by-stage progress while generation runs.",
            "Cached View Summary paths skip this prompt because no new LLM work is required."
          ],
          confirmLabel: "Continue Summary",
          cancelLabel: "Stay Here"
        });
        return;
      }
      await executeSummaryOpen(sessionId, { initialProgress: activeSummaryProgress });
    };
    const resetSummarySurfaceState = () => {
      cancelPendingSummaryRequest();
      setIsSummaryModalOpen(false);
      setSummaryActionDialog(null);
      setSummaryData(null);
      setIsLoadingSummary(false);
      setIsAbortingSummary(false);
      setCurrentSessionId(null);
      setActiveTab("summary");
      setQueryFilter("all");
      setQueryFocus(null);
      setTaskFilter("all");
      setRiskFocus(null);
      setShowAllUnknownData(false);
      setSummaryProgress({
        stage: "idle",
        progress: 0,
        message: "Not started"
      });
      setSummaryInfographicCapability({
        status: "idle",
        available: false,
        checkedSession: null,
        checkedProvider: null,
        canGenerate: false,
        hasExisting: false,
        existingArtifact: null,
        reason: ""
      });
      setIsGeneratingSummaryInfographic(false);
    };
    const enterSummaryFullscreen = () => {
      setIsSummaryModalOpen(false);
      setIsSummaryFullscreen(true);
      setWorkspaceTab("summary-workspace");
    };
    const exitSummaryFullscreen = ({ reopenModal = false } = {}) => {
      const nextTab = lastPrimaryWorkspaceTab && lastPrimaryWorkspaceTab !== "summary-workspace" ? lastPrimaryWorkspaceTab : "mission";
      setIsSummaryFullscreen(false);
      if (workspaceTab === "summary-workspace") {
        setWorkspaceTab(nextTab);
      }
      setIsSummaryModalOpen(reopenModal);
    };
    const closeSummaryModal = () => {
      if (isSummaryFullscreen) {
        exitSummaryFullscreen({ reopenModal: false });
      }
      resetSummarySurfaceState();
    };
    const normalizeSummaryText = (value) => {
      if (typeof value !== "string") return "";
      return value.replace(/\*\*/g, "").replace(/`/g, "").replace(/\s+/g, " ").trim();
    };
    const normalizeSummarySectionTitle = (value) => {
      return normalizeSummaryText(value).replace(/^\d+[.)]\s+/, "").trim();
    };
    const escapeHtml = (value) => String(value != null ? value : "").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");
    const generateSummaryInfographic = async () => {
      if (isGeneratingSummaryInfographic || !summaryData || !currentSessionId) {
        return;
      }
      setIsGeneratingSummaryInfographic(true);
      try {
        const response = await fetch("/api/summary/generate-infographic", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            timestamp: currentSessionId,
            summary_data: summaryData
          })
        });
        const result = await response.json();
        if (!response.ok) {
          throw new Error((result == null ? void 0 : result.detail) || (result == null ? void 0 : result.error) || `Image generation failed (${response.status})`);
        }
        const artifactName = typeof (result == null ? void 0 : result.filename) === "string" ? result.filename : "";
        if (!artifactName) {
          throw new Error("Image generation completed but no saved artifact was returned.");
        }
        closeSummaryModal();
        await openArtifactInWorkspace(artifactName);
        addMessage("success", {
          message: (result == null ? void 0 : result.reused_existing) ? `Opened existing summary infographic: ${artifactName}` : `Summary infographic created: ${artifactName}`
        });
      } catch (error) {
        console.error("Failed to generate summary infographic:", error);
        addMessage("error", { message: `Failed to generate summary infographic: ${error.message}` });
      } finally {
        setIsGeneratingSummaryInfographic(false);
      }
    };
    const parseAiSummarySections = (summaryText) => {
      if (typeof summaryText !== "string" || !summaryText.trim()) {
        return [];
      }
      const sections = [];
      let currentSection = null;
      const pushSection = () => {
        if (!currentSection) {
          return;
        }
        const body = currentSection.lines.join("\n").trim();
        if (!body) {
          return;
        }
        const items = [];
        const paragraphs = [];
        let activeItemIndex = -1;
        body.split(/\r?\n/).forEach((rawLine) => {
          const line = rawLine.trim();
          if (!line) {
            activeItemIndex = -1;
            return;
          }
          const itemMatch = line.match(/^(?:[-*•]|\d+\.)\s+(.*)$/);
          if (itemMatch) {
            const normalizedItem = normalizeSummaryText(itemMatch[1]);
            if (normalizedItem) {
              items.push(normalizedItem);
              activeItemIndex = items.length - 1;
            }
            return;
          }
          const normalizedLine = normalizeSummaryText(line);
          if (!normalizedLine) {
            return;
          }
          if (activeItemIndex >= 0) {
            items[activeItemIndex] = `${items[activeItemIndex]} ${normalizedLine}`.trim();
          } else {
            paragraphs.push(normalizedLine);
          }
        });
        sections.push({
          title: currentSection.title,
          body,
          items,
          paragraphs
        });
      };
      summaryText.split(/\r?\n/).forEach((line) => {
        const headingMatch = line.match(/^##\s+(.+)$/);
        if (headingMatch) {
          pushSection();
          currentSection = {
            title: normalizeSummarySectionTitle(headingMatch[1]),
            lines: []
          };
          return;
        }
        if (!currentSection) {
          currentSection = {
            title: "Executive Summary",
            lines: []
          };
        }
        currentSection.lines.push(line);
      });
      pushSection();
      return sections;
    };
    const getSummarySection = (sections, title) => {
      const normalizedTitle = normalizeSummarySectionTitle(title).toLowerCase();
      return sections.find((section) => normalizeSummarySectionTitle(section.title).toLowerCase() === normalizedTitle) || null;
    };
    const getReadinessLabel = (score) => {
      if (typeof score !== "number") return "Control posture unavailable";
      if (score >= 85) return "Control posture strong";
      if (score >= 70) return "Control posture improving";
      if (score >= 50) return "Control posture exposed";
      return "Control posture needs intervention";
    };
    const formatVolumeCategory = (category) => {
      const value = typeof category === "string" ? category.replace(/_/g, " ") : "unknown";
      return value.charAt(0).toUpperCase() + value.slice(1);
    };
    const getUnknownItemRank = (item) => {
      var _a2;
      const volumeRanks = { very_high: 0, high: 1, medium: 2, low: 3, very_low: 4 };
      const context = item && typeof item.context === "object" ? item.context : {};
      return [
        context.has_significant_data ? 0 : 1,
        (_a2 = volumeRanks[context.volume_category]) != null ? _a2 : 5,
        String((item == null ? void 0 : item.name) || "").length
      ];
    };
    const getQueryPriorityRank = (priority) => {
      if (typeof priority !== "string") return 3;
      if (priority.startsWith("🔴")) return 0;
      if (priority.startsWith("🟠")) return 1;
      if (priority.startsWith("🟡")) return 2;
      return 3;
    };
    const getTaskPriorityRank = (priority) => {
      if (priority === "HIGH") return 0;
      if (priority === "MEDIUM") return 1;
      if (priority === "LOW") return 2;
      return 3;
    };
    const getQuerySourceLabel = (source) => {
      if (source === "ai_finding") return "AI-generated";
      if (source === "context_engine") return "Environment-based";
      if (source === "template") return "Template-based";
      return "Query";
    };
    const getRiskTaskFilterKey = (risk) => {
      const riskText = [risk == null ? void 0 : risk.domain, risk == null ? void 0 : risk.risk, risk == null ? void 0 : risk.impact, risk == null ? void 0 : risk.mitigation].filter(Boolean).join(" ").toLowerCase();
      if (riskText.includes("security") || riskText.includes("authentication") || riskText.includes("privilege")) {
        return "category:Security";
      }
      if (riskText.includes("data quality") || riskText.includes("freshness") || riskText.includes("clock skew") || riskText.includes("timestamp")) {
        return "category:Data Quality";
      }
      if (riskText.includes("ingestion") || riskText.includes("collector") || riskText.includes("pipeline") || riskText.includes("configuration")) {
        return "category:Configuration";
      }
      if (riskText.includes("performance") || riskText.includes("platform") || riskText.includes("health") || riskText.includes("availability") || riskText.includes("latency") || riskText.includes("throughput") || riskText.includes("infrastructure") || riskText.includes("application")) {
        return "category:Performance";
      }
      if (typeof (risk == null ? void 0 : risk.domain) === "string" && risk.domain.trim()) {
        return `category:${risk.domain.trim()}`;
      }
      return "open";
    };
    const getRiskQueryCategories = (risk) => {
      const riskText = [risk == null ? void 0 : risk.domain, risk == null ? void 0 : risk.risk, risk == null ? void 0 : risk.impact, risk == null ? void 0 : risk.mitigation].filter(Boolean).join(" ").toLowerCase();
      const categories = /* @__PURE__ */ new Set();
      if (riskText.includes("security") || riskText.includes("authentication") || riskText.includes("privilege")) {
        categories.add("Security & Compliance");
      }
      if (riskText.includes("data quality") || riskText.includes("freshness") || riskText.includes("clock skew") || riskText.includes("timestamp")) {
        categories.add("Data Quality");
      }
      if (riskText.includes("ingestion") || riskText.includes("collector") || riskText.includes("pipeline") || riskText.includes("configuration")) {
        categories.add("Infrastructure & Performance");
        categories.add("Data Quality");
      }
      if (riskText.includes("performance") || riskText.includes("platform") || riskText.includes("health") || riskText.includes("availability") || riskText.includes("latency") || riskText.includes("throughput") || riskText.includes("infrastructure") || riskText.includes("application")) {
        categories.add("Infrastructure & Performance");
        categories.add("Capacity Planning");
      }
      if (riskText.includes("coverage")) {
        categories.add("Data Quality");
      }
      if (categories.size === 0) {
        categories.add("Infrastructure & Performance");
      }
      return Array.from(categories);
    };
    const buildRiskInvestigationPrompt = (risk) => [
      "Help me investigate and mitigate this risk in Splunk:",
      "",
      `Risk: ${(risk == null ? void 0 : risk.risk) || ""}`,
      `Impact: ${(risk == null ? void 0 : risk.impact) || ""}`,
      `Mitigation: ${(risk == null ? void 0 : risk.mitigation) || ""}`
    ].join("\n");
    const getTaskQueryCategories = (task) => {
      switch (task == null ? void 0 : task.category) {
        case "Security":
        case "Compliance":
          return ["Security & Compliance"];
        case "Performance":
          return ["Infrastructure & Performance", "Capacity Planning"];
        case "Data Quality":
          return ["Data Quality", "Data Exploration"];
        case "Configuration":
          return ["Infrastructure & Performance", "Data Quality"];
        default:
          return [];
      }
    };
    const buildUnknownEntityValidationQueries = (item) => {
      var _a2;
      const entityType = String((item == null ? void 0 : item.type) || "").toLowerCase() === "sourcetype" ? "sourcetype" : "index";
      const entityName = String((item == null ? void 0 : item.name) || "").trim();
      if (!entityName) {
        return [];
      }
      const searchAnchor = entityType === "index" ? `index=${entityName}` : `index=* sourcetype=${entityName}`;
      const breakoutFields = entityType === "index" ? "sourcetype host" : "index host";
      const trendField = entityType === "index" ? "sourcetype" : "index";
      const entityLabel = entityType === "index" ? `index=${entityName}` : `sourcetype=${entityName}`;
      const priority = ((_a2 = item == null ? void 0 : item.context) == null ? void 0 : _a2.has_significant_data) ? "🔴 HIGH" : "🟠 MEDIUM";
      const findingReference = (item == null ? void 0 : item.question) || `Classify and validate ${entityName} before it becomes an unmanaged blind spot.`;
      const businessValue = entityType === "index" ? `Shows whether ${entityName} is an active data set, what sources feed it, and which hosts are contributing telemetry.` : `Shows where sourcetype ${entityName} is present and whether it represents a meaningful operational or security signal.`;
      return [
        {
          title: `🧭 ${entityName} Footprint by ${entityType === "index" ? "Sourcetype and Host" : "Index and Host"}`,
          description: `Establish the basic coverage and volume profile for ${entityLabel} before deciding how it should be classified.`,
          use_case: "Data Quality",
          category: "Data Quality",
          spl: `${searchAnchor} earliest=-24h | stats count by ${breakoutFields} | sort - count`,
          finding_reference: findingReference,
          execution_time: "< 30s",
          business_value: businessValue,
          priority,
          difficulty: "Beginner",
          environment_evidence: [entityLabel],
          query_source: "context_engine"
        },
        {
          title: `📈 ${entityName} Activity Trend`,
          description: `Trend ${entityLabel} over time so you can tell whether it is steady, bursty, or mostly dormant.`,
          use_case: "Data Quality",
          category: "Data Quality",
          spl: `${searchAnchor} earliest=-7d | timechart span=1h count by ${trendField} limit=10 useother=true`,
          finding_reference: findingReference,
          execution_time: "< 30s",
          business_value: "Shows whether the entity is stable enough to warrant monitoring coverage or onboarding work.",
          priority,
          difficulty: "Intermediate",
          environment_evidence: [entityLabel],
          query_source: "context_engine"
        },
        {
          title: `🔎 ${entityName} Sample Event Triage`,
          description: `Pull a small sample so an operator can quickly inspect what this entity actually contains.`,
          use_case: "Data Quality",
          category: "Data Quality",
          spl: `${searchAnchor} earliest=-24h | head 20 | table _time index sourcetype host source`,
          finding_reference: findingReference,
          execution_time: "< 15s",
          business_value: "Provides fast human inspection of representative events before creating dashboards or detections.",
          priority,
          difficulty: "Beginner",
          environment_evidence: [entityLabel],
          query_source: "context_engine"
        }
      ];
    };
    const buildUnknownEntityValidationChatPrompt = (item) => {
      var _a2, _b2;
      const entityType = String((item == null ? void 0 : item.type) || "").toLowerCase() === "sourcetype" ? "sourcetype" : "index";
      const entityName = String((item == null ? void 0 : item.name) || "").trim();
      const generatedQueries = buildUnknownEntityValidationQueries(item);
      if (!entityName || generatedQueries.length === 0) {
        return "";
      }
      const entityLabel = entityType === "index" ? `index=${entityName}` : `sourcetype=${entityName}`;
      const likelyCategories = Array.isArray(item == null ? void 0 : item.suggestions) && item.suggestions.length > 0 ? item.suggestions.slice(0, 3).map((suggestion) => suggestion.label).join(", ") : "unknown";
      const starterQueries = generatedQueries.map((query, idx) => `${idx + 1}. ${query.spl}`).join("\n");
      const question = (item == null ? void 0 : item.question) || "Classify this entity and determine what it contains.";
      const volumeSignal = formatVolumeCategory((_a2 = item == null ? void 0 : item.context) == null ? void 0 : _a2.volume_category);
      const significanceNote = ((_b2 = item == null ? void 0 : item.context) == null ? void 0 : _b2.has_significant_data) ? "This entity already appears to have significant data." : "This entity may still be low-signal or poorly understood.";
      return [
        `Build context for this unclear Splunk ${entityType} and decide whether it is expected, important, and worth monitoring coverage.`,
        "",
        `Use the exact entity anchor ${entityLabel}. Do not substitute another ${entityType} name.`,
        `Name: ${entityName}`,
        `Question: ${question}`,
        `Likely categories: ${likelyCategories}`,
        `Volume signal: ${volumeSignal}`,
        significanceNote,
        "",
        "Start by executing one or more of these exact SPL queries, then improve or branch from them only if the results justify it:",
        starterQueries,
        "",
        "Return:",
        "1. What this entity most likely contains",
        "2. Whether it looks expected or risky",
        "3. What monitoring, ownership, or validation should happen next"
      ].join("\n");
    };
    const buildContextExplorerQueries = (anchorType, item) => {
      const resolvedAnchorType = anchorType === "sourcetype" ? "sourcetype" : anchorType === "host" ? "host" : "index";
      const anchorName = String((item == null ? void 0 : item.name) || "").trim();
      if (!anchorName) {
        return [];
      }
      const searchAnchor = `${resolvedAnchorType}=${anchorName}`;
      const evidence = [`${resolvedAnchorType}:${anchorName}`];
      const priority = resolvedAnchorType === "index" ? "🔴 HIGH" : "🟠 MEDIUM";
      const breakdownFields = resolvedAnchorType === "index" ? "sourcetype host" : resolvedAnchorType === "sourcetype" ? "index host" : "index sourcetype";
      const trendField = resolvedAnchorType === "host" ? "sourcetype" : resolvedAnchorType === "sourcetype" ? "index" : "sourcetype";
      return [
        {
          title: `🔎 ${anchorName} Context Snapshot`,
          description: `Profile ${searchAnchor} so an operator can quickly see where it shows up and how much signal it carries.`,
          use_case: "Data Quality",
          category: "Data Quality",
          spl: `${searchAnchor} earliest=-24h | stats count by ${breakdownFields} | sort - count | head 20`,
          finding_reference: `Context explorer anchor for ${searchAnchor}`,
          execution_time: "< 30s",
          business_value: "Shows the immediate shape and spread of this anchor before you decide on monitoring or ownership.",
          priority,
          difficulty: "Beginner",
          environment_evidence: evidence,
          query_source: "context_engine"
        },
        {
          title: `📈 ${anchorName} Activity Trend`,
          description: `Trend ${searchAnchor} over time to identify whether it is stable, bursty, or drifting.`,
          use_case: "Performance Monitoring",
          category: "Infrastructure & Performance",
          spl: `${searchAnchor} earliest=-7d | timechart span=1h count by ${trendField} limit=10 useother=true`,
          finding_reference: `Trend exploration for ${searchAnchor}`,
          execution_time: "< 45s",
          business_value: "Helps determine whether this anchor deserves coverage or more targeted alerting.",
          priority,
          difficulty: "Intermediate",
          environment_evidence: evidence,
          query_source: "context_engine"
        },
        {
          title: `🧪 ${anchorName} Sample Events`,
          description: `Pull a small sample from ${searchAnchor} so the operator can inspect representative events directly.`,
          use_case: "Data Exploration",
          category: "Data Quality",
          spl: `${searchAnchor} earliest=-24h | head 20 | table _time index sourcetype host source`,
          finding_reference: `Sample event triage for ${searchAnchor}`,
          execution_time: "< 15s",
          business_value: "Speeds up fast human classification before creating tasks or controls.",
          priority,
          difficulty: "Beginner",
          environment_evidence: evidence,
          query_source: "context_engine"
        }
      ];
    };
    const buildContextExplorerChatPrompt = (anchorType, item) => {
      const resolvedAnchorType = anchorType === "sourcetype" ? "sourcetype" : anchorType === "host" ? "host" : "index";
      const anchorName = String((item == null ? void 0 : item.name) || "").trim();
      const generatedQueries = buildContextExplorerQueries(resolvedAnchorType, item);
      if (!anchorName || generatedQueries.length === 0) {
        return "";
      }
      const searchAnchor = `${resolvedAnchorType}=${anchorName}`;
      const starterQueries = generatedQueries.map((query, idx) => `${idx + 1}. ${query.spl}`).join("\n");
      const volumeSignal = (item == null ? void 0 : item.events) != null && Number.isFinite(Number(item.events)) ? `${Number(item.events).toLocaleString()} observed events in discovery.` : "Use the first query to determine current volume and spread.";
      const sizeSignal = (item == null ? void 0 : item.size_mb) != null && Number.isFinite(Number(item.size_mb)) ? `Approximate indexed size: ${Number(item.size_mb).toFixed(1)} MB.` : "";
      return [
        `Build operational context for ${searchAnchor} within this discovery session.`,
        "",
        `Use the exact entity anchor ${searchAnchor}. Do not substitute another ${resolvedAnchorType} name.`,
        `Anchor type: ${resolvedAnchorType}`,
        `Name: ${anchorName}`,
        volumeSignal,
        sizeSignal,
        "",
        "Start by executing one or more of these exact SPL queries before broadening the investigation:",
        starterQueries,
        "",
        "Return:",
        "1. What this anchor most likely represents in the environment",
        "2. Which related indexes, sourcetypes, or hosts stand out",
        "3. What monitoring, ownership, or validation should happen next"
      ].filter(Boolean).join("\n");
    };
    const focusQueriesForContextExplorer = (anchorType, item) => {
      const generatedQueries = buildContextExplorerQueries(anchorType, item);
      if (generatedQueries.length === 0) {
        return;
      }
      const resolvedAnchorType = anchorType === "sourcetype" ? "sourcetype" : anchorType === "host" ? "host" : "index";
      const anchorName = String((item == null ? void 0 : item.name) || "").trim() || "unknown anchor";
      const searchAnchor = `${resolvedAnchorType}=${anchorName}`;
      setQueryFocus({
        title: `${anchorName} Context Explorer`,
        category: "Data Quality",
        categories: ["Data Quality", "Infrastructure & Performance"],
        findingReference: `Context explorer for ${searchAnchor}`,
        environmentEvidence: [`${resolvedAnchorType}:${anchorName}`],
        sourceLabel: "Focused From Context Explorer",
        description: `Showing discovery-aligned context queries for ${searchAnchor} so you can classify, validate, and route follow-up work without leaving exec-control.`,
        generatedQueries
      });
      setQueryFilter("all");
      setActiveTab("queries");
    };
    const getSharedEvidenceCount = (left, right) => {
      const rightSet = new Set((Array.isArray(right) ? right : []).map((item) => String(item || "").toLowerCase()));
      return (Array.isArray(left) ? left : []).reduce((count, item) => {
        return rightSet.has(String(item || "").toLowerCase()) ? count + 1 : count;
      }, 0);
    };
    const getQueryFocusMatchScore = (query, focus) => {
      if (!focus || typeof focus !== "object") {
        return 0;
      }
      let score = 0;
      const allowedCategories = Array.isArray(focus.categories) ? focus.categories : [];
      const queryCategory = typeof (query == null ? void 0 : query.category) === "string" ? query.category : "";
      const queryFinding = normalizeSummaryText((query == null ? void 0 : query.finding_reference) || "").toLowerCase();
      const focusFinding = normalizeSummaryText(focus.findingReference || "").toLowerCase();
      if (allowedCategories.includes(queryCategory)) {
        score += 3;
      }
      if (focusFinding && queryFinding) {
        const focusAnchor = focusFinding.slice(0, 48);
        const queryAnchor = queryFinding.slice(0, 48);
        if (focusAnchor && queryFinding.includes(focusAnchor) || queryAnchor && focusFinding.includes(queryAnchor)) {
          score += 2;
        }
      }
      score += Math.min(2, getSharedEvidenceCount(focus.environmentEvidence, query == null ? void 0 : query.environment_evidence));
      return score;
    };
    const focusRiskControlPath = (risk) => {
      const nextTaskFilter = getRiskTaskFilterKey(risk);
      setRiskFocus({
        title: (risk == null ? void 0 : risk.risk) || "Operational risk",
        domain: (risk == null ? void 0 : risk.domain) || "general",
        taskFilter: nextTaskFilter,
        riskData: risk
      });
      setQueryFilter("all");
      setQueryFocus(null);
      setTaskFilter(nextTaskFilter);
      setActiveTab("tasks");
    };
    const focusQueriesForRisk = (risk) => {
      const riskTitle = (risk == null ? void 0 : risk.risk) || "Operational risk";
      const queryCategories = getRiskQueryCategories(risk);
      setQueryFocus({
        title: riskTitle,
        category: (risk == null ? void 0 : risk.domain) || "general",
        categories: queryCategories,
        findingReference: [risk == null ? void 0 : risk.risk, risk == null ? void 0 : risk.impact].filter(Boolean).join(" "),
        environmentEvidence: [],
        sourceLabel: "Focused From Risk Register",
        description: `Showing validation queries aligned to the ${(risk == null ? void 0 : risk.domain) || "general"} risk lane so you can verify the current control gap before or after task execution.`,
        generatedQueries: []
      });
      setQueryFilter("all");
      setActiveTab("queries");
    };
    const clearRiskFocus = () => {
      setRiskFocus(null);
      setTaskFilter("all");
    };
    const focusQueriesForTask = (task) => {
      setQueryFocus({
        title: (task == null ? void 0 : task.title) || "Selected task",
        category: (task == null ? void 0 : task.category) || "General",
        categories: getTaskQueryCategories(task),
        findingReference: (task == null ? void 0 : task.finding_reference) || "",
        environmentEvidence: Array.isArray(task == null ? void 0 : task.environment_evidence) ? task.environment_evidence : [],
        sourceLabel: "Focused From Task Queue",
        description: `Showing validation queries aligned to the ${(task == null ? void 0 : task.category) || "General"} workstream using matching finding and telemetry evidence.`,
        generatedQueries: []
      });
      setQueryFilter("all");
      setActiveTab("queries");
    };
    const getSummaryContextActionClasses = (tone) => {
      switch (String(tone || "").toLowerCase()) {
        case "cyan":
          return "bg-cyan-700 hover:bg-cyan-800 text-white";
        case "indigo":
          return "bg-indigo-600 hover:bg-indigo-700 text-white";
        case "red":
          return "bg-red-600 hover:bg-red-700 text-white";
        case "amber":
          return "bg-amber-600 hover:bg-amber-700 text-white";
        case "emerald":
          return "bg-emerald-600 hover:bg-emerald-700 text-white";
        default:
          return "bg-slate-700 hover:bg-slate-800 text-white";
      }
    };
    const saveSummaryContextAssetToLibrary = async (action) => {
      const assetImport = (action == null ? void 0 : action.assetImport) && typeof action.assetImport === "object" ? action.assetImport : null;
      if (!assetImport) {
        return null;
      }
      return importKnowledgeAssetToLibrary(assetImport, {
        successMessage: (action == null ? void 0 : action.successMessage) || "Context asset saved to the context library.",
        errorMessage: (action == null ? void 0 : action.errorMessage) || "Failed to save context asset to the library.",
        logLabel: "save summary context asset to library"
      });
    };
    const applySummaryContextQueryFocus = (queryFocus2) => {
      if (!queryFocus2 || typeof queryFocus2 !== "object") {
        return;
      }
      setQueryFocus({
        title: queryFocus2.title || "Focused Query Set",
        category: queryFocus2.category || "General",
        categories: Array.isArray(queryFocus2.categories) ? queryFocus2.categories : [],
        findingReference: queryFocus2.findingReference || "",
        environmentEvidence: Array.isArray(queryFocus2.environmentEvidence) ? queryFocus2.environmentEvidence : [],
        sourceLabel: queryFocus2.sourceLabel || "Focused From Context Explorer",
        description: queryFocus2.description || "",
        generatedQueries: Array.isArray(queryFocus2.generatedQueries) ? queryFocus2.generatedQueries : []
      });
      setQueryFilter("all");
      setActiveTab("queries");
    };
    const applySummaryContextTaskFocus = (taskFocus) => {
      var _a2, _b2;
      const nextTaskFilter = typeof (taskFocus == null ? void 0 : taskFocus.taskFilter) === "string" && taskFocus.taskFilter.trim() ? taskFocus.taskFilter.trim() : "all";
      if ((taskFocus == null ? void 0 : taskFocus.riskData) && typeof taskFocus.riskData === "object") {
        setRiskFocus({
          title: taskFocus.title || ((_a2 = taskFocus.riskData) == null ? void 0 : _a2.risk) || "Operational risk",
          domain: taskFocus.domain || ((_b2 = taskFocus.riskData) == null ? void 0 : _b2.domain) || "general",
          taskFilter: nextTaskFilter,
          riskData: taskFocus.riskData
        });
      } else {
        clearRiskFocus();
      }
      setQueryFilter("all");
      setQueryFocus(null);
      setTaskFilter(nextTaskFilter);
      setActiveTab("tasks");
    };
    const executeSummaryContextAction = async (action) => {
      if (!action || typeof action !== "object") {
        return;
      }
      switch (action.kind) {
        case "launch_chat": {
          const prompt = typeof action.prompt === "string" ? action.prompt.trim() : "";
          if (!prompt) {
            return;
          }
          await launchChatInvestigation(prompt, {
            ...action.launchOptions && typeof action.launchOptions === "object" ? action.launchOptions : {}
          });
          return;
        }
        case "focus_queries":
          applySummaryContextQueryFocus(action.queryFocus);
          return;
        case "focus_tasks":
          applySummaryContextTaskFocus(action.taskFocus);
          return;
        case "save_context_asset":
          await saveSummaryContextAssetToLibrary(action);
          return;
        default:
          console.warn("Unsupported summary context action:", action);
      }
    };
    const renderSummaryContextActionButtons = (actions, options = {}) => {
      const safeActions = Array.isArray(actions) ? actions.filter((action) => action && typeof action === "object" && action.kind) : [];
      if (safeActions.length === 0) {
        return null;
      }
      return /* @__PURE__ */ React.createElement(
        "div",
        {
          className: options.containerClassName || "mt-3 flex flex-wrap gap-2",
          "data-testid": options.testId || "summary-context-action-group"
        },
        safeActions.map((action, idx) => /* @__PURE__ */ React.createElement(
          "button",
          {
            key: `${action.kind || "action"}-${action.label || idx}-${idx}`,
            type: "button",
            onClick: () => executeSummaryContextAction(action),
            "data-testid": action.kind === "save_context_asset" ? "summary-context-save-action" : "summary-context-action-button",
            className: `inline-flex items-center rounded px-3 py-1.5 text-xs font-medium transition-colors ${getSummaryContextActionClasses(action.tone)} ${options.buttonClassName || ""}`.trim()
          },
          action.icon && /* @__PURE__ */ React.createElement("i", { className: `fas ${action.icon} mr-1.5` }),
          /* @__PURE__ */ React.createElement("span", null, action.label || "Action")
        ))
      );
    };
    const normalizeSummaryContextPatternEntry = (pattern) => {
      if (!pattern) {
        return [];
      }
      if (Array.isArray(pattern)) {
        return pattern.flatMap((item) => normalizeSummaryContextPatternEntry(item));
      }
      if (typeof pattern === "string") {
        const trimmedPattern = pattern.trim();
        if (!trimmedPattern) {
          return [];
        }
        try {
          return normalizeSummaryContextPatternEntry(JSON.parse(trimmedPattern));
        } catch (error) {
          return [{
            title: trimmedPattern,
            description: "",
            signal: ""
          }];
        }
      }
      if (typeof pattern !== "object") {
        return [];
      }
      const embeddedPatternPayload = [
        pattern.title,
        pattern.name,
        pattern.pattern,
        pattern.description,
        pattern.summary,
        pattern.insight
      ].find((value) => typeof value === "string" && value.trim().startsWith("{") && value.includes('"patterns"'));
      if (embeddedPatternPayload) {
        try {
          return normalizeSummaryContextPatternEntry(JSON.parse(embeddedPatternPayload));
        } catch (error) {
        }
      }
      if (Array.isArray(pattern.patterns)) {
        return pattern.patterns.flatMap((item) => normalizeSummaryContextPatternEntry(item));
      }
      const title = String(pattern.title || pattern.name || pattern.pattern || pattern.category || pattern.signal || "").trim();
      const description = String(pattern.description || pattern.summary || pattern.insight || "").trim();
      let signal = "";
      if (Array.isArray(pattern.evidence)) {
        signal = pattern.evidence.map((item) => String(item || "").trim()).filter(Boolean).slice(0, 2).join(", ");
      } else if (typeof pattern.evidence === "string") {
        signal = pattern.evidence.trim();
      } else if (typeof pattern.signal === "string") {
        signal = pattern.signal.trim();
      }
      if (!title && !description && !signal) {
        return [];
      }
      return [{
        title: title || description || "Pattern",
        description: title && description === title ? "" : description,
        signal
      }];
    };
    const normalizeSummaryContextPatterns = (rawPatterns) => {
      if (!Array.isArray(rawPatterns)) {
        return [];
      }
      const seenPatterns = /* @__PURE__ */ new Set();
      return rawPatterns.flatMap((pattern) => normalizeSummaryContextPatternEntry(pattern)).filter((pattern) => {
        const key = `${pattern.title || ""}::${pattern.description || ""}::${pattern.signal || ""}`.trim().toLowerCase();
        if (!key || seenPatterns.has(key)) {
          return false;
        }
        seenPatterns.add(key);
        return true;
      });
    };
    const clearQueryFocus = () => {
      setQueryFocus(null);
      setQueryFilter("all");
    };
    const summarySections = parseAiSummarySections((summaryData == null ? void 0 : summaryData.ai_summary) || "");
    const executiveNarrativeSection = getSummarySection(summarySections, "Executive Summary");
    const priorityActionsSection = getSummarySection(summarySections, "Priority Actions");
    const quickWinsSection = getSummarySection(summarySections, "Quick Wins");
    const riskAreasSection = getSummarySection(summarySections, "Risk Areas");
    const trendStorySection = getSummarySection(summarySections, "Trend Story");
    const nextLoopSection = getSummarySection(summarySections, "Recursive Next Loop");
    const readinessScore = typeof ((_N = summaryData == null ? void 0 : summaryData.readiness_score) != null ? _N : (_M = summaryData == null ? void 0 : summaryData.v2_context) == null ? void 0 : _M.readiness_score) === "number" ? (_P = summaryData == null ? void 0 : summaryData.readiness_score) != null ? _P : (_O = summaryData == null ? void 0 : summaryData.v2_context) == null ? void 0 : _O.readiness_score : null;
    const coverageGapItems = Array.isArray(summaryData == null ? void 0 : summaryData.coverage_gaps) ? summaryData.coverage_gaps.filter((gap) => gap && typeof gap === "object" && gap.gap).slice(0, 3) : [];
    const trendDomainEntries = ((_Q = summaryData == null ? void 0 : summaryData.trend_signals) == null ? void 0 : _Q.recommendation_by_domain) ? Object.entries(summaryData.trend_signals.recommendation_by_domain) : [];
    const contextExplorer = (summaryData == null ? void 0 : summaryData.context_explorer) && typeof summaryData.context_explorer === "object" ? summaryData.context_explorer : {};
    const contextOverview = (contextExplorer == null ? void 0 : contextExplorer.overview) && typeof contextExplorer.overview === "object" ? contextExplorer.overview : {};
    const contextAnchors = (contextExplorer == null ? void 0 : contextExplorer.anchors) && typeof contextExplorer.anchors === "object" ? contextExplorer.anchors : {};
    const contextLanes = (contextExplorer == null ? void 0 : contextExplorer.lanes) && typeof contextExplorer.lanes === "object" ? contextExplorer.lanes : {};
    const contextPatterns = normalizeSummaryContextPatterns(contextExplorer == null ? void 0 : contextExplorer.patterns);
    const visibleContextPatterns = contextPatterns.slice(0, 4);
    const leadContextPattern = visibleContextPatterns[0] || null;
    const supportingContextPatterns = visibleContextPatterns.slice(1);
    const hiddenContextPatternCount = Math.max(0, contextPatterns.length - visibleContextPatterns.length);
    const contextIndexAnchors = Array.isArray(contextAnchors == null ? void 0 : contextAnchors.indexes) ? contextAnchors.indexes : [];
    const contextSourcetypeAnchors = Array.isArray(contextAnchors == null ? void 0 : contextAnchors.sourcetypes) ? contextAnchors.sourcetypes : [];
    const contextHostAnchors = Array.isArray(contextAnchors == null ? void 0 : contextAnchors.hosts) ? contextAnchors.hosts : [];
    const contextUnknownEntities = Array.isArray(contextLanes == null ? void 0 : contextLanes.unknown_entities) ? contextLanes.unknown_entities : [];
    const contextCoverageGapItems = Array.isArray(contextLanes == null ? void 0 : contextLanes.coverage_gaps) ? contextLanes.coverage_gaps : [];
    const contextRiskItems = Array.isArray(contextLanes == null ? void 0 : contextLanes.risks) ? contextLanes.risks : [];
    const contextPriorityTasks = Array.isArray(contextLanes == null ? void 0 : contextLanes.priority_tasks) ? contextLanes.priority_tasks : [];
    const hasContextExplorer = [
      contextIndexAnchors.length,
      contextSourcetypeAnchors.length,
      contextHostAnchors.length,
      contextPatterns.length,
      contextUnknownEntities.length,
      contextCoverageGapItems.length,
      contextRiskItems.length,
      contextPriorityTasks.length
    ].some((count) => count > 0);
    const unknownDataItems = Array.isArray(summaryData == null ? void 0 : summaryData.unknown_data) ? [...summaryData.unknown_data].sort((left, right) => {
      const leftRank = getUnknownItemRank(left);
      const rightRank = getUnknownItemRank(right);
      for (let index = 0; index < leftRank.length; index += 1) {
        if (leftRank[index] !== rightRank[index]) {
          return leftRank[index] - rightRank[index];
        }
      }
      return String((left == null ? void 0 : left.name) || "").localeCompare(String((right == null ? void 0 : right.name) || ""));
    }) : [];
    const visibleUnknownData = showAllUnknownData ? unknownDataItems : unknownDataItems.slice(0, 4);
    const unknownHiddenCount = Math.max(0, unknownDataItems.length - visibleUnknownData.length);
    const sortedSummaryQueries = Array.isArray(summaryData == null ? void 0 : summaryData.spl_queries) ? [...summaryData.spl_queries].sort((left, right) => {
      var _a2, _b2;
      const priorityDelta = getQueryPriorityRank(left == null ? void 0 : left.priority) - getQueryPriorityRank(right == null ? void 0 : right.priority);
      if (priorityDelta !== 0) {
        return priorityDelta;
      }
      return (((_a2 = right == null ? void 0 : right.environment_evidence) == null ? void 0 : _a2.length) || 0) - (((_b2 = left == null ? void 0 : left.environment_evidence) == null ? void 0 : _b2.length) || 0);
    }) : [];
    const focusedGeneratedQueries = Array.isArray(queryFocus == null ? void 0 : queryFocus.generatedQueries) ? queryFocus.generatedQueries : [];
    const rawFocusedSummaryQueries = queryFocus && focusedGeneratedQueries.length === 0 ? sortedSummaryQueries.filter((query) => getQueryFocusMatchScore(query, queryFocus) > 0) : sortedSummaryQueries;
    const fallbackFocusedSummaryQueries = queryFocus && focusedGeneratedQueries.length === 0 ? sortedSummaryQueries.filter((query) => (Array.isArray(queryFocus.categories) ? queryFocus.categories : []).includes(query == null ? void 0 : query.category)) : sortedSummaryQueries;
    const focusScopedSummaryQueries = focusedGeneratedQueries.length > 0 ? focusedGeneratedQueries : queryFocus ? rawFocusedSummaryQueries.length > 0 ? rawFocusedSummaryQueries : fallbackFocusedSummaryQueries : sortedSummaryQueries;
    const querySourceCounts = {
      ai_finding: focusScopedSummaryQueries.filter((query) => (query == null ? void 0 : query.query_source) === "ai_finding").length,
      context_engine: focusScopedSummaryQueries.filter((query) => (query == null ? void 0 : query.query_source) === "context_engine").length,
      template: focusScopedSummaryQueries.filter((query) => (query == null ? void 0 : query.query_source) === "template").length
    };
    const queryFilterOptions = [
      { key: "all", label: "All", count: focusScopedSummaryQueries.length, activeClass: "bg-indigo-600 text-white" },
      { key: "ai_finding", label: "AI-generated", count: querySourceCounts.ai_finding, activeClass: "bg-purple-600 text-white" },
      { key: "context_engine", label: "Environment-based", count: querySourceCounts.context_engine, activeClass: "bg-emerald-600 text-white" },
      { key: "template", label: "Template-based", count: querySourceCounts.template, activeClass: "bg-blue-600 text-white" }
    ].filter((option) => option.key === "all" || option.count > 0);
    const activeQueryFilterKey = queryFilterOptions.some((option) => option.key === queryFilter) ? queryFilter : "all";
    const filteredSummaryQueries = focusScopedSummaryQueries.filter((query) => activeQueryFilterKey === "all" || (query == null ? void 0 : query.query_source) === activeQueryFilterKey);
    const taskProgressSnapshots = Array.isArray(summaryData == null ? void 0 : summaryData.admin_tasks) ? summaryData.admin_tasks.map((task, idx) => {
      var _a2;
      return {
        taskIndex: idx,
        task,
        progress: getTaskProgress(currentSessionId, idx),
        completionPct: getTaskCompletionPercentage(currentSessionId, idx, ((_a2 = task == null ? void 0 : task.steps) == null ? void 0 : _a2.length) || 0)
      };
    }) : [];
    const sortedTaskProgressSnapshots = [...taskProgressSnapshots].sort((left, right) => {
      var _a2, _b2, _c2, _d2, _e2, _f2;
      const leftStatusRank = ((_a2 = left == null ? void 0 : left.progress) == null ? void 0 : _a2.status) === "in-progress" ? 0 : ((_b2 = left == null ? void 0 : left.progress) == null ? void 0 : _b2.status) === "completed" ? 2 : 1;
      const rightStatusRank = ((_c2 = right == null ? void 0 : right.progress) == null ? void 0 : _c2.status) === "in-progress" ? 0 : ((_d2 = right == null ? void 0 : right.progress) == null ? void 0 : _d2.status) === "completed" ? 2 : 1;
      const statusDelta = leftStatusRank - rightStatusRank;
      if (statusDelta !== 0) {
        return statusDelta;
      }
      const priorityDelta = getTaskPriorityRank((_e2 = left == null ? void 0 : left.task) == null ? void 0 : _e2.priority) - getTaskPriorityRank((_f2 = right == null ? void 0 : right.task) == null ? void 0 : _f2.priority);
      if (priorityDelta !== 0) {
        return priorityDelta;
      }
      return ((right == null ? void 0 : right.completionPct) || 0) - ((left == null ? void 0 : left.completionPct) || 0);
    });
    const highPriorityTaskCount = taskProgressSnapshots.filter(({ task }) => (task == null ? void 0 : task.priority) === "HIGH").length;
    const inProgressTaskCount = taskProgressSnapshots.filter(({ progress: progress2 }) => (progress2 == null ? void 0 : progress2.status) === "in-progress").length;
    const completedTaskCount = taskProgressSnapshots.filter(({ progress: progress2 }) => (progress2 == null ? void 0 : progress2.status) === "completed").length;
    const openTaskCount = taskProgressSnapshots.filter(({ progress: progress2 }) => (progress2 == null ? void 0 : progress2.status) !== "completed").length;
    const taskCategoryCounts = sortedTaskProgressSnapshots.reduce((counts, snapshot) => {
      var _a2;
      const category = (_a2 = snapshot == null ? void 0 : snapshot.task) == null ? void 0 : _a2.category;
      if (!category) {
        return counts;
      }
      counts[category] = (counts[category] || 0) + 1;
      return counts;
    }, {});
    const taskFilterOptions = [
      { key: "all", label: "All", count: sortedTaskProgressSnapshots.length, activeClass: "bg-indigo-600 text-white" },
      { key: "open", label: "Open", count: openTaskCount, activeClass: "bg-slate-700 text-white" },
      { key: "in-progress", label: "In Progress", count: inProgressTaskCount, activeClass: "bg-blue-600 text-white" },
      { key: "completed", label: "Completed", count: completedTaskCount, activeClass: "bg-green-600 text-white" },
      ...Object.entries(taskCategoryCounts).sort((left, right) => right[1] - left[1] || left[0].localeCompare(right[0])).map(([category, count]) => ({
        key: `category:${category}`,
        label: category,
        count,
        activeClass: "bg-purple-600 text-white"
      }))
    ].filter((option) => option.key === "all" || option.count > 0);
    const activeTaskFilterKey = taskFilterOptions.some((option) => option.key === taskFilter) ? taskFilter : "all";
    const activeTaskFilterLabel = ((_R = taskFilterOptions.find((option) => option.key === activeTaskFilterKey)) == null ? void 0 : _R.label) || "All";
    const filteredTaskSnapshots = sortedTaskProgressSnapshots.filter(({ task, progress: progress2 }) => {
      if (activeTaskFilterKey === "all") {
        return true;
      }
      if (activeTaskFilterKey === "open") {
        return (progress2 == null ? void 0 : progress2.status) !== "completed";
      }
      if (activeTaskFilterKey === "in-progress") {
        return (progress2 == null ? void 0 : progress2.status) === "in-progress";
      }
      if (activeTaskFilterKey === "completed") {
        return (progress2 == null ? void 0 : progress2.status) === "completed";
      }
      if (activeTaskFilterKey.startsWith("category:")) {
        return (task == null ? void 0 : task.category) === activeTaskFilterKey.slice("category:".length);
      }
      return true;
    });
    const copyToClipboard = (text) => {
      navigator.clipboard.writeText(text).then(() => {
        addMessage("success", { message: "Copied to clipboard!" });
      }).catch((err) => {
        console.error("Failed to copy:", err);
        addMessage("error", { message: "Failed to copy to clipboard" });
      });
    };
    const exportReport = (filename, content) => {
      const blob = new Blob([content], { type: "text/plain" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    };
    const downloadReportArtifact = (filename, content) => {
      if (!filename || !content) {
        return;
      }
      if (content.type === "image") {
        const imageSrc = buildReportImageSrc(content);
        if (!imageSrc) {
          addMessage("error", { message: "No image payload is available for download." });
          return;
        }
        const link = document.createElement("a");
        link.href = imageSrc;
        link.download = filename;
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        return;
      }
      exportReport(
        filename,
        content.type === "json" ? JSON.stringify(content.content, null, 2) : content.content
      );
    };
    const handleLogMouseDown = (e) => {
      setIsResizingLog(true);
      e.preventDefault();
    };
    const handleReportMouseDown = (e) => {
      setIsResizingReport(true);
      e.preventDefault();
    };
    useEffect(() => {
      const handleMouseMove = (e) => {
        if (isResizingLog) {
          const newHeight = Math.max(200, Math.min(800, e.clientY - 300));
          setDiscoveryLogHeight(newHeight);
        }
        if (isResizingReport) {
          const newHeight = Math.max(300, Math.min(1e3, e.clientY - 400));
          setReportViewerHeight(newHeight);
        }
      };
      const handleMouseUp = () => {
        setIsResizingLog(false);
        setIsResizingReport(false);
      };
      if (isResizingLog || isResizingReport) {
        document.addEventListener("mousemove", handleMouseMove);
        document.addEventListener("mouseup", handleMouseUp);
        document.body.style.cursor = "ns-resize";
        document.body.style.userSelect = "none";
      }
      return () => {
        document.removeEventListener("mousemove", handleMouseMove);
        document.removeEventListener("mouseup", handleMouseUp);
        document.body.style.cursor = "";
        document.body.style.userSelect = "";
      };
    }, [isResizingLog, isResizingReport]);
    const renderMessage = (message) => {
      const { type, data } = message;
      switch (type) {
        case "banner":
          return /* @__PURE__ */ React.createElement("div", { className: "bg-gradient-to-r from-purple-600 to-blue-600 text-white p-6 rounded-lg fade-in" }, /* @__PURE__ */ React.createElement("h1", { className: "text-2xl font-bold" }, data.title), /* @__PURE__ */ React.createElement("p", { className: "text-purple-100" }, data.subtitle), /* @__PURE__ */ React.createElement("p", { className: "text-sm text-purple-200 mt-2" }, "Started: ", data.start_time));
        case "phase":
          return /* @__PURE__ */ React.createElement("div", { className: `border-l-4 p-4 slide-in ${isDarkTheme ? "bg-indigo-950 border-indigo-500" : "bg-indigo-50 border-indigo-500"}` }, /* @__PURE__ */ React.createElement("h2", { className: `text-lg font-semibold ${isDarkTheme ? "text-indigo-200" : "text-indigo-900"}` }, data.title));
        case "success":
          return /* @__PURE__ */ React.createElement("div", { className: `flex items-center p-2 rounded fade-in ${isDarkTheme ? "text-emerald-300 bg-emerald-950" : "text-green-700 bg-green-50"}` }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-check-circle mr-2" }), /* @__PURE__ */ React.createElement("span", null, data.message));
        case "error":
          return /* @__PURE__ */ React.createElement("div", { className: `flex items-center p-3 rounded fade-in ${isDarkTheme ? "text-red-200 bg-red-950" : "text-red-700 bg-red-50"}` }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-exclamation-circle mr-2" }), /* @__PURE__ */ React.createElement("span", null, data.message));
        case "warning":
          return /* @__PURE__ */ React.createElement("div", { className: `flex items-center p-3 rounded fade-in ${isDarkTheme ? "text-amber-200 bg-amber-950" : "text-yellow-700 bg-yellow-50"}` }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-exclamation-triangle mr-2" }), /* @__PURE__ */ React.createElement("span", null, data.message));
        case "info":
          return /* @__PURE__ */ React.createElement("div", { className: `flex items-center p-2 rounded fade-in ${isDarkTheme ? "text-blue-300 bg-blue-950" : "text-blue-700"}` }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-info-circle mr-2" }), /* @__PURE__ */ React.createElement("span", null, data.message));
        case "overview":
          return /* @__PURE__ */ React.createElement("div", { className: `p-4 rounded-lg fade-in border ${isDarkTheme ? "bg-slate-800 border-slate-700" : "bg-blue-50 border-blue-200"}` }, /* @__PURE__ */ React.createElement("h3", { className: `font-semibold mb-2 ${isDarkTheme ? "text-blue-200" : "text-blue-900"}` }, "Environment Overview"), /* @__PURE__ */ React.createElement("div", { className: `grid grid-cols-2 gap-2 text-sm ${isDarkTheme ? "text-slate-200" : "text-slate-800"}` }, /* @__PURE__ */ React.createElement("div", { className: isDarkTheme ? "bg-slate-700 rounded px-2 py-1" : "" }, "Indexes: ", data.total_indexes), /* @__PURE__ */ React.createElement("div", { className: isDarkTheme ? "bg-slate-700 rounded px-2 py-1" : "" }, "Source Types: ", data.total_sourcetypes), /* @__PURE__ */ React.createElement("div", { className: isDarkTheme ? "bg-slate-700 rounded px-2 py-1" : "" }, "Data Volume: ", data.data_volume_24h), /* @__PURE__ */ React.createElement("div", { className: isDarkTheme ? "bg-slate-700 rounded px-2 py-1" : "" }, "Active Sources: ", data.active_sources)));
        case "rate_limit":
          if (data.event === "rate_limit_start") {
            return /* @__PURE__ */ React.createElement("div", { className: `border p-4 rounded-lg fade-in ${isDarkTheme ? "bg-amber-950 border-amber-700" : "bg-yellow-50 border-yellow-200"}` }, /* @__PURE__ */ React.createElement("div", { className: `flex items-center ${isDarkTheme ? "text-amber-200" : "text-yellow-700"}` }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-clock mr-2" }), /* @__PURE__ */ React.createElement("span", null, "Rate limit encountered - waiting ", data.details.delay, "s (attempt ", data.details.retry_count, "/", data.details.max_retries, ")")));
          } else if (data.event === "rate_limit_countdown") {
            return /* @__PURE__ */ React.createElement("div", { className: `p-3 rounded border ${isDarkTheme ? "bg-amber-950 border-amber-700" : "bg-yellow-50 border-yellow-200"}` }, /* @__PURE__ */ React.createElement("div", { className: `flex items-center justify-between text-sm ${isDarkTheme ? "text-amber-200" : "text-yellow-700"}` }, /* @__PURE__ */ React.createElement("span", null, "Waiting..."), /* @__PURE__ */ React.createElement("span", null, Math.ceil(data.details.remaining_seconds), "s remaining")), /* @__PURE__ */ React.createElement("div", { className: `w-full rounded-full h-2 mt-2 ${isDarkTheme ? "bg-amber-900" : "bg-yellow-200"}` }, /* @__PURE__ */ React.createElement(
              "div",
              {
                className: `h-2 rounded-full progress-bar ${isDarkTheme ? "bg-amber-400" : "bg-yellow-500"}`,
                style: { width: `${data.details.percentage}%` }
              }
            )));
          } else if (data.event === "rate_limit_complete") {
            return /* @__PURE__ */ React.createElement("div", { className: `flex items-center p-2 rounded fade-in ${isDarkTheme ? "text-emerald-300 bg-emerald-950" : "text-green-700 bg-green-50"}` }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-check-circle mr-2" }), /* @__PURE__ */ React.createElement("span", null, "Rate limit wait complete - resuming"));
          }
          break;
        case "completion":
          return /* @__PURE__ */ React.createElement("div", { className: `border p-4 rounded-lg fade-in ${isDarkTheme ? "bg-emerald-950 border-emerald-700" : "bg-green-50 border-green-200"}` }, /* @__PURE__ */ React.createElement("div", { className: `flex items-center mb-2 ${isDarkTheme ? "text-emerald-200" : "text-green-700"}` }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-trophy mr-2" }), /* @__PURE__ */ React.createElement("span", { className: "font-semibold" }, "Discovery Complete!")), /* @__PURE__ */ React.createElement("p", { className: `text-sm ${isDarkTheme ? "text-emerald-300" : "text-green-600"}` }, "Duration: ", data.duration || "N/A"), /* @__PURE__ */ React.createElement("p", { className: `text-sm ${isDarkTheme ? "text-emerald-300" : "text-green-600"}` }, "Generated ", data.report_count || 0, " reports"));
        default:
          return /* @__PURE__ */ React.createElement("div", { className: `fade-in ${isDarkTheme ? "text-gray-300" : "text-gray-600"}` }, /* @__PURE__ */ React.createElement("pre", { className: `text-xs p-2 rounded ${isDarkTheme ? "bg-gray-800 border border-gray-700" : "bg-gray-50 border border-gray-200"}` }, JSON.stringify(data, null, 2)));
      }
    };
    const renderExecutiveControlSummary = () => {
      var _a2, _b2, _c2, _d2, _e2, _f2, _g2, _h2, _i2, _j2, _k2, _l2, _m2, _n2, _o2, _p2, _q2, _r2, _s2, _t2, _u2, _v2, _w2, _x2, _y2, _z2, _A2, _B2;
      return /* @__PURE__ */ React.createElement(React.Fragment, null, /* @__PURE__ */ React.createElement("div", { className: `border rounded-2xl overflow-hidden shadow-sm ${isDarkTheme ? "bg-gray-900 border-gray-700" : "bg-white border-gray-200"}` }, /* @__PURE__ */ React.createElement("div", { className: `p-6 md:p-7 border-b ${isDarkTheme ? "border-gray-700 bg-gradient-to-r from-slate-900 via-indigo-950 to-slate-900" : "border-gray-200 bg-gradient-to-r from-slate-50 via-indigo-50 to-white"}` }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-col gap-6 xl:flex-row xl:items-start xl:justify-between" }, /* @__PURE__ */ React.createElement("div", { className: "xl:max-w-3xl" }, /* @__PURE__ */ React.createElement("div", { className: `text-xs font-semibold uppercase tracking-[0.24em] ${isDarkTheme ? "text-indigo-300" : "text-indigo-700"}` }, "Executive Control Process"), /* @__PURE__ */ React.createElement("h3", { className: `mt-2 text-2xl font-semibold ${isDarkTheme ? "text-gray-100" : "text-gray-900"}` }, "Decide, direct, and verify from one summary"), /* @__PURE__ */ React.createElement("p", { className: `mt-3 max-w-3xl text-sm leading-6 ${isDarkTheme ? "text-gray-300" : "text-gray-700"}` }, ((_a2 = executiveNarrativeSection == null ? void 0 : executiveNarrativeSection.paragraphs) == null ? void 0 : _a2[0]) || "Use this board to translate discovery output into control decisions, validation work, and the next review cycle.")), /* @__PURE__ */ React.createElement("div", { className: "grid grid-cols-2 gap-3 xl:w-[440px]" }, /* @__PURE__ */ React.createElement("div", { className: `rounded-xl border p-4 ${isDarkTheme ? "bg-gray-950 border-indigo-800" : "bg-white border-indigo-200"}` }, /* @__PURE__ */ React.createElement("div", { className: `text-xs uppercase tracking-wide ${isDarkTheme ? "text-indigo-300" : "text-indigo-700"}` }, "Readiness"), /* @__PURE__ */ React.createElement("div", { className: `mt-2 text-3xl font-bold ${isDarkTheme ? "text-gray-100" : "text-gray-900"}` }, readinessScore != null ? readinessScore : "N/A"), /* @__PURE__ */ React.createElement("div", { className: `mt-1 text-xs ${isDarkTheme ? "text-gray-400" : "text-gray-600"}` }, getReadinessLabel(readinessScore))), /* @__PURE__ */ React.createElement("div", { className: `rounded-xl border p-4 ${isDarkTheme ? "bg-gray-950 border-red-800" : "bg-white border-red-200"}` }, /* @__PURE__ */ React.createElement("div", { className: `text-xs uppercase tracking-wide ${isDarkTheme ? "text-red-300" : "text-red-700"}` }, "Open Risks"), /* @__PURE__ */ React.createElement("div", { className: `mt-2 text-3xl font-bold ${isDarkTheme ? "text-gray-100" : "text-gray-900"}` }, (_e2 = (_d2 = (_b2 = summaryData.risk_register) == null ? void 0 : _b2.length) != null ? _d2 : (_c2 = summaryData.v2_context) == null ? void 0 : _c2.risk_register) != null ? _e2 : 0), /* @__PURE__ */ React.createElement("div", { className: `mt-1 text-xs ${isDarkTheme ? "text-gray-400" : "text-gray-600"}` }, "Controls needing attention")), /* @__PURE__ */ React.createElement("div", { className: `rounded-xl border p-4 ${isDarkTheme ? "bg-gray-950 border-amber-800" : "bg-white border-amber-200"}` }, /* @__PURE__ */ React.createElement("div", { className: `text-xs uppercase tracking-wide ${isDarkTheme ? "text-amber-300" : "text-amber-700"}` }, "Coverage Gaps"), /* @__PURE__ */ React.createElement("div", { className: `mt-2 text-3xl font-bold ${isDarkTheme ? "text-gray-100" : "text-gray-900"}` }, (_i2 = (_h2 = (_f2 = summaryData.coverage_gaps) == null ? void 0 : _f2.length) != null ? _h2 : (_g2 = summaryData.v2_context) == null ? void 0 : _g2.coverage_gaps) != null ? _i2 : 0), /* @__PURE__ */ React.createElement("div", { className: `mt-1 text-xs ${isDarkTheme ? "text-gray-400" : "text-gray-600"}` }, "Missing or incomplete controls")), /* @__PURE__ */ React.createElement("div", { className: `rounded-xl border p-4 ${isDarkTheme ? "bg-gray-950 border-emerald-800" : "bg-white border-emerald-200"}` }, /* @__PURE__ */ React.createElement("div", { className: `text-xs uppercase tracking-wide ${isDarkTheme ? "text-emerald-300" : "text-emerald-700"}` }, "Action Queue"), /* @__PURE__ */ React.createElement("div", { className: `mt-2 text-3xl font-bold ${isDarkTheme ? "text-gray-100" : "text-gray-900"}` }, ((_j2 = summaryData.admin_tasks) == null ? void 0 : _j2.length) || 0), /* @__PURE__ */ React.createElement("div", { className: `mt-1 text-xs ${isDarkTheme ? "text-gray-400" : "text-gray-600"}` }, "Implementation tasks ready")))), /* @__PURE__ */ React.createElement("div", { className: "mt-6 grid gap-3 md:grid-cols-4" }, [
        { step: "1", title: "Assess posture", detail: `${(_l2 = (_k2 = summaryData.trend_signals) == null ? void 0 : _k2.evidence_steps) != null ? _l2 : 0} evidence steps captured.` },
        { step: "2", title: "Set directives", detail: `${((_m2 = priorityActionsSection == null ? void 0 : priorityActionsSection.items) == null ? void 0 : _m2.length) || 0} priority actions are ready.` },
        { step: "3", title: "Validate coverage", detail: `${((_n2 = summaryData.stats) == null ? void 0 : _n2.unknown_items) || 0} data items need classification.` },
        { step: "4", title: "Verify next loop", detail: `${((_o2 = summaryData.recursive_investigations) == null ? void 0 : _o2.length) || 0} follow-up loops defined.` }
      ].map((stage) => /* @__PURE__ */ React.createElement("div", { key: stage.step, className: `rounded-xl border px-4 py-3 ${isDarkTheme ? "bg-gray-950 border-gray-800" : "bg-white border-gray-200"}` }, /* @__PURE__ */ React.createElement("div", { className: "flex items-center gap-3" }, /* @__PURE__ */ React.createElement("span", { className: `inline-flex h-8 w-8 items-center justify-center rounded-full text-sm font-bold ${isDarkTheme ? "bg-indigo-900 text-indigo-100" : "bg-indigo-100 text-indigo-700"}` }, stage.step), /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("div", { className: `text-sm font-semibold ${isDarkTheme ? "text-gray-100" : "text-gray-900"}` }, stage.title), /* @__PURE__ */ React.createElement("div", { className: `text-xs ${isDarkTheme ? "text-gray-400" : "text-gray-600"}` }, stage.detail))))))), /* @__PURE__ */ React.createElement("div", { className: "grid gap-6 p-6 xl:grid-cols-[minmax(0,1.55fr),minmax(320px,0.95fr)]" }, /* @__PURE__ */ React.createElement("div", { className: "space-y-6" }, /* @__PURE__ */ React.createElement("div", { className: `rounded-xl border p-5 ${isDarkTheme ? "bg-gray-950 border-gray-800" : "bg-gray-50 border-gray-200"}` }, /* @__PURE__ */ React.createElement("div", { className: "flex items-center gap-2 mb-3" }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-brain text-indigo-600" }), /* @__PURE__ */ React.createElement("h4", { className: `text-lg font-semibold ${isDarkTheme ? "text-gray-100" : "text-gray-900"}` }, "Operating Narrative")), /* @__PURE__ */ React.createElement("div", { className: "space-y-3" }, (((_p2 = executiveNarrativeSection == null ? void 0 : executiveNarrativeSection.paragraphs) == null ? void 0 : _p2.length) ? executiveNarrativeSection.paragraphs : [summaryData.ai_summary]).slice(0, 3).map((paragraph, idx) => /* @__PURE__ */ React.createElement("p", { key: idx, className: `text-sm leading-6 ${isDarkTheme ? "text-gray-300" : "text-gray-700"}` }, paragraph))), trendStorySection && (trendStorySection.paragraphs.length > 0 || trendStorySection.items.length > 0) && /* @__PURE__ */ React.createElement("div", { className: `mt-4 rounded-lg border px-4 py-3 ${isDarkTheme ? "bg-slate-900 border-slate-800" : "bg-white border-slate-200"}` }, /* @__PURE__ */ React.createElement("div", { className: `text-xs font-semibold uppercase tracking-wide ${isDarkTheme ? "text-blue-300" : "text-blue-700"}` }, "Trend Story"), /* @__PURE__ */ React.createElement("div", { className: "mt-2 space-y-2" }, (trendStorySection.paragraphs.length > 0 ? trendStorySection.paragraphs : trendStorySection.items).slice(0, 2).map((paragraph, idx) => /* @__PURE__ */ React.createElement("p", { key: idx, className: `text-sm leading-6 ${isDarkTheme ? "text-gray-300" : "text-gray-700"}` }, paragraph))))), /* @__PURE__ */ React.createElement("div", { className: "grid gap-4 lg:grid-cols-2" }, /* @__PURE__ */ React.createElement("div", { className: `rounded-xl border p-5 ${isDarkTheme ? "bg-gray-950 border-gray-800" : "bg-white border-gray-200"}` }, /* @__PURE__ */ React.createElement("div", { className: "flex items-center gap-2 mb-3" }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-bullseye text-red-600" }), /* @__PURE__ */ React.createElement("h4", { className: `text-lg font-semibold ${isDarkTheme ? "text-gray-100" : "text-gray-900"}` }, "Priority Actions")), /* @__PURE__ */ React.createElement("ol", { className: "space-y-3" }, (((_q2 = priorityActionsSection == null ? void 0 : priorityActionsSection.items) == null ? void 0 : _q2.length) ? priorityActionsSection.items : ["No priority actions were extracted from this summary."]).slice(0, 3).map((item, idx) => /* @__PURE__ */ React.createElement("li", { key: idx, className: `flex items-start gap-3 text-sm ${isDarkTheme ? "text-gray-300" : "text-gray-700"}` }, /* @__PURE__ */ React.createElement("span", { className: `mt-0.5 inline-flex h-6 w-6 shrink-0 items-center justify-center rounded-full text-xs font-bold ${isDarkTheme ? "bg-red-900 text-red-100" : "bg-red-100 text-red-700"}` }, idx + 1), /* @__PURE__ */ React.createElement("span", { className: "leading-6" }, item))))), /* @__PURE__ */ React.createElement("div", { className: `rounded-xl border p-5 ${isDarkTheme ? "bg-gray-950 border-gray-800" : "bg-white border-gray-200"}` }, /* @__PURE__ */ React.createElement("div", { className: "flex items-center gap-2 mb-3" }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-bolt text-amber-500" }), /* @__PURE__ */ React.createElement("h4", { className: `text-lg font-semibold ${isDarkTheme ? "text-gray-100" : "text-gray-900"}` }, "Quick Wins")), /* @__PURE__ */ React.createElement("ul", { className: "space-y-3" }, (((_r2 = quickWinsSection == null ? void 0 : quickWinsSection.items) == null ? void 0 : _r2.length) ? quickWinsSection.items : ["No quick wins were extracted from this summary."]).slice(0, 3).map((item, idx) => /* @__PURE__ */ React.createElement("li", { key: idx, className: `flex items-start gap-3 text-sm ${isDarkTheme ? "text-gray-300" : "text-gray-700"}` }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-check-circle mt-1 text-emerald-500" }), /* @__PURE__ */ React.createElement("span", { className: "leading-6" }, item))))))), /* @__PURE__ */ React.createElement("div", { className: "space-y-6" }, /* @__PURE__ */ React.createElement("div", { className: `rounded-xl border p-5 ${isDarkTheme ? "bg-gray-950 border-gray-800" : "bg-white border-gray-200"}` }, /* @__PURE__ */ React.createElement("div", { className: "flex items-center gap-2 mb-3" }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-satellite-dish text-blue-600" }), /* @__PURE__ */ React.createElement("h4", { className: `text-lg font-semibold ${isDarkTheme ? "text-gray-100" : "text-gray-900"}` }, "Control Signals")), /* @__PURE__ */ React.createElement("div", { className: "grid grid-cols-2 gap-3" }, /* @__PURE__ */ React.createElement("div", { className: `rounded-lg border px-3 py-3 ${isDarkTheme ? "bg-slate-900 border-slate-800" : "bg-slate-50 border-slate-200"}` }, /* @__PURE__ */ React.createElement("div", { className: `text-xs uppercase tracking-wide ${isDarkTheme ? "text-blue-300" : "text-blue-700"}` }, "Evidence Steps"), /* @__PURE__ */ React.createElement("div", { className: `mt-1 text-2xl font-bold ${isDarkTheme ? "text-gray-100" : "text-gray-900"}` }, (_t2 = (_s2 = summaryData.trend_signals) == null ? void 0 : _s2.evidence_steps) != null ? _t2 : 0)), /* @__PURE__ */ React.createElement("div", { className: `rounded-lg border px-3 py-3 ${isDarkTheme ? "bg-slate-900 border-slate-800" : "bg-slate-50 border-slate-200"}` }, /* @__PURE__ */ React.createElement("div", { className: `text-xs uppercase tracking-wide ${isDarkTheme ? "text-emerald-300" : "text-emerald-700"}` }, "High Priority Recs"), /* @__PURE__ */ React.createElement("div", { className: `mt-1 text-2xl font-bold ${isDarkTheme ? "text-gray-100" : "text-gray-900"}` }, (_v2 = (_u2 = summaryData.trend_signals) == null ? void 0 : _u2.high_priority_recommendations) != null ? _v2 : 0)), /* @__PURE__ */ React.createElement("div", { className: `rounded-lg border px-3 py-3 ${isDarkTheme ? "bg-slate-900 border-slate-800" : "bg-slate-50 border-slate-200"}` }, /* @__PURE__ */ React.createElement("div", { className: `text-xs uppercase tracking-wide ${isDarkTheme ? "text-amber-300" : "text-amber-700"}` }, "Use Case Categories"), /* @__PURE__ */ React.createElement("div", { className: `mt-1 text-2xl font-bold ${isDarkTheme ? "text-gray-100" : "text-gray-900"}` }, ((_x2 = (_w2 = summaryData.stats) == null ? void 0 : _w2.categories) == null ? void 0 : _x2.length) || 0)), /* @__PURE__ */ React.createElement("div", { className: `rounded-lg border px-3 py-3 ${isDarkTheme ? "bg-slate-900 border-slate-800" : "bg-slate-50 border-slate-200"}` }, /* @__PURE__ */ React.createElement("div", { className: `text-xs uppercase tracking-wide ${isDarkTheme ? "text-orange-300" : "text-orange-700"}` }, "Unclassified Data"), /* @__PURE__ */ React.createElement("div", { className: `mt-1 text-2xl font-bold ${isDarkTheme ? "text-gray-100" : "text-gray-900"}` }, ((_y2 = summaryData.stats) == null ? void 0 : _y2.unknown_items) || 0))), trendDomainEntries.length > 0 && /* @__PURE__ */ React.createElement("div", { className: "mt-4 flex flex-wrap gap-2" }, trendDomainEntries.map(([domain, count]) => /* @__PURE__ */ React.createElement("span", { key: domain, className: `inline-flex items-center rounded-full border px-2.5 py-1 text-xs ${isDarkTheme ? "bg-gray-900 border-gray-700 text-gray-200" : "bg-gray-50 border-gray-200 text-gray-700"}` }, /* @__PURE__ */ React.createElement("span", { className: "font-semibold mr-2" }, domain.replace(/_/g, " ")), /* @__PURE__ */ React.createElement("span", null, count)))), (((_z2 = riskAreasSection == null ? void 0 : riskAreasSection.items) == null ? void 0 : _z2.length) > 0 || coverageGapItems.length > 0) && /* @__PURE__ */ React.createElement("div", { className: `mt-4 rounded-lg border px-4 py-3 ${isDarkTheme ? "bg-slate-900 border-slate-800" : "bg-slate-50 border-slate-200"}` }, /* @__PURE__ */ React.createElement("div", { className: `text-xs font-semibold uppercase tracking-wide ${isDarkTheme ? "text-red-300" : "text-red-700"}` }, "Control Pressure"), /* @__PURE__ */ React.createElement("ul", { className: "mt-2 space-y-2" }, (((_A2 = riskAreasSection == null ? void 0 : riskAreasSection.items) == null ? void 0 : _A2.length) ? riskAreasSection.items : coverageGapItems.map((gap) => gap.gap)).slice(0, 3).map((item, idx) => /* @__PURE__ */ React.createElement("li", { key: idx, className: `text-sm leading-6 ${isDarkTheme ? "text-gray-300" : "text-gray-700"}` }, item))))), /* @__PURE__ */ React.createElement("div", { className: `rounded-xl border p-5 ${isDarkTheme ? "bg-gray-950 border-gray-800" : "bg-white border-gray-200"}` }, /* @__PURE__ */ React.createElement("div", { className: "flex items-center gap-2 mb-3" }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-sync-alt text-purple-600" }), /* @__PURE__ */ React.createElement("h4", { className: `text-lg font-semibold ${isDarkTheme ? "text-gray-100" : "text-gray-900"}` }, "Next Review Loop")), /* @__PURE__ */ React.createElement("ul", { className: "space-y-3" }, (((_B2 = nextLoopSection == null ? void 0 : nextLoopSection.items) == null ? void 0 : _B2.length) ? nextLoopSection.items : ["No explicit re-check loop was extracted from this summary."]).slice(0, 5).map((item, idx) => /* @__PURE__ */ React.createElement("li", { key: idx, className: `flex items-start gap-3 text-sm ${isDarkTheme ? "text-gray-300" : "text-gray-700"}` }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-arrow-rotate-right mt-1 text-purple-500" }), /* @__PURE__ */ React.createElement("span", { className: "leading-6" }, item)))), summaryData.recursive_investigations && summaryData.recursive_investigations.length > 0 && /* @__PURE__ */ React.createElement("div", { className: "mt-4 space-y-2" }, summaryData.recursive_investigations.slice(0, 2).map((loop, idx) => /* @__PURE__ */ React.createElement("div", { key: idx, className: `rounded-lg border px-3 py-3 ${isDarkTheme ? "bg-slate-900 border-slate-800" : "bg-slate-50 border-slate-200"}` }, /* @__PURE__ */ React.createElement("div", { className: `text-sm font-semibold ${isDarkTheme ? "text-gray-100" : "text-gray-900"}` }, loop.loop || `Loop ${idx + 1}`), /* @__PURE__ */ React.createElement("div", { className: `mt-1 text-xs ${isDarkTheme ? "text-gray-400" : "text-gray-600"}` }, /* @__PURE__ */ React.createElement("strong", null, "Trigger:"), " ", loop.next_iteration_trigger || "N/A")))))))), summaryData.risk_register && summaryData.risk_register.length > 0 && /* @__PURE__ */ React.createElement("div", { className: `${isDarkTheme ? "bg-red-950 border-red-700" : "bg-red-50 border-red-200"} border rounded-xl p-5` }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-col gap-2 mb-4 sm:flex-row sm:items-end sm:justify-between" }, /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("div", { className: `text-xs font-semibold uppercase tracking-[0.2em] ${isDarkTheme ? "text-red-300" : "text-red-700"}` }, "Executive Attention"), /* @__PURE__ */ React.createElement("h3", { className: `text-lg font-semibold mt-1 flex items-center ${isDarkTheme ? "text-red-200" : "text-red-900"}` }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-shield-alt text-red-600 mr-2" }), "Risk Register (Top ", Math.min(summaryData.risk_register.length, 6), ")")), /* @__PURE__ */ React.createElement("p", { className: `text-sm ${isDarkTheme ? "text-red-300" : "text-red-800"}` }, "These are the control gaps most likely to drive outages, blind spots, or loss of confidence.")), /* @__PURE__ */ React.createElement("div", { className: "space-y-3" }, summaryData.risk_register.slice(0, 6).map((risk, idx) => /* @__PURE__ */ React.createElement("div", { key: idx, className: `${isDarkTheme ? "bg-gray-900 border-red-700" : "bg-white border-red-200"} border rounded-xl p-4` }, /* @__PURE__ */ React.createElement("div", { className: "flex items-start justify-between gap-3" }, /* @__PURE__ */ React.createElement("div", { className: "flex-1" }, /* @__PURE__ */ React.createElement("div", { className: "flex items-center gap-2 mb-1 flex-wrap" }, /* @__PURE__ */ React.createElement("span", { className: `px-2 py-0.5 text-xs font-semibold rounded-full ${String(risk.severity || "").toLowerCase() === "high" ? "bg-red-600 text-white" : String(risk.severity || "").toLowerCase() === "critical" ? "bg-red-700 text-white" : String(risk.severity || "").toLowerCase() === "medium" ? "bg-orange-700 text-white" : "bg-gray-500 text-white"}` }, (risk.severity || "medium").toString().toUpperCase()), /* @__PURE__ */ React.createElement("span", { className: `text-xs ${isDarkTheme ? "text-gray-400" : "text-gray-500"}` }, risk.domain || "general")), /* @__PURE__ */ React.createElement("p", { className: `font-semibold ${isDarkTheme ? "text-gray-100" : "text-gray-900"}` }, risk.risk || "Operational risk"), risk.impact && /* @__PURE__ */ React.createElement("p", { className: `text-sm mt-1 leading-6 ${isDarkTheme ? "text-gray-300" : "text-gray-700"}` }, risk.impact)), /* @__PURE__ */ React.createElement("div", { className: "flex flex-col gap-2 sm:items-end" }, /* @__PURE__ */ React.createElement(
        "button",
        {
          type: "button",
          onClick: () => focusRiskControlPath(risk),
          className: "px-3 py-1.5 bg-red-600 hover:bg-red-700 text-white text-xs rounded"
        },
        "Open Control Path"
      ), /* @__PURE__ */ React.createElement(
        "button",
        {
          type: "button",
          onClick: () => focusQueriesForRisk(risk),
          className: "px-3 py-1.5 bg-indigo-600 hover:bg-indigo-700 text-white text-xs rounded"
        },
        "Open Validation Queries"
      ), /* @__PURE__ */ React.createElement(
        "button",
        {
          type: "button",
          onClick: () => launchChatInvestigation(
            buildRiskInvestigationPrompt(risk),
            { freshContext: true }
          ),
          className: `px-3 py-1.5 text-xs font-medium rounded border transition-colors ${isDarkTheme ? "border-red-700 bg-red-950 text-red-100 hover:bg-red-900" : "border-red-700 bg-red-700 text-white hover:bg-red-800"}`
        },
        "Investigate in Chat"
      ))))))), unknownDataItems.length > 0 && /* @__PURE__ */ React.createElement("div", { className: `${isDarkTheme ? "bg-gray-900 border-orange-700" : "bg-orange-50 border-orange-200"} border rounded-xl p-5` }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-col gap-4 md:flex-row md:items-start md:justify-between" }, /* @__PURE__ */ React.createElement("div", { className: "max-w-3xl" }, /* @__PURE__ */ React.createElement("div", { className: `text-xs font-semibold uppercase tracking-[0.2em] ${isDarkTheme ? "text-orange-300" : "text-orange-700"}` }, "Control Validation Queue"), /* @__PURE__ */ React.createElement("h3", { className: `text-xl font-semibold mt-1 flex items-center ${isDarkTheme ? "text-gray-100" : "text-gray-900"}` }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-layer-group text-orange-500 mr-2" }), "Classify Unclear Data Sources (", unknownDataItems.length, ")"), /* @__PURE__ */ React.createElement("p", { className: `text-sm mt-2 leading-6 ${isDarkTheme ? "text-gray-300" : "text-gray-700"}` }, "The summary artifact already knows these entities are weakly understood. Use this queue to decide ownership, business value, and whether they deserve monitoring or control coverage.")), unknownDataItems.length > 4 && /* @__PURE__ */ React.createElement(
        "button",
        {
          type: "button",
          onClick: () => setShowAllUnknownData((current) => !current),
          className: `inline-flex items-center justify-center rounded-lg px-4 py-2 text-sm font-medium transition-colors ${isDarkTheme ? "bg-orange-900 text-orange-100 hover:bg-orange-800" : "bg-white text-orange-800 hover:bg-orange-100 border border-orange-200"}`
        },
        showAllUnknownData ? "Show Fewer" : `Show All ${unknownDataItems.length}`
      )), /* @__PURE__ */ React.createElement("div", { className: "mt-5 grid gap-4 lg:grid-cols-2" }, visibleUnknownData.map((item, idx) => {
        var _a3, _b3;
        return /* @__PURE__ */ React.createElement("div", { key: `${item.name || "unknown"}-${idx}`, className: `${isDarkTheme ? "border-orange-700 bg-gray-950" : "border-orange-200 bg-white"} border rounded-xl p-4` }, /* @__PURE__ */ React.createElement("div", { className: "flex items-start justify-between gap-3" }, /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("div", { className: "flex flex-wrap items-center gap-2 mb-2" }, /* @__PURE__ */ React.createElement("span", { className: `inline-flex items-center rounded-full px-2.5 py-1 text-xs font-semibold ${isDarkTheme ? "bg-orange-900 text-orange-100" : "bg-orange-100 text-orange-800"}` }, item.type === "index" ? "Index" : "Sourcetype"), ((_a3 = item.context) == null ? void 0 : _a3.volume_category) && /* @__PURE__ */ React.createElement("span", { className: `inline-flex items-center rounded-full px-2.5 py-1 text-xs border ${isDarkTheme ? "bg-gray-900 border-gray-700 text-gray-200" : "bg-gray-50 border-gray-200 text-gray-700"}` }, formatVolumeCategory(item.context.volume_category), " signal"), ((_b3 = item.context) == null ? void 0 : _b3.has_significant_data) && /* @__PURE__ */ React.createElement("span", { className: `inline-flex items-center rounded-full px-2.5 py-1 text-xs border ${isDarkTheme ? "bg-emerald-950 border-emerald-800 text-emerald-200" : "bg-emerald-50 border-emerald-200 text-emerald-700"}` }, "Significant telemetry")), /* @__PURE__ */ React.createElement("h4", { className: `text-base font-semibold ${isDarkTheme ? "text-gray-100" : "text-gray-900"}` }, /* @__PURE__ */ React.createElement("code", { className: `px-2 py-1 rounded text-sm ${isDarkTheme ? "bg-gray-900 text-orange-200" : "bg-orange-50 text-gray-900"}` }, item.name || "unknown")))), /* @__PURE__ */ React.createElement("p", { className: `mt-3 text-sm leading-6 ${isDarkTheme ? "text-gray-300" : "text-gray-700"}` }, item.question || `Classify and validate ${item.name || "this entity"} before it becomes an unmanaged blind spot.`), Array.isArray(item.suggestions) && item.suggestions.length > 0 && /* @__PURE__ */ React.createElement("div", { className: "mt-4" }, /* @__PURE__ */ React.createElement("div", { className: `text-xs font-semibold uppercase tracking-wide ${isDarkTheme ? "text-gray-400" : "text-gray-500"}` }, "Likely Classifications"), /* @__PURE__ */ React.createElement("div", { className: "mt-2 grid gap-2 sm:grid-cols-2" }, item.suggestions.slice(0, 2).map((suggestion, suggestionIdx) => /* @__PURE__ */ React.createElement("div", { key: `${suggestion.value || suggestion.label || "suggestion"}-${suggestionIdx}`, className: `${isDarkTheme ? "bg-gray-900 border-gray-800" : "bg-gray-50 border-gray-200"} border rounded-lg px-3 py-2` }, /* @__PURE__ */ React.createElement("div", { className: `text-sm font-medium ${isDarkTheme ? "text-gray-100" : "text-gray-900"}` }, suggestion.label), suggestion.description && /* @__PURE__ */ React.createElement("div", { className: `text-xs mt-1 leading-5 ${isDarkTheme ? "text-gray-400" : "text-gray-600"}` }, suggestion.description))))), /* @__PURE__ */ React.createElement("div", { className: "mt-4 flex flex-wrap gap-2" }, /* @__PURE__ */ React.createElement(
          "button",
          {
            onClick: () => {
              var _a4, _b4;
              return launchChatInvestigation(
                `Help me classify this Splunk ${item.type || "entity"} and decide whether it needs monitoring coverage.

Name: ${item.name || "unknown"}
Question: ${item.question || "Classify this data source"}
Likely categories: ${Array.isArray(item.suggestions) ? item.suggestions.slice(0, 3).map((suggestion) => suggestion.label).join(", ") : "unknown"}
Volume signal: ${formatVolumeCategory((_a4 = item.context) == null ? void 0 : _a4.volume_category)}${((_b4 = item.context) == null ? void 0 : _b4.has_significant_data) ? "\nThis entity appears to have significant data." : ""}`,
                { freshContext: true }
              );
            },
            className: "px-3 py-1.5 bg-orange-700 hover:bg-orange-800 text-white text-xs font-medium rounded transition-colors"
          },
          "Investigate in Chat"
        ), /* @__PURE__ */ React.createElement(
          "button",
          {
            onClick: () => launchChatInvestigation(
              buildUnknownEntityValidationChatPrompt(item),
              {
                freshContext: true,
                investigationMode: "unknown_entity_context_builder"
              }
            ),
            className: "px-3 py-1.5 bg-indigo-600 hover:bg-indigo-700 text-white text-xs rounded"
          },
          "Build Validation Query"
        )));
      })), unknownHiddenCount > 0 && !showAllUnknownData && /* @__PURE__ */ React.createElement("p", { className: `mt-4 text-sm text-center ${isDarkTheme ? "text-gray-400" : "text-gray-500"}` }, unknownHiddenCount, " more item(s) remain in the queue.")));
    };
    const renderReportViewerPanel = () => {
      var _a2, _b2;
      if (!hasSelectedReport) {
        return null;
      }
      const viewerLabel = isArtifactsTab ? "Discovery Output Viewer" : isMissionDiscoveryActive ? "Selected Report Focus" : "Report Focus";
      const selectedReportType = String((selectedWorkspaceReportRecord == null ? void 0 : selectedWorkspaceReportRecord.type) || (reportContent == null ? void 0 : reportContent.type) || "file").toUpperCase();
      const selectedReportSize = (_b2 = (_a2 = selectedWorkspaceReportRecord == null ? void 0 : selectedWorkspaceReportRecord.size_bytes) != null ? _a2 : selectedWorkspaceReportRecord == null ? void 0 : selectedWorkspaceReportRecord.size) != null ? _b2 : null;
      const selectedReportModifiedAt = (selectedWorkspaceReportRecord == null ? void 0 : selectedWorkspaceReportRecord.modified_at) || (selectedWorkspaceReportRecord == null ? void 0 : selectedWorkspaceReportRecord.modified) || null;
      const reportSplQueries = Array.isArray(reportContent == null ? void 0 : reportContent.spl_queries) ? reportContent.spl_queries : [];
      const reportContextExcerpt = (reportContent == null ? void 0 : reportContent.type) === "text" ? String((reportContent == null ? void 0 : reportContent.content) || "").slice(0, 900) : "";
      return /* @__PURE__ */ React.createElement("div", { className: `rounded-lg shadow-sm border ${panelClass}` }, /* @__PURE__ */ React.createElement("div", { className: `p-6 border-b ${isDarkTheme ? "border-gray-700" : "border-gray-200"}` }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-col gap-4 xl:flex-row xl:items-start xl:justify-between" }, /* @__PURE__ */ React.createElement("div", { className: "min-w-0" }, /* @__PURE__ */ React.createElement("div", { className: `text-[11px] uppercase tracking-[0.18em] ${mutedTextClass}` }, viewerLabel), /* @__PURE__ */ React.createElement("h3", { className: `mt-2 text-lg font-medium break-all ${headingClass}` }, selectedReport), /* @__PURE__ */ React.createElement("div", { className: `mt-2 flex flex-wrap items-center gap-2 text-xs ${mutedTextClass}` }, /* @__PURE__ */ React.createElement("span", { className: `inline-flex items-center rounded-full px-2.5 py-1 border ${isDarkTheme ? "bg-gray-900 border-gray-700 text-gray-200" : "bg-gray-50 border-gray-200 text-gray-700"}` }, selectedReportType), selectedReportSize != null && /* @__PURE__ */ React.createElement("span", null, (selectedReportSize / 1024).toFixed(1), " KB"), selectedReportModifiedAt && /* @__PURE__ */ React.createElement("span", null, new Date(selectedReportModifiedAt).toLocaleString()))), /* @__PURE__ */ React.createElement("div", { className: "flex items-center gap-3" }, reportContent.type === "image" && /* @__PURE__ */ React.createElement(
        "button",
        {
          type: "button",
          onClick: () => setIsReportFullViewOpen(true),
          className: "text-indigo-600 hover:text-indigo-800"
        },
        /* @__PURE__ */ React.createElement("i", { className: "fas fa-expand mr-1" }),
        "Full View"
      ), /* @__PURE__ */ React.createElement(
        "button",
        {
          type: "button",
          onClick: () => downloadReportArtifact(selectedReport, reportContent),
          className: "text-indigo-600 hover:text-indigo-800"
        },
        /* @__PURE__ */ React.createElement("i", { className: "fas fa-download mr-1" }),
        "Export"
      )))), /* @__PURE__ */ React.createElement(
        "div",
        {
          className: "p-6 overflow-y-auto scroll-container",
          style: { height: `${reportViewerHeight}px` }
        },
        reportSplQueries.length > 0 && /* @__PURE__ */ React.createElement("div", { className: "mb-6 space-y-3", "data-testid": "report-viewer-spl-blocks" }, /* @__PURE__ */ React.createElement("div", { className: `rounded-lg border px-4 py-3 ${panelMutedClass}` }, /* @__PURE__ */ React.createElement("div", { className: `text-sm font-medium ${headingClass}` }, "Detected SPL Blocks"), /* @__PURE__ */ React.createElement("div", { className: `mt-1 text-xs ${subtextClass}` }, "Save report-visible SPL into the context library, open it in Splunk Web, or bring it into chat.")), reportSplQueries.map((splQuery, splIndex) => /* @__PURE__ */ React.createElement("div", { key: `${selectedReport || "report"}-spl-${splIndex}`, "data-testid": "report-viewer-spl-card", className: `rounded-lg border px-4 py-3 ${isDarkTheme ? "bg-gray-900 border-gray-700" : "bg-white border-gray-300"}` }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-col gap-2 sm:flex-row sm:items-start sm:justify-between" }, /* @__PURE__ */ React.createElement("div", { className: `text-xs font-semibold uppercase tracking-wide ${mutedTextClass}` }, "SPL Block ", splIndex + 1), renderSplQueryActionButtons2(splQuery, {
          originKind: "report_viewer",
          originLabel: selectedReport || "Report Viewer",
          sourceLabel: selectedReport || "Report Viewer",
          contextExcerpt: reportContextExcerpt,
          className: "sm:justify-end"
        })), /* @__PURE__ */ React.createElement("pre", { className: `mt-3 max-h-40 overflow-auto rounded-lg border px-3 py-3 text-xs whitespace-pre-wrap font-mono ${isDarkTheme ? "bg-gray-950 border-gray-700 text-gray-100" : "bg-gray-50 border-gray-200 text-gray-900"}` }, splQuery)))),
        reportContent.type === "image" ? /* @__PURE__ */ React.createElement("div", { className: "h-full flex flex-col gap-4" }, /* @__PURE__ */ React.createElement("div", { className: `text-xs uppercase tracking-[0.18em] ${mutedTextClass}` }, isInfographicArtifact(selectedReport) ? "Summary infographic preview" : "Image preview"), /* @__PURE__ */ React.createElement("div", { className: `flex-1 min-h-[320px] rounded-2xl border p-4 ${isDarkTheme ? "bg-gray-950 border-gray-700" : "bg-slate-50 border-gray-200"}` }, /* @__PURE__ */ React.createElement(
          "img",
          {
            src: buildReportImageSrc(reportContent),
            alt: selectedReport,
            className: "h-full w-full object-contain rounded-xl shadow-lg"
          }
        ))) : reportContent.type === "json" ? /* @__PURE__ */ React.createElement("pre", { className: `text-sm whitespace-pre-wrap font-mono ${isDarkTheme ? "text-gray-100" : "text-gray-800"}` }, JSON.stringify(reportContent.content, null, 2)) : /* @__PURE__ */ React.createElement("div", { className: "prose prose-sm max-w-none" }, /* @__PURE__ */ React.createElement("pre", { className: `text-sm whitespace-pre-wrap font-sans leading-relaxed break-words ${isDarkTheme ? "text-gray-100" : "text-gray-800"}` }, reportContent.content))
      ), /* @__PURE__ */ React.createElement(
        "div",
        {
          className: `h-2 border-t cursor-ns-resize flex items-center justify-center group ${isDarkTheme ? "bg-gray-700 border-gray-600 hover:bg-gray-600" : "bg-gray-100 border-gray-200 hover:bg-gray-200"}`,
          onMouseDown: handleReportMouseDown
        },
        /* @__PURE__ */ React.createElement("div", { className: "w-12 h-1 bg-gray-400 rounded group-hover:bg-gray-500" })
      ));
    };
    const renderArtifactEmptyState = () => /* @__PURE__ */ React.createElement("div", { className: `rounded-lg shadow-sm border p-8 ${panelClass}` }, /* @__PURE__ */ React.createElement("div", { className: "max-w-2xl" }, /* @__PURE__ */ React.createElement("div", { className: `text-[11px] uppercase tracking-[0.18em] ${mutedTextClass}` }, "Discovery Workspace"), /* @__PURE__ */ React.createElement("h3", { className: `mt-2 text-xl font-semibold ${headingClass}` }, "Select a discovery output to inspect it alongside the live log"), /* @__PURE__ */ React.createElement("p", { className: `mt-3 text-sm leading-6 ${subtextClass}` }, "The report library stays pinned in the smallest column while the main canvas focuses on the current output or the active discovery run."), /* @__PURE__ */ React.createElement("div", { className: "mt-5 grid gap-3 sm:grid-cols-3" }, /* @__PURE__ */ React.createElement("div", { className: `rounded-xl border p-4 ${isDarkTheme ? "bg-gray-900 border-gray-700" : "bg-gray-50 border-gray-200"}` }, /* @__PURE__ */ React.createElement("div", { className: `text-xs uppercase tracking-wide ${mutedTextClass}` }, "Available"), /* @__PURE__ */ React.createElement("div", { className: `mt-2 text-2xl font-semibold ${headingClass}` }, reports.length || 0), /* @__PURE__ */ React.createElement("div", { className: `mt-1 text-xs ${subtextClass}` }, "Generated reports ready to inspect")), /* @__PURE__ */ React.createElement("div", { className: `rounded-xl border p-4 ${isDarkTheme ? "bg-gray-900 border-gray-700" : "bg-gray-50 border-gray-200"}` }, /* @__PURE__ */ React.createElement("div", { className: `text-xs uppercase tracking-wide ${mutedTextClass}` }, "Formats"), /* @__PURE__ */ React.createElement("div", { className: `mt-2 text-sm font-semibold ${headingClass}` }, "Markdown, JSON, Image"), /* @__PURE__ */ React.createElement("div", { className: `mt-1 text-xs ${subtextClass}` }, "Preview images inline or inspect generated text and structured output directly")), /* @__PURE__ */ React.createElement("div", { className: `rounded-xl border p-4 ${isDarkTheme ? "bg-gray-900 border-gray-700" : "bg-gray-50 border-gray-200"}` }, /* @__PURE__ */ React.createElement("div", { className: `text-xs uppercase tracking-wide ${mutedTextClass}` }, "Workflow"), /* @__PURE__ */ React.createElement("div", { className: `mt-2 text-sm font-semibold ${headingClass}` }, "Run, inspect, export"), /* @__PURE__ */ React.createElement("div", { className: `mt-1 text-xs ${subtextClass}` }, "Start discovery, move across the workspace, and use the header monitor to jump back into the live run")))));
    const renderDiscoveryReportLibraryPanel = () => /* @__PURE__ */ React.createElement("div", { className: `rounded-lg shadow-sm border overflow-hidden min-w-0 lg:flex lg:max-h-[calc(100vh-8.5rem)] lg:flex-col ${panelClass}` }, /* @__PURE__ */ React.createElement("div", { className: `p-6 border-b ${isDarkTheme ? "border-gray-700" : "border-gray-200"}` }, /* @__PURE__ */ React.createElement("div", { className: "flex justify-between items-center gap-3" }, /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("h2", { className: `text-lg font-medium ${headingClass}` }, "Discovery Report Library"), /* @__PURE__ */ React.createElement("p", { className: `text-xs mt-1 ${mutedTextClass}` }, sessionCatalog.length, " discovery session(s)")), /* @__PURE__ */ React.createElement(
      "button",
      {
        type: "button",
        onClick: refreshArtifactsWorkspace,
        className: "text-indigo-600 hover:text-indigo-800",
        "aria-label": "Refresh generated reports"
      },
      /* @__PURE__ */ React.createElement("i", { className: "fas fa-refresh" })
    ))), /* @__PURE__ */ React.createElement("div", { className: `divide-y overflow-x-hidden min-w-0 lg:flex-1 lg:overflow-y-auto ${isDarkTheme ? "divide-gray-700" : "divide-gray-200"}` }, reports.length === 0 ? /* @__PURE__ */ React.createElement("p", { className: `p-6 text-center ${mutedTextClass}` }, "No reports generated yet") : (() => {
      const hierarchy = groupReportsByHierarchy(reports);
      return Object.entries(hierarchy).sort((a, b) => b[1].year - a[1].year).map(([yearKey, yearData]) => /* @__PURE__ */ React.createElement("div", { key: yearKey }, yearData.visible && /* @__PURE__ */ React.createElement(
        "button",
        {
          type: "button",
          "data-testid": "discovery-report-year-toggle",
          className: `w-full p-3 border-b text-left font-semibold ${isDarkTheme ? "bg-indigo-900 border-gray-700 hover:bg-indigo-800" : "bg-gradient-to-r from-indigo-100 to-purple-100 border-gray-200"}`,
          onClick: () => toggleYear(yearKey),
          "aria-expanded": !!expandedYears[yearKey]
        },
        /* @__PURE__ */ React.createElement("div", { className: "flex items-center" }, /* @__PURE__ */ React.createElement("i", { className: `fas ${expandedYears[yearKey] ? "fa-chevron-down" : "fa-chevron-right"} mr-2 text-xs ${isDarkTheme ? "text-indigo-200" : "text-indigo-600"}` }), /* @__PURE__ */ React.createElement("span", { className: `text-sm ${isDarkTheme ? "text-indigo-100" : "text-indigo-900"}` }, yearData.display))
      ), (!yearData.visible || expandedYears[yearKey]) && Object.entries(yearData.months).sort((a, b) => b[1].month - a[1].month).map(([monthKey, monthData]) => /* @__PURE__ */ React.createElement("div", { key: monthKey }, monthData.visible && /* @__PURE__ */ React.createElement(
        "button",
        {
          type: "button",
          "data-testid": "discovery-report-month-toggle",
          className: `w-full p-3 border-b text-left ${isDarkTheme ? "bg-blue-900 border-gray-700 hover:bg-blue-800" : "bg-gradient-to-r from-blue-50 to-indigo-50 border-gray-200"}`,
          onClick: () => toggleMonth(monthKey),
          style: { paddingLeft: yearData.visible ? "1.5rem" : "0.75rem" },
          "aria-expanded": !!expandedMonths[monthKey]
        },
        /* @__PURE__ */ React.createElement("div", { className: "flex items-center" }, /* @__PURE__ */ React.createElement("i", { className: `fas ${expandedMonths[monthKey] ? "fa-chevron-down" : "fa-chevron-right"} mr-2 text-xs ${isDarkTheme ? "text-blue-200" : "text-blue-600"}` }), /* @__PURE__ */ React.createElement("span", { className: `text-sm font-medium ${isDarkTheme ? "text-blue-100" : "text-blue-900"}` }, monthData.display))
      ), (!monthData.visible || expandedMonths[monthKey]) && Object.entries(monthData.days).sort((a, b) => b[1].day - a[1].day).map(([dayKey, dayData]) => /* @__PURE__ */ React.createElement("div", { key: dayKey }, /* @__PURE__ */ React.createElement(
        "button",
        {
          type: "button",
          "data-testid": "discovery-report-day-toggle",
          className: `w-full p-3 border-b text-left ${dayData.isToday ? isDarkTheme ? "bg-green-900" : "bg-green-50" : isDarkTheme ? "bg-gray-800" : "bg-gray-50"} ${isDarkTheme ? "hover:bg-gray-700 border-gray-700" : "hover:bg-gray-100 border-gray-200"}`,
          onClick: () => toggleDay(dayKey),
          style: { paddingLeft: monthData.visible ? yearData.visible ? "3rem" : "1.5rem" : yearData.visible ? "1.5rem" : "0.75rem" },
          "aria-expanded": !!expandedDays[dayKey]
        },
        /* @__PURE__ */ React.createElement("div", { className: "flex items-center" }, /* @__PURE__ */ React.createElement("i", { className: `fas ${expandedDays[dayKey] ? "fa-chevron-down" : "fa-chevron-right"} mr-2 text-xs ${dayData.isToday ? isDarkTheme ? "text-green-200" : "text-green-600" : mutedTextClass}` }), /* @__PURE__ */ React.createElement("span", { className: `text-sm ${dayData.isToday ? isDarkTheme ? "text-green-100 font-semibold" : "text-green-900 font-semibold" : isDarkTheme ? "text-gray-100 font-medium" : "text-gray-900 font-medium"}` }, dayData.display), /* @__PURE__ */ React.createElement("span", { className: `ml-2 text-xs ${mutedTextClass}` }, "(", dayData.sessions.length, ")"))
      ), expandedDays[dayKey] && dayData.sessions.map((session) => {
        const summaryArtifact = (session.reports || []).find((report) => isSummaryArtifact(report.name));
        return /* @__PURE__ */ React.createElement("div", { key: session.timestamp }, /* @__PURE__ */ React.createElement(
          "div",
          {
            "data-testid": "discovery-report-session-toggle",
            className: `p-4 border-b cursor-pointer transition-colors overflow-hidden ${isDarkTheme ? "bg-gray-800 hover:bg-gray-700 border-gray-700" : "bg-white hover:bg-gray-50 border-gray-200"}`,
            onClick: () => toggleSession(session.timestamp),
            onKeyDown: (event2) => handleKeyActivate(event2, () => toggleSession(session.timestamp)),
            style: { paddingLeft: monthData.visible ? yearData.visible ? "3rem" : "2rem" : yearData.visible ? "2rem" : "1.25rem" },
            role: "button",
            tabIndex: 0,
            "aria-expanded": !!expandedSessions[session.timestamp]
          },
          /* @__PURE__ */ React.createElement("div", { className: "flex flex-col gap-2" }, /* @__PURE__ */ React.createElement("div", { className: "flex items-start flex-1 min-w-0" }, /* @__PURE__ */ React.createElement("i", { className: `fas ${expandedSessions[session.timestamp] ? "fa-chevron-down" : "fa-chevron-right"} mr-3 text-xs mt-1 ${mutedTextClass}` }), /* @__PURE__ */ React.createElement("div", { className: "flex-1 min-w-0" }, /* @__PURE__ */ React.createElement("h3", { className: `text-sm font-semibold mb-1 tracking-wide ${headingClass}` }, formatSessionTime(session.timestamp)), /* @__PURE__ */ React.createElement("div", { className: `flex items-center gap-2 text-xs flex-wrap ${mutedTextClass}` }, /* @__PURE__ */ React.createElement("span", { className: `flex items-center px-2 py-0.5 rounded ${isDarkTheme ? "bg-gray-700 text-gray-300" : "bg-gray-100 text-gray-600"}` }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-file-alt mr-1" }), session.reports.length, " reports"), session.hasSummary && /* @__PURE__ */ React.createElement("span", { className: `flex items-center px-2 py-0.5 rounded-full font-medium ${isDarkTheme ? "bg-emerald-900 text-emerald-100 border border-emerald-700" : "bg-emerald-100 text-emerald-800 border border-emerald-200"}` }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-check-circle mr-1" }), "Summarized"), (summaryArtifact == null ? void 0 : summaryArtifact.modified) && /* @__PURE__ */ React.createElement("span", { className: `hidden xl:flex items-center px-2 py-0.5 rounded ${isDarkTheme ? "bg-gray-700 text-gray-400" : "bg-gray-100 text-gray-500"}` }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-clock mr-1" }), new Date(summaryArtifact.modified).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }))))), /* @__PURE__ */ React.createElement("div", { className: "flex items-center w-full" }, /* @__PURE__ */ React.createElement(
            "button",
            {
              onClick: (e) => {
                e.stopPropagation();
                openSummaryModal(session.timestamp, { hasSummary: session.hasSummary });
              },
              className: `w-full text-xs px-3 py-1.5 rounded-md font-medium inline-flex justify-center items-center space-x-1 whitespace-nowrap shadow-sm transition-colors ${session.hasSummary ? "bg-emerald-600 hover:bg-emerald-700 text-white" : "bg-indigo-600 hover:bg-indigo-700 text-white"}`,
              title: session.hasSummary ? "View saved summary" : "Generate summary with LLM"
            },
            /* @__PURE__ */ React.createElement("i", { className: `fas ${session.hasSummary ? "fa-eye" : "fa-magic"}` }),
            /* @__PURE__ */ React.createElement("span", null, session.hasSummary ? "View Summary" : "Summarize")
          )))
        ), expandedSessions[session.timestamp] && /* @__PURE__ */ React.createElement("div", { className: `divide-y ${isDarkTheme ? "divide-gray-700" : "divide-gray-100"}` }, session.reports.map((report) => /* @__PURE__ */ React.createElement(
          "div",
          {
            key: report.name,
            "data-testid": "discovery-report-row",
            className: `p-4 cursor-pointer ${isDarkTheme ? "hover:bg-gray-700" : "hover:bg-gray-50"} ${selectedReport === report.name ? isDarkTheme ? "bg-indigo-900 border-r-4 border-indigo-400" : "bg-indigo-50 border-r-4 border-indigo-500" : ""}`,
            onClick: () => loadReport(report.name),
            onKeyDown: (event2) => handleKeyActivate(event2, () => loadReport(report.name)),
            style: { paddingLeft: monthData.visible ? yearData.visible ? "4rem" : "3rem" : yearData.visible ? "3rem" : "2rem" },
            role: "button",
            tabIndex: 0
          },
          /* @__PURE__ */ React.createElement("div", { className: "flex items-center justify-between gap-2 min-w-0" }, /* @__PURE__ */ React.createElement("div", { className: "flex-1 min-w-0" }, /* @__PURE__ */ React.createElement("p", { className: `text-sm font-medium truncate ${headingClass}`, title: report.name }, report.name.replace(/_[0-9]{8}_[0-9]{6}/, "")), /* @__PURE__ */ React.createElement("p", { className: `text-xs ${mutedTextClass}` }, (report.size / 1024).toFixed(1), " KB")), /* @__PURE__ */ React.createElement("div", { className: "flex items-center space-x-2 shrink-0" }, /* @__PURE__ */ React.createElement("span", { className: `px-2 py-1 text-xs rounded ${report.type === "json" ? isDarkTheme ? "bg-blue-900 text-blue-100" : "bg-blue-100 text-blue-800" : isDarkTheme ? "bg-green-900 text-green-100" : "bg-green-100 text-green-800"}` }, report.type.toUpperCase())))
        ))));
      })))))));
    })()));
    return /* @__PURE__ */ React.createElement("div", { className: `min-h-screen ${isDarkTheme ? "bg-gray-900 text-gray-100" : "bg-gray-50 text-gray-900"}` }, /* @__PURE__ */ React.createElement("header", { ref: headerRef, className: `${isDarkTheme ? "bg-gray-800 border-gray-700" : "bg-white border-gray-200"} sticky top-0 z-50 shadow-sm border-b` }, /* @__PURE__ */ React.createElement("div", { className: `${workspaceShellWidthClass} mx-auto px-4 sm:px-6 lg:px-8` }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-wrap lg:flex-nowrap justify-between items-center gap-3 py-2 sm:py-3" }, /* @__PURE__ */ React.createElement("div", { className: "flex items-center" }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-search text-xl sm:text-2xl text-indigo-600 mr-2 sm:mr-3" }), /* @__PURE__ */ React.createElement("h1", { className: `text-lg sm:text-xl font-semibold ${isDarkTheme ? "text-gray-100" : "text-gray-900"}` }, "Splunk MCP Discovery Tool")), /* @__PURE__ */ React.createElement("div", { className: "flex-1 min-w-[320px] flex items-center justify-center" }, /* @__PURE__ */ React.createElement("div", { className: `w-full max-w-3xl rounded-lg px-2 py-1.5 ${isDarkTheme ? "bg-indigo-950/70 border border-indigo-700" : "bg-indigo-50 border border-indigo-200"}` }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-wrap items-center justify-center gap-2" }, /* @__PURE__ */ React.createElement("div", { className: "inline-flex rounded-lg border border-indigo-300 overflow-hidden text-[11px] sm:text-xs bg-indigo-900", role: "tablist", "aria-label": "Workspace views" }, /* @__PURE__ */ React.createElement(
      "button",
      {
        type: "button",
        id: "workspace-tab-mission",
        role: "tab",
        "aria-selected": isMissionTab,
        tabIndex: isMissionTab ? 0 : -1,
        onClick: () => setWorkspaceTab("mission"),
        className: `px-3 sm:px-4 py-1.5 ${isMissionTab ? "bg-white text-indigo-900 font-semibold" : "bg-transparent text-indigo-200 hover:bg-indigo-700"}`,
        title: "Mission tab: readiness, analysis, and action planning"
      },
      "Mission"
    ), /* @__PURE__ */ React.createElement(
      "button",
      {
        type: "button",
        id: "workspace-tab-intelligence",
        role: "tab",
        "aria-selected": isIntelligenceTab,
        tabIndex: isIntelligenceTab ? 0 : -1,
        onClick: () => {
          setWorkspaceTab("intelligence");
          refreshIntelligenceWorkspace();
        },
        className: `px-3 sm:px-4 py-1.5 border-l border-indigo-300 ${isIntelligenceTab ? "bg-white text-indigo-900 font-semibold" : "bg-transparent text-indigo-200 hover:bg-indigo-700"}`,
        title: "Intelligence tab: KPI trends, compare, and persona workflows"
      },
      "Intelligence"
    ), /* @__PURE__ */ React.createElement(
      "button",
      {
        type: "button",
        id: "workspace-tab-discovery",
        "data-testid": "workspace-tab-discovery",
        role: "tab",
        "aria-selected": isArtifactsTab,
        tabIndex: isArtifactsTab ? 0 : -1,
        onClick: openDiscoveryWorkspace,
        className: `px-3 sm:px-4 py-1.5 border-l border-indigo-300 ${isArtifactsTab ? "bg-white text-indigo-900 font-semibold" : "bg-transparent text-indigo-200 hover:bg-indigo-700"}`,
        title: "Discovery tab: pipeline execution, live log, and output viewer"
      },
      "Discovery"
    ), /* @__PURE__ */ React.createElement(
      "button",
      {
        type: "button",
        id: "workspace-tab-context",
        "data-testid": "workspace-tab-context",
        role: "tab",
        "aria-selected": isCapabilitiesRagView,
        tabIndex: isCapabilitiesRagView ? 0 : -1,
        onClick: () => openRagCapabilitiesWorkspace({ libraryFilter: "spl_library" }),
        className: `px-3 sm:px-4 py-1.5 border-l border-indigo-300 ${isCapabilitiesRagView ? "bg-white text-indigo-900 font-semibold" : "bg-transparent text-indigo-200 hover:bg-indigo-700"}`,
        title: "Context tab: managed SPL library and indexed retrieval workspace"
      },
      "Context"
    ), /* @__PURE__ */ React.createElement(
      "button",
      {
        type: "button",
        id: "workspace-tab-capabilities",
        "data-testid": "workspace-tab-capabilities",
        role: "tab",
        "aria-selected": isCapabilitiesOverview,
        tabIndex: isCapabilitiesOverview ? 0 : -1,
        onClick: openCapabilitiesOverview,
        className: `px-3 sm:px-4 py-1.5 border-l border-indigo-300 ${isCapabilitiesOverview ? "bg-white text-indigo-900 font-semibold" : "bg-transparent text-indigo-200 hover:bg-indigo-700"}`,
        title: "Capabilities tab: optional capability packs, health, and control surface"
      },
      "Capabilities"
    ), isChatFullscreen && /* @__PURE__ */ React.createElement(
      "button",
      {
        type: "button",
        id: "workspace-tab-chat",
        role: "tab",
        "aria-selected": isChatTab,
        tabIndex: isChatTab ? 0 : -1,
        onClick: () => {
          setIsChatOpen(false);
          setWorkspaceTab("chat");
        },
        className: `px-3 sm:px-4 py-1.5 border-l border-indigo-300 ${isChatTab ? "bg-white text-indigo-900 font-semibold" : "bg-transparent text-indigo-200 hover:bg-indigo-700"}`,
        title: "Chat tab: full-screen conversation workspace"
      },
      "Chat"
    ), isSummaryFullscreen && /* @__PURE__ */ React.createElement(
      "button",
      {
        type: "button",
        id: "workspace-tab-summary",
        role: "tab",
        "aria-selected": isSummaryTab,
        tabIndex: isSummaryTab ? 0 : -1,
        onClick: () => {
          setIsSummaryModalOpen(false);
          setWorkspaceTab("summary-workspace");
        },
        className: `px-3 sm:px-4 py-1.5 border-l border-indigo-300 ${isSummaryTab ? "bg-white text-indigo-900 font-semibold" : "bg-transparent text-indigo-200 hover:bg-indigo-700"}`,
        title: "Summary tab: full-screen discovery intelligence workspace"
      },
      "Summary"
    )), /* @__PURE__ */ React.createElement("div", { className: "flex flex-wrap items-center gap-1.5 sm:gap-2 text-[11px] sm:text-xs" }, isArtifactsTab && /* @__PURE__ */ React.createElement(
      "button",
      {
        onClick: isMissionDiscoveryActive ? abortDiscovery : startDiscovery,
        className: `px-2.5 sm:px-3 py-1.5 rounded ${isMissionDiscoveryActive ? "bg-red-600 hover:bg-red-700 text-white" : "bg-indigo-600 hover:bg-indigo-700 text-white"}`,
        title: isMissionDiscoveryActive ? "Abort active discovery pipeline" : "Run full discovery pipeline"
      },
      isMissionDiscoveryActive ? /* @__PURE__ */ React.createElement(React.Fragment, null, /* @__PURE__ */ React.createElement("i", { className: "fas fa-stop mr-1" }), "Abort Discovery") : /* @__PURE__ */ React.createElement(React.Fragment, null, /* @__PURE__ */ React.createElement("i", { className: "fas fa-rocket mr-1" }), "Run Discovery")
    ), isIntelligenceTab && /* @__PURE__ */ React.createElement(
      "button",
      {
        onClick: refreshIntelligenceWorkspace,
        className: "px-2.5 sm:px-3 py-1.5 rounded bg-blue-600 hover:bg-blue-700 text-white",
        title: "Refresh intelligence KPIs and trends"
      },
      /* @__PURE__ */ React.createElement("i", { className: "fas fa-brain mr-1" }),
      "Refresh Intelligence"
    ), isArtifactsTab && /* @__PURE__ */ React.createElement(
      "button",
      {
        onClick: refreshArtifactsWorkspace,
        className: "px-2.5 sm:px-3 py-1.5 rounded bg-emerald-600 hover:bg-emerald-700 text-white",
        title: "Reload discovery outputs and report library"
      },
      /* @__PURE__ */ React.createElement("i", { className: "fas fa-folder-open mr-1" }),
      "Refresh Discovery"
    ), isCapabilitiesOverview && /* @__PURE__ */ React.createElement(
      "button",
      {
        onClick: refreshCapabilitiesWorkspace,
        className: "px-2.5 sm:px-3 py-1.5 rounded bg-violet-600 hover:bg-violet-700 text-white",
        title: "Refresh optional capability inventory and health"
      },
      /* @__PURE__ */ React.createElement("i", { className: "fas fa-puzzle-piece mr-1" }),
      "Refresh Capabilities"
    ), isCapabilitiesRagView && /* @__PURE__ */ React.createElement(
      "button",
      {
        onClick: () => openRagCapabilitiesWorkspace({ libraryFilter: ragLibraryFilter }),
        className: "px-2.5 sm:px-3 py-1.5 rounded bg-sky-600 hover:bg-sky-700 text-white",
        title: "Refresh the context workspace and managed SPL library"
      },
      /* @__PURE__ */ React.createElement("i", { className: "fas fa-book-open mr-1" }),
      "Refresh Context"
    ), (isMissionTab || isIntelligenceTab) && /* @__PURE__ */ React.createElement(
      "label",
      {
        className: `inline-flex items-center gap-2 rounded border px-2.5 py-1.5 ${isDarkTheme ? "border-gray-600 bg-gray-800 text-gray-100" : "border-gray-300 bg-white text-gray-900"}`,
        title: operatorVoiceDefinition.description
      },
      /* @__PURE__ */ React.createElement("span", { className: `text-[11px] font-semibold uppercase tracking-wide ${mutedTextClass}` }, "Operator Voice"),
      /* @__PURE__ */ React.createElement(
        "select",
        {
          "data-testid": "workspace-operator-voice-select",
          value: operatorVoice,
          onChange: (event2) => setOperatorVoice(event2.target.value),
          className: `rounded border px-2 py-1 text-xs ${isDarkTheme ? "border-gray-600 bg-gray-900 text-gray-100" : "border-gray-300 bg-white text-gray-900"}`,
          "aria-label": "Select operator voice"
        },
        OPERATOR_VOICE_OPTIONS.map((option) => /* @__PURE__ */ React.createElement("option", { key: option.value, value: option.value }, option.label))
      )
    ), /* @__PURE__ */ React.createElement(
      "button",
      {
        onClick: openChatSurface,
        className: "px-2.5 sm:px-3 py-1.5 rounded bg-purple-600 hover:bg-purple-700 text-white",
        title: isChatFullscreen ? "Open the full-screen chat workspace tab" : "Open chat workspace with deterministic query support"
      },
      /* @__PURE__ */ React.createElement("i", { className: "fas fa-comments mr-1" }),
      "Open Chat"
    ))))), /* @__PURE__ */ React.createElement("div", { className: "flex items-center flex-wrap justify-end gap-2 sm:gap-3" }, /* @__PURE__ */ React.createElement(
      "button",
      {
        type: "button",
        "data-testid": "header-discovery-status-chip",
        onClick: openDiscoveryWorkspace,
        className: `flex items-center gap-2 px-2 py-1.5 sm:px-3 sm:py-2 rounded-lg border transition-colors ${discoveryStatusMeta.headerChipClass}`,
        title: `${discoveryHeaderChipLabel}. ${discoveryNarrative}`,
        "aria-label": `${discoveryHeaderChipLabel}. Open the Discovery workspace.`
      },
      /* @__PURE__ */ React.createElement("span", { "aria-hidden": "true", className: `w-2.5 h-2.5 rounded-full ${discoveryStatusMeta.dotClass} ${isMissionDiscoveryActive ? "animate-pulse" : ""}` }),
      /* @__PURE__ */ React.createElement("span", { className: "text-xs font-semibold uppercase tracking-wide" }, "Discovery"),
      /* @__PURE__ */ React.createElement("span", { className: "text-xs sm:text-sm font-medium" }, isMissionDiscoveryActive ? `${Math.max(discoveryProgressPercent, 1)}%` : discoveryStatusMeta.shortValue)
    ), /* @__PURE__ */ React.createElement(
      "button",
      {
        type: "button",
        className: `flex items-center cursor-pointer px-2 py-1.5 sm:px-3 sm:py-2 rounded-lg transition-colors ${isDarkTheme ? "hover:bg-gray-700" : "hover:bg-gray-100"}`,
        onClick: openConnectionModal,
        title: "View MCP connection details",
        "aria-label": isConnected ? "View MCP connection details. MCP connected." : "View MCP connection details. MCP disconnected.",
        "aria-haspopup": "dialog",
        "aria-expanded": isConnectionModalOpen,
        "aria-controls": "connection-details-popover"
      },
      /* @__PURE__ */ React.createElement("span", { "aria-hidden": "true", className: `w-3 h-3 rounded-full mr-2 ${isConnected ? "bg-green-500" : "bg-red-500"}` }),
      /* @__PURE__ */ React.createElement("span", { className: `text-xs sm:text-sm ${isDarkTheme ? "text-gray-300" : "text-gray-600"}` }, isConnected ? "MCP Connected" : "MCP Disconnected")
    ), /* @__PURE__ */ React.createElement(
      "div",
      {
        className: `flex items-center px-2 py-1.5 sm:px-3 sm:py-2 rounded-lg border ${isDarkTheme ? "bg-gray-800 border-purple-500" : "bg-white border-purple-200"}`,
        title: "Active LLM connection"
      },
      /* @__PURE__ */ React.createElement("i", { className: "fas fa-brain text-purple-600 mr-2" }),
      /* @__PURE__ */ React.createElement("div", { className: "flex flex-col" }, /* @__PURE__ */ React.createElement("span", { className: `text-xs leading-tight ${isDarkTheme ? "text-gray-400" : "text-gray-500"}` }, "LLM:"), /* @__PURE__ */ React.createElement("span", { className: `text-xs sm:text-sm font-medium leading-tight ${isDarkTheme ? "text-gray-100" : "text-gray-900"}` }, (config == null ? void 0 : config.active_credential_name) || ((_S = config == null ? void 0 : config.llm) == null ? void 0 : _S.model) || "Not configured"))
    ), /* @__PURE__ */ React.createElement(
      "button",
      {
        onClick: openSettings,
        className: `px-2 py-1.5 sm:px-3 sm:py-2 rounded-lg border font-medium ${isDarkTheme ? "bg-gray-700 hover:bg-gray-600 text-gray-100 border-gray-600" : "bg-gray-100 hover:bg-gray-200 text-gray-700 border-gray-300"}`,
        title: "Open settings",
        "aria-label": "Open settings"
      },
      /* @__PURE__ */ React.createElement("i", { className: "fas fa-cog" })
    ))))), /* @__PURE__ */ React.createElement("div", { className: `${workspaceShellWidthClass} mx-auto px-4 sm:px-6 lg:px-8 py-6` }, /* @__PURE__ */ React.createElement("div", { className: workspaceShellClass }, /* @__PURE__ */ React.createElement("div", { className: workspaceMainClass }, isMissionTab && /* @__PURE__ */ React.createElement("div", { className: `rounded-lg shadow-sm p-6 mb-6 border ${panelClass}` }, /* @__PURE__ */ React.createElement("div", { className: "flex items-center justify-between mb-4" }, /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("h2", { className: `text-lg font-semibold ${headingClass}` }, "Discovery Intelligence Hub"), /* @__PURE__ */ React.createElement("p", { className: `text-sm ${subtextClass}` }, "Actionable view for admins, analysts, and executives")), /* @__PURE__ */ React.createElement(
      "button",
      {
        type: "button",
        onClick: loadDiscoveryDashboard,
        className: "text-indigo-600 hover:text-indigo-800",
        title: "Refresh intelligence view",
        "aria-label": "Refresh discovery intelligence view"
      },
      /* @__PURE__ */ React.createElement("i", { className: "fas fa-sync" })
    )), !discoveryDashboard || !discoveryDashboard.has_data ? /* @__PURE__ */ React.createElement("div", { className: `text-sm rounded p-4 border ${panelMutedClass} ${mutedTextClass}` }, "No discovery intelligence available yet. Run discovery to generate KPI trends and persona playbooks.") : /* @__PURE__ */ React.createElement(React.Fragment, null, /* @__PURE__ */ React.createElement("div", { className: "grid grid-cols-1 xl:grid-cols-5 gap-4 mb-4" }, /* @__PURE__ */ React.createElement("div", { className: `xl:col-span-3 rounded-xl border p-5 ${isDarkTheme ? "bg-gray-950 border-gray-800" : "bg-slate-50 border-slate-200"}` }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between" }, /* @__PURE__ */ React.createElement("div", { className: "max-w-3xl" }, /* @__PURE__ */ React.createElement("div", { className: `text-[11px] uppercase tracking-[0.18em] ${mutedTextClass}` }, "Mission Status"), /* @__PURE__ */ React.createElement("div", { className: "mt-2 flex flex-wrap items-center gap-2" }, /* @__PURE__ */ React.createElement("span", { className: `inline-flex items-center rounded-full px-2.5 py-1 text-xs font-semibold ${missionFreshness.badgeClass}` }, missionFreshness.label), /* @__PURE__ */ React.createElement("span", { className: `text-xs ${mutedTextClass}` }, "Latest snapshot: ", formatMissionDateTime((latestMissionSession == null ? void 0 : latestMissionSession.created_at) || (latestMissionSession == null ? void 0 : latestMissionSession.timestamp), (latestMissionSession == null ? void 0 : latestMissionSession.timestamp) || "Unavailable"))), /* @__PURE__ */ React.createElement("h3", { className: `mt-3 text-xl font-semibold ${headingClass}` }, missionExecutiveHeadline), /* @__PURE__ */ React.createElement("p", { className: `mt-2 text-sm leading-6 ${subtextClass}` }, missionWhyNow)), /* @__PURE__ */ React.createElement("div", { className: `rounded-xl border px-4 py-3 max-w-sm ${panelMutedClass}` }, /* @__PURE__ */ React.createElement("div", { className: `text-xs font-semibold uppercase tracking-wide ${mutedTextClass}` }, "Immediate Value"), /* @__PURE__ */ React.createElement("div", { className: `mt-2 text-sm leading-6 ${subtextClass}` }, missionFreshness.summary))), /* @__PURE__ */ React.createElement("div", { className: "mt-5 grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-3" }, missionSummaryCards.map((card) => /* @__PURE__ */ React.createElement("div", { key: card.label, className: `rounded-xl border px-4 py-4 ${card.shellClass}` }, /* @__PURE__ */ React.createElement("div", { className: `text-xs uppercase tracking-wide ${card.labelClass}` }, card.label), /* @__PURE__ */ React.createElement("div", { className: `mt-2 text-2xl font-semibold ${card.valueClass}` }, card.value), /* @__PURE__ */ React.createElement("div", { className: `mt-2 text-xs leading-5 ${subtextClass}` }, card.detail))))), /* @__PURE__ */ React.createElement("div", { className: `xl:col-span-2 rounded-xl border p-5 ${isDarkTheme ? "bg-gray-950 border-gray-800" : "bg-white border-gray-200"}` }, /* @__PURE__ */ React.createElement("div", { className: "flex items-center gap-2 mb-3" }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-chart-line text-indigo-600" }), /* @__PURE__ */ React.createElement("h3", { className: `text-sm font-semibold ${headingClass}` }, "What Changed Since Last Run")), /* @__PURE__ */ React.createElement("div", { className: "space-y-3" }, missionChangeCards.map((card) => /* @__PURE__ */ React.createElement("div", { key: card.label, className: `rounded-xl border px-4 py-3 ${card.shellClass}` }, /* @__PURE__ */ React.createElement("div", { className: "flex items-start justify-between gap-3" }, /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("div", { className: `text-xs uppercase tracking-wide ${card.labelClass}` }, card.label), /* @__PURE__ */ React.createElement("div", { className: `mt-1 text-xs leading-5 ${subtextClass}` }, card.detail)), /* @__PURE__ */ React.createElement("div", { className: `text-sm font-semibold whitespace-nowrap ${card.valueClass}` }, missionHasPreviousSession ? card.value : "First run"))))))), /* @__PURE__ */ React.createElement("div", { className: `rounded-xl border p-5 mb-4 ${discoveryStatusMeta.tonePanelClass}` }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between" }, /* @__PURE__ */ React.createElement("div", { className: "max-w-3xl" }, /* @__PURE__ */ React.createElement("div", { className: `text-[11px] uppercase tracking-[0.18em] ${discoveryStatusMeta.toneTextClass}` }, "Mission Handoff"), /* @__PURE__ */ React.createElement("h3", { className: `mt-1 text-lg font-semibold ${discoveryStatusMeta.toneTextClass}` }, missionDiscoveryMonitorCard.title), /* @__PURE__ */ React.createElement("p", { className: `mt-2 text-sm leading-6 ${discoveryStatusMeta.toneTextClass}` }, missionDiscoveryMonitorCard.summary)), /* @__PURE__ */ React.createElement("div", { className: "flex flex-wrap items-center gap-2" }, /* @__PURE__ */ React.createElement("span", { className: `inline-flex items-center rounded-full px-3 py-1 text-xs font-semibold ${discoveryStatusMeta.statusBadgeClass}` }, /* @__PURE__ */ React.createElement("span", { "aria-hidden": "true", className: `mr-2 h-2 w-2 rounded-full ${discoveryStatusMeta.dotClass} ${isMissionDiscoveryActive ? "animate-pulse" : ""}` }), discoveryStatusMeta.label), /* @__PURE__ */ React.createElement(
      "button",
      {
        type: "button",
        onClick: openDiscoveryWorkspace,
        className: "inline-flex items-center rounded-lg bg-indigo-600 px-3 py-2 text-sm font-medium text-white transition-colors hover:bg-indigo-700"
      },
      /* @__PURE__ */ React.createElement("i", { className: "fas fa-satellite-dish mr-2" }),
      missionDiscoveryMonitorCard.ctaLabel
    ))), /* @__PURE__ */ React.createElement("div", { className: "mt-4 grid grid-cols-1 gap-3 md:grid-cols-4" }, /* @__PURE__ */ React.createElement("div", { className: `rounded-xl border px-4 py-3 ${isDarkTheme ? "bg-gray-950 border-gray-700" : "bg-white border-gray-200"}` }, /* @__PURE__ */ React.createElement("div", { className: `text-[11px] uppercase tracking-wide ${mutedTextClass}` }, "Phase"), /* @__PURE__ */ React.createElement("div", { className: `mt-1 text-sm font-semibold ${headingClass}` }, discoveryPhaseLeadTitle)), /* @__PURE__ */ React.createElement("div", { className: `rounded-xl border px-4 py-3 ${isDarkTheme ? "bg-gray-950 border-gray-700" : "bg-white border-gray-200"}` }, /* @__PURE__ */ React.createElement("div", { className: `text-[11px] uppercase tracking-wide ${mutedTextClass}` }, discoveryEtaMethodLabel), /* @__PURE__ */ React.createElement("div", { className: `mt-1 text-sm font-semibold ${headingClass}` }, isMissionDiscoveryActive ? discoveryEtaLabel : missionDiscoveryMonitorCard.detail)), /* @__PURE__ */ React.createElement("div", { className: `rounded-xl border px-4 py-3 ${isDarkTheme ? "bg-gray-950 border-gray-700" : "bg-white border-gray-200"}` }, /* @__PURE__ */ React.createElement("div", { className: `text-[11px] uppercase tracking-wide ${mutedTextClass}` }, "Outputs"), /* @__PURE__ */ React.createElement("div", { className: `mt-1 text-sm font-semibold ${headingClass}` }, discoveryReportCount > 0 ? discoveryReportCount : "No new artifacts")), /* @__PURE__ */ React.createElement("div", { className: `rounded-xl border px-4 py-3 ${isDarkTheme ? "bg-gray-950 border-gray-700" : "bg-white border-gray-200"}` }, /* @__PURE__ */ React.createElement("div", { className: `text-[11px] uppercase tracking-wide ${mutedTextClass}` }, "Monitor"), /* @__PURE__ */ React.createElement("div", { className: `mt-1 text-sm font-semibold ${headingClass}` }, missionDiscoveryMonitorCard.meta)))), /* @__PURE__ */ React.createElement("div", { className: "grid grid-cols-1 xl:grid-cols-3 gap-4 mb-4" }, /* @__PURE__ */ React.createElement("div", { className: `rounded-xl border p-4 ${isDarkTheme ? "bg-gray-950 border-gray-800" : "bg-white border-gray-200"}` }, /* @__PURE__ */ React.createElement("div", { className: "flex items-center gap-2 mb-3" }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-clipboard-list text-emerald-600" }), /* @__PURE__ */ React.createElement("h3", { className: `text-sm font-semibold ${headingClass}` }, "Admin Next Actions")), missionAdminActions.length === 0 ? /* @__PURE__ */ React.createElement("div", { className: `text-xs ${mutedTextClass}` }, "No admin actions were captured in the latest mission snapshot.") : /* @__PURE__ */ React.createElement("ul", { className: "space-y-2 text-xs" }, missionAdminVoiceCards.map((action, idx) => /* @__PURE__ */ React.createElement("li", { key: `mission-admin-${idx}`, className: `${isDarkTheme ? "bg-gray-900 border-gray-800" : "bg-gray-50 border-gray-200"} border rounded-lg px-3 py-3` }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-wrap items-start justify-between gap-2" }, /* @__PURE__ */ React.createElement("div", { className: `font-medium ${headingClass}` }, action.title), /* @__PURE__ */ React.createElement("span", { className: `rounded-full px-2 py-0.5 border text-[11px] ${panelMutedClass} ${mutedTextClass}` }, action.badge)), /* @__PURE__ */ React.createElement("div", { className: `mt-1 leading-5 ${subtextClass}` }, action.summary), /* @__PURE__ */ React.createElement("div", { className: `mt-2 ${mutedTextClass}` }, action.meta))))), /* @__PURE__ */ React.createElement("div", { className: `rounded-xl border p-4 ${isDarkTheme ? "bg-gray-950 border-gray-800" : "bg-white border-gray-200"}` }, /* @__PURE__ */ React.createElement("div", { className: "flex items-center gap-2 mb-3" }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-crosshairs text-indigo-600" }), /* @__PURE__ */ React.createElement("h3", { className: `text-sm font-semibold ${headingClass}` }, "Analyst Investigation Tracks")), missionAnalystTracks.length === 0 ? /* @__PURE__ */ React.createElement("div", { className: `text-xs ${mutedTextClass}` }, "No analyst hypotheses were captured in the latest mission snapshot.") : /* @__PURE__ */ React.createElement("ul", { className: "space-y-2 text-xs" }, missionAnalystVoiceCards.map((track, idx) => /* @__PURE__ */ React.createElement("li", { key: `mission-analyst-${idx}`, className: `${isDarkTheme ? "bg-gray-900 border-gray-800" : "bg-gray-50 border-gray-200"} border rounded-lg px-3 py-3` }, /* @__PURE__ */ React.createElement("div", { className: `font-medium ${headingClass}` }, track.title), /* @__PURE__ */ React.createElement("div", { className: `mt-1 leading-5 ${subtextClass}` }, track.summary), /* @__PURE__ */ React.createElement("div", { className: `mt-2 ${mutedTextClass}` }, track.meta))))), /* @__PURE__ */ React.createElement("div", { className: `rounded-xl border p-4 ${isDarkTheme ? "bg-gray-950 border-gray-800" : "bg-white border-gray-200"}` }, /* @__PURE__ */ React.createElement("div", { className: "flex items-center gap-2 mb-3" }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-briefcase text-purple-600" }), /* @__PURE__ */ React.createElement("h3", { className: `text-sm font-semibold ${headingClass}` }, "Executive Readout")), /* @__PURE__ */ React.createElement("div", { className: `${isDarkTheme ? "bg-purple-950 border-purple-800" : "bg-purple-50 border-purple-200"} border rounded-lg px-3 py-3` }, /* @__PURE__ */ React.createElement("div", { className: `text-sm font-medium ${headingClass}` }, missionExecutiveHeadline), /* @__PURE__ */ React.createElement("div", { className: `mt-2 text-xs leading-5 ${subtextClass}` }, missionFreshness.summary)), /* @__PURE__ */ React.createElement("div", { className: "mt-3 space-y-2 text-xs" }, missionExecutiveVoiceCards.map((item, idx) => /* @__PURE__ */ React.createElement("div", { key: `mission-executive-${idx}`, className: `${isDarkTheme ? "bg-gray-900 border-gray-800" : "bg-gray-50 border-gray-200"} border rounded-lg px-3 py-3` }, /* @__PURE__ */ React.createElement("div", { className: `font-medium ${headingClass}` }, item.title), /* @__PURE__ */ React.createElement("div", { className: `mt-1 leading-5 ${subtextClass}` }, item.summary), /* @__PURE__ */ React.createElement("div", { className: `mt-2 ${mutedTextClass}` }, item.meta))), missionExecutiveThemes.length === 0 && missionExecutiveFocus.length === 0 && /* @__PURE__ */ React.createElement("div", { className: `rounded-lg border px-3 py-3 ${panelMutedClass} ${mutedTextClass}` }, "No executive narrative was recorded. Generate the runbook below to build a current executive framing package.")))), /* @__PURE__ */ React.createElement("div", { className: "grid grid-cols-1 md:grid-cols-5 gap-3 mb-4" }, /* @__PURE__ */ React.createElement("div", { className: `rounded p-3 ${isDarkTheme ? "bg-indigo-900 border border-indigo-700" : "bg-indigo-50"}` }, /* @__PURE__ */ React.createElement("div", { className: `text-xs uppercase tracking-wide ${isDarkTheme ? "text-indigo-200" : "text-indigo-800"}` }, "Readiness"), /* @__PURE__ */ React.createElement("div", { className: `text-xl font-bold ${isDarkTheme ? "text-indigo-50" : "text-indigo-900"}` }, formatMissionMetricValue((_T = discoveryDashboard.kpis) == null ? void 0 : _T.readiness_score), "/100"), /* @__PURE__ */ React.createElement("div", { className: `text-xs ${isDarkTheme ? "text-indigo-300" : "text-indigo-800"}` }, missionHasPreviousSession ? `${formatMissionTrendValue((_U = discoveryDashboard.trends) == null ? void 0 : _U.readiness_delta)} vs previous run` : "First recorded session")), /* @__PURE__ */ React.createElement("div", { className: `rounded p-3 ${isDarkTheme ? "bg-blue-900 border border-blue-700" : "bg-blue-50"}` }, /* @__PURE__ */ React.createElement("div", { className: `text-xs uppercase tracking-wide ${isDarkTheme ? "text-blue-200" : "text-blue-800"}` }, "Indexes"), /* @__PURE__ */ React.createElement("div", { className: `text-xl font-bold ${isDarkTheme ? "text-blue-50" : "text-blue-900"}` }, formatMissionMetricValue((_V = discoveryDashboard.kpis) == null ? void 0 : _V.total_indexes)), /* @__PURE__ */ React.createElement("div", { className: `text-xs ${isDarkTheme ? "text-blue-300" : "text-blue-800"}` }, missionHasPreviousSession ? `${formatMissionTrendValue((_W = discoveryDashboard.trends) == null ? void 0 : _W.indexes_delta)} vs previous run` : "First recorded session")), /* @__PURE__ */ React.createElement("div", { className: `rounded p-3 ${isDarkTheme ? "bg-green-900 border border-green-700" : "bg-green-50"}` }, /* @__PURE__ */ React.createElement("div", { className: `text-xs uppercase tracking-wide ${isDarkTheme ? "text-green-200" : "text-green-800"}` }, "Sourcetypes"), /* @__PURE__ */ React.createElement("div", { className: `text-xl font-bold ${isDarkTheme ? "text-green-50" : "text-green-900"}` }, formatMissionMetricValue((_X = discoveryDashboard.kpis) == null ? void 0 : _X.total_sourcetypes)), /* @__PURE__ */ React.createElement("div", { className: `text-xs ${isDarkTheme ? "text-green-300" : "text-green-800"}` }, missionHasPreviousSession ? `${formatMissionTrendValue((_Y = discoveryDashboard.trends) == null ? void 0 : _Y.sourcetypes_delta)} vs previous run` : "First recorded session")), /* @__PURE__ */ React.createElement("div", { className: `rounded p-3 ${isDarkTheme ? "bg-amber-900 border border-amber-700" : "bg-amber-50"}` }, /* @__PURE__ */ React.createElement("div", { className: `text-xs uppercase tracking-wide ${isDarkTheme ? "text-amber-200" : "text-amber-900"}` }, "Recommendations"), /* @__PURE__ */ React.createElement("div", { className: `text-xl font-bold ${isDarkTheme ? "text-amber-50" : "text-amber-900"}` }, formatMissionMetricValue((_Z = discoveryDashboard.kpis) == null ? void 0 : _Z.recommendation_count)), /* @__PURE__ */ React.createElement("div", { className: `text-xs ${isDarkTheme ? "text-amber-300" : "text-amber-900"}` }, missionHasPreviousSession ? `${formatMissionTrendValue((__ = discoveryDashboard.trends) == null ? void 0 : __.recommendations_delta)} vs previous run` : "First recorded session")), /* @__PURE__ */ React.createElement("div", { className: `rounded p-3 ${isDarkTheme ? "bg-purple-900 border border-purple-700" : "bg-purple-50"}` }, /* @__PURE__ */ React.createElement("div", { className: `text-xs uppercase tracking-wide ${isDarkTheme ? "text-purple-200" : "text-purple-800"}` }, "Available Tools"), /* @__PURE__ */ React.createElement("div", { className: `text-xl font-bold ${isDarkTheme ? "text-purple-50" : "text-purple-900"}` }, formatMissionMetricValue((_$ = discoveryDashboard.kpis) == null ? void 0 : _$.tool_count)), /* @__PURE__ */ React.createElement("div", { className: `text-xs ${isDarkTheme ? "text-purple-300" : "text-purple-800"}` }, "Available to execute right now"))), /* @__PURE__ */ React.createElement("div", { className: `border rounded p-3 mb-4 ${isDarkTheme ? "border-gray-600" : "border-gray-200"}` }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-col md:flex-row md:items-end md:justify-between gap-3" }, /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("h3", { className: `text-sm font-semibold ${headingClass}` }, "Session Compare"), /* @__PURE__ */ React.createElement("p", { className: `text-xs ${mutedTextClass}` }, "Track changes between two discovery runs")), /* @__PURE__ */ React.createElement("div", { className: "flex flex-wrap items-center gap-2 text-xs" }, /* @__PURE__ */ React.createElement(
      "select",
      {
        value: compareSelection.current,
        onChange: (e) => setCompareSelection((prev) => ({ ...prev, current: e.target.value })),
        className: `border rounded px-2 py-1 ${isDarkTheme ? "border-gray-600 bg-gray-700 text-gray-100" : "border-gray-300 bg-white text-gray-900"}`
      },
      /* @__PURE__ */ React.createElement("option", { value: "latest" }, "Latest Session"),
      sessionCatalog.map((session) => /* @__PURE__ */ React.createElement("option", { key: `current-${session.timestamp}`, value: session.timestamp }, formatMissionSessionSelectionLabel(session.timestamp)))
    ), /* @__PURE__ */ React.createElement("span", { className: mutedTextClass }, "vs"), /* @__PURE__ */ React.createElement(
      "select",
      {
        value: compareSelection.baseline,
        onChange: (e) => setCompareSelection((prev) => ({ ...prev, baseline: e.target.value })),
        className: `border rounded px-2 py-1 ${isDarkTheme ? "border-gray-600 bg-gray-700 text-gray-100" : "border-gray-300 bg-white text-gray-900"}`
      },
      /* @__PURE__ */ React.createElement("option", { value: "previous" }, "Previous Session"),
      sessionCatalog.map((session) => /* @__PURE__ */ React.createElement("option", { key: `baseline-${session.timestamp}`, value: session.timestamp }, formatMissionSessionSelectionLabel(session.timestamp)))
    ), /* @__PURE__ */ React.createElement(
      "button",
      {
        onClick: refreshCompareSelection,
        className: "px-3 py-1 bg-indigo-600 hover:bg-indigo-700 text-white rounded"
      },
      "Compare"
    ))), !discoveryCompare || !discoveryCompare.has_data ? /* @__PURE__ */ React.createElement("div", { className: `text-xs mt-3 ${mutedTextClass}` }, (discoveryCompare == null ? void 0 : discoveryCompare.message) || "Compare data will appear once at least two sessions exist.") : /* @__PURE__ */ React.createElement("div", { className: "grid grid-cols-2 md:grid-cols-5 gap-2 mt-3 text-xs" }, /* @__PURE__ */ React.createElement("div", { className: `${isDarkTheme ? "bg-gray-700" : "bg-gray-50"} rounded p-2` }, /* @__PURE__ */ React.createElement("div", { className: mutedTextClass }, "Readiness Δ"), /* @__PURE__ */ React.createElement("div", { className: `font-semibold ${headingClass}` }, (_ca = (_ba = (_aa = discoveryCompare.metrics) == null ? void 0 : _aa.readiness) == null ? void 0 : _ba.delta) != null ? _ca : 0)), /* @__PURE__ */ React.createElement("div", { className: `${isDarkTheme ? "bg-gray-700" : "bg-gray-50"} rounded p-2` }, /* @__PURE__ */ React.createElement("div", { className: mutedTextClass }, "Indexes Δ"), /* @__PURE__ */ React.createElement("div", { className: `font-semibold ${headingClass}` }, (_fa = (_ea = (_da = discoveryCompare.metrics) == null ? void 0 : _da.indexes) == null ? void 0 : _ea.delta) != null ? _fa : 0)), /* @__PURE__ */ React.createElement("div", { className: `${isDarkTheme ? "bg-gray-700" : "bg-gray-50"} rounded p-2` }, /* @__PURE__ */ React.createElement("div", { className: mutedTextClass }, "Sourcetypes Δ"), /* @__PURE__ */ React.createElement("div", { className: `font-semibold ${headingClass}` }, (_ia = (_ha = (_ga = discoveryCompare.metrics) == null ? void 0 : _ga.sourcetypes) == null ? void 0 : _ha.delta) != null ? _ia : 0)), /* @__PURE__ */ React.createElement("div", { className: `${isDarkTheme ? "bg-gray-700" : "bg-gray-50"} rounded p-2` }, /* @__PURE__ */ React.createElement("div", { className: mutedTextClass }, "Recommendations Δ"), /* @__PURE__ */ React.createElement("div", { className: `font-semibold ${headingClass}` }, (_la = (_ka = (_ja = discoveryCompare.metrics) == null ? void 0 : _ja.recommendations) == null ? void 0 : _ka.delta) != null ? _la : 0)), /* @__PURE__ */ React.createElement("div", { className: `${isDarkTheme ? "bg-gray-700" : "bg-gray-50"} rounded p-2` }, /* @__PURE__ */ React.createElement("div", { className: mutedTextClass }, "Tool Count Δ"), /* @__PURE__ */ React.createElement("div", { className: `font-semibold ${headingClass}` }, (_oa = (_na = (_ma = discoveryCompare.metrics) == null ? void 0 : _ma.tools) == null ? void 0 : _na.delta) != null ? _oa : 0)))), /* @__PURE__ */ React.createElement("div", { className: "grid grid-cols-1 xl:grid-cols-5 gap-4" }, /* @__PURE__ */ React.createElement("div", { className: `xl:col-span-3 border rounded p-3 ${isDarkTheme ? "border-gray-600 bg-gray-800/40" : "border-gray-200 bg-white"}` }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-col md:flex-row md:items-start md:justify-between gap-3 mb-3" }, /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("h3", { className: `text-sm font-semibold ${headingClass}` }, "Persona Runbook"), /* @__PURE__ */ React.createElement("p", { className: `text-xs mt-1 ${mutedTextClass}` }, "Generate and export the active persona playbook for the selected session. On-screen previews are currently framed in ", operatorVoiceDefinition.label, " voice.")), /* @__PURE__ */ React.createElement("div", { className: "flex items-center gap-2 text-xs" }, /* @__PURE__ */ React.createElement(
      "button",
      {
        onClick: refreshRunbook,
        className: "px-3 py-1 bg-green-700 hover:bg-green-800 text-white rounded"
      },
      "Generate Runbook"
    ), /* @__PURE__ */ React.createElement(
      "button",
      {
        onClick: async () => {
          const currentRunbook = await ensureCurrentRunbookPayload();
          if ((currentRunbook == null ? void 0 : currentRunbook.markdown) && (currentRunbook == null ? void 0 : currentRunbook.filename)) {
            exportReport(currentRunbook.filename, currentRunbook.markdown);
          }
        },
        disabled: !(discoveryDashboard == null ? void 0 : discoveryDashboard.has_data),
        className: `px-3 py-1 rounded ${(discoveryDashboard == null ? void 0 : discoveryDashboard.has_data) ? "bg-indigo-600 hover:bg-indigo-700 text-white" : "bg-gray-200 text-gray-500 cursor-not-allowed"}`
      },
      "Export Runbook"
    ))), /* @__PURE__ */ React.createElement("div", { className: "inline-flex rounded border border-gray-300 overflow-hidden text-xs mb-3", role: "tablist", "aria-label": "Runbook personas" }, /* @__PURE__ */ React.createElement(
      "button",
      {
        type: "button",
        id: "workflow-tab-admin",
        role: "tab",
        "aria-selected": workflowTab === "admin",
        "aria-controls": "workflow-panel-admin",
        tabIndex: workflowTab === "admin" ? 0 : -1,
        onClick: () => setWorkflowTab("admin"),
        className: `px-3 py-1 ${workflowTab === "admin" ? "bg-indigo-600 text-white" : "bg-white text-gray-700"}`
      },
      "Admin"
    ), /* @__PURE__ */ React.createElement(
      "button",
      {
        type: "button",
        id: "workflow-tab-analyst",
        role: "tab",
        "aria-selected": workflowTab === "analyst",
        "aria-controls": "workflow-panel-analyst",
        tabIndex: workflowTab === "analyst" ? 0 : -1,
        onClick: () => setWorkflowTab("analyst"),
        className: `px-3 py-1 border-l border-gray-300 ${workflowTab === "analyst" ? "bg-indigo-600 text-white" : "bg-white text-gray-700"}`
      },
      "Analyst"
    ), /* @__PURE__ */ React.createElement(
      "button",
      {
        type: "button",
        id: "workflow-tab-executive",
        role: "tab",
        "aria-selected": workflowTab === "executive",
        "aria-controls": "workflow-panel-executive",
        tabIndex: workflowTab === "executive" ? 0 : -1,
        onClick: () => setWorkflowTab("executive"),
        className: `px-3 py-1 border-l border-gray-300 ${workflowTab === "executive" ? "bg-indigo-600 text-white" : "bg-white text-gray-700"}`
      },
      "Executive"
    )), workflowTab === "admin" && /* @__PURE__ */ React.createElement("ul", { id: "workflow-panel-admin", role: "tabpanel", "aria-labelledby": "workflow-tab-admin", className: `text-xs space-y-2 ${subtextClass}` }, missionRunbookAdminCards.map((action, idx) => /* @__PURE__ */ React.createElement("li", { key: idx, className: `${isDarkTheme ? "bg-gray-900 border-gray-700" : "bg-gray-50 border-gray-200"} border rounded px-3 py-2` }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-wrap items-start justify-between gap-2" }, /* @__PURE__ */ React.createElement("div", { className: `font-medium ${headingClass}` }, action.title), /* @__PURE__ */ React.createElement("span", { className: `rounded-full px-2 py-0.5 border text-[11px] ${panelMutedClass} ${mutedTextClass}` }, action.badge)), /* @__PURE__ */ React.createElement("div", { className: `mt-1 ${subtextClass}` }, action.summary), /* @__PURE__ */ React.createElement("div", { className: `mt-1 ${mutedTextClass}` }, action.meta)))), workflowTab === "analyst" && /* @__PURE__ */ React.createElement("ul", { id: "workflow-panel-analyst", role: "tabpanel", "aria-labelledby": "workflow-tab-analyst", className: `text-xs space-y-2 ${subtextClass}` }, missionRunbookAnalystCards.map((track, idx) => /* @__PURE__ */ React.createElement("li", { key: idx, className: `${isDarkTheme ? "bg-gray-900 border-gray-700" : "bg-gray-50 border-gray-200"} border rounded px-3 py-2` }, /* @__PURE__ */ React.createElement("div", { className: `font-medium ${headingClass}` }, track.title), /* @__PURE__ */ React.createElement("div", { className: `mt-1 ${subtextClass}` }, track.summary), /* @__PURE__ */ React.createElement("div", { className: `mt-1 ${mutedTextClass}` }, track.meta)))), workflowTab === "executive" && /* @__PURE__ */ React.createElement("div", { id: "workflow-panel-executive", role: "tabpanel", "aria-labelledby": "workflow-tab-executive", className: `text-xs space-y-2 ${subtextClass}` }, ((_ra = (_qa = (_pa = discoveryDashboard.latest) == null ? void 0 : _pa.personas) == null ? void 0 : _qa.executive) == null ? void 0 : _ra.headline) && /* @__PURE__ */ React.createElement("div", { className: `${isDarkTheme ? "bg-indigo-950 border-indigo-800" : "bg-indigo-50 border-indigo-200"} border rounded px-3 py-2` }, /* @__PURE__ */ React.createElement("div", { className: `font-medium ${headingClass}` }, "Headline"), /* @__PURE__ */ React.createElement("div", { className: `mt-1 ${subtextClass}` }, discoveryDashboard.latest.personas.executive.headline)), missionRunbookExecutiveCards.map((item, idx) => /* @__PURE__ */ React.createElement("div", { key: `executive-focus-${idx}`, className: `${isDarkTheme ? "bg-gray-900 border-gray-700" : "bg-gray-50 border-gray-200"} border rounded px-3 py-2` }, /* @__PURE__ */ React.createElement("div", { className: `font-medium ${headingClass}` }, item.title), /* @__PURE__ */ React.createElement("div", { className: `mt-1 ${subtextClass}` }, item.summary), /* @__PURE__ */ React.createElement("div", { className: `mt-1 ${mutedTextClass}` }, item.meta)))), runbookPayload && runbookPayload.has_data && /* @__PURE__ */ React.createElement("div", { className: `mt-3 text-xs ${mutedTextClass}` }, "Ready: ", runbookPayload.title || "Runbook", " (", runbookPayload.filename || "runbook.md", ") • Voice: ", runbookPayload.voice_label || operatorVoiceDefinition.label)), /* @__PURE__ */ React.createElement("div", { className: `xl:col-span-2 border rounded p-3 ${isDarkTheme ? "border-gray-600 bg-gray-800/40" : "border-gray-200 bg-white"}` }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-col gap-3" }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-col md:flex-row md:items-start md:justify-between gap-3" }, /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("h3", { className: `text-sm font-semibold ${headingClass}` }, "Report Package"), /* @__PURE__ */ React.createElement("p", { className: `text-xs mt-1 ${mutedTextClass}` }, "Build and download a zip with session artifacts plus the active persona runbook.")), /* @__PURE__ */ React.createElement("div", { className: "flex items-center gap-2 text-xs" }, /* @__PURE__ */ React.createElement(
      "button",
      {
        onClick: async () => {
          const currentRunbook = await ensureCurrentRunbookPayload();
          await buildCapabilityExport({
            timestamp: compareSelection.current || "latest",
            persona: workflowTab,
            voice: operatorVoice,
            title: `${operatorVoiceDefinition.label} ${workflowTab} discovery package`,
            runbook_markdown: (currentRunbook == null ? void 0 : currentRunbook.markdown) || void 0,
            runbook_filename: (currentRunbook == null ? void 0 : currentRunbook.filename) || void 0
          });
        },
        disabled: !canUseExportTools || exportBuildState.status === "loading",
        className: `px-3 py-1 rounded ${canUseExportTools && exportBuildState.status !== "loading" ? "bg-cyan-700 hover:bg-cyan-800 text-white" : "bg-gray-200 text-gray-500 cursor-not-allowed"}`
      },
      exportBuildState.status === "loading" ? "Building Package..." : "Build Report Package"
    ), /* @__PURE__ */ React.createElement(
      "button",
      {
        onClick: () => {
          var _a2, _b2;
          return downloadCapabilityExport(((_a2 = exportBuildState.bundle) == null ? void 0 : _a2.download_name) || ((_b2 = exportCapability == null ? void 0 : exportCapability.latest_bundle) == null ? void 0 : _b2.name));
        },
        disabled: !(((_sa = exportBuildState.bundle) == null ? void 0 : _sa.download_name) || ((_ta = exportCapability == null ? void 0 : exportCapability.latest_bundle) == null ? void 0 : _ta.name)),
        className: `px-3 py-1 rounded ${((_ua = exportBuildState.bundle) == null ? void 0 : _ua.download_name) || ((_va = exportCapability == null ? void 0 : exportCapability.latest_bundle) == null ? void 0 : _va.name) ? "bg-slate-700 hover:bg-slate-800 text-white" : "bg-gray-200 text-gray-500 cursor-not-allowed"}`
      },
      downloadPackageLabel
    ))), /* @__PURE__ */ React.createElement("div", { className: `text-[11px] ${mutedTextClass}` }, "Target: ", packageTargetLabel, ". Build creates a zip with the selected session artifacts plus that runbook."), !canUseExportTools && /* @__PURE__ */ React.createElement("div", { className: `text-[11px] ${mutedTextClass}` }, "Report package actions stay disabled until the Export Tools capability is installed, enabled, and healthy."), exportBuildState.status === "error" && /* @__PURE__ */ React.createElement("div", { className: `rounded-lg border px-3 py-2 text-xs ${isDarkTheme ? "border-red-800 bg-red-950 text-red-200" : "border-red-200 bg-red-50 text-red-700"}` }, exportBuildState.error), activePackageBundle ? /* @__PURE__ */ React.createElement("div", { className: `rounded-lg border px-3 py-2 text-xs ${panelMutedClass} ${subtextClass}` }, /* @__PURE__ */ React.createElement("div", { className: "font-medium mb-1" }, packageCardTitle), /* @__PURE__ */ React.createElement("div", null, "Target: ", packageTargetLabel), /* @__PURE__ */ React.createElement("div", null, "Package: ", formatPackageFileLabel(((_wa = exportBuildState.bundle) == null ? void 0 : _wa.bundle_name) || ((_xa = exportCapability == null ? void 0 : exportCapability.latest_bundle) == null ? void 0 : _xa.name))), ((_ya = exportBuildState.bundle) == null ? void 0 : _ya.session_timestamp) && /* @__PURE__ */ React.createElement("div", null, "Session: ", exportBuildState.bundle.session_timestamp), ((_za = exportBuildState.bundle) == null ? void 0 : _za.artifact_count) != null && /* @__PURE__ */ React.createElement("div", null, "Included artifacts: ", exportBuildState.bundle.artifact_count), ((_Aa = exportBuildState.bundle) == null ? void 0 : _Aa.operator_voice_label) && /* @__PURE__ */ React.createElement("div", null, "Voice: ", exportBuildState.bundle.operator_voice_label), (((_Ba = exportBuildState.bundle) == null ? void 0 : _Ba.bundle_size_bytes) || ((_Ca = exportCapability == null ? void 0 : exportCapability.latest_bundle) == null ? void 0 : _Ca.size_bytes)) && /* @__PURE__ */ React.createElement("div", null, "Package size: ", Number(((_Da = exportBuildState.bundle) == null ? void 0 : _Da.bundle_size_bytes) || ((_Ea = exportCapability == null ? void 0 : exportCapability.latest_bundle) == null ? void 0 : _Ea.size_bytes)).toLocaleString(), " bytes"), /* @__PURE__ */ React.createElement("div", { className: `mt-2 ${mutedTextClass}` }, hasFreshPackageBuild ? "This package was built from the selected session and the active persona runbook." : "This is the most recently built package. Build Report Package to create a fresh zip for the current target.")) : /* @__PURE__ */ React.createElement("div", { className: `rounded-lg border px-3 py-2 text-xs ${panelMutedClass} ${mutedTextClass}` }, "No package has been built for the current target yet.")))))), isIntelligenceTab && /* @__PURE__ */ React.createElement("div", { className: `rounded-lg shadow-sm p-6 mb-6 border ${panelClass}` }, /* @__PURE__ */ React.createElement("div", { className: "flex items-center justify-between mb-4" }, /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("h2", { className: `text-lg font-semibold ${headingClass}` }, "Discovery Intelligence Blueprint"), /* @__PURE__ */ React.createElement("p", { className: `text-sm ${subtextClass}` }, "Immediate blueprint briefing, priority gaps, and voice-adapted operator readouts from the latest discovery run")), /* @__PURE__ */ React.createElement(
      "button",
      {
        type: "button",
        onClick: refreshIntelligenceWorkspace,
        className: "text-indigo-600 hover:text-indigo-800",
        title: "Refresh discovery intelligence",
        "aria-label": "Refresh discovery intelligence"
      },
      /* @__PURE__ */ React.createElement("i", { className: "fas fa-sync" })
    )), !v2Intelligence || !v2Intelligence.has_data ? /* @__PURE__ */ React.createElement("div", { className: `text-sm rounded p-4 border ${panelMutedClass} ${mutedTextClass}` }, (v2Intelligence == null ? void 0 : v2Intelligence.message) || "No discovery intelligence blueprint available yet. Run Discovery to generate the blueprint.") : /* @__PURE__ */ React.createElement(React.Fragment, null, /* @__PURE__ */ React.createElement("div", { className: "grid grid-cols-1 xl:grid-cols-5 gap-4 mb-4" }, /* @__PURE__ */ React.createElement("div", { className: `xl:col-span-3 rounded-xl border p-5 ${isDarkTheme ? "bg-gray-950 border-gray-800" : "bg-slate-50 border-slate-200"}` }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between" }, /* @__PURE__ */ React.createElement("div", { className: "max-w-3xl" }, /* @__PURE__ */ React.createElement("div", { className: `text-[11px] uppercase tracking-[0.18em] ${mutedTextClass}` }, "Intelligence Status"), /* @__PURE__ */ React.createElement("div", { className: "mt-2 flex flex-wrap items-center gap-2" }, /* @__PURE__ */ React.createElement("span", { className: `inline-flex items-center rounded-full px-2.5 py-1 text-xs font-semibold ${missionFreshness.badgeClass}` }, missionFreshness.label), /* @__PURE__ */ React.createElement("span", { className: `inline-flex items-center rounded-full px-2.5 py-1 text-xs font-semibold ${panelMutedClass} ${mutedTextClass}` }, "Voice: ", operatorVoiceDefinition.label), /* @__PURE__ */ React.createElement("span", { className: `text-xs ${mutedTextClass}` }, "Latest snapshot: ", formatMissionDateTime((latestMissionSession == null ? void 0 : latestMissionSession.created_at) || (latestMissionSession == null ? void 0 : latestMissionSession.timestamp), (latestMissionSession == null ? void 0 : latestMissionSession.timestamp) || "Unavailable"))), /* @__PURE__ */ React.createElement("h3", { className: `mt-3 text-xl font-semibold ${headingClass}` }, intelligenceHeadline), /* @__PURE__ */ React.createElement("p", { className: `mt-2 text-sm leading-6 ${subtextClass}` }, intelligenceWhyNow)), /* @__PURE__ */ React.createElement("div", { className: `rounded-xl border px-4 py-3 max-w-sm ${panelMutedClass}` }, /* @__PURE__ */ React.createElement("div", { className: `text-xs font-semibold uppercase tracking-wide ${mutedTextClass}` }, "Immediate Value"), /* @__PURE__ */ React.createElement("div", { className: `mt-2 text-sm leading-6 ${subtextClass}` }, "This view translates the blueprint into ", operatorVoiceDefinition.label, " language so admins, analysts, and leaders can act without parsing the raw ledger first."))), /* @__PURE__ */ React.createElement("div", { className: "mt-5 grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-3" }, intelligenceSummaryCards.map((card) => /* @__PURE__ */ React.createElement("div", { key: card.label, className: `rounded-xl border px-4 py-4 ${card.shellClass}` }, /* @__PURE__ */ React.createElement("div", { className: `text-xs uppercase tracking-wide ${card.labelClass}` }, card.label), /* @__PURE__ */ React.createElement("div", { className: `mt-2 text-2xl font-semibold ${card.valueClass}` }, card.value), /* @__PURE__ */ React.createElement("div", { className: `mt-2 text-xs leading-5 ${subtextClass}` }, card.detail))))), /* @__PURE__ */ React.createElement("div", { className: `xl:col-span-2 rounded-xl border p-5 ${isDarkTheme ? "bg-gray-950 border-gray-800" : "bg-white border-gray-200"}` }, /* @__PURE__ */ React.createElement("div", { className: "flex items-center gap-2 mb-3" }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-layer-group text-rose-600" }), /* @__PURE__ */ React.createElement("h3", { className: `text-sm font-semibold ${headingClass}` }, "Priority Board")), /* @__PURE__ */ React.createElement("div", { className: `text-xs mb-3 ${subtextClass}` }, "The top blueprint signals, already translated into the next decisions that matter."), /* @__PURE__ */ React.createElement("div", { className: "space-y-3" }, intelligencePriorityBoard.map((item) => /* @__PURE__ */ React.createElement("div", { key: item.label, className: `${isDarkTheme ? "bg-gray-900 border-gray-800" : "bg-gray-50 border-gray-200"} border rounded-xl px-4 py-3` }, /* @__PURE__ */ React.createElement("div", { className: "flex items-start justify-between gap-3" }, /* @__PURE__ */ React.createElement("div", { className: `text-xs uppercase tracking-wide ${mutedTextClass}` }, item.label), /* @__PURE__ */ React.createElement("span", { className: `rounded-full px-2 py-0.5 border text-[11px] ${item.badgeClass}` }, item.badge)), /* @__PURE__ */ React.createElement("div", { className: `mt-2 text-xs leading-5 ${subtextClass}` }, item.detail)))))), /* @__PURE__ */ React.createElement("div", { className: "grid grid-cols-1 xl:grid-cols-3 gap-4 mb-4" }, /* @__PURE__ */ React.createElement("div", { className: `rounded-xl border p-4 ${isDarkTheme ? "bg-gray-950 border-gray-800" : "bg-white border-gray-200"}` }, /* @__PURE__ */ React.createElement("div", { className: "flex items-center gap-2 mb-3" }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-clipboard-check text-emerald-600" }), /* @__PURE__ */ React.createElement("h3", { className: `text-sm font-semibold ${headingClass}` }, "Admin Control Brief")), intelligenceAdminBriefs.length === 0 ? /* @__PURE__ */ React.createElement("div", { className: `text-xs ${mutedTextClass}` }, "No admin-facing control gaps were generated from the current blueprint.") : /* @__PURE__ */ React.createElement("ul", { className: "space-y-2 text-xs" }, intelligenceAdminBriefs.map((item, idx) => /* @__PURE__ */ React.createElement("li", { key: `intelligence-admin-${idx}`, className: `${isDarkTheme ? "bg-gray-900 border-gray-800" : "bg-gray-50 border-gray-200"} border rounded-lg px-3 py-3` }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-wrap items-start justify-between gap-2" }, /* @__PURE__ */ React.createElement("div", { className: `font-medium ${headingClass}` }, item.title), /* @__PURE__ */ React.createElement("span", { className: `rounded-full px-2 py-0.5 border text-[11px] ${panelMutedClass} ${mutedTextClass}` }, item.badge)), /* @__PURE__ */ React.createElement("div", { className: `mt-1 leading-5 ${subtextClass}` }, item.summary), /* @__PURE__ */ React.createElement("div", { className: `mt-2 ${mutedTextClass}` }, item.meta))))), /* @__PURE__ */ React.createElement("div", { className: `rounded-xl border p-4 ${isDarkTheme ? "bg-gray-950 border-gray-800" : "bg-white border-gray-200"}` }, /* @__PURE__ */ React.createElement("div", { className: "flex items-center gap-2 mb-3" }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-search text-indigo-600" }), /* @__PURE__ */ React.createElement("h3", { className: `text-sm font-semibold ${headingClass}` }, "Analyst Investigation Brief")), intelligenceAnalystBriefs.length === 0 ? /* @__PURE__ */ React.createElement("div", { className: `text-xs ${mutedTextClass}` }, "No analyst investigation paths were generated from the current blueprint.") : /* @__PURE__ */ React.createElement("ul", { className: "space-y-2 text-xs" }, intelligenceAnalystBriefs.map((item, idx) => /* @__PURE__ */ React.createElement("li", { key: `intelligence-analyst-${idx}`, className: `${isDarkTheme ? "bg-gray-900 border-gray-800" : "bg-gray-50 border-gray-200"} border rounded-lg px-3 py-3` }, /* @__PURE__ */ React.createElement("div", { className: `font-medium ${headingClass}` }, item.title), /* @__PURE__ */ React.createElement("div", { className: `mt-1 leading-5 ${subtextClass}` }, item.summary), /* @__PURE__ */ React.createElement("div", { className: `mt-2 ${mutedTextClass}` }, item.meta))))), /* @__PURE__ */ React.createElement("div", { className: `rounded-xl border p-4 ${isDarkTheme ? "bg-gray-950 border-gray-800" : "bg-white border-gray-200"}` }, /* @__PURE__ */ React.createElement("div", { className: "flex items-center gap-2 mb-3" }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-briefcase text-purple-600" }), /* @__PURE__ */ React.createElement("h3", { className: `text-sm font-semibold ${headingClass}` }, "Executive Framing")), intelligenceExecutiveBriefs.length === 0 ? /* @__PURE__ */ React.createElement("div", { className: `text-xs ${mutedTextClass}` }, "No executive framing was generated from the current blueprint.") : /* @__PURE__ */ React.createElement("div", { className: "space-y-2 text-xs" }, intelligenceExecutiveBriefs.map((item, idx) => /* @__PURE__ */ React.createElement("div", { key: `intelligence-executive-${idx}`, className: `${isDarkTheme ? "bg-gray-900 border-gray-800" : "bg-gray-50 border-gray-200"} border rounded-lg px-3 py-3` }, /* @__PURE__ */ React.createElement("div", { className: `font-medium ${headingClass}` }, item.title), /* @__PURE__ */ React.createElement("div", { className: `mt-1 leading-5 ${subtextClass}` }, item.summary), /* @__PURE__ */ React.createElement("div", { className: `mt-2 ${mutedTextClass}` }, item.meta)))))), /* @__PURE__ */ React.createElement("div", { className: "grid grid-cols-1 md:grid-cols-2 gap-4 mb-4" }, /* @__PURE__ */ React.createElement("div", { className: `border rounded p-4 ${isDarkTheme ? "border-gray-600 bg-gray-800" : "border-gray-200 bg-white"}` }, /* @__PURE__ */ React.createElement("div", { className: "flex items-center gap-2 mb-3" }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-shield-alt text-rose-600" }), /* @__PURE__ */ React.createElement("h3", { className: `text-sm font-semibold ${headingClass}` }, "Priority Coverage Gaps")), v2CoverageGaps.length === 0 ? /* @__PURE__ */ React.createElement("div", { className: `text-xs ${mutedTextClass}` }, "No high-priority gaps were identified.") : /* @__PURE__ */ React.createElement("ul", { className: "space-y-2 text-xs" }, v2CoverageGaps.slice(0, 6).map((gap, idx) => /* @__PURE__ */ React.createElement("li", { key: idx, className: `${isDarkTheme ? "bg-gray-900 border-gray-700" : "bg-gray-50 border-gray-200"} border rounded-lg p-3` }, /* @__PURE__ */ React.createElement("div", { className: "flex items-start justify-between gap-3" }, /* @__PURE__ */ React.createElement("div", { className: `font-medium ${headingClass}` }, gap.gap || "Coverage gap"), /* @__PURE__ */ React.createElement("span", { className: `rounded-full px-2 py-0.5 border text-[11px] ${getOperatorPriorityClasses(gap.priority)}` }, formatOperatorPriorityLabel(gap.priority))), /* @__PURE__ */ React.createElement("div", { className: `mt-1 ${subtextClass}` }, gap.why_it_matters || "No description provided."))))), /* @__PURE__ */ React.createElement("div", { className: `border rounded p-4 ${isDarkTheme ? "border-gray-600 bg-gray-800" : "border-gray-200 bg-white"}` }, /* @__PURE__ */ React.createElement("div", { className: "flex items-center gap-2 mb-3" }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-project-diagram text-sky-600" }), /* @__PURE__ */ React.createElement("h3", { className: `text-sm font-semibold ${headingClass}` }, "Environment Profile")), /* @__PURE__ */ React.createElement("div", { className: "grid grid-cols-2 gap-2 text-xs mb-3" }, /* @__PURE__ */ React.createElement("div", { className: `${isDarkTheme ? "bg-gray-900 border-gray-700" : "bg-gray-50 border-gray-200"} border rounded-lg px-3 py-3` }, /* @__PURE__ */ React.createElement("div", { className: mutedTextClass }, "Splunk"), /* @__PURE__ */ React.createElement("div", { className: `mt-1 font-medium ${headingClass}` }, v2Overview.splunk_version || "unknown"), /* @__PURE__ */ React.createElement("div", { className: `mt-1 ${subtextClass}` }, "License: ", v2Overview.license_state || "unknown")), /* @__PURE__ */ React.createElement("div", { className: `${isDarkTheme ? "bg-gray-900 border-gray-700" : "bg-gray-50 border-gray-200"} border rounded-lg px-3 py-3` }, /* @__PURE__ */ React.createElement("div", { className: mutedTextClass }, "Discovery Effort"), /* @__PURE__ */ React.createElement("div", { className: `mt-1 font-medium ${headingClass}` }, formatMissionMetricValue(v2Overview.estimated_discovery_steps)), /* @__PURE__ */ React.createElement("div", { className: `mt-1 ${subtextClass}` }, v2Overview.estimated_time || "Time estimate unavailable")), /* @__PURE__ */ React.createElement("div", { className: `${isDarkTheme ? "bg-gray-900 border-gray-700" : "bg-gray-50 border-gray-200"} border rounded-lg px-3 py-3` }, /* @__PURE__ */ React.createElement("div", { className: mutedTextClass }, "Data Surface"), /* @__PURE__ */ React.createElement("div", { className: `mt-1 font-medium ${headingClass}` }, formatMissionMetricValue(((_Fa = v2CapabilityGraph == null ? void 0 : v2CapabilityGraph.data_surface) == null ? void 0 : _Fa.indexes) || v2Overview.total_indexes), " indexes"), /* @__PURE__ */ React.createElement("div", { className: `mt-1 ${subtextClass}` }, formatMissionMetricValue(((_Ga = v2CapabilityGraph == null ? void 0 : v2CapabilityGraph.data_surface) == null ? void 0 : _Ga.sourcetypes) || v2Overview.total_sourcetypes), " sourcetypes • ", formatMissionMetricValue(((_Ha = v2CapabilityGraph == null ? void 0 : v2CapabilityGraph.data_surface) == null ? void 0 : _Ha.sources) || v2Overview.total_sources), " sources")), /* @__PURE__ */ React.createElement("div", { className: `${isDarkTheme ? "bg-gray-900 border-gray-700" : "bg-gray-50 border-gray-200"} border rounded-lg px-3 py-3` }, /* @__PURE__ */ React.createElement("div", { className: mutedTextClass }, "Operations Surface"), /* @__PURE__ */ React.createElement("div", { className: `mt-1 font-medium ${headingClass}` }, formatMissionMetricValue(((_Ia = v2CapabilityGraph == null ? void 0 : v2CapabilityGraph.operations_surface) == null ? void 0 : _Ia.users) || v2Overview.total_users), " users"), /* @__PURE__ */ React.createElement("div", { className: `mt-1 ${subtextClass}` }, formatMissionMetricValue(((_Ja = v2CapabilityGraph == null ? void 0 : v2CapabilityGraph.operations_surface) == null ? void 0 : _Ja.knowledge_objects) || v2Overview.total_knowledge_objects), " knowledge objects • ", formatMissionMetricValue(((_Ka = v2CapabilityGraph == null ? void 0 : v2CapabilityGraph.operations_surface) == null ? void 0 : _Ka.kv_collections) || v2Overview.total_kv_collections), " KV collections"))))), /* @__PURE__ */ React.createElement("div", { className: `border rounded p-4 mb-4 ${isDarkTheme ? "border-gray-600 bg-gray-800" : "border-gray-200 bg-white"}` }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between mb-3" }, /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("div", { className: "flex items-center gap-2" }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-fingerprint text-sky-600" }), /* @__PURE__ */ React.createElement("h3", { className: `text-sm font-semibold ${headingClass}` }, "Notable Patterns")), /* @__PURE__ */ React.createElement("div", { className: `mt-2 text-xs ${subtextClass}` }, "Recurring discovery themes from the current blueprint, reduced into readable operator cues instead of raw pattern blobs.")), intelligenceNotablePatterns.length > 0 && /* @__PURE__ */ React.createElement("div", { className: "flex flex-wrap items-center justify-end gap-2" }, hasExpandableIntelligencePatterns && /* @__PURE__ */ React.createElement(
      "button",
      {
        type: "button",
        "data-testid": "intelligence-notable-patterns-toggle",
        "aria-expanded": showAllIntelligencePatterns,
        onClick: () => setShowAllIntelligencePatterns((current) => !current),
        className: `inline-flex items-center rounded-full px-3 py-1 text-[11px] font-medium border ${isDarkTheme ? "bg-gray-900 border-gray-700 text-sky-100 hover:bg-gray-950" : "bg-white border-gray-300 text-sky-700 hover:bg-sky-50"}`
      },
      showAllIntelligencePatterns ? "Show fewer" : `View all ${intelligenceNotablePatterns.length} patterns`
    ), /* @__PURE__ */ React.createElement("div", { className: `inline-flex items-center rounded-full px-2.5 py-1 text-[11px] border ${panelMutedClass} ${mutedTextClass}` }, "Showing ", visibleIntelligenceNotablePatterns.length, " of ", intelligenceNotablePatterns.length))), intelligenceNotablePatterns.length === 0 ? /* @__PURE__ */ React.createElement("div", { className: `text-xs ${mutedTextClass}` }, "No notable patterns were recorded in the current blueprint.") : /* @__PURE__ */ React.createElement("div", { className: "grid grid-cols-1 xl:grid-cols-3 gap-3", "data-testid": "intelligence-notable-patterns" }, visibleIntelligenceNotablePatterns.map((pattern, idx) => {
      const distinctEvidenceItems = getDistinctIntelligencePatternEvidence(pattern);
      return /* @__PURE__ */ React.createElement(
        "div",
        {
          key: `notable-pattern-${idx}`,
          "data-testid": "intelligence-notable-pattern-card",
          className: `${isDarkTheme ? "bg-gray-900 border-gray-700" : "bg-gray-50 border-gray-200"} border rounded-xl px-4 py-4`
        },
        /* @__PURE__ */ React.createElement("div", { className: "flex items-start justify-between gap-3" }, /* @__PURE__ */ React.createElement("div", { className: `text-[11px] uppercase tracking-[0.18em] ${mutedTextClass}` }, getIntelligencePatternEyebrowLabel(pattern, idx)), pattern.signal && /* @__PURE__ */ React.createElement("span", { className: `rounded-full px-2 py-0.5 border text-[11px] ${panelMutedClass} ${mutedTextClass}` }, "Lead signal")),
        /* @__PURE__ */ React.createElement("div", { className: `mt-2 text-sm font-semibold ${headingClass}` }, formatIntelligencePatternLabel(pattern.title || pattern.category || `Pattern ${idx + 1}`, `Pattern ${idx + 1}`)),
        /* @__PURE__ */ React.createElement("div", { className: `mt-2 text-xs leading-5 ${subtextClass}` }, pattern.description || "Discovery identified this as a recurring environment theme, but did not attach a longer narrative."),
        pattern.signal && /* @__PURE__ */ React.createElement("div", { className: `mt-3 text-[11px] ${mutedTextClass}` }, "Lead signal: ", pattern.signal),
        distinctEvidenceItems.length > 0 && /* @__PURE__ */ React.createElement("div", { className: "mt-3 flex flex-wrap gap-2" }, distinctEvidenceItems.slice(0, 2).map((item, evidenceIdx) => /* @__PURE__ */ React.createElement(
          "span",
          {
            key: `notable-pattern-${idx}-evidence-${evidenceIdx}`,
            className: `rounded-full px-2 py-0.5 border text-[11px] ${isDarkTheme ? "bg-gray-800 text-gray-200 border-gray-600" : "bg-white text-gray-700 border-gray-300"}`
          },
          item
        )))
      );
    }))), /* @__PURE__ */ React.createElement("div", { className: "grid grid-cols-1 md:grid-cols-2 gap-4" }, /* @__PURE__ */ React.createElement("div", { className: `border rounded p-4 ${isDarkTheme ? "border-gray-600 bg-gray-800" : "border-gray-200 bg-white"}` }, /* @__PURE__ */ React.createElement("div", { className: "flex items-center gap-2 mb-3" }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-stream text-emerald-600" }), /* @__PURE__ */ React.createElement("h3", { className: `text-sm font-semibold ${headingClass}` }, "Highest-Signal Evidence")), v2FindingLedger.length === 0 ? /* @__PURE__ */ React.createElement("div", { className: `text-xs ${mutedTextClass}` }, "No ledger entries available.") : /* @__PURE__ */ React.createElement("ul", { className: "space-y-2 text-xs" }, v2FindingLedger.slice(0, 6).map((entry, idx) => /* @__PURE__ */ React.createElement("li", { key: idx, className: `${isDarkTheme ? "bg-gray-900 border-gray-700" : "bg-gray-50 border-gray-200"} border rounded-lg p-3` }, /* @__PURE__ */ React.createElement("div", { className: "flex items-start justify-between gap-3" }, /* @__PURE__ */ React.createElement("div", { className: `font-medium ${headingClass}` }, "Step ", entry.step || 0, ": ", entry.title || "Discovery step"), /* @__PURE__ */ React.createElement("span", { className: `text-[11px] ${mutedTextClass}` }, formatMissionDateTime(entry.timestamp, "Captured"))), /* @__PURE__ */ React.createElement("div", { className: `mt-1 ${subtextClass}` }, summarizeFindingEntry(entry)))))), /* @__PURE__ */ React.createElement("div", { className: `border rounded p-4 ${isDarkTheme ? "border-gray-600 bg-gray-800" : "border-gray-200 bg-white"}` }, /* @__PURE__ */ React.createElement("div", { className: "flex items-center gap-2 mb-3" }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-lightbulb text-amber-600" }), /* @__PURE__ */ React.createElement("h3", { className: `text-sm font-semibold ${headingClass}` }, "Investigation Opportunities")), v2UseCases.length === 0 ? /* @__PURE__ */ React.createElement("div", { className: `text-xs ${mutedTextClass}` }, "No suggested use cases were generated.") : /* @__PURE__ */ React.createElement("ul", { className: "space-y-2 text-xs" }, v2UseCases.slice(0, 6).map((item, idx) => /* @__PURE__ */ React.createElement("li", { key: idx, className: `${isDarkTheme ? "bg-gray-900 border-gray-700" : "bg-gray-50 border-gray-200"} border rounded-lg p-3` }, /* @__PURE__ */ React.createElement("div", { className: "flex items-start justify-between gap-3" }, /* @__PURE__ */ React.createElement("div", { className: `font-medium ${headingClass}` }, item.title || item.name || `Use Case ${idx + 1}`), /* @__PURE__ */ React.createElement("span", { className: `rounded-full px-2 py-0.5 border text-[11px] ${getOperatorPriorityClasses(item.implementation_complexity === "high" ? "high" : "medium")}` }, item.implementation_complexity ? `Complexity ${item.implementation_complexity}` : "Complexity unknown")), /* @__PURE__ */ React.createElement("div", { className: `mt-1 ${subtextClass}` }, item.description || item.use_case || "No description available."), /* @__PURE__ */ React.createElement("div", { className: `mt-2 ${mutedTextClass}` }, Array.isArray(item.success_metrics) && item.success_metrics[0] || item.business_value || "No explicit success metric was provided.")))))))), isCapabilitiesTab && /* @__PURE__ */ React.createElement("div", { className: "space-y-6 mb-6" }, /* @__PURE__ */ React.createElement("div", { className: `rounded-lg shadow-sm p-6 border ${panelClass}` }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-col xl:flex-row xl:items-start xl:justify-between gap-4" }, /* @__PURE__ */ React.createElement("div", { className: "max-w-3xl" }, /* @__PURE__ */ React.createElement("div", { className: `text-[11px] uppercase tracking-[0.18em] ${mutedTextClass}` }, "Capability Control Surface"), /* @__PURE__ */ React.createElement("h2", { className: `text-lg font-semibold mt-1 ${headingClass}` }, isCapabilitiesRagView ? "RAG Workspace" : "Capability Management"), /* @__PURE__ */ React.createElement("p", { className: `text-sm mt-2 ${subtextClass}` }, isCapabilitiesRagView ? "Dedicated workspace for indexed retrieval, managed knowledge assets, and context-preview inspection." : "Install, enable, test, inspect, and tune optional capabilities without leaving the app. RAG now has a dedicated workspace so the overview can stay focused on platform control.")), /* @__PURE__ */ React.createElement("div", { className: "flex flex-col sm:items-end gap-3" }, /* @__PURE__ */ React.createElement("div", { className: `inline-flex rounded-lg border overflow-hidden ${isDarkTheme ? "border-gray-600 bg-gray-900" : "border-gray-300 bg-gray-100"}`, role: "tablist", "aria-label": "Capabilities workspace views" }, /* @__PURE__ */ React.createElement(
      "button",
      {
        type: "button",
        role: "tab",
        "aria-selected": isCapabilitiesOverview,
        tabIndex: isCapabilitiesOverview ? 0 : -1,
        onClick: openCapabilitiesOverview,
        className: `px-3 py-1.5 text-xs sm:text-sm font-medium ${isCapabilitiesOverview ? "bg-indigo-600 text-white" : isDarkTheme ? "text-gray-200 hover:bg-gray-800" : "text-gray-700 hover:bg-white"}`
      },
      "Overview"
    ), /* @__PURE__ */ React.createElement(
      "button",
      {
        type: "button",
        role: "tab",
        "aria-selected": isCapabilitiesRagView,
        tabIndex: isCapabilitiesRagView ? 0 : -1,
        onClick: openRagCapabilitiesWorkspace,
        className: `px-3 py-1.5 text-xs sm:text-sm font-medium border-l ${isCapabilitiesRagView ? "bg-sky-600 text-white border-sky-500" : isDarkTheme ? "border-gray-700 text-gray-200 hover:bg-gray-800" : "border-gray-300 text-gray-700 hover:bg-white"}`
      },
      "RAG Workspace"
    )), /* @__PURE__ */ React.createElement("div", { className: `text-xs rounded-lg px-3 py-2 border ${panelMutedClass} ${mutedTextClass}` }, "Capability state is persisted in the encrypted application configuration."))), capabilityNotice && /* @__PURE__ */ React.createElement("div", { className: `mt-4 rounded-lg border px-3 py-2 text-sm ${capabilityNotice.type === "error" ? isDarkTheme ? "bg-red-950 border-red-800 text-red-100" : "bg-red-50 border-red-200 text-red-800" : isDarkTheme ? "bg-emerald-950 border-emerald-800 text-emerald-100" : "bg-emerald-50 border-emerald-200 text-emerald-800"}` }, capabilityNotice.message)), capabilitiesData.status === "error" ? /* @__PURE__ */ React.createElement("div", { className: `rounded-lg shadow-sm p-4 border ${isDarkTheme ? "bg-red-950 border-red-800 text-red-100" : "bg-red-50 border-red-200 text-red-800"}` }, capabilitiesData.error || "Failed to load capabilities.") : isCapabilitiesOverview ? /* @__PURE__ */ React.createElement(React.Fragment, null, /* @__PURE__ */ React.createElement("div", { className: `rounded-lg shadow-sm p-6 border ${panelClass}` }, /* @__PURE__ */ React.createElement("div", { className: "grid grid-cols-2 lg:grid-cols-5 gap-3" }, /* @__PURE__ */ React.createElement("div", { className: `${isDarkTheme ? "bg-indigo-900 border border-indigo-700" : "bg-indigo-50"} rounded-lg p-3` }, /* @__PURE__ */ React.createElement("div", { className: `${isDarkTheme ? "text-indigo-200" : "text-indigo-700"} text-xs uppercase tracking-wide` }, "Registered"), /* @__PURE__ */ React.createElement("div", { className: `${isDarkTheme ? "text-indigo-100" : "text-indigo-900"} text-2xl font-semibold` }, ((_La = capabilitiesData.summary) == null ? void 0 : _La.total) || 0)), /* @__PURE__ */ React.createElement("div", { className: `${isDarkTheme ? "bg-blue-900 border border-blue-700" : "bg-blue-50"} rounded-lg p-3` }, /* @__PURE__ */ React.createElement("div", { className: `${isDarkTheme ? "text-blue-200" : "text-blue-700"} text-xs uppercase tracking-wide` }, "Installed"), /* @__PURE__ */ React.createElement("div", { className: `${isDarkTheme ? "text-blue-100" : "text-blue-900"} text-2xl font-semibold` }, ((_Ma = capabilitiesData.summary) == null ? void 0 : _Ma.installed) || 0)), /* @__PURE__ */ React.createElement("div", { className: `${isDarkTheme ? "bg-emerald-900 border border-emerald-700" : "bg-emerald-50"} rounded-lg p-3` }, /* @__PURE__ */ React.createElement("div", { className: `${isDarkTheme ? "text-emerald-200" : "text-emerald-700"} text-xs uppercase tracking-wide` }, "Enabled"), /* @__PURE__ */ React.createElement("div", { className: `${isDarkTheme ? "text-emerald-100" : "text-emerald-900"} text-2xl font-semibold` }, ((_Na = capabilitiesData.summary) == null ? void 0 : _Na.enabled) || 0)), /* @__PURE__ */ React.createElement("div", { className: `${isDarkTheme ? "bg-amber-900 border border-amber-700" : "bg-amber-50"} rounded-lg p-3` }, /* @__PURE__ */ React.createElement("div", { className: `${isDarkTheme ? "text-amber-200" : "text-amber-700"} text-xs uppercase tracking-wide` }, "Ready"), /* @__PURE__ */ React.createElement("div", { className: `${isDarkTheme ? "text-amber-100" : "text-amber-900"} text-2xl font-semibold` }, ((_Oa = capabilitiesData.summary) == null ? void 0 : _Oa.ready) || 0)), /* @__PURE__ */ React.createElement("div", { className: `${isDarkTheme ? "bg-purple-900 border border-purple-700" : "bg-purple-50"} rounded-lg p-3` }, /* @__PURE__ */ React.createElement("div", { className: `${isDarkTheme ? "text-purple-200" : "text-purple-700"} text-xs uppercase tracking-wide` }, "Restart Required"), /* @__PURE__ */ React.createElement("div", { className: `${isDarkTheme ? "text-purple-100" : "text-purple-900"} text-2xl font-semibold` }, ((_Pa = capabilitiesData.summary) == null ? void 0 : _Pa.restart_required) || 0)))), /* @__PURE__ */ React.createElement("div", { className: `rounded-lg shadow-sm p-6 border ${panelClass}` }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-col lg:flex-row lg:items-start lg:justify-between gap-4 mb-4" }, /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("h3", { className: `text-base font-semibold ${headingClass}` }, "Focused Capability Workspaces"), /* @__PURE__ */ React.createElement("p", { className: `text-sm mt-1 ${subtextClass}` }, "Capabilities that have grown into full operator workflows are surfaced here first.")), /* @__PURE__ */ React.createElement("div", { className: `text-xs rounded-lg px-3 py-2 border ${panelMutedClass} ${mutedTextClass}` }, "RAG moved into a dedicated workspace so capability controls and retrieval operations no longer compete for the same canvas.")), renderRagOverviewCard()), /* @__PURE__ */ React.createElement("div", { className: `rounded-lg shadow-sm p-6 border ${panelClass}` }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-col lg:flex-row lg:items-start lg:justify-between gap-4 mb-4" }, /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("h3", { className: `text-base font-semibold ${headingClass}` }, "Capability Catalog"), /* @__PURE__ */ React.createElement("p", { className: `text-sm mt-1 ${subtextClass}` }, "Install, test, and configure the remaining optional platform capabilities here.")), /* @__PURE__ */ React.createElement("div", { className: `text-xs rounded-lg px-3 py-2 border ${panelMutedClass} ${mutedTextClass}` }, "Retrieval-specific operations live in the RAG workspace. Other capability packs stay in this overview.")), /* @__PURE__ */ React.createElement("div", { className: "grid grid-cols-1 xl:grid-cols-2 gap-4" }, genericCapabilityList.map((capability) => {
      var _a2, _b2, _c2, _d2, _e2, _f2, _g2, _h2, _i2, _j2, _k2;
      const actionInProgress = capabilityActionState[capability.name];
      const isBusy = !!actionInProgress;
      const statusLabel = capability.health_status || "unknown";
      const canInstall = !!capability.runtime_available && !capability.installed;
      const canEnable = !!capability.installed && !capability.enabled && !capability.restart_required;
      const canDisable = !!capability.installed && !!capability.enabled;
      const canTest = !!capability.installed;
      const canReindex = capability.name === "rag_chromadb" && !!capability.installed && !capability.restart_required;
      const canBuildDeeplink = capability.name === "splunk_deeplink_tools" && !!capability.installed && !!capability.enabled && !capability.restart_required && String(statusLabel).toLowerCase() === "ready";
      const indexSummary = (capability == null ? void 0 : capability.index_summary) && typeof capability.index_summary === "object" ? capability.index_summary : null;
      const knowledgeAssetSummary = (capability == null ? void 0 : capability.knowledge_asset_summary) && typeof capability.knowledge_asset_summary === "object" ? capability.knowledge_asset_summary : null;
      const indexSourceTypes = (indexSummary == null ? void 0 : indexSummary.source_type_counts) && typeof indexSummary.source_type_counts === "object" ? Object.entries(indexSummary.source_type_counts) : [];
      const knowledgeAssetTypeCounts = capability.name === "rag_chromadb" ? Object.entries(((_a2 = ragAssetWorkspace.summary) == null ? void 0 : _a2.asset_type_counts) || (knowledgeAssetSummary == null ? void 0 : knowledgeAssetSummary.asset_type_counts) || {}) : [];
      const displayedRagAssets = capability.name === "rag_chromadb" ? Array.isArray(ragAssetWorkspace.assets) && ragAssetWorkspace.assets.length > 0 ? ragAssetWorkspace.assets : [] : [];
      const displayedRagAssetCount = capability.name === "rag_chromadb" ? (_d2 = (_c2 = (_b2 = ragAssetWorkspace.summary) == null ? void 0 : _b2.asset_count) != null ? _c2 : knowledgeAssetSummary == null ? void 0 : knowledgeAssetSummary.asset_count) != null ? _d2 : 0 : 0;
      const displayedRagAssetDir = capability.name === "rag_chromadb" ? ((_e2 = ragAssetWorkspace.summary) == null ? void 0 : _e2.asset_dir) || (knowledgeAssetSummary == null ? void 0 : knowledgeAssetSummary.asset_dir) || "" : "";
      const deeplinkDraft = deeplinkDrafts[capability.name] || {};
      const deeplinkBuildResult = deeplinkBuildResults[capability.name] || null;
      return /* @__PURE__ */ React.createElement("div", { key: capability.name, className: `rounded-lg border p-4 ${isDarkTheme ? "bg-gray-900 border-gray-700" : "bg-white border-gray-200"}` }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-col sm:flex-row sm:items-start sm:justify-between gap-3 mb-3" }, /* @__PURE__ */ React.createElement("div", { className: "min-w-0" }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-wrap items-center gap-2 mb-1" }, /* @__PURE__ */ React.createElement("h3", { className: `text-base font-semibold ${headingClass}` }, capability.title || capability.name), /* @__PURE__ */ React.createElement("span", { className: `inline-flex items-center rounded-full px-2 py-0.5 text-[11px] font-medium ${getCapabilityStatusClasses(statusLabel)}` }, formatCapabilityStatusLabel(statusLabel)), /* @__PURE__ */ React.createElement("span", { className: `inline-flex items-center rounded-full px-2 py-0.5 text-[11px] font-medium ${isDarkTheme ? "bg-gray-800 text-gray-200 border border-gray-600" : "bg-gray-100 text-gray-700 border border-gray-300"}` }, formatCapabilityCategoryLabel(capability.category || "capability"))), /* @__PURE__ */ React.createElement("p", { className: `text-sm ${subtextClass}` }, capability.description || "Optional capability package.")), /* @__PURE__ */ React.createElement("div", { className: "flex items-center gap-2 sm:self-start" }, /* @__PURE__ */ React.createElement(
        "button",
        {
          type: "button",
          onClick: () => openCapabilityDetail(capability.name),
          "aria-label": `View details for ${capability.title || capability.name}`,
          title: "View details",
          className: `inline-flex h-9 w-9 items-center justify-center rounded-full border ${isDarkTheme ? "border-gray-600 bg-gray-800 text-sky-200 hover:bg-gray-700" : "border-gray-300 bg-white text-sky-700 hover:bg-sky-50"}`
        },
        /* @__PURE__ */ React.createElement("i", { className: "fa-solid fa-circle-info text-sm", "aria-hidden": "true" })
      ), /* @__PURE__ */ React.createElement("div", { className: `text-xs rounded-lg px-2.5 py-1.5 border ${panelMutedClass} ${mutedTextClass}` }, capability.runtime_available ? "Available now" : "Planned add-on"))), /* @__PURE__ */ React.createElement("div", { className: "grid grid-cols-2 gap-2 text-xs mb-3" }, /* @__PURE__ */ React.createElement("div", { className: `rounded p-2 ${isDarkTheme ? "bg-gray-800 text-gray-200" : "bg-gray-50 text-gray-700"}` }, /* @__PURE__ */ React.createElement("div", { className: mutedTextClass }, "Setup"), /* @__PURE__ */ React.createElement("div", { className: `font-medium mt-1 ${headingClass}` }, formatCapabilityInstallMethodLabel(capability.install_method || "unknown"))), /* @__PURE__ */ React.createElement("div", { className: `rounded p-2 ${isDarkTheme ? "bg-gray-800 text-gray-200" : "bg-gray-50 text-gray-700"}` }, /* @__PURE__ */ React.createElement("div", { className: mutedTextClass }, "Capability stage"), /* @__PURE__ */ React.createElement("div", { className: `font-medium mt-1 ${headingClass}` }, formatCapabilityMaturityLabel(capability.maturity || "experimental"))), /* @__PURE__ */ React.createElement("div", { className: `rounded p-2 ${isDarkTheme ? "bg-gray-800 text-gray-200" : "bg-gray-50 text-gray-700"}` }, /* @__PURE__ */ React.createElement("div", { className: mutedTextClass }, "Installed"), /* @__PURE__ */ React.createElement("div", { className: `font-medium mt-1 ${headingClass}` }, capability.installed ? "Yes" : "No")), /* @__PURE__ */ React.createElement("div", { className: `rounded p-2 ${isDarkTheme ? "bg-gray-800 text-gray-200" : "bg-gray-50 text-gray-700"}` }, /* @__PURE__ */ React.createElement("div", { className: mutedTextClass }, "Enabled"), /* @__PURE__ */ React.createElement("div", { className: `font-medium mt-1 ${headingClass}` }, capability.enabled ? "Yes" : "No"))), /* @__PURE__ */ React.createElement("div", { className: `text-xs rounded-lg border px-3 py-2 mb-3 ${panelMutedClass}` }, /* @__PURE__ */ React.createElement("div", { className: subtextClass }, capability.health_message || "Capability has not been tested yet."), (capability.last_tested_at || capability.version) && /* @__PURE__ */ React.createElement("div", { className: "flex flex-wrap gap-2 mt-2 text-[11px]" }, capability.last_tested_at && /* @__PURE__ */ React.createElement("span", { className: `rounded-full px-2 py-0.5 border ${isDarkTheme ? "bg-gray-800 text-gray-200 border-gray-600" : "bg-white text-gray-700 border-gray-300"}` }, "Checked ", new Date(capability.last_tested_at).toLocaleDateString()), capability.version && /* @__PURE__ */ React.createElement("span", { className: `rounded-full px-2 py-0.5 border ${isDarkTheme ? "bg-gray-800 text-gray-200 border-gray-600" : "bg-white text-gray-700 border-gray-300"}` }, "Version ", capability.version))), capability.name === "rag_chromadb" && /* @__PURE__ */ React.createElement(React.Fragment, null, /* @__PURE__ */ React.createElement("div", { className: `text-xs rounded-lg border px-3 py-2 mb-3 ${panelMutedClass} ${subtextClass}` }, /* @__PURE__ */ React.createElement("div", { className: "font-medium mb-1" }, "Index Status"), /* @__PURE__ */ React.createElement("div", null, "Documents indexed: ", (indexSummary == null ? void 0 : indexSummary.document_count) || 0), /* @__PURE__ */ React.createElement("div", null, "Source files indexed: ", (indexSummary == null ? void 0 : indexSummary.source_file_count) || 0), (indexSummary == null ? void 0 : indexSummary.last_indexed_at) && /* @__PURE__ */ React.createElement("div", { className: `mt-1 ${mutedTextClass}` }, "Last indexed: ", new Date(indexSummary.last_indexed_at).toLocaleString()), indexSourceTypes.length > 0 && /* @__PURE__ */ React.createElement("div", { className: "flex flex-wrap gap-2 mt-2" }, indexSourceTypes.map(([sourceType, count]) => /* @__PURE__ */ React.createElement("span", { key: sourceType, className: `rounded-full px-2 py-0.5 border ${isDarkTheme ? "bg-gray-800 text-gray-200 border-gray-600" : "bg-white text-gray-700 border-gray-300"}` }, formatCapabilitySourceTypeLabel(sourceType), ": ", count))), Array.isArray(indexSummary == null ? void 0 : indexSummary.sample_sources) && indexSummary.sample_sources.length > 0 && /* @__PURE__ */ React.createElement("div", { className: `mt-2 ${mutedTextClass}` }, "Sample sources: ", indexSummary.sample_sources.join(", "))), /* @__PURE__ */ React.createElement("div", { className: `text-xs rounded-lg border px-3 py-3 mb-3 ${panelMutedClass} ${subtextClass}` }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-col sm:flex-row sm:items-start sm:justify-between gap-2" }, /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("div", { className: "font-medium mb-1" }, "Knowledge Asset Plane"), /* @__PURE__ */ React.createElement("div", null, "Imported assets: ", displayedRagAssetCount), /* @__PURE__ */ React.createElement("div", null, "Managed asset directory: ", displayedRagAssetDir || "output/rag/assets")), /* @__PURE__ */ React.createElement("div", { className: `text-[11px] rounded-lg px-2 py-1 border ${canUseRagContextPreview ? isDarkTheme ? "bg-emerald-950 border-emerald-800 text-emerald-100" : "bg-emerald-50 border-emerald-200 text-emerald-800" : isDarkTheme ? "bg-amber-950 border-amber-800 text-amber-100" : "bg-amber-50 border-amber-200 text-amber-800"}` }, canUseRagContextPreview ? "Imported assets are available for indexed context previews." : "Import works now. Install, enable, and reindex indexed retrieval to use context previews and chat retrieval.")), knowledgeAssetTypeCounts.length > 0 && /* @__PURE__ */ React.createElement("div", { className: "flex flex-wrap gap-2 mt-2" }, knowledgeAssetTypeCounts.map(([assetType, count]) => /* @__PURE__ */ React.createElement("span", { key: assetType, className: `rounded-full px-2 py-0.5 border ${isDarkTheme ? "bg-gray-800 text-gray-200 border-gray-600" : "bg-white text-gray-700 border-gray-300"}` }, formatKnowledgeAssetTypeLabel(assetType), ": ", count)))), /* @__PURE__ */ React.createElement("div", { className: `rounded-lg border px-3 py-3 mb-3 ${isDarkTheme ? "border-gray-700 bg-gray-950" : "border-gray-200 bg-gray-50"}` }, /* @__PURE__ */ React.createElement("div", { className: `text-sm font-medium mb-2 ${headingClass}` }, "Import Knowledge Asset"), /* @__PURE__ */ React.createElement("div", { className: "grid grid-cols-1 sm:grid-cols-2 gap-2 mb-2" }, /* @__PURE__ */ React.createElement(
        "input",
        {
          value: ragAssetDraft.title || "",
          onChange: (event2) => updateRagAssetDraft("title", event2.target.value),
          placeholder: "Asset title",
          className: `rounded-lg border px-3 py-2 text-xs ${isDarkTheme ? "bg-gray-900 border-gray-700 text-gray-100" : "bg-white border-gray-300 text-gray-900"}`
        }
      ), /* @__PURE__ */ React.createElement(
        "select",
        {
          value: ragAssetDraft.asset_type || "reference_document",
          onChange: (event2) => updateRagAssetDraft("asset_type", event2.target.value),
          className: `rounded-lg border px-3 py-2 text-xs ${isDarkTheme ? "bg-gray-900 border-gray-700 text-gray-100" : "bg-white border-gray-300 text-gray-900"}`
        },
        /* @__PURE__ */ React.createElement("option", { value: "reference_document" }, "Reference Document"),
        /* @__PURE__ */ React.createElement("option", { value: "splunk_documentation" }, "Splunk Documentation"),
        /* @__PURE__ */ React.createElement("option", { value: "monitored_system_context" }, "Monitored System Context"),
        /* @__PURE__ */ React.createElement("option", { value: "connected_system_context" }, "Connected System Context"),
        /* @__PURE__ */ React.createElement("option", { value: "integration_context" }, "Integration Context"),
        /* @__PURE__ */ React.createElement("option", { value: "runbook_context" }, "Runbook Context")
      ), /* @__PURE__ */ React.createElement(
        "input",
        {
          value: ragAssetDraft.source_label || "",
          onChange: (event2) => updateRagAssetDraft("source_label", event2.target.value),
          placeholder: "Source label, system, or owner",
          className: `rounded-lg border px-3 py-2 text-xs ${isDarkTheme ? "bg-gray-900 border-gray-700 text-gray-100" : "bg-white border-gray-300 text-gray-900"}`
        }
      ), /* @__PURE__ */ React.createElement(
        "input",
        {
          value: ragAssetDraft.tags || "",
          onChange: (event2) => updateRagAssetDraft("tags", event2.target.value),
          placeholder: "Tags, comma separated",
          className: `rounded-lg border px-3 py-2 text-xs ${isDarkTheme ? "bg-gray-900 border-gray-700 text-gray-100" : "bg-white border-gray-300 text-gray-900"}`
        }
      )), /* @__PURE__ */ React.createElement(
        "textarea",
        {
          value: ragAssetDraft.description || "",
          onChange: (event2) => updateRagAssetDraft("description", event2.target.value),
          rows: 2,
          placeholder: "Why this asset matters to retrieval and what it should help answer",
          className: `w-full rounded-lg border px-3 py-2 text-xs mb-2 ${isDarkTheme ? "bg-gray-900 border-gray-700 text-gray-100" : "bg-white border-gray-300 text-gray-900"}`
        }
      ), /* @__PURE__ */ React.createElement(
        "textarea",
        {
          value: ragAssetDraft.content || "",
          onChange: (event2) => updateRagAssetDraft("content", event2.target.value),
          rows: 6,
          placeholder: "Paste documentation, system context, runbook notes, integration details, or other retrieval content here",
          className: `w-full rounded-lg border px-3 py-2 text-xs font-mono ${isDarkTheme ? "bg-gray-900 border-gray-700 text-gray-100" : "bg-white border-gray-300 text-gray-900"}`
        }
      ), /* @__PURE__ */ React.createElement("div", { className: "mt-2" }, /* @__PURE__ */ React.createElement("label", { className: `block text-xs font-medium mb-1 ${headingClass}` }, "Upload a supported asset instead"), /* @__PURE__ */ React.createElement(
        "input",
        {
          ref: ragAssetFileInputRef,
          type: "file",
          accept: ".md,.txt,.json,.log,.csv,.pdf,.docx",
          onChange: (event2) => {
            var _a3;
            return setRagAssetUploadFile(((_a3 = event2.target.files) == null ? void 0 : _a3[0]) || null);
          },
          className: `block w-full text-xs ${subtextClass}`
        }
      ), ragAssetUploadFile && /* @__PURE__ */ React.createElement("div", { className: `mt-1 ${mutedTextClass}` }, "Selected file: ", ragAssetUploadFile.name)), /* @__PURE__ */ React.createElement("div", { className: "flex flex-wrap gap-2 mt-3" }, /* @__PURE__ */ React.createElement(
        "button",
        {
          type: "button",
          onClick: importRagKnowledgeAsset,
          disabled: isBusy,
          className: `px-3 py-1.5 rounded text-sm font-medium ${!isBusy ? "bg-cyan-700 hover:bg-cyan-800 text-white" : isDarkTheme ? "bg-gray-800 text-gray-500 cursor-not-allowed" : "bg-gray-200 text-gray-500 cursor-not-allowed"}`
        },
        actionInProgress === "import-asset" ? "Importing..." : ragAssetUploadFile ? "Upload Asset" : "Import Asset"
      ), /* @__PURE__ */ React.createElement(
        "button",
        {
          type: "button",
          onClick: clearRagAssetDraft,
          disabled: isBusy,
          className: `px-3 py-1.5 rounded text-sm font-medium ${!isBusy ? "bg-slate-700 hover:bg-slate-800 text-white" : isDarkTheme ? "bg-gray-800 text-gray-500 cursor-not-allowed" : "bg-gray-200 text-gray-500 cursor-not-allowed"}`
        },
        "Reset Draft"
      )), /* @__PURE__ */ React.createElement("div", { className: `mt-2 text-xs ${mutedTextClass}` }, "Paste content or upload `.md`, `.txt`, `.json`, `.log`, `.csv`, `.pdf`, or `.docx`. If a file is selected, file import takes precedence over pasted content.")), /* @__PURE__ */ React.createElement("div", { className: `rounded-lg border px-3 py-3 mb-3 ${isDarkTheme ? "border-gray-700 bg-gray-950" : "border-gray-200 bg-gray-50"}` }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-col sm:flex-row sm:items-start sm:justify-between gap-2 mb-2" }, /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("div", { className: `text-sm font-medium ${headingClass}` }, "Build Context Preview"), /* @__PURE__ */ React.createElement("div", { className: `text-xs ${subtextClass}` }, "Preview the exact indexed context that retrieval can assemble from imported knowledge assets.")), /* @__PURE__ */ React.createElement("div", { className: `text-[11px] rounded-lg px-2 py-1 border ${canUseRagContextPreview ? isDarkTheme ? "bg-sky-950 border-sky-800 text-sky-100" : "bg-sky-50 border-sky-200 text-sky-800" : isDarkTheme ? "bg-gray-900 border-gray-700 text-gray-300" : "bg-white border-gray-300 text-gray-600"}` }, canUseRagContextPreview ? "Indexed asset search is ready." : "Indexed asset search is unavailable until rag_chromadb is installed, enabled, and reindexed.")), /* @__PURE__ */ React.createElement("div", { className: "grid grid-cols-1 sm:grid-cols-[minmax(0,1fr)_140px] gap-2" }, /* @__PURE__ */ React.createElement(
        "input",
        {
          value: ragContextQuery || "",
          onChange: (event2) => setRagContextQuery(event2.target.value),
          placeholder: "What should the assistant know about our Splunk indexer cluster dependencies?",
          className: `rounded-lg border px-3 py-2 text-xs ${isDarkTheme ? "bg-gray-900 border-gray-700 text-gray-100" : "bg-white border-gray-300 text-gray-900"}`
        }
      ), /* @__PURE__ */ React.createElement(
        "select",
        {
          value: ragContextLimit,
          onChange: (event2) => setRagContextLimit(Number(event2.target.value) || 4),
          className: `rounded-lg border px-3 py-2 text-xs ${isDarkTheme ? "bg-gray-900 border-gray-700 text-gray-100" : "bg-white border-gray-300 text-gray-900"}`
        },
        /* @__PURE__ */ React.createElement("option", { value: 2 }, "2 chunks"),
        /* @__PURE__ */ React.createElement("option", { value: 3 }, "3 chunks"),
        /* @__PURE__ */ React.createElement("option", { value: 4 }, "4 chunks"),
        /* @__PURE__ */ React.createElement("option", { value: 5 }, "5 chunks"),
        /* @__PURE__ */ React.createElement("option", { value: 6 }, "6 chunks")
      )), /* @__PURE__ */ React.createElement("div", { className: "flex flex-wrap gap-2 mt-3" }, /* @__PURE__ */ React.createElement(
        "button",
        {
          type: "button",
          onClick: buildRagContextPreview,
          disabled: !canUseRagContextPreview || isBusy,
          className: `px-3 py-1.5 rounded text-sm font-medium ${canUseRagContextPreview && !isBusy ? "bg-violet-600 hover:bg-violet-700 text-white" : isDarkTheme ? "bg-gray-800 text-gray-500 cursor-not-allowed" : "bg-gray-200 text-gray-500 cursor-not-allowed"}`
        },
        actionInProgress === "build-context" ? "Building Preview..." : "Build Preview"
      ), /* @__PURE__ */ React.createElement(
        "button",
        {
          type: "button",
          onClick: () => setRagAssetWorkspace((prev) => ({ ...prev, contextPreview: null })),
          disabled: !ragAssetWorkspace.contextPreview || isBusy,
          className: `px-3 py-1.5 rounded text-sm font-medium ${ragAssetWorkspace.contextPreview && !isBusy ? "bg-slate-700 hover:bg-slate-800 text-white" : isDarkTheme ? "bg-gray-800 text-gray-500 cursor-not-allowed" : "bg-gray-200 text-gray-500 cursor-not-allowed"}`
        },
        "Clear Preview"
      ), /* @__PURE__ */ React.createElement(
        "button",
        {
          type: "button",
          onClick: () => loadRagAssetWorkspace(),
          disabled: isBusy,
          className: `px-3 py-1.5 rounded text-sm font-medium ${!isBusy ? "bg-indigo-600 hover:bg-indigo-700 text-white" : isDarkTheme ? "bg-gray-800 text-gray-500 cursor-not-allowed" : "bg-gray-200 text-gray-500 cursor-not-allowed"}`
        },
        ragAssetWorkspace.status === "loading" ? "Refreshing..." : "Refresh Assets"
      )), ((_f2 = ragAssetWorkspace.contextPreview) == null ? void 0 : _f2.message) && /* @__PURE__ */ React.createElement("div", { className: `mt-3 text-xs rounded-lg border px-3 py-2 ${panelMutedClass} ${subtextClass}` }, ragAssetWorkspace.contextPreview.message), ((_g2 = ragAssetWorkspace.contextPreview) == null ? void 0 : _g2.operator_brief) && /* @__PURE__ */ React.createElement("div", { className: `mt-3 rounded-lg border px-3 py-3 ${isDarkTheme ? "bg-gray-900 border-gray-700" : "bg-white border-gray-300"}` }, /* @__PURE__ */ React.createElement("div", { className: `text-sm font-medium mb-2 ${headingClass}` }, "Operator Context Brief"), /* @__PURE__ */ React.createElement("pre", { className: `text-xs whitespace-pre-wrap font-mono ${isDarkTheme ? "text-gray-100" : "text-gray-900"}` }, ragAssetWorkspace.contextPreview.operator_brief)), Array.isArray((_h2 = ragAssetWorkspace.contextPreview) == null ? void 0 : _h2.matched_assets) && ragAssetWorkspace.contextPreview.matched_assets.length > 0 && /* @__PURE__ */ React.createElement("div", { className: "space-y-2 mt-3" }, ragAssetWorkspace.contextPreview.matched_assets.map((asset) => /* @__PURE__ */ React.createElement("div", { key: asset.asset_id || `${asset.title}-${asset.asset_type}`, className: `rounded-lg border px-3 py-3 text-xs ${isDarkTheme ? "bg-gray-900 border-gray-700 text-gray-100" : "bg-white border-gray-300 text-gray-800"}` }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-col sm:flex-row sm:items-start sm:justify-between gap-2" }, /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("div", { className: "flex flex-wrap items-center gap-2" }, /* @__PURE__ */ React.createElement("span", { className: `font-medium ${headingClass}` }, asset.title || "Matched asset"), /* @__PURE__ */ React.createElement("span", { className: `rounded-full px-2 py-0.5 border text-[11px] ${isDarkTheme ? "bg-sky-950 border-sky-800 text-sky-100" : "bg-sky-50 border-sky-200 text-sky-800"}` }, formatKnowledgeAssetTypeLabel(asset.asset_type))), asset.source_label && /* @__PURE__ */ React.createElement("div", { className: `mt-1 ${mutedTextClass}` }, "Source: ", asset.source_label)), /* @__PURE__ */ React.createElement("div", { className: "flex flex-wrap items-center gap-2" }, asset.match_score != null && /* @__PURE__ */ React.createElement("span", { className: `rounded-full px-2 py-0.5 border text-[11px] ${isDarkTheme ? "bg-violet-950 border-violet-800 text-violet-100" : "bg-violet-50 border-violet-200 text-violet-800"}` }, "score ", asset.match_score), asset.asset_id && /* @__PURE__ */ React.createElement(
        "button",
        {
          type: "button",
          onClick: () => loadRagAssetDetail(asset.asset_id, { force: true }),
          disabled: ragAssetWorkspace.detailStatus === "loading",
          className: `px-2.5 py-1 rounded text-[11px] font-medium ${ragAssetWorkspace.detailStatus !== "loading" ? "bg-slate-700 hover:bg-slate-800 text-white" : isDarkTheme ? "bg-gray-800 text-gray-500 cursor-not-allowed" : "bg-gray-200 text-gray-500 cursor-not-allowed"}`
        },
        ragAssetWorkspace.detailStatus === "loading" && ragAssetWorkspace.detailAssetId === asset.asset_id ? "Loading Detail..." : "Inspect Asset"
      ))), asset.why_matched && /* @__PURE__ */ React.createElement("div", { className: `mt-2 ${subtextClass}` }, asset.why_matched), asset.best_excerpt && /* @__PURE__ */ React.createElement("div", { className: `mt-2 ${subtextClass}` }, asset.best_excerpt), Array.isArray(asset.matched_chunks) && asset.matched_chunks.length > 0 && /* @__PURE__ */ React.createElement("div", { className: "flex flex-wrap gap-2 mt-2 text-[11px]" }, asset.matched_chunks.slice(0, 4).map((matchedChunk, matchedChunkIndex) => /* @__PURE__ */ React.createElement(
        "span",
        {
          key: `${asset.asset_id || asset.title}-${matchedChunk.document_id || matchedChunkIndex}`,
          className: `rounded-full px-2 py-0.5 border ${isDarkTheme ? "bg-emerald-950 border-emerald-800 text-emerald-100" : "bg-emerald-50 border-emerald-200 text-emerald-800"}`
        },
        matchedChunk.section || `Matched chunk ${matchedChunkIndex + 1}`,
        matchedChunk.score != null ? ` · ${matchedChunk.score}` : ""
      ))), Array.isArray(asset.focus_terms) && asset.focus_terms.length > 0 && /* @__PURE__ */ React.createElement("div", { className: "flex flex-wrap gap-2 mt-2 text-[11px]" }, asset.focus_terms.slice(0, 8).map((term) => /* @__PURE__ */ React.createElement("span", { key: `${asset.asset_id || asset.title}-${term}`, className: `rounded-full px-2 py-0.5 border ${isDarkTheme ? "bg-gray-800 border-gray-600 text-gray-200" : "bg-gray-100 border-gray-300 text-gray-700"}` }, term))), Array.isArray(asset.key_points) && asset.key_points.length > 0 && /* @__PURE__ */ React.createElement("ul", { className: `mt-2 list-disc pl-4 space-y-1 ${subtextClass}` }, asset.key_points.slice(0, 2).map((point, pointIndex) => /* @__PURE__ */ React.createElement("li", { key: `${asset.asset_id || asset.title}-${pointIndex}` }, point)))))), ((_i2 = ragAssetWorkspace.contextPreview) == null ? void 0 : _i2.context_text) && /* @__PURE__ */ React.createElement("pre", { className: `mt-3 rounded-lg border px-3 py-3 text-xs whitespace-pre-wrap font-mono ${isDarkTheme ? "bg-gray-900 border-gray-700 text-gray-100" : "bg-white border-gray-300 text-gray-900"}` }, ragAssetWorkspace.contextPreview.context_text), Array.isArray((_j2 = ragAssetWorkspace.contextPreview) == null ? void 0 : _j2.chunks) && ragAssetWorkspace.contextPreview.chunks.length > 0 && /* @__PURE__ */ React.createElement("div", { className: "space-y-2 mt-3" }, ragAssetWorkspace.contextPreview.chunks.map((chunk, chunkIndex) => /* @__PURE__ */ React.createElement("div", { key: `${chunk.source || "chunk"}-${chunkIndex}`, className: `rounded-lg border px-3 py-2 text-xs ${isDarkTheme ? "bg-gray-900 border-gray-700 text-gray-100" : "bg-white border-gray-300 text-gray-800"}` }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-wrap items-center gap-2 mb-1" }, /* @__PURE__ */ React.createElement("span", { className: `font-medium ${headingClass}` }, chunk.source || `Chunk ${chunkIndex + 1}`), chunk.score != null && /* @__PURE__ */ React.createElement("span", { className: `rounded-full px-2 py-0.5 border ${isDarkTheme ? "bg-violet-950 border-violet-800 text-violet-100" : "bg-violet-50 border-violet-200 text-violet-800"}` }, "score ", chunk.score)), /* @__PURE__ */ React.createElement("div", { className: subtextClass }, chunk.snippet || "No snippet returned."))))), /* @__PURE__ */ React.createElement("div", { className: `rounded-lg border px-3 py-3 mb-3 ${isDarkTheme ? "border-gray-700 bg-gray-950" : "border-gray-200 bg-gray-50"}` }, /* @__PURE__ */ React.createElement("div", { className: "flex items-center justify-between gap-2 mb-2" }, /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("div", { className: `text-sm font-medium ${headingClass}` }, "Imported Knowledge Assets"), /* @__PURE__ */ React.createElement("div", { className: `text-xs ${subtextClass}` }, "Use this list to confirm what RAG can draw from beyond generated discovery artifacts.")), /* @__PURE__ */ React.createElement("div", { className: `text-xs ${mutedTextClass}` }, displayedRagAssetCount, " asset(s)")), ragAssetWorkspace.status === "error" ? /* @__PURE__ */ React.createElement("div", { className: `text-xs rounded-lg border px-3 py-2 ${isDarkTheme ? "bg-red-950 border-red-800 text-red-100" : "bg-red-50 border-red-200 text-red-800"}` }, ragAssetWorkspace.error || "Failed to load managed knowledge assets.") : displayedRagAssets.length === 0 ? /* @__PURE__ */ React.createElement("div", { className: `text-xs rounded-lg border px-3 py-3 ${panelMutedClass} ${mutedTextClass}` }, "No managed knowledge assets have been imported yet.") : /* @__PURE__ */ React.createElement("div", { className: "space-y-2 max-h-96 overflow-y-auto pr-1" }, displayedRagAssets.map((asset) => {
        var _a3, _b3;
        return /* @__PURE__ */ React.createElement("div", { key: asset.asset_id || asset.content_path || asset.title, className: `rounded-lg border px-3 py-3 ${isDarkTheme ? "bg-gray-900 border-gray-700" : "bg-white border-gray-300"}` }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-col sm:flex-row sm:items-start sm:justify-between gap-2" }, /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("div", { className: "flex flex-wrap items-center gap-2" }, /* @__PURE__ */ React.createElement("div", { className: `text-sm font-medium ${headingClass}` }, asset.title || "Knowledge Asset"), /* @__PURE__ */ React.createElement("span", { className: `rounded-full px-2 py-0.5 border text-[11px] ${isDarkTheme ? "bg-sky-950 border-sky-800 text-sky-100" : "bg-sky-50 border-sky-200 text-sky-800"}` }, formatKnowledgeAssetTypeLabel(asset.asset_type)), /* @__PURE__ */ React.createElement("span", { className: `rounded-full px-2 py-0.5 border text-[11px] ${isDarkTheme ? "bg-gray-800 border-gray-600 text-gray-200" : "bg-gray-100 border-gray-300 text-gray-700"}` }, formatKnowledgeAssetImportMethodLabel(asset.import_method))), asset.source_label && /* @__PURE__ */ React.createElement("div", { className: `mt-1 text-xs ${mutedTextClass}` }, "Source: ", asset.source_label)), /* @__PURE__ */ React.createElement("div", { className: "flex flex-wrap gap-2" }, /* @__PURE__ */ React.createElement(
          "button",
          {
            type: "button",
            onClick: () => loadRagAssetDetail(asset.asset_id),
            disabled: ragAssetWorkspace.detailStatus === "loading" || !asset.asset_id,
            className: `px-3 py-1.5 rounded text-sm font-medium ${ragAssetWorkspace.detailStatus !== "loading" && asset.asset_id ? "bg-slate-700 hover:bg-slate-800 text-white" : isDarkTheme ? "bg-gray-800 text-gray-500 cursor-not-allowed" : "bg-gray-200 text-gray-500 cursor-not-allowed"}`
          },
          ragAssetWorkspace.detailStatus === "loading" && ragAssetWorkspace.detailAssetId === asset.asset_id ? "Loading Detail..." : ((_b3 = (_a3 = ragAssetWorkspace.assetDetail) == null ? void 0 : _a3.asset) == null ? void 0 : _b3.asset_id) === asset.asset_id ? "Hide Details" : "View Details"
        ), /* @__PURE__ */ React.createElement(
          "button",
          {
            type: "button",
            onClick: () => deleteRagKnowledgeAsset(asset.asset_id, asset.title),
            disabled: isBusy,
            className: `px-3 py-1.5 rounded text-sm font-medium ${!isBusy ? "bg-rose-600 hover:bg-rose-700 text-white" : isDarkTheme ? "bg-gray-800 text-gray-500 cursor-not-allowed" : "bg-gray-200 text-gray-500 cursor-not-allowed"}`
          },
          actionInProgress === "delete-asset" ? "Deleting..." : "Delete"
        ))), /* @__PURE__ */ React.createElement("div", { className: `mt-2 text-xs ${subtextClass}` }, asset.summary || asset.preview || "No summary available."), asset.description && /* @__PURE__ */ React.createElement("div", { className: `mt-2 text-xs ${mutedTextClass}` }, "Purpose: ", asset.description), Array.isArray(asset.tags) && asset.tags.length > 0 && /* @__PURE__ */ React.createElement("div", { className: "flex flex-wrap gap-2 mt-2 text-[11px]" }, asset.tags.map((tag) => /* @__PURE__ */ React.createElement("span", { key: `${asset.asset_id || asset.title}-${tag}`, className: `rounded-full px-2 py-0.5 border ${isDarkTheme ? "bg-gray-800 border-gray-600 text-gray-200" : "bg-gray-100 border-gray-300 text-gray-700"}` }, tag))), Array.isArray(asset.focus_terms) && asset.focus_terms.length > 0 && /* @__PURE__ */ React.createElement("div", { className: "flex flex-wrap gap-2 mt-2 text-[11px]" }, asset.focus_terms.slice(0, 8).map((term) => /* @__PURE__ */ React.createElement("span", { key: `${asset.asset_id || asset.title}-focus-${term}`, className: `rounded-full px-2 py-0.5 border ${isDarkTheme ? "bg-sky-950 border-sky-800 text-sky-100" : "bg-sky-50 border-sky-200 text-sky-800"}` }, term))), Array.isArray(asset.key_points) && asset.key_points.length > 0 && /* @__PURE__ */ React.createElement("ul", { className: `mt-2 list-disc pl-4 space-y-1 text-xs ${subtextClass}` }, asset.key_points.slice(0, 2).map((point, pointIndex) => /* @__PURE__ */ React.createElement("li", { key: `${asset.asset_id || asset.title}-point-${pointIndex}` }, point))), Array.isArray(asset.usage_guidance) && asset.usage_guidance.length > 0 && /* @__PURE__ */ React.createElement("div", { className: `mt-2 text-xs ${mutedTextClass}` }, "Best used for: ", asset.usage_guidance[0]), /* @__PURE__ */ React.createElement("div", { className: "grid grid-cols-2 gap-2 mt-3 text-[11px]" }, /* @__PURE__ */ React.createElement("div", { className: mutedTextClass }, "Words: ", asset.word_count || 0), /* @__PURE__ */ React.createElement("div", { className: mutedTextClass }, "Characters: ", asset.text_char_count || 0), /* @__PURE__ */ React.createElement("div", { className: mutedTextClass }, "Imported: ", asset.created_at ? new Date(asset.created_at).toLocaleString() : "Unknown"), /* @__PURE__ */ React.createElement("div", { className: mutedTextClass }, "Stored as: ", asset.content_path || "managed asset")));
      }))), (ragAssetWorkspace.detailAssetId || ragAssetWorkspace.assetDetail) && /* @__PURE__ */ React.createElement("div", { className: `rounded-lg border px-3 py-3 mb-3 ${isDarkTheme ? "border-gray-700 bg-gray-950" : "border-gray-200 bg-gray-50"}` }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-col sm:flex-row sm:items-start sm:justify-between gap-2 mb-3" }, /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("div", { className: `text-sm font-medium ${headingClass}` }, "Knowledge Asset Detail"), /* @__PURE__ */ React.createElement("div", { className: `text-xs ${subtextClass}` }, "Inspect the stored asset sections and the chunk splits the indexer uses for retrieval.")), /* @__PURE__ */ React.createElement(
        "button",
        {
          type: "button",
          onClick: clearRagAssetDetail,
          className: `px-3 py-1.5 rounded text-sm font-medium ${isDarkTheme ? "bg-gray-800 hover:bg-gray-700 text-gray-100" : "bg-white hover:bg-gray-100 text-gray-800 border border-gray-300"}`
        },
        "Close Detail"
      )), ragAssetWorkspace.detailStatus === "loading" ? /* @__PURE__ */ React.createElement("div", { className: `text-xs rounded-lg border px-3 py-3 ${panelMutedClass} ${subtextClass}` }, "Loading managed knowledge asset detail.") : ragAssetWorkspace.detailStatus === "error" ? /* @__PURE__ */ React.createElement("div", { className: `text-xs rounded-lg border px-3 py-3 ${isDarkTheme ? "bg-red-950 border-red-800 text-red-100" : "bg-red-50 border-red-200 text-red-800"}` }, ragAssetWorkspace.detailError || "Knowledge asset detail could not be loaded.") : ((_k2 = ragAssetWorkspace.assetDetail) == null ? void 0 : _k2.asset) ? /* @__PURE__ */ React.createElement(React.Fragment, null, /* @__PURE__ */ React.createElement("div", { className: `rounded-lg border px-3 py-3 mb-3 ${isDarkTheme ? "bg-gray-900 border-gray-700" : "bg-white border-gray-300"}` }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-col sm:flex-row sm:items-start sm:justify-between gap-2" }, /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("div", { className: "flex flex-wrap items-center gap-2" }, /* @__PURE__ */ React.createElement("span", { className: `text-sm font-medium ${headingClass}` }, ragAssetWorkspace.assetDetail.asset.title || "Knowledge Asset"), /* @__PURE__ */ React.createElement("span", { className: `rounded-full px-2 py-0.5 border text-[11px] ${isDarkTheme ? "bg-sky-950 border-sky-800 text-sky-100" : "bg-sky-50 border-sky-200 text-sky-800"}` }, formatKnowledgeAssetTypeLabel(ragAssetWorkspace.assetDetail.asset.asset_type))), ragAssetWorkspace.assetDetail.asset.source_label && /* @__PURE__ */ React.createElement("div", { className: `mt-1 text-xs ${mutedTextClass}` }, "Source: ", ragAssetWorkspace.assetDetail.asset.source_label)), /* @__PURE__ */ React.createElement("div", { className: `text-xs ${mutedTextClass}` }, "Stored as: ", ragAssetWorkspace.assetDetail.stored_path || ragAssetWorkspace.assetDetail.asset.content_path || "managed asset")), /* @__PURE__ */ React.createElement("div", { className: "grid grid-cols-2 sm:grid-cols-4 gap-2 mt-3 text-[11px]" }, /* @__PURE__ */ React.createElement("div", { className: mutedTextClass }, "Stored sections: ", Array.isArray(ragAssetWorkspace.assetDetail.stored_sections) ? ragAssetWorkspace.assetDetail.stored_sections.length : 0), /* @__PURE__ */ React.createElement("div", { className: mutedTextClass }, "Chunk sections: ", ragAssetWorkspace.assetDetail.chunk_count || 0), /* @__PURE__ */ React.createElement("div", { className: mutedTextClass }, "Context characters: ", ragAssetWorkspace.assetDetail.context_character_count || 0), /* @__PURE__ */ React.createElement("div", { className: mutedTextClass }, "Imported: ", ragAssetWorkspace.assetDetail.asset.created_at ? new Date(ragAssetWorkspace.assetDetail.asset.created_at).toLocaleString() : "Unknown"))), (() => {
        const detailAttributes = getKnowledgeAssetAttributes(ragAssetWorkspace.assetDetail.asset);
        const detailSplQuery = String(detailAttributes.spl_query || "").trim();
        if (!detailSplQuery) {
          return null;
        }
        return /* @__PURE__ */ React.createElement("div", { "data-testid": "context-library-detail-spl-query", className: `rounded-lg border px-3 py-3 mb-3 ${isDarkTheme ? "bg-gray-900 border-gray-700" : "bg-white border-gray-300"}` }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-col gap-2 sm:flex-row sm:items-start sm:justify-between" }, /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("div", { className: `text-sm font-medium ${headingClass}` }, "Saved SPL Query"), /* @__PURE__ */ React.createElement("div", { className: `mt-1 text-xs ${subtextClass}` }, "Run this query in Splunk Web, reuse it in chat, or keep it parked in the context library.")), renderSplQueryActionButtons2(detailSplQuery, {
          allowSave: false,
          originKind: "spl_library_asset",
          originLabel: ragAssetWorkspace.assetDetail.asset.title || "Saved SPL Library Query",
          sourceLabel: ragAssetWorkspace.assetDetail.asset.source_label || ragAssetWorkspace.assetDetail.asset.title || "SPL Library Query",
          contextExcerpt: ragAssetWorkspace.assetDetail.asset.summary || ragAssetWorkspace.assetDetail.asset.preview || "",
          deeplinkOptions: {
            app: detailAttributes.app,
            earliest: detailAttributes.earliest,
            latest: detailAttributes.latest
          },
          className: "sm:justify-end"
        })), /* @__PURE__ */ React.createElement("pre", { className: `mt-3 max-h-40 overflow-auto rounded-lg border px-3 py-3 text-xs whitespace-pre-wrap font-mono ${isDarkTheme ? "bg-gray-950 border-gray-700 text-gray-100" : "bg-gray-50 border-gray-200 text-gray-900"}` }, detailSplQuery), renderSplQueryIntelligence(detailAttributes, { testIdPrefix: "context-library-detail-spl" }));
      })(), /* @__PURE__ */ React.createElement("div", { className: "grid grid-cols-1 lg:grid-cols-2 gap-3" }, /* @__PURE__ */ React.createElement("div", { className: `rounded-lg border px-3 py-3 ${isDarkTheme ? "bg-gray-900 border-gray-700" : "bg-white border-gray-300"}` }, /* @__PURE__ */ React.createElement("div", { className: `text-sm font-medium mb-2 ${headingClass}` }, "Stored Sections"), /* @__PURE__ */ React.createElement("div", { className: "space-y-2 max-h-96 overflow-y-auto pr-1" }, Array.isArray(ragAssetWorkspace.assetDetail.stored_sections) && ragAssetWorkspace.assetDetail.stored_sections.length > 0 ? ragAssetWorkspace.assetDetail.stored_sections.map((section, sectionIndex) => /* @__PURE__ */ React.createElement("details", { key: `${section.title || "section"}-${sectionIndex}`, open: section.title !== "Context", className: `rounded border px-3 py-2 ${isDarkTheme ? "border-gray-700 bg-gray-950" : "border-gray-200 bg-gray-50"}` }, /* @__PURE__ */ React.createElement("summary", { className: `cursor-pointer text-xs font-medium ${headingClass}` }, section.title || `Section ${sectionIndex + 1}`, " (", section.character_count || 0, " chars)"), Array.isArray(section.items) && section.items.length > 0 ? /* @__PURE__ */ React.createElement("ul", { className: `mt-2 list-disc pl-4 space-y-1 text-xs ${subtextClass}` }, section.items.map((item, itemIndex) => /* @__PURE__ */ React.createElement("li", { key: `${section.title || "section"}-${itemIndex}` }, item))) : /* @__PURE__ */ React.createElement("pre", { className: `mt-2 text-xs whitespace-pre-wrap font-mono ${subtextClass}` }, section.content || "No section content available."))) : /* @__PURE__ */ React.createElement("div", { className: `text-xs rounded-lg border px-3 py-3 ${panelMutedClass} ${mutedTextClass}` }, "No stored sections were available for this asset."))), /* @__PURE__ */ React.createElement("div", { className: `rounded-lg border px-3 py-3 ${isDarkTheme ? "bg-gray-900 border-gray-700" : "bg-white border-gray-300"}` }, /* @__PURE__ */ React.createElement("div", { className: `text-sm font-medium mb-2 ${headingClass}` }, "Chunk Browser"), /* @__PURE__ */ React.createElement("div", { className: `text-xs mb-2 ${subtextClass}` }, "These are the current chunk splits generated from the asset file by the indexing logic."), activeDetailPreviewTrace.matchedChunkIds.length > 0 && /* @__PURE__ */ React.createElement("div", { className: `text-xs rounded-lg border px-3 py-2 mb-2 ${isDarkTheme ? "bg-sky-950 border-sky-800 text-sky-100" : "bg-sky-50 border-sky-200 text-sky-800"}` }, "Current preview matched ", activeDetailPreviewTrace.matchedChunkIds.length, " chunk-browser section(s) for this asset. Highlighted below."), /* @__PURE__ */ React.createElement("div", { className: "space-y-2 max-h-96 overflow-y-auto pr-1" }, Array.isArray(ragAssetWorkspace.assetDetail.chunk_sections) && ragAssetWorkspace.assetDetail.chunk_sections.length > 0 ? ragAssetWorkspace.assetDetail.chunk_sections.map((section, sectionIndex) => {
        const isPreviewMatched = activeDetailPreviewTrace.matchedChunkIds.includes(section.document_id);
        return /* @__PURE__ */ React.createElement("details", { key: section.document_id || `${section.section || "chunk"}-${sectionIndex}`, open: isPreviewMatched || sectionIndex === 0, className: `rounded border px-3 py-2 ${isPreviewMatched ? isDarkTheme ? "border-sky-700 bg-sky-950/40" : "border-sky-300 bg-sky-50" : isDarkTheme ? "border-gray-700 bg-gray-950" : "border-gray-200 bg-gray-50"}` }, /* @__PURE__ */ React.createElement("summary", { className: `cursor-pointer text-xs font-medium ${headingClass}` }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-wrap items-center gap-2" }, /* @__PURE__ */ React.createElement("span", null, section.section || `Chunk ${sectionIndex + 1}`, " (", section.character_count || 0, " chars)"), isPreviewMatched && /* @__PURE__ */ React.createElement("span", { className: `rounded-full px-2 py-0.5 border text-[11px] ${isDarkTheme ? "bg-sky-900 border-sky-700 text-sky-100" : "bg-sky-100 border-sky-300 text-sky-800"}` }, "Matched in Preview"))), /* @__PURE__ */ React.createElement("pre", { className: `mt-2 text-xs whitespace-pre-wrap font-mono ${subtextClass}` }, section.content || "No chunk content available."));
      }) : /* @__PURE__ */ React.createElement("div", { className: `text-xs rounded-lg border px-3 py-3 ${panelMutedClass} ${mutedTextClass}` }, "No chunk-browser sections were produced for this asset."))))) : null)), capability.name === "splunk_deeplink_tools" && /* @__PURE__ */ React.createElement("div", { className: `rounded-lg border px-3 py-3 mb-3 ${isDarkTheme ? "border-gray-700 bg-gray-950" : "border-gray-200 bg-gray-50"}` }, /* @__PURE__ */ React.createElement("div", { className: `text-sm font-medium mb-2 ${headingClass}` }, "Build Search Deeplink"), /* @__PURE__ */ React.createElement(
        "textarea",
        {
          value: deeplinkDraft.query || "",
          onChange: (event2) => updateDeeplinkDraft(capability.name, "query", event2.target.value),
          rows: 3,
          placeholder: "search index=_internal | head 20",
          className: `w-full rounded-lg border px-3 py-2 text-xs font-mono ${isDarkTheme ? "bg-gray-900 border-gray-700 text-gray-100" : "bg-white border-gray-300 text-gray-900"}`
        }
      ), /* @__PURE__ */ React.createElement("div", { className: "grid grid-cols-1 sm:grid-cols-3 gap-2 mt-2" }, /* @__PURE__ */ React.createElement(
        "input",
        {
          value: deeplinkDraft.earliest || "",
          onChange: (event2) => updateDeeplinkDraft(capability.name, "earliest", event2.target.value),
          placeholder: "-24h",
          className: `rounded-lg border px-3 py-2 text-xs font-mono ${isDarkTheme ? "bg-gray-900 border-gray-700 text-gray-100" : "bg-white border-gray-300 text-gray-900"}`
        }
      ), /* @__PURE__ */ React.createElement(
        "input",
        {
          value: deeplinkDraft.latest || "",
          onChange: (event2) => updateDeeplinkDraft(capability.name, "latest", event2.target.value),
          placeholder: "now",
          className: `rounded-lg border px-3 py-2 text-xs font-mono ${isDarkTheme ? "bg-gray-900 border-gray-700 text-gray-100" : "bg-white border-gray-300 text-gray-900"}`
        }
      ), /* @__PURE__ */ React.createElement(
        "input",
        {
          value: deeplinkDraft.app || "",
          onChange: (event2) => updateDeeplinkDraft(capability.name, "app", event2.target.value),
          placeholder: "search",
          className: `rounded-lg border px-3 py-2 text-xs font-mono ${isDarkTheme ? "bg-gray-900 border-gray-700 text-gray-100" : "bg-white border-gray-300 text-gray-900"}`
        }
      )), (deeplinkBuildResult == null ? void 0 : deeplinkBuildResult.url) && /* @__PURE__ */ React.createElement("div", { className: `mt-2 text-xs break-all ${subtextClass}` }, "Latest build:", " ", /* @__PURE__ */ React.createElement(
        "a",
        {
          href: deeplinkBuildResult.url,
          target: "_blank",
          rel: "noreferrer",
          className: "text-sky-600 hover:text-sky-800 underline"
        },
        deeplinkBuildResult.url
      )), /* @__PURE__ */ React.createElement("div", { className: "flex flex-wrap gap-2 mt-3" }, /* @__PURE__ */ React.createElement(
        "button",
        {
          onClick: () => buildCapabilityDeeplink({
            query: deeplinkDraft.query || "",
            earliest: deeplinkDraft.earliest || void 0,
            latest: deeplinkDraft.latest || void 0,
            app: deeplinkDraft.app || void 0
          }, { name: capability.name }),
          disabled: !canBuildDeeplink || isBusy,
          className: `px-3 py-1.5 rounded text-sm font-medium ${canBuildDeeplink && !isBusy ? "bg-sky-600 hover:bg-sky-700 text-white" : isDarkTheme ? "bg-gray-800 text-gray-500 cursor-not-allowed" : "bg-gray-200 text-gray-500 cursor-not-allowed"}`
        },
        actionInProgress === "build" ? "Building..." : "Build Link"
      ), /* @__PURE__ */ React.createElement(
        "button",
        {
          onClick: () => buildCapabilityDeeplink({
            query: deeplinkDraft.query || "",
            earliest: deeplinkDraft.earliest || void 0,
            latest: deeplinkDraft.latest || void 0,
            app: deeplinkDraft.app || void 0
          }, { name: capability.name, openAfterBuild: true, suppressNotice: true }),
          disabled: !canBuildDeeplink || isBusy,
          className: `px-3 py-1.5 rounded text-sm font-medium ${canBuildDeeplink && !isBusy ? "bg-cyan-700 hover:bg-cyan-800 text-white" : isDarkTheme ? "bg-gray-800 text-gray-500 cursor-not-allowed" : "bg-gray-200 text-gray-500 cursor-not-allowed"}`
        },
        "Open Link"
      ))), /* @__PURE__ */ React.createElement("details", { className: `mb-3 rounded-lg border ${isDarkTheme ? "border-gray-700 bg-gray-950" : "border-gray-200 bg-gray-50"}` }, /* @__PURE__ */ React.createElement("summary", { className: `cursor-pointer px-3 py-2 text-sm font-medium ${headingClass}` }, "Inspect Configuration"), /* @__PURE__ */ React.createElement("div", { className: "px-3 pb-3" }, /* @__PURE__ */ React.createElement(
        "textarea",
        {
          value: capabilityDrafts[capability.name] || "{}",
          onChange: (event2) => updateCapabilityDraft(capability.name, event2.target.value),
          rows: 8,
          className: `w-full rounded-lg border px-3 py-2 text-xs font-mono ${isDarkTheme ? "bg-gray-900 border-gray-700 text-gray-100" : "bg-white border-gray-300 text-gray-900"}`
        }
      ), capability.name === "rag_local" && /* @__PURE__ */ React.createElement("div", { className: `mt-2 text-xs ${mutedTextClass}` }, "To use local artifact search in chat, install and enable this capability here, then turn on Optional Local Search in Chat Settings."), capability.name === "rag_chromadb" && /* @__PURE__ */ React.createElement("div", { className: `mt-2 text-xs ${mutedTextClass}` }, "Install the capability, restart the app if prompted, then enable and reindex it before using it in chat."), capability.name === "splunk_deeplink_tools" && /* @__PURE__ */ React.createElement("div", { className: `mt-2 text-xs ${mutedTextClass}` }, "Set web_base_url to override automatic derivation from the MCP URL. Once installed and enabled, assistant SPL cards expose an Open in Splunk action."), capability.name === "visualization_tools" && /* @__PURE__ */ React.createElement("div", { className: `mt-2 text-xs ${mutedTextClass}` }, "Keep preview_enabled on to let the assistant render inline chart previews for time-series and aggregation-style query results."), capability.name === "export_tools" && /* @__PURE__ */ React.createElement("div", { className: `mt-2 text-xs ${mutedTextClass}` }, "Set source_dir and export_dir only if discovery output lives outside the default output folder. Once installed and enabled, Build Report Package creates a downloadable zip with a manifest, summary note, selected artifacts, and the current persona runbook."))), /* @__PURE__ */ React.createElement("div", { className: "flex flex-wrap gap-2" }, /* @__PURE__ */ React.createElement(
        "button",
        {
          onClick: () => runCapabilityAction(capability.name, "install"),
          disabled: !canInstall || isBusy,
          className: `px-3 py-1.5 rounded text-sm font-medium ${canInstall && !isBusy ? "bg-indigo-600 hover:bg-indigo-700 text-white" : isDarkTheme ? "bg-gray-800 text-gray-500 cursor-not-allowed" : "bg-gray-200 text-gray-500 cursor-not-allowed"}`
        },
        actionInProgress === "install" ? "Installing..." : capability.installed ? "Installed" : capability.runtime_available ? "Install" : "Planned"
      ), /* @__PURE__ */ React.createElement(
        "button",
        {
          onClick: () => runCapabilityAction(capability.name, "enable"),
          disabled: !canEnable || isBusy,
          className: `px-3 py-1.5 rounded text-sm font-medium ${canEnable && !isBusy ? "bg-emerald-600 hover:bg-emerald-700 text-white" : isDarkTheme ? "bg-gray-800 text-gray-500 cursor-not-allowed" : "bg-gray-200 text-gray-500 cursor-not-allowed"}`
        },
        actionInProgress === "enable" ? "Enabling..." : "Enable"
      ), /* @__PURE__ */ React.createElement(
        "button",
        {
          onClick: () => runCapabilityAction(capability.name, "disable"),
          disabled: !canDisable || isBusy,
          className: `px-3 py-1.5 rounded text-sm font-medium ${canDisable && !isBusy ? "bg-rose-600 hover:bg-rose-700 text-white" : isDarkTheme ? "bg-gray-800 text-gray-500 cursor-not-allowed" : "bg-gray-200 text-gray-500 cursor-not-allowed"}`
        },
        actionInProgress === "disable" ? "Disabling..." : "Disable"
      ), /* @__PURE__ */ React.createElement(
        "button",
        {
          onClick: () => runCapabilityAction(capability.name, "test"),
          disabled: !canTest || isBusy,
          className: `px-3 py-1.5 rounded text-sm font-medium ${canTest && !isBusy ? "bg-amber-600 hover:bg-amber-700 text-white" : isDarkTheme ? "bg-gray-800 text-gray-500 cursor-not-allowed" : "bg-gray-200 text-gray-500 cursor-not-allowed"}`
        },
        actionInProgress === "test" ? "Testing..." : "Test"
      ), capability.name === "rag_chromadb" && /* @__PURE__ */ React.createElement(
        "button",
        {
          onClick: () => runCapabilityAction(capability.name, "reindex"),
          disabled: !canReindex || isBusy,
          className: `px-3 py-1.5 rounded text-sm font-medium ${canReindex && !isBusy ? "bg-violet-600 hover:bg-violet-700 text-white" : isDarkTheme ? "bg-gray-800 text-gray-500 cursor-not-allowed" : "bg-gray-200 text-gray-500 cursor-not-allowed"}`
        },
        actionInProgress === "reindex" ? "Reindexing..." : "Reindex"
      ), /* @__PURE__ */ React.createElement(
        "button",
        {
          onClick: () => saveCapabilityConfig(capability.name),
          disabled: isBusy,
          className: `px-3 py-1.5 rounded text-sm font-medium ${!isBusy ? "bg-slate-700 hover:bg-slate-800 text-white" : isDarkTheme ? "bg-gray-800 text-gray-500 cursor-not-allowed" : "bg-gray-200 text-gray-500 cursor-not-allowed"}`
        },
        actionInProgress === "config" ? "Saving..." : "Save Config"
      )));
    })))) : renderRagWorkspaceView()), isArtifactsTab && /* @__PURE__ */ React.createElement("div", { className: "mb-6 space-y-6" }, /* @__PURE__ */ React.createElement("div", { className: "space-y-6" }, /* @__PURE__ */ React.createElement("div", { className: `rounded-lg shadow-sm p-6 border ${panelClass}` }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-col gap-6 2xl:flex-row 2xl:items-start 2xl:justify-between" }, /* @__PURE__ */ React.createElement("div", { className: "max-w-3xl" }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-wrap items-center gap-2" }, /* @__PURE__ */ React.createElement("span", { className: `inline-flex items-center rounded-full px-3 py-1 text-xs font-semibold ${discoveryStatusMeta.statusBadgeClass}` }, /* @__PURE__ */ React.createElement("span", { "aria-hidden": "true", className: `w-2 h-2 rounded-full mr-2 ${discoveryStatusMeta.dotClass} ${isMissionDiscoveryActive ? "animate-pulse" : ""}` }), discoveryStatusMeta.label), /* @__PURE__ */ React.createElement("span", { className: `inline-flex items-center rounded-full px-3 py-1 text-xs font-semibold ${panelMutedClass} ${mutedTextClass}` }, discoveryStatusMeta.monitorLabel)), /* @__PURE__ */ React.createElement("div", { className: `mt-4 text-[11px] uppercase tracking-[0.18em] ${mutedTextClass}` }, "Discovery Control Center"), /* @__PURE__ */ React.createElement("h2", { className: `mt-1 text-xl font-semibold ${headingClass}` }, "Run discovery without losing workspace context"), /* @__PURE__ */ React.createElement("p", { className: `mt-2 text-sm leading-6 ${subtextClass}` }, discoveryStatusMeta.summary), /* @__PURE__ */ React.createElement("div", { className: "mt-4 flex flex-wrap items-center gap-2 text-xs" }, /* @__PURE__ */ React.createElement(
      "button",
      {
        type: "button",
        onClick: isMissionDiscoveryActive ? abortDiscovery : startDiscovery,
        className: `px-3 py-2 rounded ${isMissionDiscoveryActive ? "bg-red-600 hover:bg-red-700 text-white" : "bg-indigo-600 hover:bg-indigo-700 text-white"}`,
        title: isMissionDiscoveryActive ? "Abort active discovery pipeline" : "Run full discovery pipeline"
      },
      isMissionDiscoveryActive ? /* @__PURE__ */ React.createElement(React.Fragment, null, /* @__PURE__ */ React.createElement("i", { className: "fas fa-stop mr-1" }), "Abort Discovery") : /* @__PURE__ */ React.createElement(React.Fragment, null, /* @__PURE__ */ React.createElement("i", { className: "fas fa-rocket mr-1" }), "Run Discovery")
    ), /* @__PURE__ */ React.createElement(
      "button",
      {
        type: "button",
        onClick: refreshArtifactsWorkspace,
        className: "px-3 py-2 rounded bg-emerald-600 hover:bg-emerald-700 text-white",
        title: "Reload discovery outputs and report library"
      },
      /* @__PURE__ */ React.createElement("i", { className: "fas fa-folder-open mr-1" }),
      "Refresh Discovery"
    ), /* @__PURE__ */ React.createElement("span", { className: `inline-flex items-center rounded-full px-3 py-1 border ${panelMutedClass} ${mutedTextClass}` }, "Header monitor stays visible across workspaces"))), /* @__PURE__ */ React.createElement("div", { className: "grid gap-3 sm:grid-cols-2 xl:w-[440px]" }, /* @__PURE__ */ React.createElement("div", { className: `rounded-xl border p-4 ${isDarkTheme ? "bg-gray-900 border-gray-700" : "bg-gray-50 border-gray-200"}` }, /* @__PURE__ */ React.createElement("div", { className: `text-xs uppercase tracking-wide ${mutedTextClass}` }, "Run status"), /* @__PURE__ */ React.createElement("div", { className: `mt-2 text-sm font-semibold ${headingClass}` }, discoveryStatusMeta.label), /* @__PURE__ */ React.createElement("div", { className: `mt-1 text-xs ${subtextClass}` }, discoveryNarrative)), /* @__PURE__ */ React.createElement("div", { className: `rounded-xl border p-4 ${isDarkTheme ? "bg-gray-900 border-gray-700" : "bg-gray-50 border-gray-200"}` }, /* @__PURE__ */ React.createElement("div", { className: `text-xs uppercase tracking-wide ${mutedTextClass}` }, "Progress"), /* @__PURE__ */ React.createElement("div", { className: `mt-2 text-sm font-semibold ${headingClass}` }, discoveryStatusNormalized === "idle" ? "Ready" : `${discoveryProgressPercent}%`), /* @__PURE__ */ React.createElement("div", { className: `mt-1 text-xs ${subtextClass}` }, isMissionDiscoveryActive ? "Live percentage from the pipeline" : "Last known run progress or readiness state")), /* @__PURE__ */ React.createElement("div", { className: `rounded-xl border p-4 ${isDarkTheme ? "bg-gray-900 border-gray-700" : "bg-gray-50 border-gray-200"}` }, /* @__PURE__ */ React.createElement("div", { className: `text-xs uppercase tracking-wide ${mutedTextClass}` }, isMissionDiscoveryActive ? "Elapsed" : "Last update"), /* @__PURE__ */ React.createElement("div", { className: `mt-2 text-sm font-semibold ${headingClass}` }, isMissionDiscoveryActive ? formatElapsedTime(elapsedTime) : discoveryUpdatedLabel), /* @__PURE__ */ React.createElement("div", { className: `mt-1 text-xs ${subtextClass}` }, isMissionDiscoveryActive ? `${discoveryEtaMethodLabel} ${discoveryEtaLabel}` : `Completed ${discoveryCompletedLabel}`)), /* @__PURE__ */ React.createElement("div", { className: `rounded-xl border p-4 ${isDarkTheme ? "bg-gray-900 border-gray-700" : "bg-gray-50 border-gray-200"}` }, /* @__PURE__ */ React.createElement("div", { className: `text-xs uppercase tracking-wide ${mutedTextClass}` }, selectedReport ? "Focused output" : "Latest session"), /* @__PURE__ */ React.createElement("div", { className: `mt-2 text-sm font-semibold break-all ${headingClass}` }, selectedReport || discoveryResultSessionLabel), /* @__PURE__ */ React.createElement("div", { className: `mt-1 text-xs ${subtextClass}` }, selectedReport ? "Viewer pinned to the selected discovery output" : discoveryReportCount > 0 ? `${discoveryReportCount} output artifact(s) available from the latest completed run` : "The library column is the entry point for output review."))))), discoveryStatusNormalized !== "idle" && /* @__PURE__ */ React.createElement("div", { className: `rounded-lg shadow-sm p-6 border ${discoveryStatusMeta.tonePanelClass}` }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-col gap-4 xl:flex-row xl:items-start xl:justify-between" }, /* @__PURE__ */ React.createElement("div", { className: "max-w-3xl" }, /* @__PURE__ */ React.createElement("div", { className: `text-[11px] uppercase tracking-[0.18em] ${discoveryStatusMeta.toneTextClass}` }, "Discovery Monitor"), /* @__PURE__ */ React.createElement("h2", { className: `mt-1 text-xl font-semibold ${discoveryStatusMeta.toneTextClass}` }, discoveryStatusMeta.bannerTitle), /* @__PURE__ */ React.createElement("p", { className: `mt-2 text-sm ${discoveryStatusMeta.toneTextClass}` }, discoveryNarrative)), /* @__PURE__ */ React.createElement("div", { className: "grid grid-cols-2 gap-3 xl:w-[460px] xl:grid-cols-4" }, /* @__PURE__ */ React.createElement("div", { className: `rounded-xl border px-3 py-3 ${isDarkTheme ? "bg-gray-950 border-gray-700" : "bg-white border-gray-200"}` }, /* @__PURE__ */ React.createElement("div", { className: `text-[11px] uppercase tracking-wide ${mutedTextClass}` }, "Status"), /* @__PURE__ */ React.createElement("div", { className: `mt-1 text-sm font-semibold ${headingClass}` }, discoveryStatusMeta.shortValue)), /* @__PURE__ */ React.createElement("div", { className: `rounded-xl border px-3 py-3 ${isDarkTheme ? "bg-gray-950 border-gray-700" : "bg-white border-gray-200"}` }, /* @__PURE__ */ React.createElement("div", { className: `text-[11px] uppercase tracking-wide ${mutedTextClass}` }, "Progress"), /* @__PURE__ */ React.createElement("div", { className: `mt-1 text-sm font-semibold ${headingClass}` }, discoveryStatusNormalized === "idle" ? "0%" : `${discoveryProgressPercent}%`)), /* @__PURE__ */ React.createElement("div", { className: `rounded-xl border px-3 py-3 ${isDarkTheme ? "bg-gray-950 border-gray-700" : "bg-white border-gray-200"}` }, /* @__PURE__ */ React.createElement("div", { className: `text-[11px] uppercase tracking-wide ${mutedTextClass}` }, isMissionDiscoveryActive ? "Elapsed" : "Last update"), /* @__PURE__ */ React.createElement("div", { className: `mt-1 text-sm font-semibold ${headingClass}` }, isMissionDiscoveryActive ? formatElapsedTime(elapsedTime) : discoveryUpdatedLabel)), /* @__PURE__ */ React.createElement("div", { className: `rounded-xl border px-3 py-3 ${isDarkTheme ? "bg-gray-950 border-gray-700" : "bg-white border-gray-200"}` }, /* @__PURE__ */ React.createElement("div", { className: `text-[11px] uppercase tracking-wide ${mutedTextClass}` }, isMissionDiscoveryActive ? discoveryEtaMethodLabel : "Session"), /* @__PURE__ */ React.createElement("div", { className: `mt-1 text-sm font-semibold ${headingClass}` }, isMissionDiscoveryActive ? discoveryEtaLabel : discoveryResultSessionLabel)))), /* @__PURE__ */ React.createElement("div", { className: `mt-4 h-3 rounded-full ${discoveryStatusMeta.progressTrackClass}` }, /* @__PURE__ */ React.createElement(
      "div",
      {
        className: `${discoveryStatusMeta.progressFillClass} h-3 rounded-full progress-bar`,
        style: { width: `${discoveryStatusNormalized === "completed" ? 100 : Math.max(discoveryProgressPercent, isMissionDiscoveryActive ? 6 : 0)}%` }
      }
    )), !isMissionDiscoveryActive && /* @__PURE__ */ React.createElement("div", { className: `mt-4 flex flex-wrap items-center gap-3 text-xs ${discoveryStatusMeta.toneTextClass}` }, /* @__PURE__ */ React.createElement("span", null, "Completed: ", discoveryCompletedLabel), discoveryReportCount > 0 && /* @__PURE__ */ React.createElement("span", null, "Outputs: ", discoveryReportCount), discoveryStatusNormalized === "error" && discoveryErrorMessage && /* @__PURE__ */ React.createElement("span", null, discoveryErrorMessage))), /* @__PURE__ */ React.createElement("div", { className: `rounded-lg shadow-sm border ${panelClass}` }, /* @__PURE__ */ React.createElement("div", { className: `p-6 border-b ${isDarkTheme ? "border-gray-700" : "border-gray-200"}` }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between" }, /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("div", { className: `text-[11px] uppercase tracking-[0.18em] ${mutedTextClass}` }, "Pipeline Ledger"), /* @__PURE__ */ React.createElement("h2", { className: `mt-1 text-lg font-medium ${headingClass}` }, "Discovery Stage Ledger"), /* @__PURE__ */ React.createElement("p", { className: `mt-2 text-sm leading-6 ${subtextClass}` }, "Current anchor: ", discoveryPhaseLeadTitle, ". Completed ", discoveryCompletedPhaseCount, " of ", discoveryPhaseEntries.length || 0, " tracked stages.")), /* @__PURE__ */ React.createElement("div", { className: "flex flex-wrap items-center gap-2 text-xs" }, /* @__PURE__ */ React.createElement("span", { className: `inline-flex items-center rounded-full px-2.5 py-1 border ${isDarkTheme ? "bg-gray-900 border-gray-700 text-gray-200" : "bg-gray-50 border-gray-200 text-gray-700"}` }, isMissionDiscoveryActive ? "Live stage tracking" : "Last run ledger"), /* @__PURE__ */ React.createElement("span", { className: `inline-flex items-center rounded-full px-2.5 py-1 border ${panelMutedClass} ${mutedTextClass}` }, discoveryCompletedPhaseCount, "/", discoveryPhaseEntries.length || 0, " stages completed")))), /* @__PURE__ */ React.createElement("div", { className: "p-6" }, discoveryPhaseEntries.length === 0 ? /* @__PURE__ */ React.createElement("div", { className: `rounded-xl border px-4 py-4 text-sm ${panelMutedClass} ${mutedTextClass}` }, "No stage ledger is available yet. Start discovery to populate the tracked pipeline stages.") : /* @__PURE__ */ React.createElement("div", { className: "grid gap-3 xl:grid-cols-2" }, discoveryPhaseEntries.map((phase, index) => {
      const phaseStatus = String(phase.status || "pending").trim().toLowerCase();
      const isSummaryStage = index === discoveryPhaseEntries.length - 1;
      const showSummaryAction = isSummaryStage && isDiscoverySummaryReady && discoverySummarySession;
      const phaseStatusLabel = phaseStatus === "active" ? "Active" : phaseStatus === "completed" ? "Complete" : phaseStatus === "error" ? "Issue" : phaseStatus === "aborted" ? "Stopped" : "Pending";
      const phaseShellClass = phaseStatus === "active" ? isDarkTheme ? "bg-indigo-950/40 border-indigo-700" : "bg-indigo-50 border-indigo-200" : phaseStatus === "completed" ? isDarkTheme ? "bg-emerald-950/35 border-emerald-700" : "bg-emerald-50 border-emerald-200" : phaseStatus === "error" ? isDarkTheme ? "bg-rose-950/35 border-rose-700" : "bg-rose-50 border-rose-200" : phaseStatus === "aborted" ? isDarkTheme ? "bg-orange-950/35 border-orange-700" : "bg-orange-50 border-orange-200" : isDarkTheme ? "bg-gray-950 border-gray-800" : "bg-gray-50 border-gray-200";
      const phaseBadgeClass = phaseStatus === "active" ? isDarkTheme ? "bg-indigo-950 border-indigo-700 text-indigo-100" : "bg-indigo-50 border-indigo-200 text-indigo-800" : phaseStatus === "completed" ? isDarkTheme ? "bg-emerald-950 border-emerald-700 text-emerald-100" : "bg-emerald-50 border-emerald-200 text-emerald-800" : phaseStatus === "error" ? isDarkTheme ? "bg-rose-950 border-rose-700 text-rose-100" : "bg-rose-50 border-rose-200 text-rose-800" : phaseStatus === "aborted" ? isDarkTheme ? "bg-orange-950 border-orange-700 text-orange-100" : "bg-orange-50 border-orange-200 text-orange-800" : `${panelMutedClass} ${mutedTextClass}`;
      const phaseNarrative = phaseStatus === "active" ? progress.description || phase.last_detail || phase.description : phase.last_detail || phase.description || "Awaiting this pipeline segment.";
      return /* @__PURE__ */ React.createElement("div", { key: phase.key || index, className: `rounded-xl border px-4 py-4 ${phaseShellClass}` }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-wrap items-start justify-between gap-3" }, /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("div", { className: `text-[11px] uppercase tracking-wide ${mutedTextClass}` }, "Stage ", index + 1), /* @__PURE__ */ React.createElement("div", { className: `mt-1 text-sm font-semibold ${headingClass}` }, phase.label)), /* @__PURE__ */ React.createElement("span", { className: `inline-flex items-center rounded-full border px-2.5 py-1 text-[11px] font-semibold ${phaseBadgeClass}` }, phaseStatusLabel)), /* @__PURE__ */ React.createElement("div", { className: `mt-2 text-xs leading-5 ${subtextClass}` }, phaseNarrative), /* @__PURE__ */ React.createElement("div", { className: `mt-3 flex flex-wrap items-center gap-3 text-[11px] ${mutedTextClass}` }, /* @__PURE__ */ React.createElement("span", null, phase.started_at ? `Started ${formatMissionDateTime(phase.started_at, "Live now")}` : "Pending start"), phase.completed_at && /* @__PURE__ */ React.createElement("span", null, "Finished ", formatMissionDateTime(phase.completed_at, "Awaiting completion")), phaseStatus === "active" && /* @__PURE__ */ React.createElement("span", null, discoveryProgressPercent, "% overall")), showSummaryAction && /* @__PURE__ */ React.createElement("div", { className: "mt-4 flex flex-wrap items-center gap-3" }, /* @__PURE__ */ React.createElement(
        "button",
        {
          type: "button",
          "data-testid": "discovery-ledger-summary-action",
          onClick: () => openSummaryModal(discoverySummarySession.timestamp, { hasSummary: discoverySummarySession.hasSummary }),
          className: `inline-flex items-center rounded-lg px-3 py-2 text-xs font-medium text-white shadow-sm transition-colors ${discoverySummarySession.hasSummary ? "bg-emerald-600 hover:bg-emerald-700" : "bg-indigo-600 hover:bg-indigo-700"}`,
          title: discoverySummarySession.hasSummary ? "View saved summary for this discovery run" : "Generate summary for this completed discovery run"
        },
        /* @__PURE__ */ React.createElement("i", { className: `fas ${discoverySummarySession.hasSummary ? "fa-eye" : "fa-magic"} mr-2` }),
        /* @__PURE__ */ React.createElement("span", null, discoverySummarySession.hasSummary ? "View Summary" : "Summarize")
      ), /* @__PURE__ */ React.createElement("span", { className: `text-[11px] ${mutedTextClass}` }, discoverySummarySession.hasSummary ? `Summary is ready for ${formatMissionSessionSelectionLabel(discoverySummarySession.timestamp)}.` : `Generate a summary for ${formatMissionSessionSelectionLabel(discoverySummarySession.timestamp)}.`)));
    })))), /* @__PURE__ */ React.createElement("div", { className: `rounded-lg shadow-sm border ${panelClass}` }, /* @__PURE__ */ React.createElement("div", { className: `p-6 border-b ${isDarkTheme ? "border-gray-700" : "border-gray-200"}` }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between" }, /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("div", { className: `text-[11px] uppercase tracking-[0.18em] ${mutedTextClass}` }, "Discovery Activity"), /* @__PURE__ */ React.createElement("h2", { className: `mt-1 text-lg font-medium ${headingClass}` }, "Discovery Log")), /* @__PURE__ */ React.createElement("div", { className: "flex flex-wrap items-center gap-2 text-xs" }, /* @__PURE__ */ React.createElement("span", { className: `inline-flex items-center rounded-full px-2.5 py-1 border ${isDarkTheme ? "bg-gray-900 border-gray-700 text-gray-200" : "bg-gray-50 border-gray-200 text-gray-700"}` }, isMissionDiscoveryActive ? "Live discovery" : discoveryStatusNormalized === "completed" ? "Last run complete" : discoveryStatusNormalized === "error" ? "Last run needs attention" : discoveryStatusNormalized === "aborted" ? "Last run stopped" : "Awaiting next run"), discoveryHasFocusedReport && /* @__PURE__ */ React.createElement("span", { className: `inline-flex items-center rounded-full px-2.5 py-1 border ${isDarkTheme ? "bg-indigo-950 border-indigo-800 text-indigo-100" : "bg-indigo-50 border-indigo-200 text-indigo-700"}` }, "Focused artifact selected")))), /* @__PURE__ */ React.createElement(
      "div",
      {
        ref: discoveryLogContainerRef,
        className: "p-6 overflow-y-auto scroll-container",
        style: { height: `${discoveryLogHeight}px` }
      },
      /* @__PURE__ */ React.createElement("div", { className: "space-y-4" }, messages.map((message) => /* @__PURE__ */ React.createElement("div", { key: message.id }, renderMessage(message))), /* @__PURE__ */ React.createElement("div", { ref: messagesEndRef }))
    ), /* @__PURE__ */ React.createElement(
      "div",
      {
        className: `h-2 border-t cursor-ns-resize flex items-center justify-center group ${isDarkTheme ? "bg-gray-700 border-gray-600 hover:bg-gray-600" : "bg-gray-100 border-gray-200 hover:bg-gray-200"}`,
        onMouseDown: handleLogMouseDown
      },
      /* @__PURE__ */ React.createElement("div", { className: "w-12 h-1 bg-gray-400 rounded group-hover:bg-gray-500" })
    ))), /* @__PURE__ */ React.createElement("div", { className: discoveryWorkspaceSplitClass }, /* @__PURE__ */ React.createElement("div", { className: "min-w-0 lg:col-span-2" }, discoveryHasFocusedReport ? renderReportViewerPanel() : renderArtifactEmptyState()), /* @__PURE__ */ React.createElement("div", { className: "min-w-0 lg:col-span-1" }, renderDiscoveryReportLibraryPanel())))))), discoveryActionDialog && /* @__PURE__ */ React.createElement(
      "div",
      {
        className: "fixed inset-0 z-50 flex items-center justify-center bg-black/50 px-4 py-6",
        onClick: closeDiscoveryActionDialog
      },
      /* @__PURE__ */ React.createElement(
        "div",
        {
          role: "dialog",
          "aria-modal": "true",
          "aria-labelledby": "discovery-action-dialog-title",
          className: `w-full max-w-xl rounded-2xl border shadow-2xl ${isDarkTheme ? "bg-gray-900 border-gray-700" : "bg-white border-gray-200"}`,
          onClick: (event2) => event2.stopPropagation(),
          onKeyDown: (event2) => handleDialogKeyDown(event2, closeDiscoveryActionDialog),
          tabIndex: -1
        },
        /* @__PURE__ */ React.createElement("div", { className: `rounded-t-2xl border-b px-6 py-5 ${isDarkTheme ? "border-gray-700" : "border-gray-200"} ${discoveryActionDialog.tone === "rose" ? isDarkTheme ? "bg-rose-950/40" : "bg-rose-50" : isDarkTheme ? "bg-amber-950/40" : "bg-amber-50"}` }, /* @__PURE__ */ React.createElement("div", { className: "flex items-start justify-between gap-4" }, /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("div", { className: `text-[11px] uppercase tracking-[0.18em] ${mutedTextClass}` }, discoveryActionDialog.eyebrow), /* @__PURE__ */ React.createElement("h2", { id: "discovery-action-dialog-title", className: `mt-2 text-lg font-semibold ${headingClass}` }, /* @__PURE__ */ React.createElement("i", { className: `fas ${discoveryActionDialog.icon} mr-2 ${discoveryActionDialog.tone === "rose" ? "text-rose-600" : "text-amber-600"}` }), discoveryActionDialog.title)), /* @__PURE__ */ React.createElement(
          "button",
          {
            type: "button",
            onClick: closeDiscoveryActionDialog,
            className: `rounded-lg px-2 py-1 text-sm ${isDarkTheme ? "text-gray-300 hover:bg-gray-800 hover:text-gray-100" : "text-gray-500 hover:bg-gray-100 hover:text-gray-700"}`,
            "aria-label": "Close discovery action dialog"
          },
          /* @__PURE__ */ React.createElement("i", { className: "fas fa-times" })
        ))),
        /* @__PURE__ */ React.createElement("div", { className: "px-6 py-5" }, /* @__PURE__ */ React.createElement("p", { className: `text-sm leading-6 ${subtextClass}` }, discoveryActionDialog.summary), Array.isArray(discoveryActionDialog.details) && discoveryActionDialog.details.length > 0 && /* @__PURE__ */ React.createElement("ul", { className: "mt-4 space-y-2 text-sm" }, discoveryActionDialog.details.map((detail, index) => /* @__PURE__ */ React.createElement("li", { key: `discovery-action-detail-${index}`, className: `flex items-start gap-2 ${subtextClass}` }, /* @__PURE__ */ React.createElement("i", { className: `fas fa-angle-right mt-1 ${discoveryActionDialog.tone === "rose" ? "text-rose-500" : "text-amber-500"}` }), /* @__PURE__ */ React.createElement("span", null, detail))))),
        /* @__PURE__ */ React.createElement("div", { className: `flex flex-col-reverse gap-2 rounded-b-2xl border-t px-6 py-4 sm:flex-row sm:justify-end ${isDarkTheme ? "border-gray-700 bg-gray-950" : "border-gray-200 bg-gray-50"}` }, /* @__PURE__ */ React.createElement(
          "button",
          {
            type: "button",
            onClick: closeDiscoveryActionDialog,
            className: `rounded-lg px-4 py-2 text-sm font-medium ${isDarkTheme ? "bg-gray-800 text-gray-100 hover:bg-gray-700" : "bg-white text-gray-700 hover:bg-gray-100 border border-gray-300"}`
          },
          discoveryActionDialog.cancelLabel || "Cancel"
        ), /* @__PURE__ */ React.createElement(
          "button",
          {
            type: "button",
            onClick: confirmDiscoveryAction,
            className: `rounded-lg px-4 py-2 text-sm font-medium text-white ${discoveryActionDialog.tone === "rose" ? "bg-rose-600 hover:bg-rose-700" : "bg-amber-600 hover:bg-amber-700"}`
          },
          discoveryActionDialog.confirmLabel || "Continue"
        ))
      )
    ), summaryActionDialog && /* @__PURE__ */ React.createElement(
      "div",
      {
        className: "fixed inset-0 z-50 flex items-center justify-center bg-black/50 px-4 py-6",
        onClick: closeSummaryActionDialog
      },
      /* @__PURE__ */ React.createElement(
        "div",
        {
          role: "dialog",
          "aria-modal": "true",
          "aria-labelledby": "summary-action-dialog-title",
          className: `w-full max-w-xl rounded-2xl border shadow-2xl ${isDarkTheme ? "bg-gray-900 border-gray-700" : "bg-white border-gray-200"}`,
          onClick: (event2) => event2.stopPropagation(),
          onKeyDown: (event2) => handleDialogKeyDown(event2, closeSummaryActionDialog),
          tabIndex: -1
        },
        /* @__PURE__ */ React.createElement("div", { className: `rounded-t-2xl border-b px-6 py-5 ${isDarkTheme ? "border-gray-700" : "border-gray-200"} ${summaryActionDialog.tone === "rose" ? isDarkTheme ? "bg-rose-950/40" : "bg-rose-50" : isDarkTheme ? "bg-amber-950/40" : "bg-amber-50"}` }, /* @__PURE__ */ React.createElement("div", { className: "flex items-start justify-between gap-4" }, /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("div", { className: `text-[11px] uppercase tracking-[0.18em] ${mutedTextClass}` }, summaryActionDialog.eyebrow), /* @__PURE__ */ React.createElement("h2", { id: "summary-action-dialog-title", className: `mt-2 text-lg font-semibold ${headingClass}` }, /* @__PURE__ */ React.createElement("i", { className: `fas ${summaryActionDialog.icon} mr-2 ${summaryActionDialog.tone === "rose" ? "text-rose-600" : "text-amber-600"}` }), summaryActionDialog.title)), /* @__PURE__ */ React.createElement(
          "button",
          {
            type: "button",
            onClick: closeSummaryActionDialog,
            className: `rounded-lg px-2 py-1 text-sm ${isDarkTheme ? "text-gray-300 hover:bg-gray-800 hover:text-gray-100" : "text-gray-500 hover:bg-gray-100 hover:text-gray-700"}`,
            "aria-label": "Close summary action dialog"
          },
          /* @__PURE__ */ React.createElement("i", { className: "fas fa-times" })
        ))),
        /* @__PURE__ */ React.createElement("div", { className: "px-6 py-5" }, /* @__PURE__ */ React.createElement("p", { className: `text-sm leading-6 ${subtextClass}` }, summaryActionDialog.summary), Array.isArray(summaryActionDialog.details) && summaryActionDialog.details.length > 0 && /* @__PURE__ */ React.createElement("ul", { className: "mt-4 space-y-2 text-sm" }, summaryActionDialog.details.map((detail, index) => /* @__PURE__ */ React.createElement("li", { key: `summary-action-detail-${index}`, className: `flex items-start gap-2 ${subtextClass}` }, /* @__PURE__ */ React.createElement("i", { className: `fas fa-angle-right mt-1 ${summaryActionDialog.tone === "rose" ? "text-rose-500" : "text-amber-500"}` }), /* @__PURE__ */ React.createElement("span", null, detail))))),
        /* @__PURE__ */ React.createElement("div", { className: `flex flex-col-reverse gap-2 rounded-b-2xl border-t px-6 py-4 sm:flex-row sm:justify-end ${isDarkTheme ? "border-gray-700 bg-gray-950" : "border-gray-200 bg-gray-50"}` }, /* @__PURE__ */ React.createElement(
          "button",
          {
            type: "button",
            onClick: closeSummaryActionDialog,
            className: `rounded-lg px-4 py-2 text-sm font-medium ${isDarkTheme ? "bg-gray-800 text-gray-100 hover:bg-gray-700" : "bg-white text-gray-700 hover:bg-gray-100 border border-gray-300"}`
          },
          summaryActionDialog.cancelLabel || "Cancel"
        ), /* @__PURE__ */ React.createElement(
          "button",
          {
            type: "button",
            onClick: confirmSummaryAction,
            className: `rounded-lg px-4 py-2 text-sm font-medium text-white ${summaryActionDialog.tone === "rose" ? "bg-rose-600 hover:bg-rose-700" : "bg-amber-600 hover:bg-amber-700"}`
          },
          summaryActionDialog.confirmLabel || "Continue"
        ))
      )
    ), renderCapabilityDetailModal(), isConnectionModalOpen && /* @__PURE__ */ React.createElement(
      "div",
      {
        className: "fixed inset-0 z-50",
        onClick: () => setIsConnectionModalOpen(false)
      },
      /* @__PURE__ */ React.createElement(
        "div",
        {
          id: "connection-details-popover",
          role: "dialog",
          "aria-modal": "false",
          "aria-labelledby": "connection-details-title",
          className: `connection-popover absolute rounded-xl shadow-2xl w-80 ${isDarkTheme ? "bg-gray-800 border border-gray-600" : "bg-white border border-gray-200"}`,
          onClick: (e) => e.stopPropagation(),
          onKeyDown: (event2) => handleDialogKeyDown(event2, () => setIsConnectionModalOpen(false)),
          tabIndex: -1,
          style: {
            top: `${connectionModalPosition.top}px`,
            left: `${connectionModalPosition.left}px`,
            boxShadow: "0 20px 25px -5px rgba(0, 0, 0, 0.1), 0 10px 10px -5px rgba(0, 0, 0, 0.04)"
          }
        },
        /* @__PURE__ */ React.createElement(
          "div",
          {
            className: `absolute -top-2 w-4 h-4 rotate-45 border-l border-t ${isDarkTheme ? "bg-gray-800 border-gray-600" : "bg-white border-gray-200"}`,
            style: { left: `${connectionModalPosition.pointerLeft}px` }
          }
        ),
        /* @__PURE__ */ React.createElement("div", { className: `p-4 border-b flex justify-between items-center relative z-10 rounded-t-xl ${isDarkTheme ? "border-gray-700 bg-gray-800" : "border-gray-200 bg-white"}` }, /* @__PURE__ */ React.createElement("div", { className: "flex items-center" }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-plug text-lg text-indigo-600 mr-2" }), /* @__PURE__ */ React.createElement("h2", { id: "connection-details-title", className: `text-base font-semibold ${isDarkTheme ? "text-gray-100" : "text-gray-900"}` }, "Connection Details")), /* @__PURE__ */ React.createElement(
          "button",
          {
            type: "button",
            onClick: () => setIsConnectionModalOpen(false),
            className: `${isDarkTheme ? "text-gray-400 hover:text-gray-200" : "text-gray-400 hover:text-gray-600"} transition-colors`,
            "aria-label": "Close connection details"
          },
          /* @__PURE__ */ React.createElement("i", { className: "fas fa-times" })
        )),
        /* @__PURE__ */ React.createElement("div", { className: "p-4 space-y-3" }, connectionInfo ? connectionInfo.error ? /* @__PURE__ */ React.createElement("div", { className: "text-sm text-red-600" }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-exclamation-triangle mr-2" }), connectionInfo.error) : /* @__PURE__ */ React.createElement(React.Fragment, null, /* @__PURE__ */ React.createElement("div", { className: "bg-gradient-to-br from-purple-50 to-indigo-50 rounded-lg p-3 border border-indigo-100" }, /* @__PURE__ */ React.createElement("h3", { className: "text-sm font-semibold text-gray-900 mb-2 flex items-center" }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-brain text-purple-600 mr-2 text-xs" }), "LLM Configuration"), /* @__PURE__ */ React.createElement("div", { className: "space-y-1.5" }, /* @__PURE__ */ React.createElement("div", { className: "flex items-start" }, /* @__PURE__ */ React.createElement("span", { className: "text-xs font-medium text-gray-500 w-16" }, "Provider:"), /* @__PURE__ */ React.createElement("span", { className: "text-xs text-gray-900 font-semibold" }, ((_Qa = connectionInfo.llm) == null ? void 0 : _Qa.provider) || "Unknown")), /* @__PURE__ */ React.createElement("div", { className: "flex items-start" }, /* @__PURE__ */ React.createElement("span", { className: "text-xs font-medium text-gray-500 w-16" }, "Model:"), /* @__PURE__ */ React.createElement("span", { className: "text-xs text-gray-900 font-mono bg-white px-1.5 py-0.5 rounded border border-indigo-200" }, ((_Ra = connectionInfo.llm) == null ? void 0 : _Ra.model) || "Unknown")), /* @__PURE__ */ React.createElement("div", { className: "flex items-start" }, /* @__PURE__ */ React.createElement("span", { className: "text-xs font-medium text-gray-500 w-16" }, "Endpoint:"), /* @__PURE__ */ React.createElement("span", { className: "text-xs text-gray-700 break-all flex-1" }, ((_Sa = connectionInfo.llm) == null ? void 0 : _Sa.endpoint) || "Unknown")))), /* @__PURE__ */ React.createElement("div", { className: "bg-gradient-to-br from-green-50 to-emerald-50 rounded-lg p-3 border border-green-100" }, /* @__PURE__ */ React.createElement("h3", { className: "text-sm font-semibold text-gray-900 mb-2 flex items-center" }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-server text-green-600 mr-2 text-xs" }), "MCP Server"), /* @__PURE__ */ React.createElement("div", { className: "flex items-start" }, /* @__PURE__ */ React.createElement("span", { className: "text-xs font-medium text-gray-500 w-16" }, "Endpoint:"), /* @__PURE__ */ React.createElement("span", { className: "text-xs text-gray-700 font-mono bg-white px-1.5 py-0.5 rounded border border-green-200 break-all flex-1" }, ((_Ta = connectionInfo.mcp) == null ? void 0 : _Ta.endpoint) || "Unknown"))), /* @__PURE__ */ React.createElement("div", { className: "flex items-center justify-center p-2.5 bg-green-50 rounded-lg border border-green-200" }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-check-circle text-green-600 mr-2" }), /* @__PURE__ */ React.createElement("span", { className: "text-xs font-medium text-green-800" }, "All connections active"))) : /* @__PURE__ */ React.createElement("div", { className: "flex items-center justify-center p-6" }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-spinner fa-spin text-lg text-gray-400 mr-2" }), /* @__PURE__ */ React.createElement("span", { className: "text-xs text-gray-500" }, "Loading...")))
      )
    ), (isChatOpen || isChatTab) && /* @__PURE__ */ React.createElement(
      "div",
      {
        className: isChatTab ? "fixed inset-x-0 bottom-0 z-40" : "fixed inset-0 bg-black bg-opacity-50 z-50 overflow-y-auto p-3 sm:p-6",
        style: isChatTab ? { top: `${headerHeight}px` } : void 0
      },
      /* @__PURE__ */ React.createElement("div", { className: isChatTab ? `${workspaceShellWidthClass} mx-auto h-full px-4 sm:px-6 lg:px-8 py-6` : "min-h-full w-full flex items-center justify-center" }, /* @__PURE__ */ React.createElement("div", { className: `${isChatTab ? `h-full min-h-0 rounded-2xl shadow-2xl flex flex-col overflow-hidden ${isDarkTheme ? "bg-gray-800 border border-gray-700" : "bg-white border border-gray-200"}` : `rounded-xl shadow-2xl w-full max-w-4xl min-h-0 flex flex-col overflow-hidden ${isDarkTheme ? "bg-gray-800 border border-gray-700" : "bg-white"}`}`, style: isChatTab ? void 0 : windowedChatDialogStyle, role: "dialog", "aria-modal": isChatTab ? "false" : "true", "aria-labelledby": "chat-modal-title", onKeyDown: (event2) => handleDialogKeyDown(event2, closeChatSurface) }, /* @__PURE__ */ React.createElement("div", { className: `p-6 border-b flex justify-between items-center ${isDarkTheme ? "border-gray-700" : "border-gray-200"}` }, /* @__PURE__ */ React.createElement("div", { className: "flex items-center" }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-comments text-2xl text-green-600 mr-3" }), /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("h2", { id: "chat-modal-title", className: `text-xl font-semibold ${isDarkTheme ? "text-gray-100" : "text-gray-900"}` }, isChatTab ? "Chat Workspace" : "Chat with Splunk"), isChatTab && /* @__PURE__ */ React.createElement("div", { className: `text-xs mt-1 ${mutedTextClass}` }, "Full-screen chat stays available as a workspace tab under the header."))), /* @__PURE__ */ React.createElement("div", { className: "flex items-center space-x-2" }, /* @__PURE__ */ React.createElement(
        "button",
        {
          type: "button",
          onClick: () => setIsChatSettingsOpen(true),
          className: `px-3 py-1 text-sm ${isDarkTheme ? "text-gray-300 hover:text-gray-100" : "text-gray-600 hover:text-gray-800"}`,
          title: "Chat settings",
          "aria-label": "Open chat settings"
        },
        /* @__PURE__ */ React.createElement("i", { className: "fas fa-cog" })
      ), isChatTab ? /* @__PURE__ */ React.createElement(
        "button",
        {
          type: "button",
          onClick: () => exitChatFullscreen({ reopenModal: true }),
          className: `px-3 py-1 text-sm ${isDarkTheme ? "text-gray-300 hover:text-gray-100" : "text-gray-600 hover:text-gray-800"}`,
          title: "Return chat to windowed mode",
          "aria-label": "Return chat to windowed mode"
        },
        /* @__PURE__ */ React.createElement("i", { className: "fas fa-compress-arrows-alt" })
      ) : /* @__PURE__ */ React.createElement(
        "button",
        {
          type: "button",
          onClick: enterChatFullscreen,
          className: `px-3 py-1 text-sm ${isDarkTheme ? "text-gray-300 hover:text-gray-100" : "text-gray-600 hover:text-gray-800"}`,
          title: "Open chat in full-screen workspace mode",
          "aria-label": "Open chat in full-screen workspace mode"
        },
        /* @__PURE__ */ React.createElement("i", { className: "fas fa-expand-arrows-alt" })
      ), /* @__PURE__ */ React.createElement(
        "button",
        {
          type: "button",
          onClick: () => {
            clearPersistedChatState();
            setChatMessages([]);
            setChatInput("");
            setChatStatus("");
            setServerConversationHistory(null);
            setChatSessionId(generateChatSessionId());
          },
          className: `px-3 py-1 text-sm ${isDarkTheme ? "text-gray-300 hover:text-gray-100" : "text-gray-600 hover:text-gray-800"}`,
          title: "Clear chat",
          "aria-label": "Clear chat history"
        },
        /* @__PURE__ */ React.createElement("i", { className: "fas fa-trash" })
      ), /* @__PURE__ */ React.createElement(
        "button",
        {
          type: "button",
          onClick: closeChatSurface,
          className: `${isDarkTheme ? "text-gray-400 hover:text-gray-100" : "text-gray-500 hover:text-gray-700"}`,
          "aria-label": isChatTab ? "Close full-screen chat workspace" : "Close chat"
        },
        /* @__PURE__ */ React.createElement("i", { className: "fas fa-times text-xl" })
      ))), /* @__PURE__ */ React.createElement("div", { className: `flex-1 min-h-0 overflow-y-auto p-6 ${isDarkTheme ? "bg-gray-900" : "bg-white"}` }, /* @__PURE__ */ React.createElement("div", { className: "space-y-4", style: fullscreenChatConversationStyle }, chatMessages.length === 0 && /* @__PURE__ */ React.createElement("div", { className: `text-center mt-12 ${isDarkTheme ? "text-gray-400" : "text-gray-500"}` }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-robot text-4xl mb-4" }), /* @__PURE__ */ React.createElement("p", { className: "text-lg" }, "Start a conversation with your Splunk environment"), /* @__PURE__ */ React.createElement("p", { className: "text-sm mt-2" }, "Ask questions about your data, indexes, searches, or get help with SPL queries")), chatMessages.map((msg) => /* @__PURE__ */ React.createElement("div", { key: msg.id, className: `flex min-w-0 ${msg.type === "user" ? "justify-end" : "justify-start"}` }, /* @__PURE__ */ React.createElement("div", { className: `max-w-3xl min-w-0 p-4 rounded-lg ${msg.type === "user" ? "bg-indigo-600 text-white" : msg.type === "error" ? isDarkTheme ? "bg-red-900 text-red-100 border border-red-700" : "bg-red-50 text-red-800 border border-red-200" : msg.type === "warning" ? isDarkTheme ? "bg-amber-900 text-amber-100 border border-amber-700" : "bg-amber-50 text-amber-900 border border-amber-200" : isDarkTheme ? "bg-gray-700 text-gray-100 border border-gray-600" : "bg-gray-100 text-gray-800"}`, style: getChatBubbleStyle(msg.type) }, msg.type === "user" && /* @__PURE__ */ React.createElement("div", { className: "flex items-start min-w-0" }, /* @__PURE__ */ React.createElement("div", { className: "flex-1 min-w-0" }, /* @__PURE__ */ React.createElement("p", { className: "whitespace-pre-wrap break-words", style: { overflowWrap: "anywhere" } }, msg.content)), /* @__PURE__ */ React.createElement("i", { className: "fas fa-user ml-3 mt-1" })), msg.type === "assistant" && /* @__PURE__ */ React.createElement("div", { className: "flex items-start min-w-0" }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-robot mr-3 mt-1 text-green-600" }), /* @__PURE__ */ React.createElement("div", { className: "flex-1 min-w-0" }, /* @__PURE__ */ React.createElement("p", { className: "whitespace-pre-wrap break-words", style: { overflowWrap: "anywhere" } }, msg.content), msg.spl_query && /* @__PURE__ */ React.createElement("details", { className: "mt-3", open: true }, /* @__PURE__ */ React.createElement("summary", { className: "cursor-pointer text-sm font-medium text-indigo-600 hover:text-indigo-800 flex items-center" }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-code mr-2" }), "SPL Query Executed"), /* @__PURE__ */ React.createElement("div", { className: "mt-2 p-4 bg-gray-900 text-green-300 rounded-lg font-mono text-sm" }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-col gap-2 sm:flex-row sm:items-start sm:justify-between mb-2" }, /* @__PURE__ */ React.createElement("span", { className: "text-xs text-gray-300 uppercase tracking-wide" }, "Splunk Query"), renderSplQueryActionButtons2(msg.spl_query, {
        originKind: "chat_assistant",
        originLabel: "Chat assistant response",
        sourceLabel: "Chat assistant response",
        contextExcerpt: msg.content,
        className: "sm:justify-end"
      })), /* @__PURE__ */ React.createElement("pre", { className: "whitespace-pre-wrap break-all" }, msg.spl_query))), !msg.spl_query && msg.spl_in_text && /* @__PURE__ */ React.createElement("details", { className: "mt-3" }, /* @__PURE__ */ React.createElement("summary", { className: `cursor-pointer text-sm font-medium flex items-center ${isDarkTheme ? "text-gray-300 hover:text-gray-100" : "text-gray-600 hover:text-gray-800"}` }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-code mr-2" }), "SPL Query (Not Executed)"), /* @__PURE__ */ React.createElement("div", { className: "mt-2 p-4 bg-gray-900 text-amber-300 rounded-lg font-mono text-sm" }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-col gap-2 sm:flex-row sm:items-start sm:justify-between mb-2" }, /* @__PURE__ */ React.createElement("span", { className: "text-xs text-gray-300 uppercase tracking-wide" }, "Suggested Query"), renderSplQueryActionButtons2(msg.spl_in_text, {
        originKind: "chat_assistant_suggestion",
        originLabel: "Chat assistant suggestion",
        sourceLabel: "Chat assistant suggestion",
        contextExcerpt: msg.content,
        className: "sm:justify-end"
      })), /* @__PURE__ */ React.createElement("pre", { className: "whitespace-pre-wrap break-all" }, msg.spl_in_text))), msg.visualization_spec && /* @__PURE__ */ React.createElement("details", { className: "mt-3", open: true }, /* @__PURE__ */ React.createElement("summary", { className: `cursor-pointer text-sm font-medium flex items-center ${isDarkTheme ? "text-cyan-300 hover:text-cyan-100" : "text-cyan-700 hover:text-cyan-900"}` }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-chart-line mr-2" }), "Visualization Preview"), renderVisualizationPreview(msg.visualization_spec, {
        sourceQuery: msg.spl_query || msg.spl_in_text,
        canOpenSplunk: canUseSplunkDeeplinks,
        onOpenSplunk: openSplunkSearchFromChat
      })), Array.isArray(msg.capability_usage) && msg.capability_usage.length > 0 && /* @__PURE__ */ React.createElement(
        "details",
        {
          className: "mt-3",
          "data-testid": "chat-capability-evidence"
        },
        /* @__PURE__ */ React.createElement("summary", { className: `cursor-pointer text-sm font-medium flex items-center ${isDarkTheme ? "text-emerald-300 hover:text-emerald-100" : "text-emerald-700 hover:text-emerald-900"}` }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-puzzle-piece mr-2" }), "Capability Evidence (", msg.capability_usage.length, ")"),
        /* @__PURE__ */ React.createElement("div", { className: "mt-2 space-y-3" }, msg.capability_usage.map((usage, usageIdx) => /* @__PURE__ */ React.createElement("div", { key: usageIdx, className: `rounded-lg border p-3 ${isDarkTheme ? "bg-gray-800 border-gray-700" : "bg-emerald-50 border-emerald-200"}` }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-wrap items-center gap-2 mb-2" }, /* @__PURE__ */ React.createElement("span", { className: `text-sm font-semibold ${headingClass}` }, usage.title || usage.name || "Capability"), usage.category && /* @__PURE__ */ React.createElement("span", { className: `inline-flex items-center rounded-full px-2 py-0.5 text-[11px] font-medium ${isDarkTheme ? "bg-gray-900 text-gray-200 border border-gray-600" : "bg-white text-gray-700 border border-gray-300"}` }, formatCapabilityCategoryLabel(usage.category)), usage.used_in && /* @__PURE__ */ React.createElement("span", { className: `inline-flex items-center rounded-full px-2 py-0.5 text-[11px] font-medium ${isDarkTheme ? "bg-emerald-900 text-emerald-100 border border-emerald-700" : "bg-emerald-100 text-emerald-800 border border-emerald-300"}` }, formatCapabilityUsageContextLabel(usage.used_in))), usage.contribution && /* @__PURE__ */ React.createElement("div", { className: `text-sm mb-2 ${subtextClass}` }, usage.contribution), renderCapabilityReusableQueryCards(usage), Array.isArray(usage.chunks) && usage.chunks.length > 0 && /* @__PURE__ */ React.createElement("div", { className: "space-y-2" }, usage.chunks.map((chunk, chunkIdx) => /* @__PURE__ */ React.createElement("div", { key: chunkIdx, className: `rounded border p-2 ${isDarkTheme ? "bg-gray-900 border-gray-700" : "bg-white border-emerald-200"}` }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-wrap items-center justify-between gap-2 mb-1" }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-wrap items-center gap-2" }, /* @__PURE__ */ React.createElement("span", { className: `text-xs font-medium ${headingClass}` }, chunk.source || `artifact_${chunkIdx + 1}`), chunk.source_type && /* @__PURE__ */ React.createElement("span", { className: `inline-flex items-center rounded-full px-2 py-0.5 text-[11px] font-medium ${isDarkTheme ? "bg-gray-800 text-gray-200 border border-gray-600" : "bg-emerald-100 text-emerald-800 border border-emerald-300"}` }, formatCapabilitySourceTypeLabel(chunk.source_type))), typeof chunk.score === "number" && /* @__PURE__ */ React.createElement("span", { className: `text-[11px] ${mutedTextClass}` }, "score ", chunk.score)), /* @__PURE__ */ React.createElement("div", { className: `text-xs whitespace-pre-wrap break-words ${subtextClass}`, style: { overflowWrap: "anywhere" } }, chunk.snippet)))))))
      ), msg.status_timeline && msg.status_timeline.length > 0 && /* @__PURE__ */ React.createElement("details", { className: "mt-3" }, /* @__PURE__ */ React.createElement("summary", { className: "cursor-pointer text-sm font-medium text-blue-600 hover:text-blue-800 flex items-center" }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-tasks mr-2" }), "Investigation Timeline (", msg.iterations, " iterations, ", msg.execution_time, ")"), /* @__PURE__ */ React.createElement("div", { className: "mt-2 space-y-2" }, msg.status_timeline.map((status, idx) => /* @__PURE__ */ React.createElement("div", { key: idx, className: `flex items-center justify-between px-3 py-2 rounded border-l-4 border-blue-400 ${isDarkTheme ? "bg-gray-800" : "bg-gradient-to-r from-blue-50 to-purple-50"}` }, /* @__PURE__ */ React.createElement("span", { className: `text-sm ${isDarkTheme ? "text-gray-200" : "text-gray-700"}` }, status.action), /* @__PURE__ */ React.createElement("span", { className: `text-xs ${isDarkTheme ? "text-gray-400" : "text-gray-500"}` }, status.time.toFixed(1), "s"))))), msg.mcp_data && /* @__PURE__ */ React.createElement("details", { className: "mt-3" }, /* @__PURE__ */ React.createElement("summary", { className: `cursor-pointer text-sm ${isDarkTheme ? "text-gray-300 hover:text-gray-100" : "text-gray-600 hover:text-gray-800"}` }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-database mr-1" }), "View Raw Data"), /* @__PURE__ */ React.createElement("pre", { className: `mt-2 p-3 rounded text-xs overflow-x-auto ${isDarkTheme ? "bg-gray-800 text-gray-200" : "bg-gray-200 text-gray-800"}` }, JSON.stringify(msg.mcp_data, null, 2))), msg.has_follow_on && /* @__PURE__ */ React.createElement("div", { className: `mt-3 p-3 border rounded ${isDarkTheme ? "bg-indigo-900 border-indigo-700" : "bg-indigo-50 border-indigo-200"}` }, /* @__PURE__ */ React.createElement("div", { className: `text-xs font-semibold flex items-center mb-2 ${isDarkTheme ? "text-indigo-200" : "text-indigo-700"}` }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-arrow-right mr-1" }), /* @__PURE__ */ React.createElement("span", null, "Suggested next actions")), Array.isArray(msg.follow_on_actions) && msg.follow_on_actions.length > 0 ? /* @__PURE__ */ React.createElement("div", { className: "space-y-2" }, msg.follow_on_actions.map((action, idx) => {
        const actionLabel = typeof action === "string" ? action : action.label || action.prompt || "Follow-up action";
        const actionPrompt = typeof action === "string" ? action : action.prompt || action.label || "";
        return /* @__PURE__ */ React.createElement(
          "button",
          {
            key: idx,
            onClick: () => actionPrompt && sendSuggestedQuery(actionPrompt),
            className: `w-full text-left rounded border px-3 py-2 transition-colors ${isDarkTheme ? "bg-indigo-950 border-indigo-700 hover:bg-indigo-800 text-indigo-100" : "bg-white border-indigo-200 hover:bg-indigo-100 text-indigo-900"}`,
            title: "Run this follow-up in chat"
          },
          /* @__PURE__ */ React.createElement("div", { className: "text-xs font-semibold" }, actionLabel),
          typeof action !== "string" && action.prompt && action.prompt !== actionLabel && /* @__PURE__ */ React.createElement("div", { className: `text-[11px] mt-1 ${isDarkTheme ? "text-indigo-200" : "text-indigo-700"}` }, action.prompt)
        );
      })) : /* @__PURE__ */ React.createElement("div", { className: `text-xs ${isDarkTheme ? "text-indigo-200" : "text-indigo-800"}` }, "Follow-up action available.")))), msg.type === "error" && /* @__PURE__ */ React.createElement("div", { className: "flex items-start min-w-0" }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-exclamation-triangle mr-3 mt-1 text-red-600" }), /* @__PURE__ */ React.createElement("p", { className: "flex-1 whitespace-pre-wrap break-words", style: { overflowWrap: "anywhere" } }, msg.content)), msg.type === "warning" && /* @__PURE__ */ React.createElement("div", { className: `flex items-start min-w-0 border-l-4 border-amber-400 p-4 rounded ${isDarkTheme ? "bg-amber-900" : "bg-amber-50"}` }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-exclamation-circle mr-3 mt-1 text-amber-600" }), /* @__PURE__ */ React.createElement("p", { className: `flex-1 whitespace-pre-wrap break-words ${isDarkTheme ? "text-amber-100" : "text-amber-800"}`, style: { overflowWrap: "anywhere" } }, msg.content)), /* @__PURE__ */ React.createElement("div", { className: "text-xs opacity-70 mt-2" }, new Date(msg.timestamp).toLocaleTimeString())))), isTyping && /* @__PURE__ */ React.createElement("div", { className: "flex justify-start" }, /* @__PURE__ */ React.createElement("div", { className: `p-4 rounded-lg shadow-sm border ${isDarkTheme ? "bg-gray-800 text-gray-200 border-gray-700" : "bg-gradient-to-r from-blue-50 to-green-50 text-gray-800 border-blue-100"}` }, /* @__PURE__ */ React.createElement("div", { className: "flex items-center space-x-3" }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-robot text-green-600" }), /* @__PURE__ */ React.createElement("div", { className: "flex space-x-1" }, /* @__PURE__ */ React.createElement("div", { className: "w-2 h-2 bg-green-500 rounded-full animate-bounce" }), /* @__PURE__ */ React.createElement("div", { className: "w-2 h-2 bg-blue-500 rounded-full animate-bounce", style: { animationDelay: "0.1s" } }), /* @__PURE__ */ React.createElement("div", { className: "w-2 h-2 bg-purple-500 rounded-full animate-bounce", style: { animationDelay: "0.2s" } })), chatStatus && /* @__PURE__ */ React.createElement("span", { className: `text-sm ml-2 animate-pulse ${isDarkTheme ? "text-gray-300" : "text-gray-600"}` }, chatStatus)))), /* @__PURE__ */ React.createElement("div", { ref: chatEndRef }))), /* @__PURE__ */ React.createElement("div", { className: `p-6 border-t ${isDarkTheme ? "border-gray-700 bg-gray-800" : "border-gray-200 bg-white"}` }, /* @__PURE__ */ React.createElement("div", { className: "mb-4" }, /* @__PURE__ */ React.createElement("div", { className: "flex items-center justify-between mb-2" }, /* @__PURE__ */ React.createElement("p", { className: `text-xs font-semibold uppercase tracking-wide ${isDarkTheme ? "text-gray-300" : "text-gray-600"}` }, "Suggested Queries (Demo)"), /* @__PURE__ */ React.createElement("div", { className: "flex items-center gap-3" }, /* @__PURE__ */ React.createElement("span", { className: `text-xs ${isDarkTheme ? "text-gray-500" : "text-gray-400"}` }, "Deterministic-friendly prompts"), /* @__PURE__ */ React.createElement(
        "button",
        {
          type: "button",
          onClick: () => setShowSuggestedQueries((prev) => !prev),
          className: "text-xs text-indigo-600 hover:text-indigo-800 flex items-center",
          title: showSuggestedQueries ? "Collapse suggested queries" : "Expand suggested queries",
          "aria-label": showSuggestedQueries ? "Collapse suggested queries" : "Expand suggested queries",
          "aria-expanded": showSuggestedQueries,
          "aria-controls": "suggested-queries-panel"
        },
        /* @__PURE__ */ React.createElement("i", { className: `fas ${showSuggestedQueries ? "fa-chevron-up" : "fa-chevron-down"}` })
      ))), showSuggestedQueries && /* @__PURE__ */ React.createElement("div", { id: "suggested-queries-panel", className: "grid grid-cols-1 md:grid-cols-2 gap-2" }, suggestedChatQueries.map((query, idx) => /* @__PURE__ */ React.createElement("div", { key: idx, className: `flex items-center border rounded-lg px-2 py-1.5 ${isDarkTheme ? "bg-gray-900 border-gray-700" : "bg-gray-50 border-gray-200"}` }, /* @__PURE__ */ React.createElement(
        "button",
        {
          type: "button",
          onClick: () => useSuggestedQuery(query),
          className: `flex-1 text-left text-xs truncate ${isDarkTheme ? "text-gray-200 hover:text-indigo-300" : "text-gray-700 hover:text-indigo-700"}`,
          title: query
        },
        query
      ), /* @__PURE__ */ React.createElement(
        "button",
        {
          type: "button",
          onClick: () => sendSuggestedQuery(query),
          disabled: isTyping,
          className: `ml-2 px-2 py-1 text-xs rounded ${isTyping ? isDarkTheme ? "bg-gray-700 text-gray-500 cursor-not-allowed" : "bg-gray-200 text-gray-500 cursor-not-allowed" : "bg-indigo-600 hover:bg-indigo-700 text-white"}`,
          title: "Run this query now"
        },
        /* @__PURE__ */ React.createElement("i", { className: "fas fa-play" })
      ))))), /* @__PURE__ */ React.createElement("div", { className: "flex space-x-4" }, /* @__PURE__ */ React.createElement(
        "textarea",
        {
          ref: chatInputRef,
          value: chatInput,
          onChange: (e) => setChatInput(e.target.value),
          onKeyPress: (e) => {
            if (e.key === "Enter" && !e.shiftKey) {
              e.preventDefault();
              sendChatMessage();
            }
          },
          placeholder: "Ask me about your Splunk environment...",
          "aria-label": "Chat message input",
          className: `flex-1 p-3 border rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-transparent resize-none ${isDarkTheme ? "bg-gray-900 border-gray-600 text-gray-100 placeholder-gray-500" : "bg-white border-gray-300 text-gray-900 placeholder-gray-400"}`,
          rows: "3",
          disabled: isTyping
        }
      ), /* @__PURE__ */ React.createElement(
        "button",
        {
          type: "button",
          onClick: sendChatMessage,
          disabled: !chatInput.trim() || isTyping,
          "aria-label": isTyping ? "Sending chat message" : "Send chat message",
          title: isTyping ? "Sending chat message" : "Send chat message",
          className: `px-6 py-3 rounded-lg font-medium ${chatInput.trim() && !isTyping ? "bg-indigo-600 hover:bg-indigo-700 text-white" : isDarkTheme ? "bg-gray-700 text-gray-400 cursor-not-allowed" : "bg-gray-300 text-gray-500 cursor-not-allowed"}`
        },
        /* @__PURE__ */ React.createElement("i", { className: "fas fa-paper-plane" })
      )), /* @__PURE__ */ React.createElement("p", { className: `text-xs mt-2 ${isDarkTheme ? "text-gray-400" : "text-gray-500"}` }, "Press Enter to send, Shift+Enter for new line • Ask about indexes, searches, data sources, or get help with SPL queries", /* @__PURE__ */ React.createElement("span", { className: "block mt-1" }, "Conversation context is retained across reloads until you clear chat.")))))
    ), isChatSettingsOpen && /* @__PURE__ */ React.createElement("div", { className: "fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50" }, /* @__PURE__ */ React.createElement("div", { className: `chat-settings-modal-shell rounded-xl shadow-2xl w-full max-w-3xl h-5/6 flex flex-col ${isDarkTheme ? "bg-gray-800 border border-gray-700" : "bg-white"}`, role: "dialog", "aria-modal": "true", "aria-labelledby": "chat-settings-title", onKeyDown: (event2) => handleDialogKeyDown(event2, () => setIsChatSettingsOpen(false)) }, /* @__PURE__ */ React.createElement("div", { className: "p-6 border-b border-gray-200 flex justify-between items-center bg-gradient-to-r from-purple-600 to-indigo-600 text-white rounded-t-xl" }, /* @__PURE__ */ React.createElement("div", { className: "flex items-center" }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-cog text-2xl mr-3" }), /* @__PURE__ */ React.createElement("h2", { id: "chat-settings-title", className: "text-2xl font-bold" }, "Chat Settings")), /* @__PURE__ */ React.createElement("div", { className: "flex items-center space-x-3" }, /* @__PURE__ */ React.createElement(
      "button",
      {
        type: "button",
        onClick: resetChatSettings,
        className: "px-4 py-2 bg-white bg-opacity-20 hover:bg-opacity-30 rounded-lg text-sm font-medium transition-all",
        title: "Reset to defaults"
      },
      /* @__PURE__ */ React.createElement("i", { className: "fas fa-undo mr-2" }),
      "Reset"
    ), /* @__PURE__ */ React.createElement(
      "button",
      {
        type: "button",
        onClick: () => setIsChatSettingsOpen(false),
        className: "text-white hover:text-gray-200",
        "aria-label": "Close chat settings"
      },
      /* @__PURE__ */ React.createElement("i", { className: "fas fa-times text-2xl" })
    ))), /* @__PURE__ */ React.createElement("div", { className: "flex-1 overflow-y-auto p-6 space-y-6" }, chatSettings && /* @__PURE__ */ React.createElement(React.Fragment, null, /* @__PURE__ */ React.createElement("div", { className: "bg-gradient-to-r from-green-50 to-emerald-50 rounded-lg p-5 border-2 border-green-200" }, /* @__PURE__ */ React.createElement("h3", { className: "text-lg font-semibold text-gray-900 mb-4 flex items-center" }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-search text-green-600 mr-2" }), "Discovery Settings"), /* @__PURE__ */ React.createElement("div", { className: "space-y-4" }, /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("label", { className: "block text-sm font-medium text-gray-700 mb-2" }, "Max Execution Time: ", chatSettings.max_execution_time, "s"), /* @__PURE__ */ React.createElement(
      "input",
      {
        type: "range",
        min: "30",
        max: "300",
        value: chatSettings.max_execution_time,
        onChange: (e) => updateSetting("max_execution_time", parseInt(e.target.value)),
        className: "w-full"
      }
    ), /* @__PURE__ */ React.createElement("div", { className: "flex justify-between text-xs text-gray-500 mt-1" }, /* @__PURE__ */ React.createElement("span", null, "30s"), /* @__PURE__ */ React.createElement("span", null, "300s"))), /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("label", { className: "block text-sm font-medium text-gray-700 mb-2" }, "Max Iterations: ", chatSettings.max_iterations), /* @__PURE__ */ React.createElement(
      "input",
      {
        type: "range",
        min: "1",
        max: "10",
        value: chatSettings.max_iterations,
        onChange: (e) => updateSetting("max_iterations", parseInt(e.target.value)),
        className: "w-full"
      }
    ), /* @__PURE__ */ React.createElement("div", { className: "flex justify-between text-xs text-gray-500 mt-1" }, /* @__PURE__ */ React.createElement("span", null, "1"), /* @__PURE__ */ React.createElement("span", null, "10"))), /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("label", { className: "block text-sm font-medium text-gray-700 mb-2" }, "Discovery Freshness: ", chatSettings.discovery_freshness_days, " days"), /* @__PURE__ */ React.createElement(
      "input",
      {
        type: "range",
        min: "1",
        max: "30",
        value: chatSettings.discovery_freshness_days,
        onChange: (e) => updateSetting("discovery_freshness_days", parseInt(e.target.value)),
        className: "w-full"
      }
    ), /* @__PURE__ */ React.createElement("div", { className: "flex justify-between text-xs text-gray-500 mt-1" }, /* @__PURE__ */ React.createElement("span", null, "1 day"), /* @__PURE__ */ React.createElement("span", null, "30 days"))))), /* @__PURE__ */ React.createElement("div", { className: "bg-gradient-to-r from-purple-50 to-indigo-50 rounded-lg p-5 border-2 border-purple-200" }, /* @__PURE__ */ React.createElement("h3", { className: "text-lg font-semibold text-gray-900 mb-4 flex items-center" }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-brain text-purple-600 mr-2" }), "LLM Behavior"), /* @__PURE__ */ React.createElement("div", { className: "space-y-4" }, /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("label", { className: "block text-sm font-medium text-gray-700 mb-2" }, "Max Tokens: ", chatSettings.max_tokens, ((_Ua = config == null ? void 0 : config.llm) == null ? void 0 : _Ua.max_tokens) && /* @__PURE__ */ React.createElement("span", { className: "ml-2 text-xs text-purple-600" }, "(Profile: ", config.llm.max_tokens, ")")), /* @__PURE__ */ React.createElement(
      "input",
      {
        type: "number",
        min: "1000",
        max: "128000",
        value: chatSettings.max_tokens,
        onChange: (e) => updateSetting("max_tokens", parseInt(e.target.value)),
        className: "w-full px-3 py-2 border border-gray-300 rounded-md"
      }
    )), /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("label", { className: "block text-sm font-medium text-gray-700 mb-2" }, "Temperature: ", chatSettings.temperature.toFixed(1)), /* @__PURE__ */ React.createElement(
      "input",
      {
        type: "range",
        min: "0",
        max: "2",
        step: "0.1",
        value: chatSettings.temperature,
        onChange: (e) => updateSetting("temperature", parseFloat(e.target.value)),
        className: "w-full"
      }
    ), /* @__PURE__ */ React.createElement("div", { className: "flex justify-between text-xs text-gray-500 mt-1" }, /* @__PURE__ */ React.createElement("span", null, "0.0 (Focused)"), /* @__PURE__ */ React.createElement("span", null, "2.0 (Creative)"))), /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("label", { className: "block text-sm font-medium text-gray-700 mb-2" }, "Context History: ", chatSettings.context_history, " messages"), /* @__PURE__ */ React.createElement(
      "input",
      {
        type: "range",
        min: "0",
        max: "20",
        value: chatSettings.context_history,
        onChange: (e) => updateSetting("context_history", parseInt(e.target.value)),
        className: "w-full"
      }
    ), /* @__PURE__ */ React.createElement("div", { className: "flex justify-between text-xs text-gray-500 mt-1" }, /* @__PURE__ */ React.createElement("span", null, "0"), /* @__PURE__ */ React.createElement("span", null, "20"))))), /* @__PURE__ */ React.createElement("div", { className: "bg-gradient-to-r from-amber-50 to-yellow-50 rounded-lg p-5 border-2 border-amber-200" }, /* @__PURE__ */ React.createElement("h3", { className: "text-lg font-semibold text-gray-900 mb-4 flex items-center" }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-tachometer-alt text-amber-600 mr-2" }), "Performance Tuning"), /* @__PURE__ */ React.createElement("div", { className: "space-y-4" }, /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("label", { className: "block text-sm font-medium text-gray-700 mb-2" }, "Max Retry Delay: ", chatSettings.max_retry_delay, "s"), /* @__PURE__ */ React.createElement(
      "input",
      {
        type: "range",
        min: "10",
        max: "600",
        value: chatSettings.max_retry_delay,
        onChange: (e) => updateSetting("max_retry_delay", parseInt(e.target.value)),
        className: "w-full"
      }
    ), /* @__PURE__ */ React.createElement("div", { className: "flex justify-between text-xs text-gray-500 mt-1" }, /* @__PURE__ */ React.createElement("span", null, "10s"), /* @__PURE__ */ React.createElement("span", null, "600s"))), /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("label", { className: "block text-sm font-medium text-gray-700 mb-2" }, "Max Retries: ", chatSettings.max_retries), /* @__PURE__ */ React.createElement(
      "input",
      {
        type: "range",
        min: "1",
        max: "10",
        value: chatSettings.max_retries,
        onChange: (e) => updateSetting("max_retries", parseInt(e.target.value)),
        className: "w-full"
      }
    ), /* @__PURE__ */ React.createElement("div", { className: "flex justify-between text-xs text-gray-500 mt-1" }, /* @__PURE__ */ React.createElement("span", null, "1"), /* @__PURE__ */ React.createElement("span", null, "10"))), /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("label", { className: "block text-sm font-medium text-gray-700 mb-2" }, "Query Sample Size: ", chatSettings.query_sample_size, " rows"), /* @__PURE__ */ React.createElement(
      "input",
      {
        type: "range",
        min: "1",
        max: "10",
        value: chatSettings.query_sample_size,
        onChange: (e) => updateSetting("query_sample_size", parseInt(e.target.value)),
        className: "w-full"
      }
    ), /* @__PURE__ */ React.createElement("div", { className: "flex justify-between text-xs text-gray-500 mt-1" }, /* @__PURE__ */ React.createElement("span", null, "1"), /* @__PURE__ */ React.createElement("span", null, "10"))))), /* @__PURE__ */ React.createElement("div", { className: "bg-gradient-to-r from-blue-50 to-cyan-50 rounded-lg p-5 border-2 border-blue-200" }, /* @__PURE__ */ React.createElement("h3", { className: "text-lg font-semibold text-gray-900 mb-4 flex items-center" }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-check-circle text-blue-600 mr-2" }), "Quality Control"), /* @__PURE__ */ React.createElement("div", { className: "space-y-4" }, /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("label", { className: "block text-sm font-medium text-gray-700 mb-2" }, "Quality Threshold: ", chatSettings.quality_threshold), /* @__PURE__ */ React.createElement(
      "input",
      {
        type: "range",
        min: "0",
        max: "100",
        value: chatSettings.quality_threshold,
        onChange: (e) => updateSetting("quality_threshold", parseInt(e.target.value)),
        className: "w-full"
      }
    ), /* @__PURE__ */ React.createElement("div", { className: "flex justify-between text-xs text-gray-500 mt-1" }, /* @__PURE__ */ React.createElement("span", null, "0 (Permissive)"), /* @__PURE__ */ React.createElement("span", null, "100 (Strict)"))), /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("label", { className: "block text-sm font-medium text-gray-700 mb-2" }, "Convergence Detection: ", chatSettings.convergence_detection, " iterations"), /* @__PURE__ */ React.createElement(
      "input",
      {
        type: "range",
        min: "3",
        max: "10",
        value: chatSettings.convergence_detection,
        onChange: (e) => updateSetting("convergence_detection", parseInt(e.target.value)),
        className: "w-full"
      }
    ), /* @__PURE__ */ React.createElement("div", { className: "flex justify-between text-xs text-gray-500 mt-1" }, /* @__PURE__ */ React.createElement("span", null, "3"), /* @__PURE__ */ React.createElement("span", null, "10"))))), /* @__PURE__ */ React.createElement("div", { className: "bg-gradient-to-r from-indigo-50 to-violet-50 rounded-lg p-5 border-2 border-indigo-200" }, /* @__PURE__ */ React.createElement("h3", { className: "text-lg font-semibold text-gray-900 mb-4 flex items-center" }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-magic text-indigo-600 mr-2" }), "Splunk IQ (Demo)"), /* @__PURE__ */ React.createElement("div", { className: "space-y-4" }, /* @__PURE__ */ React.createElement("label", { className: "flex items-center justify-between bg-white rounded p-3 border border-indigo-100" }, /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("div", { className: "text-sm font-medium text-gray-800" }, "Enable Splunk Augmentation"), /* @__PURE__ */ React.createElement("div", { className: "text-xs text-gray-500" }, "Use intent-specific deterministic skills for common Splunk questions")), /* @__PURE__ */ React.createElement(
      "input",
      {
        type: "checkbox",
        checked: !!chatSettings.enable_splunk_augmentation,
        onChange: (e) => updateSetting("enable_splunk_augmentation", e.target.checked),
        className: "h-4 w-4"
      }
    )), /* @__PURE__ */ React.createElement("label", { className: "flex items-center justify-between bg-white rounded p-3 border border-indigo-100" }, /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("div", { className: "text-sm font-medium text-gray-800" }, "Use Installed Optional RAG Capability"), /* @__PURE__ */ React.createElement("div", { className: "text-xs text-gray-500" }, "Use the enabled optional RAG provider to retrieve matching snippets from indexed or recent discovery artifacts")), /* @__PURE__ */ React.createElement(
      "input",
      {
        type: "checkbox",
        checked: !!chatSettings.enable_rag_context,
        onChange: (e) => updateSetting("enable_rag_context", e.target.checked),
        className: "h-4 w-4"
      }
    )), /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("label", { className: "block text-sm font-medium text-gray-700 mb-2" }, "RAG Snippet Chunks: ", chatSettings.rag_max_chunks), /* @__PURE__ */ React.createElement(
      "input",
      {
        type: "range",
        min: "1",
        max: "6",
        value: chatSettings.rag_max_chunks || 3,
        onChange: (e) => updateSetting("rag_max_chunks", parseInt(e.target.value)),
        className: "w-full",
        disabled: !chatSettings.enable_rag_context
      }
    ), /* @__PURE__ */ React.createElement("div", { className: "flex justify-between text-xs text-gray-500 mt-1" }, /* @__PURE__ */ React.createElement("span", null, "1"), /* @__PURE__ */ React.createElement("span", null, "6")), /* @__PURE__ */ React.createElement("div", { className: "text-xs text-gray-500 mt-2" }, "Install, enable, and test the capability from the Capabilities workspace before turning this on.")))))), /* @__PURE__ */ React.createElement("div", { className: `p-6 border-t rounded-b-xl ${isDarkTheme ? "border-gray-700 bg-gray-900" : "border-gray-200 bg-gray-50"}` }, /* @__PURE__ */ React.createElement("p", { className: "text-sm text-gray-600 text-center" }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-info-circle mr-2" }), "Settings apply immediately and reset to defaults on server restart")))), isReportFullViewOpen && (reportContent == null ? void 0 : reportContent.type) === "image" && /* @__PURE__ */ React.createElement(
      "div",
      {
        className: "fixed inset-0 flex items-center justify-center p-4",
        style: { backgroundColor: isDarkTheme ? "rgba(2, 6, 23, 0.92)" : "rgba(15, 23, 42, 0.82)", zIndex: 60 },
        onClick: () => setIsReportFullViewOpen(false)
      },
      /* @__PURE__ */ React.createElement(
        "div",
        {
          role: "dialog",
          "aria-modal": "true",
          "aria-label": "Full view artifact preview",
          className: `w-full h-full rounded-2xl border shadow-2xl flex flex-col ${isDarkTheme ? "bg-gray-950 border-gray-800 text-gray-100" : "bg-white border-gray-200 text-gray-900"}`,
          onClick: (event2) => event2.stopPropagation(),
          onKeyDown: (event2) => handleDialogKeyDown(event2, () => setIsReportFullViewOpen(false)),
          tabIndex: -1
        },
        /* @__PURE__ */ React.createElement("div", { className: `flex items-center justify-between gap-4 px-6 py-4 border-b ${isDarkTheme ? "border-gray-800" : "border-gray-200"}` }, /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("div", { className: `text-xs uppercase tracking-[0.2em] ${mutedTextClass}` }, "Full View"), /* @__PURE__ */ React.createElement("div", { className: `mt-1 text-lg font-semibold ${headingClass}` }, selectedReport)), /* @__PURE__ */ React.createElement("div", { className: "flex items-center gap-3" }, /* @__PURE__ */ React.createElement(
          "button",
          {
            type: "button",
            onClick: () => downloadReportArtifact(selectedReport, reportContent),
            className: `rounded-lg px-4 py-2 text-sm font-medium ${isDarkTheme ? "bg-indigo-600 text-white hover:bg-indigo-500" : "bg-indigo-600 text-white hover:bg-indigo-700"}`
          },
          /* @__PURE__ */ React.createElement("i", { className: "fas fa-download mr-2" }),
          "Download"
        ), /* @__PURE__ */ React.createElement(
          "button",
          {
            type: "button",
            onClick: () => setIsReportFullViewOpen(false),
            className: `rounded-lg px-4 py-2 text-sm font-medium border ${isDarkTheme ? "bg-gray-900 border-gray-700 text-gray-100 hover:bg-gray-800" : "bg-white border-gray-300 text-gray-700 hover:bg-gray-50"}`
          },
          /* @__PURE__ */ React.createElement("i", { className: "fas fa-times mr-2" }),
          "Close"
        ))),
        /* @__PURE__ */ React.createElement("div", { className: `flex-1 p-6 ${isDarkTheme ? "bg-black" : "bg-slate-100"}` }, /* @__PURE__ */ React.createElement(
          "img",
          {
            src: buildReportImageSrc(reportContent),
            alt: selectedReport,
            className: "h-full w-full object-contain rounded-xl"
          }
        ))
      )
    ), (isSummaryModalOpen || isSummaryTab) && /* @__PURE__ */ React.createElement(
      "div",
      {
        className: isSummaryTab ? "fixed inset-x-0 bottom-0 z-40" : "fixed inset-0 bg-black bg-opacity-50 z-50 overflow-y-auto p-4",
        style: isSummaryTab ? { top: `${headerHeight}px` } : void 0
      },
      /* @__PURE__ */ React.createElement("div", { className: isSummaryTab ? `${workspaceShellWidthClass} mx-auto h-full px-4 sm:px-6 lg:px-8 py-6` : "min-h-full w-full flex items-center justify-center" }, /* @__PURE__ */ React.createElement("div", { className: `${isSummaryTab ? `${isDarkTheme ? "bg-gray-900 text-gray-100 border border-gray-700" : "bg-white text-gray-900 border border-gray-200"} h-full rounded-2xl shadow-2xl flex flex-col overflow-hidden` : `${isDarkTheme ? "bg-gray-900 text-gray-100" : "bg-white text-gray-900"} rounded-xl shadow-2xl w-full max-w-7xl min-h-0 flex flex-col overflow-hidden`}`, style: isSummaryTab ? void 0 : windowedSummaryDialogStyle, role: "dialog", "aria-modal": isSummaryTab ? "false" : "true", "aria-labelledby": "summary-modal-title", onKeyDown: (event2) => handleDialogKeyDown(event2, closeSummaryModal) }, /* @__PURE__ */ React.createElement("div", { className: `p-6 border-b border-gray-200 flex justify-between items-center bg-gradient-to-r from-indigo-600 to-purple-600 text-white ${isSummaryTab ? "rounded-t-2xl" : "rounded-t-xl"}` }, /* @__PURE__ */ React.createElement("div", { className: "flex items-center" }, /* @__PURE__ */ React.createElement("i", { className: `fas ${(summaryData == null ? void 0 : summaryData.from_cache) ? "fa-eye" : "fa-magic"} text-2xl mr-3` }), /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("h2", { id: "summary-modal-title", className: "text-2xl font-bold" }, "Discovery Intelligence Report", (summaryData == null ? void 0 : summaryData.from_cache) && /* @__PURE__ */ React.createElement("span", { className: "ml-3 text-sm font-normal bg-green-700 border border-green-300 px-3 py-1 rounded-full text-white" }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-check-circle mr-1" }), "Cached")), /* @__PURE__ */ React.createElement("p", { className: "text-sm text-indigo-100 mt-1" }, isSummaryTab ? "Full-screen summary stays available as a workspace tab under the header." : `Session: ${currentSessionId}`))), /* @__PURE__ */ React.createElement("div", { className: "flex items-center gap-3" }, isSummaryTab ? /* @__PURE__ */ React.createElement(
        "button",
        {
          type: "button",
          onClick: () => exitSummaryFullscreen({ reopenModal: true }),
          className: "text-white hover:text-gray-200",
          "aria-label": "Return summary to windowed mode",
          title: "Return summary to windowed mode"
        },
        /* @__PURE__ */ React.createElement("i", { className: "fas fa-compress-arrows-alt text-2xl" })
      ) : /* @__PURE__ */ React.createElement(
        "button",
        {
          type: "button",
          onClick: enterSummaryFullscreen,
          className: "text-white hover:text-gray-200",
          "aria-label": "Open summary in full-screen workspace mode",
          title: "Open summary in full-screen workspace mode"
        },
        /* @__PURE__ */ React.createElement("i", { className: "fas fa-expand-arrows-alt text-2xl" })
      ), /* @__PURE__ */ React.createElement(
        "button",
        {
          type: "button",
          onClick: closeSummaryModal,
          className: "text-white hover:text-gray-200",
          "aria-label": isSummaryTab ? "Close full-screen summary workspace" : "Close discovery intelligence report"
        },
        /* @__PURE__ */ React.createElement("i", { className: "fas fa-times text-2xl" })
      ))), !isLoadingSummary && summaryData && /* @__PURE__ */ React.createElement("div", { className: `border-b ${isDarkTheme ? "border-gray-700 bg-gray-800" : "border-gray-200 bg-gray-50"}` }, /* @__PURE__ */ React.createElement("div", { className: "flex space-x-1 px-6", role: "tablist", "aria-label": "Summary views" }, /* @__PURE__ */ React.createElement(
        "button",
        {
          type: "button",
          id: "summary-tab-summary",
          role: "tab",
          "aria-selected": activeTab === "summary",
          "aria-controls": "summary-tabpanel-summary",
          tabIndex: activeTab === "summary" ? 0 : -1,
          onClick: () => setActiveTab("summary"),
          className: `px-6 py-3 font-medium text-sm transition-all ${activeTab === "summary" ? isDarkTheme ? "border-b-2 border-indigo-400 text-indigo-300 bg-gray-900" : "border-b-2 border-indigo-600 text-indigo-600 bg-white" : isDarkTheme ? "text-gray-300 hover:text-white hover:bg-gray-700" : "text-gray-600 hover:text-gray-900 hover:bg-gray-100"}`
        },
        /* @__PURE__ */ React.createElement("i", { className: "fas fa-brain mr-2" }),
        "Executive Summary"
      ), /* @__PURE__ */ React.createElement(
        "button",
        {
          type: "button",
          id: "summary-tab-context",
          role: "tab",
          "aria-selected": activeTab === "context",
          "aria-controls": "summary-tabpanel-context",
          tabIndex: activeTab === "context" ? 0 : -1,
          onClick: () => setActiveTab("context"),
          className: `px-6 py-3 font-medium text-sm transition-all ${activeTab === "context" ? isDarkTheme ? "border-b-2 border-indigo-400 text-indigo-300 bg-gray-900" : "border-b-2 border-indigo-600 text-indigo-600 bg-white" : isDarkTheme ? "text-gray-300 hover:text-white hover:bg-gray-700" : "text-gray-600 hover:text-gray-900 hover:bg-gray-100"}`
        },
        /* @__PURE__ */ React.createElement("i", { className: "fas fa-compass mr-2" }),
        "Context Explorer"
      ), /* @__PURE__ */ React.createElement(
        "button",
        {
          type: "button",
          id: "summary-tab-queries",
          role: "tab",
          "aria-selected": activeTab === "queries",
          "aria-controls": "summary-tabpanel-queries",
          tabIndex: activeTab === "queries" ? 0 : -1,
          onClick: () => setActiveTab("queries"),
          className: `px-6 py-3 font-medium text-sm transition-all ${activeTab === "queries" ? isDarkTheme ? "border-b-2 border-indigo-400 text-indigo-300 bg-gray-900" : "border-b-2 border-indigo-600 text-indigo-600 bg-white" : isDarkTheme ? "text-gray-300 hover:text-white hover:bg-gray-700" : "text-gray-600 hover:text-gray-900 hover:bg-gray-100"}`
        },
        /* @__PURE__ */ React.createElement("i", { className: "fas fa-code mr-2" }),
        "SPL Queries (",
        ((_Va = summaryData.spl_queries) == null ? void 0 : _Va.length) || 0,
        ")"
      ), /* @__PURE__ */ React.createElement(
        "button",
        {
          type: "button",
          id: "summary-tab-tasks",
          role: "tab",
          "aria-selected": activeTab === "tasks",
          "aria-controls": "summary-tabpanel-tasks",
          tabIndex: activeTab === "tasks" ? 0 : -1,
          onClick: () => setActiveTab("tasks"),
          className: `px-6 py-3 font-medium text-sm transition-all ${activeTab === "tasks" ? isDarkTheme ? "border-b-2 border-indigo-400 text-indigo-300 bg-gray-900" : "border-b-2 border-indigo-600 text-indigo-600 bg-white" : isDarkTheme ? "text-gray-300 hover:text-white hover:bg-gray-700" : "text-gray-600 hover:text-gray-900 hover:bg-gray-100"}`
        },
        /* @__PURE__ */ React.createElement("i", { className: "fas fa-tasks mr-2" }),
        "Admin Tasks (",
        ((_Wa = summaryData.admin_tasks) == null ? void 0 : _Wa.length) || 0,
        ")",
        ((_Xa = summaryData.admin_tasks) == null ? void 0 : _Xa.length) > 0 && /* @__PURE__ */ React.createElement("span", { className: "ml-2 px-2 py-0.5 text-xs bg-green-500 text-white rounded-full" }, "New")
      ))), /* @__PURE__ */ React.createElement("div", { className: "flex-1 min-h-0 overflow-y-auto p-6" }, isLoadingSummary ? /* @__PURE__ */ React.createElement("div", { className: "flex items-center justify-center h-full" }, /* @__PURE__ */ React.createElement("div", { className: "text-center max-w-md" }, /* @__PURE__ */ React.createElement("div", { className: "relative mb-8" }, /* @__PURE__ */ React.createElement("div", { className: `inline-block animate-spin rounded-full h-20 w-20 border-4 ${isDarkTheme ? "border-indigo-900 border-t-indigo-400" : "border-indigo-200 border-t-indigo-600"}` }), /* @__PURE__ */ React.createElement("i", { className: `fas fa-brain absolute top-1/2 left-1/2 transform -translate-x-1/2 -translate-y-1/2 text-3xl animate-pulse ${isDarkTheme ? "text-indigo-300" : "text-indigo-600"}` })), /* @__PURE__ */ React.createElement("h3", { className: `text-2xl font-bold mb-4 ${isDarkTheme ? "text-gray-100" : "text-gray-800"}` }, "Analyzing Your Splunk Environment"), /* @__PURE__ */ React.createElement("div", { className: `space-y-3 text-left rounded-lg shadow-sm border p-4 mb-4 ${isDarkTheme ? "bg-gray-800 border-gray-700" : "bg-white border-gray-200"}` }, /* @__PURE__ */ React.createElement("div", { className: `flex items-center text-sm ${isSummaryStepActive(1) ? "animate-pulse" : ""}` }, /* @__PURE__ */ React.createElement("div", { className: `flex-shrink-0 w-6 h-6 rounded-full flex items-center justify-center mr-3 ${isSummaryStepDone(1) ? "bg-green-500" : isSummaryStepActive(1) ? "bg-indigo-500" : isDarkTheme ? "border-2 border-gray-600" : "border-2 border-gray-300"}` }, isSummaryStepDone(1) ? /* @__PURE__ */ React.createElement("i", { className: "fas fa-check text-white text-xs" }) : isSummaryStepActive(1) ? /* @__PURE__ */ React.createElement("div", { className: "w-2 h-2 bg-white rounded-full animate-ping" }) : null), /* @__PURE__ */ React.createElement("span", { className: isSummaryStepActive(1) ? isDarkTheme ? "text-gray-100 font-medium" : "text-gray-700 font-medium" : isDarkTheme ? "text-gray-300" : "text-gray-700" }, "Loading discovery reports...")), /* @__PURE__ */ React.createElement("div", { className: `flex items-center text-sm ${isSummaryStepActive(2) ? "animate-pulse" : ""}` }, /* @__PURE__ */ React.createElement("div", { className: `flex-shrink-0 w-6 h-6 rounded-full flex items-center justify-center mr-3 ${isSummaryStepDone(2) ? "bg-green-500" : isSummaryStepActive(2) ? "bg-indigo-500" : isDarkTheme ? "border-2 border-gray-600" : "border-2 border-gray-300"}` }, isSummaryStepDone(2) ? /* @__PURE__ */ React.createElement("i", { className: "fas fa-check text-white text-xs" }) : isSummaryStepActive(2) ? /* @__PURE__ */ React.createElement("div", { className: "w-2 h-2 bg-white rounded-full animate-ping" }) : null), /* @__PURE__ */ React.createElement("span", { className: isSummaryStepActive(2) ? isDarkTheme ? "text-gray-100 font-medium" : "text-gray-700 font-medium" : isDarkTheme ? "text-gray-400" : "text-gray-500" }, "Generating SPL queries...")), /* @__PURE__ */ React.createElement("div", { className: `flex items-center text-sm ${isSummaryStepActive(3) ? "animate-pulse" : ""}` }, /* @__PURE__ */ React.createElement("div", { className: `flex-shrink-0 w-6 h-6 rounded-full flex items-center justify-center mr-3 ${isSummaryStepDone(3) ? "bg-green-500" : isSummaryStepActive(3) ? "bg-indigo-500" : isDarkTheme ? "border-2 border-gray-600" : "border-2 border-gray-300"}` }, isSummaryStepDone(3) ? /* @__PURE__ */ React.createElement("i", { className: "fas fa-check text-white text-xs" }) : isSummaryStepActive(3) ? /* @__PURE__ */ React.createElement("div", { className: "w-2 h-2 bg-white rounded-full animate-ping" }) : null), /* @__PURE__ */ React.createElement("span", { className: isSummaryStepActive(3) ? isDarkTheme ? "text-gray-100 font-medium" : "text-gray-700 font-medium" : isDarkTheme ? "text-gray-400" : "text-gray-500" }, "Building executive summary...")), /* @__PURE__ */ React.createElement("div", { className: `flex items-center text-sm ${isSummaryStepActive(4) ? "animate-pulse" : ""}` }, /* @__PURE__ */ React.createElement("div", { className: `flex-shrink-0 w-6 h-6 rounded-full flex items-center justify-center mr-3 ${isSummaryStepDone(4) ? "bg-green-500" : isSummaryStepActive(4) ? "bg-indigo-500" : isDarkTheme ? "border-2 border-gray-600" : "border-2 border-gray-300"}` }, isSummaryStepDone(4) ? /* @__PURE__ */ React.createElement("i", { className: "fas fa-check text-white text-xs" }) : isSummaryStepActive(4) ? /* @__PURE__ */ React.createElement("div", { className: "w-2 h-2 bg-white rounded-full animate-ping" }) : null), /* @__PURE__ */ React.createElement("span", { className: isSummaryStepActive(4) ? isDarkTheme ? "text-gray-100 font-medium" : "text-gray-700 font-medium" : isDarkTheme ? "text-gray-400" : "text-gray-500" }, "Creating admin tasks..."))), /* @__PURE__ */ React.createElement("div", { className: "mb-4" }, /* @__PURE__ */ React.createElement("div", { className: "flex justify-between items-center mb-1" }, /* @__PURE__ */ React.createElement("span", { className: `text-xs font-medium ${isDarkTheme ? "text-gray-200" : "text-gray-700"}` }, summaryProgress.message), /* @__PURE__ */ React.createElement("span", { className: "text-xs font-semibold text-indigo-600" }, summaryProgress.progress, "%")), /* @__PURE__ */ React.createElement("div", { className: `w-full rounded-full h-2 ${isDarkTheme ? "bg-gray-700" : "bg-gray-200"}` }, /* @__PURE__ */ React.createElement(
        "div",
        {
          className: "bg-gradient-to-r from-indigo-500 to-purple-600 h-2 rounded-full transition-all duration-500 ease-out",
          style: { width: `${summaryProgress.progress}%` }
        }
      ))), isSummaryWorkerActive && /* @__PURE__ */ React.createElement("div", { className: `mb-4 rounded-lg border px-4 py-3 text-left ${isDarkTheme ? "border-amber-800 bg-amber-950/40" : "border-amber-200 bg-amber-50"}` }, /* @__PURE__ */ React.createElement("div", { className: "flex items-start justify-between gap-3" }, /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("div", { className: `text-xs font-semibold uppercase tracking-[0.18em] ${isDarkTheme ? "text-amber-200" : "text-amber-800"}` }, "Durable Summary Worker"), /* @__PURE__ */ React.createElement("div", { className: `mt-1 text-sm leading-6 ${isDarkTheme ? "text-amber-100" : "text-amber-900"}` }, "Connected to worker PID ", summaryWorkerPid, ". You can close the workspace and resume this summary later, or stop it now.")), /* @__PURE__ */ React.createElement(
        "button",
        {
          type: "button",
          onClick: abortSummaryRun,
          disabled: isAbortingSummary,
          className: `rounded-lg px-3 py-2 text-xs font-semibold uppercase tracking-[0.14em] ${isAbortingSummary ? "cursor-wait opacity-70" : ""} ${isDarkTheme ? "bg-rose-600 text-white hover:bg-rose-500" : "bg-rose-600 text-white hover:bg-rose-700"}`
        },
        isAbortingSummary ? "Stopping..." : "Abort Summary"
      ))), /* @__PURE__ */ React.createElement("div", { className: `text-xs italic ${isDarkTheme ? "text-gray-400" : "text-gray-500"}` }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-lightbulb mr-1 text-yellow-500" }), "This analysis uses AI to understand your data patterns and recommend optimizations"))) : summaryData ? /* @__PURE__ */ React.createElement("div", null, activeTab === "summary" && /* @__PURE__ */ React.createElement("div", { id: "summary-tabpanel-summary", role: "tabpanel", "aria-labelledby": "summary-tab-summary", className: "space-y-6" }, renderExecutiveControlSummary(), summaryInfographicCapability.available && /* @__PURE__ */ React.createElement("div", { className: "flex justify-center pb-2" }, /* @__PURE__ */ React.createElement(
        "button",
        {
          type: "button",
          onClick: generateSummaryInfographic,
          disabled: isGeneratingSummaryInfographic,
          "aria-label": summaryInfographicCapability.hasExisting ? "Open the saved infographic for this summary" : "Generate an infographic from this summary using gpt-image-2",
          className: `text-xs tracking-[0.35em] lowercase focus:outline-none ${isDarkTheme ? "text-gray-900" : "text-white"} ${isGeneratingSummaryInfographic ? "cursor-wait" : "cursor-pointer"}`
        },
        "magic"
      )), false), activeTab === "context" && /* @__PURE__ */ React.createElement("div", { id: "summary-tabpanel-context", role: "tabpanel", "aria-labelledby": "summary-tab-context", className: "space-y-6" }, !hasContextExplorer ? /* @__PURE__ */ React.createElement("div", { className: `rounded-2xl border p-6 ${isDarkTheme ? "bg-gray-900 border-gray-700 text-gray-300" : "bg-white border-gray-200 text-gray-700"}` }, "Context explorer data is not available for this session yet.") : /* @__PURE__ */ React.createElement(React.Fragment, null, /* @__PURE__ */ React.createElement("div", { className: `rounded-2xl border overflow-hidden shadow-sm ${isDarkTheme ? "bg-gray-900 border-gray-700" : "bg-white border-gray-200"}` }, /* @__PURE__ */ React.createElement("div", { className: `p-6 md:p-7 border-b ${isDarkTheme ? "border-gray-700 bg-gradient-to-r from-slate-900 via-cyan-950 to-slate-900" : "border-gray-200 bg-gradient-to-r from-cyan-50 via-sky-50 to-white"}` }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-col gap-6 xl:flex-row xl:items-start xl:justify-between" }, /* @__PURE__ */ React.createElement("div", { className: "xl:max-w-3xl" }, /* @__PURE__ */ React.createElement("div", { className: `text-xs font-semibold uppercase tracking-[0.24em] ${isDarkTheme ? "text-cyan-300" : "text-cyan-700"}` }, "Executive Control Process"), /* @__PURE__ */ React.createElement("h3", { className: `mt-2 text-2xl font-semibold ${isDarkTheme ? "text-gray-100" : "text-gray-900"}` }, "Context Explorer"), /* @__PURE__ */ React.createElement("p", { className: `mt-3 max-w-3xl text-sm leading-6 ${isDarkTheme ? "text-gray-300" : "text-gray-700"}` }, "Inspect the anchors this discovery session surfaced, then pivot directly into chat, query validation, or control follow-up without leaving the exec-control loop.")), /* @__PURE__ */ React.createElement("div", { className: "grid grid-cols-2 gap-3 xl:w-[440px]" }, /* @__PURE__ */ React.createElement("div", { className: `rounded-xl border p-4 ${isDarkTheme ? "bg-gray-950 border-cyan-800" : "bg-white border-cyan-200"}` }, /* @__PURE__ */ React.createElement("div", { className: `text-xs uppercase tracking-wide ${isDarkTheme ? "text-cyan-300" : "text-cyan-700"}` }, "Readiness"), /* @__PURE__ */ React.createElement("div", { className: `mt-2 text-3xl font-bold ${isDarkTheme ? "text-gray-100" : "text-gray-900"}` }, (_pb = (_ob = contextOverview.readiness_score) != null ? _ob : readinessScore) != null ? _pb : "N/A"), /* @__PURE__ */ React.createElement("div", { className: `mt-1 text-xs ${isDarkTheme ? "text-gray-400" : "text-gray-600"}` }, "Session posture baseline")), /* @__PURE__ */ React.createElement("div", { className: `rounded-xl border p-4 ${isDarkTheme ? "bg-gray-950 border-blue-800" : "bg-white border-blue-200"}` }, /* @__PURE__ */ React.createElement("div", { className: `text-xs uppercase tracking-wide ${isDarkTheme ? "text-blue-300" : "text-blue-700"}` }, "Indexes"), /* @__PURE__ */ React.createElement("div", { className: `mt-2 text-3xl font-bold ${isDarkTheme ? "text-gray-100" : "text-gray-900"}` }, (_qb = contextOverview.total_indexes) != null ? _qb : contextIndexAnchors.length), /* @__PURE__ */ React.createElement("div", { className: `mt-1 text-xs ${isDarkTheme ? "text-gray-400" : "text-gray-600"}` }, "Discovery-known index inventory")), /* @__PURE__ */ React.createElement("div", { className: `rounded-xl border p-4 ${isDarkTheme ? "bg-gray-950 border-emerald-800" : "bg-white border-emerald-200"}` }, /* @__PURE__ */ React.createElement("div", { className: `text-xs uppercase tracking-wide ${isDarkTheme ? "text-emerald-300" : "text-emerald-700"}` }, "Sourcetypes"), /* @__PURE__ */ React.createElement("div", { className: `mt-2 text-3xl font-bold ${isDarkTheme ? "text-gray-100" : "text-gray-900"}` }, (_rb = contextOverview.total_sourcetypes) != null ? _rb : contextSourcetypeAnchors.length), /* @__PURE__ */ React.createElement("div", { className: `mt-1 text-xs ${isDarkTheme ? "text-gray-400" : "text-gray-600"}` }, "Active data shapes")), /* @__PURE__ */ React.createElement("div", { className: `rounded-xl border p-4 ${isDarkTheme ? "bg-gray-950 border-amber-800" : "bg-white border-amber-200"}` }, /* @__PURE__ */ React.createElement("div", { className: `text-xs uppercase tracking-wide ${isDarkTheme ? "text-amber-300" : "text-amber-700"}` }, "Hosts"), /* @__PURE__ */ React.createElement("div", { className: `mt-2 text-3xl font-bold ${isDarkTheme ? "text-gray-100" : "text-gray-900"}` }, (_sb = contextOverview.total_hosts) != null ? _sb : contextHostAnchors.length), /* @__PURE__ */ React.createElement("div", { className: `mt-1 text-xs ${isDarkTheme ? "text-gray-400" : "text-gray-600"}` }, contextOverview.data_volume_24h || "Unknown volume"))))), /* @__PURE__ */ React.createElement("div", { className: "p-6 space-y-6" }, contextPatterns.length > 0 && /* @__PURE__ */ React.createElement("div", { className: `rounded-xl border p-5 ${isDarkTheme ? "bg-gray-950 border-gray-800" : "bg-cyan-50 border-cyan-200"}` }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-col gap-3 md:flex-row md:items-start md:justify-between" }, /* @__PURE__ */ React.createElement("div", { className: "max-w-3xl" }, /* @__PURE__ */ React.createElement("div", { className: "flex items-center gap-2" }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-radar text-cyan-600" }), /* @__PURE__ */ React.createElement("h4", { className: `text-lg font-semibold ${isDarkTheme ? "text-gray-100" : "text-gray-900"}` }, "Observed Patterns")), /* @__PURE__ */ React.createElement("p", { className: `mt-2 text-sm leading-6 ${isDarkTheme ? "text-gray-300" : "text-gray-700"}` }, "Scan the main takeaway first, then review the supporting patterns without digging through a dense card wall.")), /* @__PURE__ */ React.createElement("div", { className: `inline-flex items-center rounded-full px-3 py-1 text-xs font-semibold ${isDarkTheme ? "bg-cyan-950 border border-cyan-800 text-cyan-100" : "bg-white border border-cyan-200 text-cyan-800"}` }, contextPatterns.length, " surfaced")), leadContextPattern && /* @__PURE__ */ React.createElement("div", { className: "mt-4 grid gap-4 xl:grid-cols-[minmax(0,1.15fr),minmax(0,0.85fr)]" }, /* @__PURE__ */ React.createElement("div", { className: `rounded-2xl border p-5 ${isDarkTheme ? "bg-slate-900 border-slate-800" : "bg-white border-slate-200"}` }, /* @__PURE__ */ React.createElement("div", { className: `text-[11px] font-semibold uppercase tracking-[0.24em] ${isDarkTheme ? "text-cyan-300" : "text-cyan-700"}` }, "Lead pattern"), /* @__PURE__ */ React.createElement("div", { className: `mt-3 text-lg font-semibold ${isDarkTheme ? "text-gray-100" : "text-gray-900"}` }, leadContextPattern.title || "Pattern 1"), /* @__PURE__ */ React.createElement("p", { className: `mt-3 text-sm leading-6 ${isDarkTheme ? "text-gray-300" : "text-gray-700"}` }, leadContextPattern.description || "Discovery surfaced this pattern without additional narrative detail."), leadContextPattern.signal && /* @__PURE__ */ React.createElement("div", { className: `mt-4 rounded-xl border px-4 py-3 ${isDarkTheme ? "bg-cyan-950/40 border-cyan-900 text-cyan-100" : "bg-cyan-50 border-cyan-200 text-cyan-900"}` }, /* @__PURE__ */ React.createElement("div", { className: `text-[11px] font-semibold uppercase tracking-[0.22em] ${isDarkTheme ? "text-cyan-300" : "text-cyan-700"}` }, "Signal"), /* @__PURE__ */ React.createElement("div", { className: "mt-1 text-sm leading-6 break-words" }, leadContextPattern.signal))), /* @__PURE__ */ React.createElement("div", { className: "space-y-3" }, supportingContextPatterns.length > 0 ? supportingContextPatterns.map((pattern, idx) => /* @__PURE__ */ React.createElement("div", { key: `context-pattern-${idx + 1}`, className: `rounded-xl border px-4 py-4 ${isDarkTheme ? "bg-slate-900 border-slate-800" : "bg-white border-slate-200"}` }, /* @__PURE__ */ React.createElement("div", { className: "flex items-start gap-3" }, /* @__PURE__ */ React.createElement("span", { className: `mt-0.5 inline-flex h-7 w-7 shrink-0 items-center justify-center rounded-full text-xs font-bold ${isDarkTheme ? "bg-gray-950 text-cyan-200 border border-gray-700" : "bg-cyan-100 text-cyan-800 border border-cyan-200"}` }, idx + 2), /* @__PURE__ */ React.createElement("div", { className: "min-w-0" }, /* @__PURE__ */ React.createElement("div", { className: `text-sm font-semibold ${isDarkTheme ? "text-gray-100" : "text-gray-900"}` }, pattern.title || `Pattern ${idx + 2}`), pattern.description && /* @__PURE__ */ React.createElement("p", { className: `mt-1 text-xs leading-5 ${isDarkTheme ? "text-gray-300" : "text-gray-700"}` }, pattern.description), pattern.signal && /* @__PURE__ */ React.createElement("div", { className: `mt-2 text-xs leading-5 ${isDarkTheme ? "text-cyan-200" : "text-cyan-800"}` }, /* @__PURE__ */ React.createElement("span", { className: "font-semibold" }, "Signal:"), " ", pattern.signal))))) : /* @__PURE__ */ React.createElement("div", { className: `rounded-xl border px-4 py-4 text-sm ${isDarkTheme ? "bg-slate-900 border-slate-800 text-gray-300" : "bg-white border-slate-200 text-gray-700"}` }, "No additional supporting patterns were extracted for this session."))), hiddenContextPatternCount > 0 && /* @__PURE__ */ React.createElement("div", { className: `mt-4 text-xs ${isDarkTheme ? "text-gray-400" : "text-gray-600"}` }, "Showing the top ", visibleContextPatterns.length, " patterns first to keep the review focused.")), /* @__PURE__ */ React.createElement("div", { className: "grid gap-6 xl:grid-cols-3" }, [
        {
          key: "index",
          title: "Index Anchors",
          icon: "fa-database",
          accent: isDarkTheme ? "text-blue-300" : "text-blue-700",
          panel: isDarkTheme ? "bg-gray-950 border-gray-800" : "bg-blue-50 border-blue-200",
          items: contextIndexAnchors
        },
        {
          key: "sourcetype",
          title: "Sourcetype Anchors",
          icon: "fa-stream",
          accent: isDarkTheme ? "text-emerald-300" : "text-emerald-700",
          panel: isDarkTheme ? "bg-gray-950 border-gray-800" : "bg-emerald-50 border-emerald-200",
          items: contextSourcetypeAnchors
        },
        {
          key: "host",
          title: "Host Anchors",
          icon: "fa-server",
          accent: isDarkTheme ? "text-amber-300" : "text-amber-700",
          panel: isDarkTheme ? "bg-gray-950 border-gray-800" : "bg-amber-50 border-amber-200",
          items: contextHostAnchors
        }
      ].map((section) => /* @__PURE__ */ React.createElement("div", { key: section.key, className: `rounded-xl border p-5 ${section.panel}` }, /* @__PURE__ */ React.createElement("div", { className: "flex items-center gap-2 mb-4" }, /* @__PURE__ */ React.createElement("i", { className: `fas ${section.icon} ${section.accent}` }), /* @__PURE__ */ React.createElement("h4", { className: `text-lg font-semibold ${isDarkTheme ? "text-gray-100" : "text-gray-900"}` }, section.title)), /* @__PURE__ */ React.createElement("div", { className: "space-y-3" }, section.items.length === 0 ? /* @__PURE__ */ React.createElement("div", { className: `text-sm ${isDarkTheme ? "text-gray-400" : "text-gray-600"}` }, "No anchors captured for this view.") : section.items.slice(0, 4).map((item, idx) => /* @__PURE__ */ React.createElement("div", { key: `${section.key}-${item.name || idx}`, className: `rounded-xl border px-4 py-3 ${isDarkTheme ? "bg-slate-900 border-slate-800" : "bg-white border-slate-200"}` }, /* @__PURE__ */ React.createElement("div", { className: "flex items-start justify-between gap-3" }, /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("div", { className: `text-base font-semibold ${isDarkTheme ? "text-gray-100" : "text-gray-900"}` }, item.name || "Unknown"), /* @__PURE__ */ React.createElement("div", { className: `mt-1 text-xs ${isDarkTheme ? "text-gray-400" : "text-gray-600"}` }, item.events != null ? `${Number(item.events).toLocaleString()} events` : "Event count unknown", item.size_mb != null ? ` • ${Number(item.size_mb).toFixed(1)} MB` : "")), /* @__PURE__ */ React.createElement("div", { className: `text-[11px] uppercase tracking-wide ${section.accent}` }, section.key)), renderSummaryContextActionButtons(item.actions))))))), /* @__PURE__ */ React.createElement("div", { className: "grid gap-6 xl:grid-cols-[minmax(0,1.1fr),minmax(0,0.9fr),minmax(0,0.9fr)]" }, /* @__PURE__ */ React.createElement("div", { className: `rounded-xl border p-5 ${isDarkTheme ? "bg-gray-950 border-gray-800" : "bg-white border-gray-200"}` }, /* @__PURE__ */ React.createElement("div", { className: "flex items-center gap-2 mb-4" }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-puzzle-piece text-indigo-600" }), /* @__PURE__ */ React.createElement("h4", { className: `text-lg font-semibold ${isDarkTheme ? "text-gray-100" : "text-gray-900"}` }, "Context-Building Queue")), /* @__PURE__ */ React.createElement("div", { className: "space-y-3" }, contextUnknownEntities.length === 0 ? /* @__PURE__ */ React.createElement("div", { className: `text-sm ${isDarkTheme ? "text-gray-400" : "text-gray-600"}` }, "No unclear entities are waiting for classification.") : contextUnknownEntities.slice(0, 3).map((item, idx) => /* @__PURE__ */ React.createElement("div", { key: `context-unknown-${item.name || idx}`, className: `rounded-xl border px-4 py-3 ${isDarkTheme ? "bg-slate-900 border-slate-800" : "bg-slate-50 border-slate-200"}` }, /* @__PURE__ */ React.createElement("div", { className: "flex items-start justify-between gap-3" }, /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("div", { className: `text-base font-semibold ${isDarkTheme ? "text-gray-100" : "text-gray-900"}` }, item.name || "Unknown entity"), /* @__PURE__ */ React.createElement("div", { className: `mt-1 text-xs ${isDarkTheme ? "text-gray-400" : "text-gray-600"}` }, item.question || item.reason || "Needs context and ownership.")), /* @__PURE__ */ React.createElement("div", { className: `text-[11px] uppercase tracking-wide ${isDarkTheme ? "text-indigo-300" : "text-indigo-700"}` }, item.type || "entity")), renderSummaryContextActionButtons(item.actions))))), /* @__PURE__ */ React.createElement("div", { className: `rounded-xl border p-5 ${isDarkTheme ? "bg-gray-950 border-gray-800" : "bg-white border-gray-200"}` }, /* @__PURE__ */ React.createElement("div", { className: "flex items-center gap-2 mb-4" }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-shield-alt text-red-600" }), /* @__PURE__ */ React.createElement("h4", { className: `text-lg font-semibold ${isDarkTheme ? "text-gray-100" : "text-gray-900"}` }, "Risk & Coverage Lanes")), /* @__PURE__ */ React.createElement("div", { className: "space-y-3" }, contextRiskItems.slice(0, 2).map((risk, idx) => /* @__PURE__ */ React.createElement("div", { key: `context-risk-${idx}`, className: `rounded-xl border px-4 py-3 ${isDarkTheme ? "bg-slate-900 border-slate-800" : "bg-red-50 border-red-200"}` }, /* @__PURE__ */ React.createElement("div", { className: `text-xs uppercase tracking-wide ${isDarkTheme ? "text-red-300" : "text-red-700"}` }, (risk.severity || "medium").toString().toUpperCase(), " • ", risk.domain || "general"), /* @__PURE__ */ React.createElement("div", { className: `mt-1 text-sm font-semibold ${isDarkTheme ? "text-gray-100" : "text-gray-900"}` }, risk.risk || "Operational risk"), renderSummaryContextActionButtons(risk.actions))), contextCoverageGapItems.slice(0, 2).map((gap, idx) => /* @__PURE__ */ React.createElement("div", { key: `context-gap-${idx}`, className: `rounded-xl border px-4 py-3 ${isDarkTheme ? "bg-slate-900 border-slate-800" : "bg-amber-50 border-amber-200"}` }, /* @__PURE__ */ React.createElement("div", { className: `text-xs uppercase tracking-wide ${isDarkTheme ? "text-amber-300" : "text-amber-700"}` }, gap.priority || "Priority not set"), /* @__PURE__ */ React.createElement("div", { className: `mt-1 text-sm font-semibold ${isDarkTheme ? "text-gray-100" : "text-gray-900"}` }, gap.gap || "Coverage gap"), gap.why_it_matters && /* @__PURE__ */ React.createElement("div", { className: `mt-1 text-xs ${isDarkTheme ? "text-gray-400" : "text-gray-600"}` }, gap.why_it_matters), renderSummaryContextActionButtons(gap.actions))))), /* @__PURE__ */ React.createElement("div", { className: `rounded-xl border p-5 ${isDarkTheme ? "bg-gray-950 border-gray-800" : "bg-white border-gray-200"}` }, /* @__PURE__ */ React.createElement("div", { className: "flex items-center gap-2 mb-4" }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-tasks text-emerald-600" }), /* @__PURE__ */ React.createElement("h4", { className: `text-lg font-semibold ${isDarkTheme ? "text-gray-100" : "text-gray-900"}` }, "Priority Tasks in Context")), /* @__PURE__ */ React.createElement("div", { className: "space-y-3" }, contextPriorityTasks.length === 0 ? /* @__PURE__ */ React.createElement("div", { className: `text-sm ${isDarkTheme ? "text-gray-400" : "text-gray-600"}` }, "Task context will appear once the summary produces actionable work items.") : contextPriorityTasks.slice(0, 4).map((task, idx) => /* @__PURE__ */ React.createElement("div", { key: `context-task-${idx}`, className: `rounded-xl border px-4 py-3 ${isDarkTheme ? "bg-slate-900 border-slate-800" : "bg-emerald-50 border-emerald-200"}` }, /* @__PURE__ */ React.createElement("div", { className: "flex items-start justify-between gap-3" }, /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("div", { className: `text-sm font-semibold ${isDarkTheme ? "text-gray-100" : "text-gray-900"}` }, task.title || `Task ${idx + 1}`), /* @__PURE__ */ React.createElement("div", { className: `mt-1 text-xs ${isDarkTheme ? "text-gray-400" : "text-gray-600"}` }, task.category || "General", " workstream")), /* @__PURE__ */ React.createElement("div", { className: `text-[11px] uppercase tracking-wide ${isDarkTheme ? "text-emerald-300" : "text-emerald-700"}` }, task.priority || "MEDIUM")), renderSummaryContextActionButtons(task.actions)))))))))), activeTab === "queries" && /* @__PURE__ */ React.createElement("div", { id: "summary-tabpanel-queries", role: "tabpanel", "aria-labelledby": "summary-tab-queries", className: isDarkTheme ? "text-gray-100" : "text-gray-900" }, queryFocus && /* @__PURE__ */ React.createElement("div", { className: `mb-4 rounded-lg p-4 border ${isDarkTheme ? "bg-indigo-950 border-indigo-700" : "bg-indigo-50 border-indigo-200"}` }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between" }, /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("div", { className: `text-xs font-semibold uppercase tracking-[0.2em] ${isDarkTheme ? "text-indigo-300" : "text-indigo-700"}` }, queryFocus.sourceLabel || "Focused Query Set"), /* @__PURE__ */ React.createElement("h4", { className: `mt-1 text-base font-semibold ${isDarkTheme ? "text-indigo-100" : "text-indigo-900"}` }, queryFocus.title), /* @__PURE__ */ React.createElement("p", { className: `mt-2 text-sm ${isDarkTheme ? "text-indigo-200" : "text-indigo-800"}` }, queryFocus.description || `Showing validation queries aligned to the ${queryFocus.category} workstream using matching finding and telemetry evidence.`)), /* @__PURE__ */ React.createElement(
        "button",
        {
          type: "button",
          onClick: clearQueryFocus,
          className: `inline-flex items-center justify-center rounded-lg px-4 py-2 text-sm font-medium transition-colors ${isDarkTheme ? "bg-gray-900 text-gray-100 hover:bg-gray-800 border border-gray-700" : "bg-white text-gray-800 hover:bg-gray-100 border border-gray-200"}`
        },
        "Clear Focus"
      ))), summaryData.risk_register && summaryData.risk_register.length > 0 && /* @__PURE__ */ React.createElement("div", { className: `mb-4 rounded-lg p-4 border ${isDarkTheme ? "bg-red-950 border-red-700" : "bg-red-50 border-red-200"}` }, /* @__PURE__ */ React.createElement("h4", { className: `text-sm font-semibold mb-2 flex items-center ${isDarkTheme ? "text-red-200" : "text-red-900"}` }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-shield-alt mr-2" }), "Risk-Linked Query Focus"), /* @__PURE__ */ React.createElement("p", { className: `text-sm mb-3 ${isDarkTheme ? "text-red-300" : "text-red-800"}` }, "Prioritize queries that validate or reduce the highest-severity risks discovered in this session."), /* @__PURE__ */ React.createElement("div", { className: "space-y-1" }, summaryData.risk_register.slice(0, 3).map((risk, idx) => /* @__PURE__ */ React.createElement("div", { key: idx, className: `text-xs rounded px-3 py-2 border ${isDarkTheme ? "text-red-200 bg-gray-900 border-red-800" : "text-red-900 bg-white border-red-200"}` }, /* @__PURE__ */ React.createElement("span", { className: "font-semibold" }, (risk.severity || "medium").toString().toUpperCase(), ":"), " ", risk.risk || "Operational risk")))), /* @__PURE__ */ React.createElement("div", { className: "flex flex-col gap-3 mb-4 lg:flex-row lg:items-center lg:justify-between" }, /* @__PURE__ */ React.createElement("h3", { className: `text-xl font-semibold flex items-center ${isDarkTheme ? "text-gray-100" : "text-gray-900"}` }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-code text-purple-600 mr-2" }), "Ready-to-Use SPL Queries (", filteredSummaryQueries.length, ")"), /* @__PURE__ */ React.createElement("div", { className: "flex flex-wrap items-center gap-2" }, queryFilterOptions.map((option) => /* @__PURE__ */ React.createElement(
        "button",
        {
          key: option.key,
          onClick: () => setQueryFilter(option.key),
          className: `px-3 py-1 text-sm font-medium rounded-lg transition-colors ${activeQueryFilterKey === option.key ? option.activeClass : isDarkTheme ? "bg-gray-700 text-gray-200 hover:bg-gray-600" : "bg-gray-100 text-gray-700 hover:bg-gray-200"}`
        },
        option.label,
        " (",
        option.count,
        ")"
      )))), /* @__PURE__ */ React.createElement("div", { className: "space-y-4" }, filteredSummaryQueries.length > 0 ? filteredSummaryQueries.map((query, idx) => {
        var _a2, _b2, _c2;
        return /* @__PURE__ */ React.createElement("div", { key: idx, className: `border rounded-xl p-5 shadow-sm hover:shadow-md transition-shadow ${((_a2 = query.priority) == null ? void 0 : _a2.startsWith("🔴")) ? isDarkTheme ? "border-red-700 bg-red-950" : "border-red-300 bg-red-50" : ((_b2 = query.priority) == null ? void 0 : _b2.startsWith("🟠")) ? isDarkTheme ? "border-orange-700 bg-orange-950" : "border-orange-300 bg-orange-50" : ((_c2 = query.priority) == null ? void 0 : _c2.startsWith("🟡")) ? isDarkTheme ? "border-yellow-700 bg-yellow-950" : "border-yellow-300 bg-yellow-50" : isDarkTheme ? "border-gray-700 bg-gray-800" : "border-gray-200 bg-white"}` }, query.priority && /* @__PURE__ */ React.createElement("div", { className: "mb-2" }, /* @__PURE__ */ React.createElement("span", { className: `px-3 py-1 text-xs font-bold rounded-full ${query.priority.startsWith("🔴") ? "bg-red-600 text-white" : query.priority.startsWith("🟠") ? "bg-orange-700 text-white" : query.priority.startsWith("🟡") ? "bg-yellow-500 text-gray-900" : "bg-gray-600 text-white"}` }, query.priority), /* @__PURE__ */ React.createElement("span", { className: `ml-2 px-2 py-1 text-xs rounded-full ${query.query_source === "ai_finding" ? "bg-purple-600 text-white" : query.query_source === "context_engine" ? "bg-emerald-600 text-white" : query.query_source === "template" ? "bg-blue-600 text-white" : "bg-gray-600 text-white"}` }, getQuerySourceLabel(query.query_source))), /* @__PURE__ */ React.createElement("div", { className: "flex justify-between items-start mb-3" }, /* @__PURE__ */ React.createElement("div", { className: "flex-1" }, /* @__PURE__ */ React.createElement("div", { className: "flex items-center flex-wrap gap-2 mb-2" }, /* @__PURE__ */ React.createElement("h4", { className: `text-lg font-semibold ${isDarkTheme ? "text-gray-100" : "text-gray-900"}` }, query.title), /* @__PURE__ */ React.createElement("span", { className: `px-2 py-1 text-xs rounded-full ${query.category === "Security & Compliance" ? isDarkTheme ? "bg-red-900 text-red-200" : "bg-red-100 text-red-700" : query.category === "Infrastructure & Performance" ? isDarkTheme ? "bg-blue-900 text-blue-200" : "bg-blue-100 text-blue-700" : query.category === "Capacity Planning" ? isDarkTheme ? "bg-green-900 text-green-200" : "bg-green-100 text-green-700" : isDarkTheme ? "bg-gray-700 text-gray-200" : "bg-gray-100 text-gray-700"}` }, query.category), /* @__PURE__ */ React.createElement("span", { className: `px-2 py-1 text-xs rounded-full ${isDarkTheme ? "bg-purple-900 text-purple-200" : "bg-purple-100 text-purple-700"}` }, query.difficulty)), /* @__PURE__ */ React.createElement("p", { className: `text-sm mb-2 ${isDarkTheme ? "text-gray-300" : "text-gray-600"}` }, query.description), query.finding_reference && /* @__PURE__ */ React.createElement("div", { className: `mt-2 p-2 border-l-2 rounded-r text-xs ${isDarkTheme ? "bg-indigo-950 border-indigo-500 text-indigo-200" : "bg-indigo-50 border-indigo-600 text-indigo-900"}` }, /* @__PURE__ */ React.createElement("strong", null, "📋 Discovery Finding:"), " ", query.finding_reference), query.environment_evidence && query.environment_evidence.length > 0 && /* @__PURE__ */ React.createElement("div", { className: "mt-2 flex flex-wrap gap-2" }, query.environment_evidence.map((evidence, evidenceIdx) => /* @__PURE__ */ React.createElement("span", { key: evidenceIdx, className: `px-2 py-1 text-xs rounded-full border ${isDarkTheme ? "bg-emerald-900 text-emerald-200 border-emerald-700" : "bg-emerald-100 text-emerald-800 border-emerald-300"}` }, evidence))), /* @__PURE__ */ React.createElement("div", { className: `flex items-center space-x-4 text-xs mt-2 ${isDarkTheme ? "text-gray-300" : "text-gray-600"}` }, /* @__PURE__ */ React.createElement("span", null, /* @__PURE__ */ React.createElement("i", { className: "fas fa-clock mr-1" }), query.execution_time), /* @__PURE__ */ React.createElement("span", null, /* @__PURE__ */ React.createElement("i", { className: "fas fa-chart-line mr-1" }), query.use_case))), /* @__PURE__ */ React.createElement("div", { className: "ml-4 flex space-x-2" }, canUseSplunkDeeplinks && /* @__PURE__ */ React.createElement(
          "button",
          {
            type: "button",
            onClick: () => openSplunkSearchFromChat(query.spl),
            className: "px-3 py-1 bg-sky-600 hover:bg-sky-700 text-white text-sm rounded flex items-center space-x-1",
            title: "Open this query in Splunk Web"
          },
          /* @__PURE__ */ React.createElement("i", { className: "fas fa-external-link-alt" }),
          /* @__PURE__ */ React.createElement("span", null, "Open in Splunk")
        ), /* @__PURE__ */ React.createElement(
          "button",
          {
            onClick: () => launchChatInvestigation(
              `Can you help me understand this query and run it?

${query.spl}`,
              { freshContext: true }
            ),
            className: "px-3 py-1 bg-green-600 hover:bg-green-700 text-white text-sm rounded flex items-center space-x-1",
            title: "Ask AI about this query"
          },
          /* @__PURE__ */ React.createElement("i", { className: "fas fa-comments" }),
          /* @__PURE__ */ React.createElement("span", null, "Ask AI")
        ), /* @__PURE__ */ React.createElement(
          "button",
          {
            onClick: () => copyToClipboard(query.spl),
            className: "px-3 py-1 bg-indigo-600 hover:bg-indigo-700 text-white text-sm rounded flex items-center space-x-1",
            title: "Copy to clipboard"
          },
          /* @__PURE__ */ React.createElement("i", { className: "fas fa-copy" }),
          /* @__PURE__ */ React.createElement("span", null, "Copy")
        ))), /* @__PURE__ */ React.createElement("details", { className: "mt-3" }, /* @__PURE__ */ React.createElement("summary", { className: `cursor-pointer text-sm font-medium ${isDarkTheme ? "text-indigo-300 hover:text-indigo-200" : "text-indigo-600 hover:text-indigo-800"}` }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-code mr-1" }), "View SPL Code"), /* @__PURE__ */ React.createElement("pre", { className: "mt-2 p-4 bg-gray-900 text-green-400 rounded text-sm overflow-x-auto" }, query.spl)), query.business_value && /* @__PURE__ */ React.createElement("div", { className: `mt-3 p-3 border-l-4 rounded-r ${isDarkTheme ? "bg-yellow-950 border-yellow-600" : "bg-yellow-50 border-yellow-400"}` }, /* @__PURE__ */ React.createElement("p", { className: `text-sm ${isDarkTheme ? "text-yellow-200" : "text-yellow-900"}` }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-lightbulb mr-1" }), /* @__PURE__ */ React.createElement("strong", null, "Business Value:"), " ", query.business_value)));
      }) : /* @__PURE__ */ React.createElement("div", { className: `rounded-xl border border-dashed p-6 text-center ${isDarkTheme ? "border-gray-700 bg-gray-900 text-gray-300" : "border-gray-300 bg-gray-50 text-gray-600"}` }, /* @__PURE__ */ React.createElement("div", { className: "text-sm font-semibold" }, "No queries match the current focus and source filter."), /* @__PURE__ */ React.createElement("p", { className: "mt-2 text-sm" }, "Clear the focus or switch the source filter to broaden the validation set.")))), activeTab === "tasks" && /* @__PURE__ */ React.createElement("div", { id: "summary-tabpanel-tasks", role: "tabpanel", "aria-labelledby": "summary-tab-tasks", className: isDarkTheme ? "text-gray-100" : "text-gray-900" }, riskFocus && /* @__PURE__ */ React.createElement("div", { className: `mb-5 rounded-lg p-4 border ${isDarkTheme ? "bg-red-950 border-red-700" : "bg-red-50 border-red-200"}` }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between" }, /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("div", { className: `text-xs font-semibold uppercase tracking-[0.2em] ${isDarkTheme ? "text-red-300" : "text-red-700"}` }, "Focused From Risk Register"), /* @__PURE__ */ React.createElement("h4", { className: `mt-1 text-base font-semibold ${isDarkTheme ? "text-red-100" : "text-red-900"}` }, riskFocus.title), /* @__PURE__ */ React.createElement("p", { className: `mt-2 text-sm ${isDarkTheme ? "text-red-200" : "text-red-800"}` }, riskFocus.domain, " is now driving the execution queue. Current task lens: ", activeTaskFilterLabel, ". Use validation queries to verify the gap before or after executing the filtered tasks.")), /* @__PURE__ */ React.createElement("div", { className: "flex flex-wrap items-center gap-2" }, /* @__PURE__ */ React.createElement(
        "button",
        {
          type: "button",
          onClick: () => focusQueriesForRisk(riskFocus.riskData || { risk: riskFocus.title, domain: riskFocus.domain }),
          className: "inline-flex items-center justify-center rounded-lg px-4 py-2 text-sm font-medium bg-indigo-600 text-white transition-colors hover:bg-indigo-700"
        },
        "Open Validation Queries"
      ), /* @__PURE__ */ React.createElement(
        "button",
        {
          type: "button",
          onClick: () => launchChatInvestigation(
            buildRiskInvestigationPrompt(riskFocus.riskData || { risk: riskFocus.title }),
            { freshContext: true }
          ),
          className: `inline-flex items-center justify-center rounded-lg px-4 py-2 text-sm font-medium transition-colors ${isDarkTheme ? "bg-gray-900 text-gray-100 hover:bg-gray-800 border border-gray-700" : "bg-white text-gray-800 hover:bg-gray-100 border border-gray-200"}`
        },
        "Investigate in Chat"
      ), /* @__PURE__ */ React.createElement(
        "button",
        {
          type: "button",
          onClick: clearRiskFocus,
          className: `inline-flex items-center justify-center rounded-lg px-4 py-2 text-sm font-medium transition-colors ${isDarkTheme ? "bg-gray-900 text-gray-100 hover:bg-gray-800 border border-gray-700" : "bg-white text-gray-800 hover:bg-gray-100 border border-gray-200"}`
        },
        "Clear Focus"
      )))), summaryData.recursive_investigations && summaryData.recursive_investigations.length > 0 && /* @__PURE__ */ React.createElement("div", { className: `mb-5 rounded-lg p-4 border ${isDarkTheme ? "bg-purple-950 border-purple-700" : "bg-purple-50 border-purple-200"}` }, /* @__PURE__ */ React.createElement("h4", { className: `text-sm font-semibold mb-2 flex items-center ${isDarkTheme ? "text-purple-200" : "text-purple-900"}` }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-sync-alt mr-2" }), "Recursive Execution Guidance"), /* @__PURE__ */ React.createElement("div", { className: "space-y-2" }, summaryData.recursive_investigations.slice(0, 2).map((loop, idx) => /* @__PURE__ */ React.createElement("div", { key: idx, className: `rounded p-3 text-xs border ${isDarkTheme ? "bg-gray-900 border-purple-800 text-purple-200" : "bg-white border-purple-200 text-purple-900"}` }, /* @__PURE__ */ React.createElement("div", { className: "font-semibold" }, loop.loop || `Loop ${idx + 1}`), /* @__PURE__ */ React.createElement("div", { className: "mt-1" }, /* @__PURE__ */ React.createElement("strong", null, "Trigger:"), " ", loop.next_iteration_trigger || "N/A"))))), summaryData.admin_tasks && summaryData.admin_tasks.length > 0 ? /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("div", { className: "mb-6" }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between" }, /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("h3", { className: `text-2xl font-bold mb-2 flex items-center ${isDarkTheme ? "text-gray-100" : "text-gray-900"}` }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-tasks text-indigo-600 mr-3" }), "Recommended Implementation Tasks (", filteredTaskSnapshots.length, ")"), /* @__PURE__ */ React.createElement("p", { className: isDarkTheme ? "text-gray-300" : "text-gray-600" }, "Prioritized tasks based on your environment analysis. Narrow by execution state or control domain to focus the next loop.")), /* @__PURE__ */ React.createElement("div", { className: "flex flex-wrap items-center gap-2" }, taskFilterOptions.map((option) => /* @__PURE__ */ React.createElement(
        "button",
        {
          key: option.key,
          onClick: () => setTaskFilter(option.key),
          className: `px-3 py-1 text-sm font-medium rounded-lg transition-colors ${activeTaskFilterKey === option.key ? option.activeClass : isDarkTheme ? "bg-gray-700 text-gray-200 hover:bg-gray-600" : "bg-gray-100 text-gray-700 hover:bg-gray-200"}`
        },
        option.label,
        " (",
        option.count,
        ")"
      ))))), /* @__PURE__ */ React.createElement("div", { className: "grid gap-3 mb-6 sm:grid-cols-2 xl:grid-cols-4" }, /* @__PURE__ */ React.createElement("div", { className: `rounded-xl border px-4 py-3 ${isDarkTheme ? "bg-gray-900 border-gray-700" : "bg-white border-gray-200"}` }, /* @__PURE__ */ React.createElement("div", { className: `text-xs uppercase tracking-wide ${isDarkTheme ? "text-indigo-300" : "text-indigo-700"}` }, "Tasks Queued"), /* @__PURE__ */ React.createElement("div", { className: `mt-1 text-2xl font-bold ${isDarkTheme ? "text-gray-100" : "text-gray-900"}` }, taskProgressSnapshots.length)), /* @__PURE__ */ React.createElement("div", { className: `rounded-xl border px-4 py-3 ${isDarkTheme ? "bg-gray-900 border-red-800" : "bg-white border-red-200"}` }, /* @__PURE__ */ React.createElement("div", { className: `text-xs uppercase tracking-wide ${isDarkTheme ? "text-red-300" : "text-red-700"}` }, "High Priority"), /* @__PURE__ */ React.createElement("div", { className: `mt-1 text-2xl font-bold ${isDarkTheme ? "text-gray-100" : "text-gray-900"}` }, highPriorityTaskCount)), /* @__PURE__ */ React.createElement("div", { className: `rounded-xl border px-4 py-3 ${isDarkTheme ? "bg-gray-900 border-indigo-800" : "bg-white border-indigo-200"}` }, /* @__PURE__ */ React.createElement("div", { className: `text-xs uppercase tracking-wide ${isDarkTheme ? "text-indigo-300" : "text-indigo-700"}` }, "In Progress"), /* @__PURE__ */ React.createElement("div", { className: `mt-1 text-2xl font-bold ${isDarkTheme ? "text-gray-100" : "text-gray-900"}` }, inProgressTaskCount)), /* @__PURE__ */ React.createElement("div", { className: `rounded-xl border px-4 py-3 ${isDarkTheme ? "bg-gray-900 border-green-800" : "bg-white border-green-200"}` }, /* @__PURE__ */ React.createElement("div", { className: `text-xs uppercase tracking-wide ${isDarkTheme ? "text-green-300" : "text-green-700"}` }, "Completed"), /* @__PURE__ */ React.createElement("div", { className: `mt-1 text-2xl font-bold ${isDarkTheme ? "text-gray-100" : "text-gray-900"}` }, completedTaskCount))), /* @__PURE__ */ React.createElement("div", { className: "space-y-4" }, filteredTaskSnapshots.length > 0 ? filteredTaskSnapshots.map(({ task, progress: progress2, completionPct, taskIndex }) => {
        var _a2, _b2, _c2, _d2;
        const taskSurfaceClass = isDarkTheme ? "rounded-xl border border-gray-700 bg-gray-950/70" : "rounded-xl border border-gray-200 bg-gray-50";
        const taskNestedSurfaceClass = isDarkTheme ? "rounded-xl border border-gray-800 bg-gray-900" : "rounded-xl border border-gray-200 bg-white shadow-sm";
        return /* @__PURE__ */ React.createElement("div", { key: taskIndex, className: `border rounded-xl overflow-hidden shadow-sm transition-all ${progress2.status === "completed" ? isDarkTheme ? "border-green-700 bg-gray-900" : "border-green-300 bg-white" : progress2.status === "in-progress" ? isDarkTheme ? "border-indigo-700 bg-gray-900" : "border-indigo-300 bg-white" : task.priority === "HIGH" ? isDarkTheme ? "border-red-800 bg-gray-900" : "border-red-200 bg-white" : task.priority === "MEDIUM" ? isDarkTheme ? "border-orange-800 bg-gray-900" : "border-orange-200 bg-white" : isDarkTheme ? "border-yellow-800 bg-gray-900" : "border-yellow-200 bg-white"}` }, /* @__PURE__ */ React.createElement("div", { className: `p-5 border-b ${isDarkTheme ? "bg-gray-900 border-gray-700" : "bg-white border-gray-200"}` }, /* @__PURE__ */ React.createElement("div", { className: "flex items-start justify-between mb-3" }, /* @__PURE__ */ React.createElement("div", { className: "flex-1" }, /* @__PURE__ */ React.createElement("div", { className: "flex items-center gap-2 mb-2 flex-wrap" }, progress2.status === "completed" && /* @__PURE__ */ React.createElement("span", { className: "px-3 py-1 text-xs font-bold rounded-full bg-green-600 text-white" }, "✓ COMPLETED"), progress2.status === "in-progress" && /* @__PURE__ */ React.createElement("span", { className: "px-3 py-1 text-xs font-bold rounded-full bg-indigo-600 text-white animate-pulse" }, "⟳ IN PROGRESS"), /* @__PURE__ */ React.createElement("span", { className: `px-3 py-1 text-xs font-bold rounded-full ${task.priority === "HIGH" ? "bg-red-600 text-white" : task.priority === "MEDIUM" ? "bg-orange-700 text-white" : "bg-yellow-500 text-gray-900"}` }, task.priority === "HIGH" ? "🔴 HIGH" : task.priority === "MEDIUM" ? "🟠 MEDIUM" : "🟡 LOW", " PRIORITY"), /* @__PURE__ */ React.createElement("span", { className: `px-2 py-1 text-xs font-semibold rounded-full ${task.category === "Security" ? isDarkTheme ? "bg-red-900 text-red-200" : "bg-red-100 text-red-700" : task.category === "Performance" ? isDarkTheme ? "bg-blue-900 text-blue-200" : "bg-blue-100 text-blue-700" : task.category === "Compliance" ? isDarkTheme ? "bg-purple-900 text-purple-200" : "bg-purple-100 text-purple-700" : task.category === "Data Quality" ? isDarkTheme ? "bg-green-900 text-green-200" : "bg-green-100 text-green-700" : isDarkTheme ? "bg-gray-700 text-gray-200" : "bg-gray-100 text-gray-700"}` }, task.category), task.estimated_time && /* @__PURE__ */ React.createElement("span", { className: `px-2 py-1 text-xs rounded-full ${isDarkTheme ? "bg-indigo-900 text-indigo-200" : "bg-indigo-100 text-indigo-700"}` }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-clock mr-1" }), task.estimated_time)), /* @__PURE__ */ React.createElement("h4", { className: `text-xl font-bold mb-2 ${isDarkTheme ? "text-gray-100" : "text-gray-900"}` }, task.title), /* @__PURE__ */ React.createElement("p", { className: `text-sm ${isDarkTheme ? "text-gray-300" : "text-gray-700"}` }, task.description), /* @__PURE__ */ React.createElement("div", { className: "mt-3" }, /* @__PURE__ */ React.createElement("div", { className: `flex items-center justify-between text-xs mb-1 ${isDarkTheme ? "text-gray-400" : "text-gray-600"}` }, /* @__PURE__ */ React.createElement("span", { className: "font-medium" }, "Progress: ", completionPct, "%"), /* @__PURE__ */ React.createElement("span", null, progress2.completedSteps.length, " / ", ((_a2 = task.steps) == null ? void 0 : _a2.length) || 0, " steps")), /* @__PURE__ */ React.createElement("div", { className: `w-full rounded-full h-2 overflow-hidden ${isDarkTheme ? "bg-gray-700" : "bg-gray-200"}` }, /* @__PURE__ */ React.createElement(
          "div",
          {
            className: `h-full rounded-full transition-all duration-500 ${completionPct === 100 ? "bg-green-500" : completionPct > 0 ? "bg-indigo-500" : "bg-gray-300"}`,
            style: { width: `${completionPct}%` }
          }
        ))))), task.impact && /* @__PURE__ */ React.createElement("div", { className: `mt-3 p-3 border-l-4 rounded-r ${isDarkTheme ? "bg-green-950 border-green-600" : "bg-green-50 border-green-500"}` }, /* @__PURE__ */ React.createElement("p", { className: `text-sm ${isDarkTheme ? "text-green-200" : "text-green-900"}` }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-chart-line mr-2" }), /* @__PURE__ */ React.createElement("strong", null, "Impact:"), " ", task.impact)), /* @__PURE__ */ React.createElement("div", { className: "mt-4 flex flex-wrap gap-2" }, /* @__PURE__ */ React.createElement(
          "button",
          {
            type: "button",
            onClick: () => focusQueriesForTask(task),
            className: "inline-flex items-center rounded-lg bg-indigo-600 px-3 py-2 text-sm font-medium text-white transition-colors hover:bg-indigo-700"
          },
          /* @__PURE__ */ React.createElement("i", { className: "fas fa-code mr-2" }),
          "Open Validation Queries"
        ))), /* @__PURE__ */ React.createElement("details", { className: "group", open: progress2.status === "in-progress" }, /* @__PURE__ */ React.createElement("summary", { className: `cursor-pointer px-5 py-3 transition-colors list-none flex items-center justify-between ${isDarkTheme ? "bg-gradient-to-r from-indigo-950 to-purple-950 hover:from-indigo-900 hover:to-purple-900" : "bg-gradient-to-r from-indigo-50 to-purple-50 hover:from-indigo-100 hover:to-purple-100"}` }, /* @__PURE__ */ React.createElement("span", { className: `font-semibold flex items-center ${isDarkTheme ? "text-gray-100" : "text-gray-900"}` }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-chevron-right mr-2 group-open:rotate-90 transition-transform" }), "Implementation Steps"), /* @__PURE__ */ React.createElement("span", { className: `text-sm ${isDarkTheme ? "text-gray-300" : "text-gray-600"}` }, ((_b2 = task.steps) == null ? void 0 : _b2.length) || 0, " steps")), /* @__PURE__ */ React.createElement("div", { className: `p-5 ${isDarkTheme ? "bg-gray-900" : "bg-white"}` }, /* @__PURE__ */ React.createElement("div", { className: "grid gap-5 lg:grid-cols-2" }, /* @__PURE__ */ React.createElement("div", { className: "space-y-4 min-w-0" }, task.prerequisites && task.prerequisites.length > 0 && /* @__PURE__ */ React.createElement("div", { className: taskSurfaceClass }, /* @__PURE__ */ React.createElement("div", { className: "flex items-center justify-between gap-3" }, /* @__PURE__ */ React.createElement("h5", { className: `font-semibold flex items-center ${isDarkTheme ? "text-gray-100" : "text-gray-900"}` }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-list-check mr-2 text-blue-600" }), "Prerequisites"), /* @__PURE__ */ React.createElement("span", { className: `text-xs uppercase tracking-wide ${isDarkTheme ? "text-gray-400" : "text-gray-500"}` }, task.prerequisites.length, " item", task.prerequisites.length === 1 ? "" : "s")), /* @__PURE__ */ React.createElement("ul", { className: "mt-3 space-y-2" }, task.prerequisites.map((prereq, pIdx) => /* @__PURE__ */ React.createElement("li", { key: pIdx, className: `text-sm flex items-start ${isDarkTheme ? "text-gray-300" : "text-gray-700"}` }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-angle-right mr-2 mt-1 text-blue-500" }), /* @__PURE__ */ React.createElement("span", null, prereq))))), /* @__PURE__ */ React.createElement("div", { className: taskSurfaceClass }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between" }, /* @__PURE__ */ React.createElement("h5", { className: `font-semibold flex items-center ${isDarkTheme ? "text-gray-100" : "text-gray-900"}` }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-list-ol mr-2 text-indigo-600" }), "Implementation Checklist"), /* @__PURE__ */ React.createElement("span", { className: `text-xs uppercase tracking-wide ${isDarkTheme ? "text-gray-400" : "text-gray-500"}` }, ((_c2 = task.steps) == null ? void 0 : _c2.length) || 0, " step", (((_d2 = task.steps) == null ? void 0 : _d2.length) || 0) === 1 ? "" : "s")), /* @__PURE__ */ React.createElement("div", { className: "mt-4 space-y-3" }, task.steps && task.steps.length > 0 && task.steps.map((step, sIdx) => {
          const isCompleted = progress2.completedSteps.includes(step.number);
          return /* @__PURE__ */ React.createElement("div", { key: sIdx, className: `border rounded-xl p-4 transition-all ${isCompleted ? isDarkTheme ? "border-green-700 bg-green-950/40" : "border-green-300 bg-green-50" : isDarkTheme ? "border-gray-700 bg-gray-900" : "border-gray-200 bg-white"}` }, /* @__PURE__ */ React.createElement("div", { className: "flex items-start gap-3 min-w-0" }, /* @__PURE__ */ React.createElement(
            "input",
            {
              type: "checkbox",
              checked: isCompleted,
              onChange: () => toggleStepCompletion(currentSessionId, taskIndex, step.number),
              className: "mt-1 w-5 h-5 text-indigo-600 border-gray-300 rounded focus:ring-indigo-500 cursor-pointer"
            }
          ), /* @__PURE__ */ React.createElement("div", { className: "flex-shrink-0 w-8 h-8 bg-indigo-600 text-white rounded-full flex items-center justify-center font-bold text-sm" }, isCompleted ? "✓" : step.number), /* @__PURE__ */ React.createElement("div", { className: "flex-1 min-w-0" }, /* @__PURE__ */ React.createElement("p", { className: `text-sm font-medium leading-6 ${isCompleted ? "text-gray-500 line-through" : isDarkTheme ? "text-gray-100" : "text-gray-900"}` }, step.action))), step.spl && /* @__PURE__ */ React.createElement("div", { className: "mt-3 sm:ml-16" }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between mb-2" }, /* @__PURE__ */ React.createElement("span", { className: `text-xs font-semibold uppercase tracking-wide ${isDarkTheme ? "text-gray-400" : "text-gray-500"}` }, "Step SPL"), renderSplQueryActionButtons2(step.spl, {
            originKind: "summary_task_step",
            originLabel: task.title || `Task ${taskIndex + 1}`,
            sourceLabel: task.title || "Summary task",
            contextExcerpt: step.action,
            className: "sm:justify-end"
          })), /* @__PURE__ */ React.createElement("pre", { className: "max-h-48 overflow-auto rounded-lg bg-gray-950 p-3 text-xs text-green-400" }, step.spl)));
        })))), /* @__PURE__ */ React.createElement("div", { className: "space-y-4 min-w-0" }, task.verification_spl && /* @__PURE__ */ React.createElement("div", { className: `rounded-xl border p-4 ${isDarkTheme ? "border-blue-800 bg-blue-950/40" : "border-blue-200 bg-blue-50"}` }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between" }, /* @__PURE__ */ React.createElement("div", { className: "min-w-0" }, /* @__PURE__ */ React.createElement("h5", { className: `font-semibold flex items-center ${isDarkTheme ? "text-blue-200" : "text-blue-900"}` }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-check-circle mr-2" }), "Verification"), /* @__PURE__ */ React.createElement("div", { className: `mt-2 rounded-lg border px-3 py-3 text-sm ${isDarkTheme ? "border-blue-900 bg-gray-950 text-blue-100" : "border-blue-100 bg-white text-blue-900"}` }, /* @__PURE__ */ React.createElement("strong", null, "Expected Outcome:"), " ", task.expected_outcome)), /* @__PURE__ */ React.createElement(
          "button",
          {
            onClick: () => runVerification(currentSessionId, taskIndex, task),
            disabled: verifyingTask === taskIndex,
            className: `inline-flex items-center justify-center rounded-lg px-4 py-2 text-sm font-medium transition-all ${verifyingTask === taskIndex ? "bg-gray-400 text-white cursor-not-allowed" : "bg-blue-600 hover:bg-blue-700 text-white shadow-sm hover:shadow"}`
          },
          verifyingTask === taskIndex ? /* @__PURE__ */ React.createElement(React.Fragment, null, /* @__PURE__ */ React.createElement("i", { className: "fas fa-spinner fa-spin mr-2" }), "Verifying...") : /* @__PURE__ */ React.createElement(React.Fragment, null, /* @__PURE__ */ React.createElement("i", { className: "fas fa-play-circle mr-2" }), "Run Verification")
        )), /* @__PURE__ */ React.createElement("details", { className: "mt-3" }, /* @__PURE__ */ React.createElement("summary", { className: `cursor-pointer text-xs font-semibold ${isDarkTheme ? "text-blue-300 hover:text-blue-200" : "text-blue-700 hover:text-blue-900"}` }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-code mr-1" }), "View Verification SPL"), /* @__PURE__ */ React.createElement("div", { className: "mt-2 flex flex-wrap items-center justify-end gap-2 mb-2" }, renderSplQueryActionButtons2(task.verification_spl, {
          originKind: "summary_verification",
          originLabel: task.title || `Task ${taskIndex + 1}`,
          sourceLabel: task.title || "Verification task",
          contextExcerpt: task.expected_outcome,
          className: "justify-end"
        })), /* @__PURE__ */ React.createElement("pre", { className: "max-h-48 overflow-auto rounded-lg bg-gray-950 p-3 text-xs text-green-400" }, task.verification_spl)), (() => {
          const verResult = getVerificationResult(currentSessionId, taskIndex);
          if (!verResult) return null;
          const verificationResultSurfaceClass = verResult.status === "success" ? isDarkTheme ? "bg-green-950/40 border-green-700" : "bg-green-50 border-green-200" : verResult.status === "partial" ? isDarkTheme ? "bg-amber-950/40 border-amber-700" : "bg-amber-50 border-amber-200" : verResult.status === "failed" ? isDarkTheme ? "bg-red-950/40 border-red-700" : "bg-red-50 border-red-200" : isDarkTheme ? "bg-gray-900 border-gray-700" : "bg-gray-50 border-gray-200";
          const verificationResultTextClass = verResult.status === "success" ? isDarkTheme ? "text-green-100" : "text-green-900" : verResult.status === "partial" ? isDarkTheme ? "text-amber-100" : "text-amber-900" : verResult.status === "failed" ? isDarkTheme ? "text-red-100" : "text-red-900" : isDarkTheme ? "text-gray-100" : "text-gray-900";
          return /* @__PURE__ */ React.createElement("div", { className: `mt-4 rounded-xl border p-4 fade-in ${verificationResultSurfaceClass}` }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between" }, /* @__PURE__ */ React.createElement("div", { className: "flex items-center gap-2 flex-wrap" }, verResult.status === "success" && /* @__PURE__ */ React.createElement("span", { className: "px-3 py-1 bg-green-600 text-white text-xs font-bold rounded-full" }, "✓ SUCCESS"), verResult.status === "partial" && /* @__PURE__ */ React.createElement("span", { className: "px-3 py-1 bg-yellow-500 text-gray-900 text-xs font-bold rounded-full" }, "⚠ PARTIAL SUCCESS"), verResult.status === "failed" && /* @__PURE__ */ React.createElement("span", { className: "px-3 py-1 bg-red-600 text-white text-xs font-bold rounded-full" }, "✗ FAILED"), verResult.status === "error" && /* @__PURE__ */ React.createElement("span", { className: "px-3 py-1 bg-gray-600 text-white text-xs font-bold rounded-full" }, "⚠ ERROR")), /* @__PURE__ */ React.createElement("span", { className: `text-xs ${isDarkTheme ? "text-gray-400" : "text-gray-500"}` }, new Date(verResult.timestamp).toLocaleString())), /* @__PURE__ */ React.createElement("p", { className: `mt-3 text-sm leading-6 ${verificationResultTextClass}` }, verResult.message), verResult.metrics && /* @__PURE__ */ React.createElement("div", { className: `${taskNestedSurfaceClass} mt-4 p-3` }, /* @__PURE__ */ React.createElement("h6", { className: `text-xs font-semibold uppercase tracking-wide ${isDarkTheme ? "text-gray-300" : "text-gray-600"}` }, "Metrics"), /* @__PURE__ */ React.createElement("div", { className: "mt-3 grid gap-3 text-xs md:grid-cols-2" }, verResult.metrics.current_value && /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("span", { className: `${isDarkTheme ? "text-gray-400" : "text-gray-500"}` }, "Current:"), /* @__PURE__ */ React.createElement("div", { className: `mt-1 font-medium leading-5 ${isDarkTheme ? "text-gray-100" : "text-gray-900"}` }, verResult.metrics.current_value)), verResult.metrics.expected_value && /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("span", { className: `${isDarkTheme ? "text-gray-400" : "text-gray-500"}` }, "Expected:"), /* @__PURE__ */ React.createElement("div", { className: `mt-1 font-medium leading-5 ${isDarkTheme ? "text-gray-100" : "text-gray-900"}` }, verResult.metrics.expected_value)), verResult.metrics.gap && /* @__PURE__ */ React.createElement("div", { className: "md:col-span-2" }, /* @__PURE__ */ React.createElement("span", { className: `${isDarkTheme ? "text-gray-400" : "text-gray-500"}` }, "Gap:"), /* @__PURE__ */ React.createElement("div", { className: `mt-1 font-medium leading-5 ${isDarkTheme ? "text-amber-200" : "text-orange-700"}` }, verResult.metrics.gap)))), verResult.recommendations && verResult.recommendations.length > 0 && /* @__PURE__ */ React.createElement("div", { className: `${taskNestedSurfaceClass} mt-4 p-3` }, /* @__PURE__ */ React.createElement("h6", { className: `text-xs font-semibold uppercase tracking-wide flex items-center ${isDarkTheme ? "text-gray-300" : "text-gray-600"}` }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-lightbulb mr-2 text-yellow-500" }), "Recommendations"), /* @__PURE__ */ React.createElement("ul", { className: "mt-3 space-y-2" }, verResult.recommendations.map((rec, rIdx) => /* @__PURE__ */ React.createElement("li", { key: rIdx, className: `text-xs flex items-start leading-5 ${isDarkTheme ? "text-gray-200" : "text-gray-700"}` }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-arrow-right mr-2 mt-0.5 text-blue-500" }), /* @__PURE__ */ React.createElement("span", null, rec))))), (verResult.status === "failed" || verResult.status === "partial") && /* @__PURE__ */ React.createElement("div", { className: "mt-4 flex flex-wrap gap-2" }, /* @__PURE__ */ React.createElement(
            "button",
            {
              onClick: () => getRemediation(currentSessionId, taskIndex, task, verResult),
              disabled: loadingRemediation === taskIndex,
              className: "flex-1 min-w-[180px] px-3 py-2 bg-indigo-600 hover:bg-indigo-700 text-white text-xs font-medium rounded disabled:opacity-50 disabled:cursor-not-allowed"
            },
            loadingRemediation === taskIndex ? /* @__PURE__ */ React.createElement(React.Fragment, null, /* @__PURE__ */ React.createElement("i", { className: "fas fa-spinner fa-spin mr-1" }), "Analyzing...") : /* @__PURE__ */ React.createElement(React.Fragment, null, /* @__PURE__ */ React.createElement("i", { className: "fas fa-wrench mr-1" }), "Get Remediation Help")
          ), /* @__PURE__ */ React.createElement(
            "button",
            {
              onClick: () => runVerification(currentSessionId, taskIndex, task),
              disabled: verifyingTask === taskIndex,
              className: "px-3 py-2 bg-green-600 hover:bg-green-700 text-white text-xs font-medium rounded disabled:opacity-50 disabled:cursor-not-allowed"
            },
            /* @__PURE__ */ React.createElement("i", { className: "fas fa-redo mr-1" }),
            "Re-verify"
          ), /* @__PURE__ */ React.createElement(
            "button",
            {
              onClick: () => {
                loadVerificationHistory(currentSessionId, taskIndex);
                setShowHistory(showHistory === taskIndex ? null : taskIndex);
              },
              className: "px-3 py-2 bg-gray-600 hover:bg-gray-700 text-white text-xs font-medium rounded"
            },
            /* @__PURE__ */ React.createElement("i", { className: "fas fa-history mr-1" }),
            "History"
          )), verResult.status === "success" && /* @__PURE__ */ React.createElement("div", { className: "mt-4 flex flex-wrap gap-2" }, /* @__PURE__ */ React.createElement(
            "button",
            {
              onClick: () => {
                loadVerificationHistory(currentSessionId, taskIndex);
                setShowHistory(showHistory === taskIndex ? null : taskIndex);
              },
              className: "px-3 py-2 bg-gray-600 hover:bg-gray-700 text-white text-xs font-medium rounded"
            },
            /* @__PURE__ */ React.createElement("i", { className: "fas fa-history mr-1" }),
            "View History"
          )), (() => {
            var _a3, _b3;
            const remediation = remediationData[`${currentSessionId}_task${taskIndex}`];
            if (!remediation) return null;
            return /* @__PURE__ */ React.createElement("div", { className: `mt-4 rounded-xl border p-4 fade-in ${isDarkTheme ? "border-indigo-700 bg-gradient-to-r from-purple-950 via-indigo-950 to-slate-950" : "border-indigo-200 bg-gradient-to-r from-purple-50 to-indigo-50"}` }, /* @__PURE__ */ React.createElement("h6", { className: `text-sm font-bold mb-3 flex items-center ${isDarkTheme ? "text-indigo-100" : "text-indigo-900"}` }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-magic mr-2" }), "AI-Powered Remediation Guide"), /* @__PURE__ */ React.createElement("div", { className: `${taskNestedSurfaceClass} p-3 mb-3` }, /* @__PURE__ */ React.createElement("div", { className: `text-xs font-semibold mb-1 flex items-center ${isDarkTheme ? "text-gray-300" : "text-gray-700"}` }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-search mr-1 text-red-600" }), "Root Cause"), /* @__PURE__ */ React.createElement("p", { className: `text-xs leading-5 ${isDarkTheme ? "text-gray-200" : "text-gray-800"}` }, remediation.root_cause)), /* @__PURE__ */ React.createElement("div", { className: `${taskNestedSurfaceClass} p-3 mb-3` }, /* @__PURE__ */ React.createElement("div", { className: `text-xs font-semibold mb-2 flex items-center ${isDarkTheme ? "text-gray-300" : "text-gray-700"}` }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-list-ol mr-1 text-green-600" }), "Remediation Steps"), /* @__PURE__ */ React.createElement("div", { className: "space-y-3" }, (_a3 = remediation.remediation_steps) == null ? void 0 : _a3.map((step, sIdx) => {
              var _a4;
              return /* @__PURE__ */ React.createElement("div", { key: sIdx, className: `border-l-2 pl-3 ${isDarkTheme ? "border-indigo-500" : "border-indigo-300"}` }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-col gap-2 sm:flex-row sm:items-start sm:justify-between" }, /* @__PURE__ */ React.createElement("span", { className: `text-xs font-medium leading-5 ${isDarkTheme ? "text-gray-100" : "text-gray-900"}` }, step.number, ". ", step.action), /* @__PURE__ */ React.createElement("span", { className: `px-2 py-0.5 text-xs rounded self-start ${step.risk === "low" ? "bg-green-100 text-green-800" : step.risk === "medium" ? "bg-yellow-100 text-yellow-800" : "bg-red-100 text-red-800"}` }, (_a4 = step.risk) == null ? void 0 : _a4.toUpperCase(), " RISK")), step.explanation && /* @__PURE__ */ React.createElement("p", { className: `mt-2 text-xs leading-5 ${isDarkTheme ? "text-gray-300" : "text-gray-600"}` }, step.explanation), step.spl && /* @__PURE__ */ React.createElement("pre", { className: "mt-2 max-h-40 overflow-auto rounded bg-gray-950 p-2 text-xs font-mono text-green-400" }, step.spl));
            }))), /* @__PURE__ */ React.createElement("div", { className: "grid gap-2 text-xs sm:grid-cols-2" }, /* @__PURE__ */ React.createElement("div", { className: `${taskNestedSurfaceClass} p-3` }, /* @__PURE__ */ React.createElement("span", { className: `${isDarkTheme ? "text-gray-400" : "text-gray-500"}` }, "Estimated Time:"), /* @__PURE__ */ React.createElement("div", { className: `mt-1 font-medium ${isDarkTheme ? "text-gray-100" : "text-gray-900"}` }, remediation.estimated_time)), /* @__PURE__ */ React.createElement("div", { className: `${taskNestedSurfaceClass} p-3` }, /* @__PURE__ */ React.createElement("span", { className: `${isDarkTheme ? "text-gray-400" : "text-gray-500"}` }, "Success Probability:"), /* @__PURE__ */ React.createElement("div", { className: `mt-1 font-medium ${remediation.success_probability === "high" ? "text-green-600" : remediation.success_probability === "medium" ? "text-yellow-600" : "text-red-600"}` }, (_b3 = remediation.success_probability) == null ? void 0 : _b3.toUpperCase()))), remediation.preventive_measures && remediation.preventive_measures.length > 0 && /* @__PURE__ */ React.createElement("details", { className: `${taskNestedSurfaceClass} mt-3 p-3` }, /* @__PURE__ */ React.createElement("summary", { className: `text-xs font-semibold cursor-pointer ${isDarkTheme ? "text-gray-300" : "text-gray-700"}` }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-shield-alt mr-1 text-blue-600" }), "Preventive Measures"), /* @__PURE__ */ React.createElement("ul", { className: "mt-2 space-y-1" }, remediation.preventive_measures.map((measure, mIdx) => /* @__PURE__ */ React.createElement("li", { key: mIdx, className: `text-xs flex items-start leading-5 ${isDarkTheme ? "text-gray-200" : "text-gray-700"}` }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-check-circle mr-2 mt-0.5 text-green-500" }), /* @__PURE__ */ React.createElement("span", null, measure))))));
          })(), showHistory === taskIndex && (() => {
            var _a3;
            const history = verificationHistory[`${currentSessionId}_task${taskIndex}`];
            if (!history) {
              return /* @__PURE__ */ React.createElement("div", { className: `mt-4 text-xs ${isDarkTheme ? "text-gray-400" : "text-gray-500"}` }, "Loading history...");
            }
            return /* @__PURE__ */ React.createElement("div", { className: `${taskNestedSurfaceClass} mt-4 p-4 fade-in` }, /* @__PURE__ */ React.createElement("h6", { className: `text-sm font-bold mb-3 flex items-center justify-between ${isDarkTheme ? "text-gray-100" : "text-gray-900"}` }, /* @__PURE__ */ React.createElement("span", null, /* @__PURE__ */ React.createElement("i", { className: "fas fa-history mr-2" }), "Verification History"), /* @__PURE__ */ React.createElement(
              "button",
              {
                onClick: () => setShowHistory(null),
                className: `${isDarkTheme ? "text-gray-400 hover:text-gray-200" : "text-gray-500 hover:text-gray-700"}`
              },
              /* @__PURE__ */ React.createElement("i", { className: "fas fa-times" })
            )), /* @__PURE__ */ React.createElement("div", { className: "grid gap-2 mb-3 sm:grid-cols-2 lg:grid-cols-4" }, /* @__PURE__ */ React.createElement("div", { className: `${taskNestedSurfaceClass} p-3 text-center` }, /* @__PURE__ */ React.createElement("div", { className: "text-lg font-bold text-blue-600" }, history.total_attempts), /* @__PURE__ */ React.createElement("div", { className: `text-xs ${isDarkTheme ? "text-gray-400" : "text-gray-600"}` }, "Attempts")), /* @__PURE__ */ React.createElement("div", { className: `${taskNestedSurfaceClass} p-3 text-center` }, /* @__PURE__ */ React.createElement("div", { className: "text-lg font-bold text-green-600" }, history.successful_attempts), /* @__PURE__ */ React.createElement("div", { className: `text-xs ${isDarkTheme ? "text-gray-400" : "text-gray-600"}` }, "Successful")), /* @__PURE__ */ React.createElement("div", { className: `${taskNestedSurfaceClass} p-3 text-center` }, /* @__PURE__ */ React.createElement("div", { className: "text-lg font-bold text-purple-600" }, Math.round(history.success_rate * 100), "%"), /* @__PURE__ */ React.createElement("div", { className: `text-xs ${isDarkTheme ? "text-gray-400" : "text-gray-600"}` }, "Success Rate")), /* @__PURE__ */ React.createElement("div", { className: `${taskNestedSurfaceClass} p-3 text-center` }, /* @__PURE__ */ React.createElement("div", { className: `text-lg font-bold ${history.improvement_trend === "improving" ? "text-green-600" : history.improvement_trend === "stable" ? "text-blue-600" : "text-red-600"}` }, history.improvement_trend === "improving" ? "↑" : history.improvement_trend === "stable" ? "→" : "↓"), /* @__PURE__ */ React.createElement("div", { className: `text-xs ${isDarkTheme ? "text-gray-400" : "text-gray-600"}` }, "Trend"))), history.time_to_success && /* @__PURE__ */ React.createElement("div", { className: `rounded-lg border p-2 mb-3 text-xs ${isDarkTheme ? "bg-green-950/40 border-green-700 text-green-200" : "bg-green-100 border-green-300 text-green-800"}` }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-clock mr-1" }), "Time to success: ", /* @__PURE__ */ React.createElement("span", { className: "font-semibold" }, history.time_to_success)), /* @__PURE__ */ React.createElement("div", { className: "space-y-2 max-h-64 overflow-y-auto pr-1" }, (_a3 = history.verifications) == null ? void 0 : _a3.map((ver, vIdx) => {
              var _a4;
              return /* @__PURE__ */ React.createElement("div", { key: vIdx, className: `rounded-lg p-3 border-l-4 ${ver.status === "success" ? isDarkTheme ? "bg-green-950/30 border-green-500" : "bg-green-50 border-green-500" : ver.status === "partial" ? isDarkTheme ? "bg-amber-950/30 border-amber-500" : "bg-amber-50 border-amber-500" : isDarkTheme ? "bg-red-950/30 border-red-500" : "bg-red-50 border-red-500"}` }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-col gap-1 sm:flex-row sm:items-center sm:justify-between mb-1" }, /* @__PURE__ */ React.createElement("span", { className: `text-xs font-semibold ${ver.status === "success" ? "text-green-700" : ver.status === "partial" ? "text-yellow-700" : "text-red-700"}` }, "Attempt #", vIdx + 1, " - ", (_a4 = ver.status) == null ? void 0 : _a4.toUpperCase()), /* @__PURE__ */ React.createElement("span", { className: `text-xs ${isDarkTheme ? "text-gray-400" : "text-gray-500"}` }, new Date(ver.timestamp).toLocaleString())), /* @__PURE__ */ React.createElement("p", { className: `text-xs leading-5 ${isDarkTheme ? "text-gray-200" : "text-gray-700"}` }, ver.message));
            })));
          })());
        })()), task.rollback && /* @__PURE__ */ React.createElement("div", { className: `rounded-xl border p-4 ${isDarkTheme ? "border-yellow-700 bg-yellow-950/30" : "border-yellow-200 bg-yellow-50"}` }, /* @__PURE__ */ React.createElement("h5", { className: `font-semibold mb-2 flex items-center text-sm ${isDarkTheme ? "text-yellow-200" : "text-yellow-900"}` }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-undo mr-2" }), "Rollback Instructions"), /* @__PURE__ */ React.createElement("p", { className: `text-sm leading-6 ${isDarkTheme ? "text-yellow-100" : "text-yellow-800"}` }, task.rollback)))))));
      }) : /* @__PURE__ */ React.createElement("div", { className: `rounded-xl border p-8 text-center ${isDarkTheme ? "bg-gray-900 border-gray-700 text-gray-300" : "bg-white border-gray-200 text-gray-600"}` }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-filter text-3xl text-indigo-500 mb-3" }), /* @__PURE__ */ React.createElement("p", { className: "text-base font-semibold" }, "No tasks match the current filter."), /* @__PURE__ */ React.createElement("p", { className: "text-sm mt-2" }, "Switch the task filter to broaden the execution queue.")))) : /* @__PURE__ */ React.createElement("div", { className: "text-center py-20" }, /* @__PURE__ */ React.createElement("div", { className: "inline-block p-6 bg-gradient-to-br from-indigo-50 to-purple-50 rounded-2xl mb-6" }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-tools text-7xl text-indigo-400 mb-4" })), /* @__PURE__ */ React.createElement("h3", { className: "text-3xl font-bold text-gray-800 mb-3" }, "Generating Tasks..."), /* @__PURE__ */ React.createElement("p", { className: "text-lg text-gray-600 mb-6 max-w-2xl mx-auto" }, "Admin tasks are being generated based on your environment analysis")))) : /* @__PURE__ */ React.createElement("div", { className: "text-center text-gray-500 py-12" }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-exclamation-circle text-4xl mb-4" }), /* @__PURE__ */ React.createElement("p", null, "No summary data available")))))
    ), isSettingsOpen && config && /* @__PURE__ */ React.createElement("div", { className: "fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50", onClick: closeSettings }, /* @__PURE__ */ React.createElement("div", { className: `settings-modal-shell rounded-xl shadow-2xl w-full max-w-5xl h-5/6 flex flex-col ${isDarkTheme ? "bg-gray-800" : "bg-white"}`, onClick: (e) => e.stopPropagation(), role: "dialog", "aria-modal": "true", "aria-labelledby": "settings-modal-title", onKeyDown: (event2) => handleDialogKeyDown(event2, closeSettings) }, /* @__PURE__ */ React.createElement("div", { className: `p-6 border-b flex justify-between items-center ${isDarkTheme ? "border-gray-700" : "border-gray-200"}` }, /* @__PURE__ */ React.createElement("div", { className: "flex items-center" }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-cog text-2xl text-indigo-600 mr-3" }), /* @__PURE__ */ React.createElement("h2", { id: "settings-modal-title", className: `text-xl font-semibold ${isDarkTheme ? "text-gray-100" : "text-gray-900"}` }, "Settings")), /* @__PURE__ */ React.createElement("button", { type: "button", onClick: closeSettings, className: `${isDarkTheme ? "text-gray-400 hover:text-gray-200" : "text-gray-500 hover:text-gray-700"}`, "aria-label": "Close settings" }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-times text-xl" }))), /* @__PURE__ */ React.createElement("div", { className: `px-6 py-4 border-b ${isDarkTheme ? "border-gray-700 bg-gray-900" : "border-gray-200 bg-gray-50"}` }, /* @__PURE__ */ React.createElement("div", { className: "flex items-center justify-between mb-3" }, /* @__PURE__ */ React.createElement("h3", { className: `text-sm font-semibold ${isDarkTheme ? "text-gray-100" : "text-gray-900"}` }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-adjust mr-2 text-indigo-600" }), "Appearance Theme"), /* @__PURE__ */ React.createElement("span", { className: `text-xs ${isDarkTheme ? "text-gray-400" : "text-gray-500"}` }, "Active: ", resolvedTheme)), /* @__PURE__ */ React.createElement("div", { className: `inline-flex rounded-lg border overflow-hidden ${isDarkTheme ? "border-gray-600" : "border-gray-300"}`, role: "group", "aria-label": "Theme preference" }, /* @__PURE__ */ React.createElement(
      "button",
      {
        type: "button",
        onClick: () => setThemePreference("light"),
        className: `px-3 py-2 text-xs font-medium ${themePreference === "light" ? "bg-indigo-600 text-white" : isDarkTheme ? "bg-gray-800 text-gray-200 hover:bg-gray-700" : "bg-white text-gray-700 hover:bg-gray-100"}`,
        "aria-pressed": themePreference === "light"
      },
      "Light"
    ), /* @__PURE__ */ React.createElement(
      "button",
      {
        type: "button",
        onClick: () => setThemePreference("dark"),
        className: `px-3 py-2 text-xs font-medium border-l ${themePreference === "dark" ? "bg-indigo-600 text-white border-indigo-500" : isDarkTheme ? "bg-gray-800 text-gray-200 hover:bg-gray-700 border-gray-600" : "bg-white text-gray-700 hover:bg-gray-100 border-gray-300"}`,
        "aria-pressed": themePreference === "dark"
      },
      "Dark"
    ), /* @__PURE__ */ React.createElement(
      "button",
      {
        type: "button",
        onClick: () => setThemePreference("system"),
        className: `px-3 py-2 text-xs font-medium border-l ${themePreference === "system" ? "bg-indigo-600 text-white border-indigo-500" : isDarkTheme ? "bg-gray-800 text-gray-200 hover:bg-gray-700 border-gray-600" : "bg-white text-gray-700 hover:bg-gray-100 border-gray-300"}`,
        "aria-pressed": themePreference === "system"
      },
      "System"
    )), /* @__PURE__ */ React.createElement("p", { className: `text-xs mt-2 ${isDarkTheme ? "text-gray-400" : "text-gray-500"}` }, "System mode follows your OS appearance preference automatically."), /* @__PURE__ */ React.createElement("div", { className: `mt-4 pt-4 border-t ${isDarkTheme ? "border-gray-700" : "border-gray-200"}` }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-col gap-3 md:flex-row md:items-start md:justify-between" }, /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("h3", { className: `text-sm font-semibold ${isDarkTheme ? "text-gray-100" : "text-gray-900"}` }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-door-open mr-2 text-indigo-600" }), "Welcome Splash"), /* @__PURE__ */ React.createElement("p", { className: `mt-1 text-xs ${isDarkTheme ? "text-gray-400" : "text-gray-500"}` }, "Controls the first-run introduction shown when the interface opens in this browser.")), /* @__PURE__ */ React.createElement("span", { className: `inline-flex items-center rounded-full px-2.5 py-1 text-[11px] font-medium border ${hasDismissedWelcomeSplash ? isDarkTheme ? "bg-gray-950 border-emerald-800 text-emerald-200" : "bg-emerald-50 border-emerald-200 text-emerald-800" : isDarkTheme ? "bg-gray-900 border-amber-800 text-amber-200" : "bg-amber-50 border-amber-200 text-amber-800"}` }, hasDismissedWelcomeSplash ? "Hidden after first view" : "Will show on next open")), /* @__PURE__ */ React.createElement("div", { className: "mt-3 flex flex-wrap gap-2" }, /* @__PURE__ */ React.createElement(
      "button",
      {
        type: "button",
        "data-testid": "settings-preview-welcome-splash",
        onClick: previewWelcomeSplash,
        className: `rounded-lg px-3 py-2 text-xs font-medium ${isDarkTheme ? "bg-gray-800 text-gray-100 border border-gray-700 hover:bg-gray-700" : "bg-white text-gray-700 border border-gray-300 hover:bg-gray-50"}`
      },
      /* @__PURE__ */ React.createElement("i", { className: "fas fa-eye mr-2" }),
      "Preview Welcome Splash"
    ), /* @__PURE__ */ React.createElement(
      "button",
      {
        type: "button",
        "data-testid": "settings-reset-welcome-splash",
        onClick: resetWelcomeSplashPreference,
        className: `rounded-lg px-3 py-2 text-xs font-medium ${isDarkTheme ? "bg-indigo-950 text-indigo-100 border border-indigo-800 hover:bg-indigo-900" : "bg-indigo-50 text-indigo-800 border border-indigo-200 hover:bg-indigo-100"}`
      },
      /* @__PURE__ */ React.createElement("i", { className: "fas fa-rotate-left mr-2" }),
      "Reset for Demo"
    )), /* @__PURE__ */ React.createElement("p", { className: `mt-2 text-xs ${isDarkTheme ? "text-gray-400" : "text-gray-500"}` }, "Reset clears the local preference so the welcome screen appears again the next time this browser opens the DT4SMS interface."))), /* @__PURE__ */ React.createElement("div", { className: "flex-1 overflow-y-auto p-6 space-y-6" }, /* @__PURE__ */ React.createElement("div", { className: `rounded-xl border p-2 ${isDarkTheme ? "bg-gray-900 border-gray-700" : "bg-gray-50 border-gray-200"}` }, /* @__PURE__ */ React.createElement("div", { className: "grid gap-2 md:grid-cols-3" }, SETTINGS_MODAL_TABS.map((tab) => {
      const isActive = activeSettingsTab === tab.id;
      return /* @__PURE__ */ React.createElement(
        "button",
        {
          key: `settings-tab-${tab.id}`,
          type: "button",
          onClick: () => setActiveSettingsTab(tab.id),
          className: `flex items-center justify-center gap-2 rounded-lg px-4 py-3 text-sm font-medium transition-colors ${isActive ? "bg-indigo-600 text-white shadow-sm" : isDarkTheme ? "bg-gray-800 text-gray-200 hover:bg-gray-700" : "bg-white text-gray-700 hover:bg-gray-100"}`,
          "aria-pressed": isActive
        },
        /* @__PURE__ */ React.createElement("i", { className: `fas ${tab.icon}` }),
        /* @__PURE__ */ React.createElement("span", null, tab.label)
      );
    }))), renderSecurityAccessSettings(), activeSettingsTab === "connections" && /* @__PURE__ */ React.createElement(React.Fragment, null, /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("div", { className: `rounded-lg p-6 border-2 ${isDarkTheme ? "bg-gray-800 border-green-700" : "bg-gradient-to-r from-green-50 to-emerald-50 border-green-200"}` }, /* @__PURE__ */ React.createElement("div", { className: "mb-4" }, /* @__PURE__ */ React.createElement("h3", { className: "text-lg font-semibold text-gray-900 mb-2" }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-server mr-2 text-green-600" }), "MCP Server Configurations"), /* @__PURE__ */ React.createElement("p", { className: "text-sm text-gray-600" }, "Manage your Splunk MCP server connections")), (loadedMCPConfigName || (config == null ? void 0 : config.active_mcp_config_name)) && /* @__PURE__ */ React.createElement("div", { className: "mb-4 bg-emerald-50 border-l-4 border-emerald-500 rounded-r-lg p-3" }, /* @__PURE__ */ React.createElement("div", { className: "flex items-center justify-between" }, /* @__PURE__ */ React.createElement("div", { className: "flex items-center gap-2" }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-check-circle text-emerald-600" }), /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("p", { className: "text-sm font-semibold text-gray-900" }, "Active Configuration:"), /* @__PURE__ */ React.createElement("p", { className: "text-base font-bold text-gray-800" }, loadedMCPConfigName || (config == null ? void 0 : config.active_mcp_config_name)))), /* @__PURE__ */ React.createElement(
      "button",
      {
        onClick: () => {
          setLoadedMCPConfigName(null);
          setShowMCPConfigForm(false);
        },
        className: "text-emerald-700 hover:text-emerald-900 text-sm font-medium",
        title: "Clear and close editor"
      },
      /* @__PURE__ */ React.createElement("i", { className: "fas fa-times-circle mr-1" }),
      "Close"
    ))), !showMCPConfigForm && /* @__PURE__ */ React.createElement("div", { className: "mb-4" }, /* @__PURE__ */ React.createElement(
      "button",
      {
        onClick: () => {
          setShowMCPConfigForm(true);
          setLoadedMCPConfigName(null);
          setMCPTokenPlaceholder("Enter token");
        },
        className: "w-full px-4 py-3 bg-gradient-to-r from-green-600 to-emerald-600 hover:from-green-700 hover:to-emerald-700 text-white rounded-lg font-bold shadow-md hover:shadow-lg transition-all transform hover:scale-[1.02]"
      },
      /* @__PURE__ */ React.createElement("i", { className: "fas fa-plus-circle mr-2" }),
      "Create New Configuration"
    )), /* @__PURE__ */ React.createElement("div", { id: "mcp-configs-list", className: "space-y-2 max-h-96 overflow-y-auto" }, /* @__PURE__ */ React.createElement("div", { className: "text-sm text-gray-500 text-center py-4 italic" }, "Loading configurations...")))), showMCPConfigForm && /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("div", { className: "flex items-center justify-between mb-3" }, /* @__PURE__ */ React.createElement("h3", { className: "text-lg font-semibold text-gray-900" }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-server mr-2 text-green-600" }), loadedMCPConfigName ? "Edit Configuration" : "New Configuration"), /* @__PURE__ */ React.createElement(
      "button",
      {
        onClick: () => {
          setShowMCPConfigForm(false);
          setLoadedMCPConfigName(null);
        },
        className: "px-3 py-1 text-sm text-gray-600 hover:text-gray-900 hover:bg-gray-100 rounded transition-colors"
      },
      /* @__PURE__ */ React.createElement("i", { className: "fas fa-times mr-1" }),
      "Cancel"
    )), /* @__PURE__ */ React.createElement("div", { className: "space-y-3" }, /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("label", { className: "block text-sm font-medium text-gray-700 mb-1" }, "MCP URL"), /* @__PURE__ */ React.createElement(
      "input",
      {
        type: "text",
        defaultValue: config.mcp.url,
        className: "w-full px-3 py-2 border border-gray-300 rounded-md",
        id: "mcp-url"
      }
    )), /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("label", { className: "block text-sm font-medium text-gray-700 mb-1" }, "Token"), /* @__PURE__ */ React.createElement(
      "input",
      {
        type: "password",
        placeholder: mcpTokenPlaceholder,
        className: "w-full px-3 py-2 border border-gray-300 rounded-md",
        id: "mcp-token",
        onChange: () => setMCPTokenPlaceholder("Enter token")
      }
    )), /* @__PURE__ */ React.createElement("div", { className: "flex items-center" }, /* @__PURE__ */ React.createElement(
      "input",
      {
        type: "checkbox",
        checked: config.mcp.verify_ssl,
        onChange: (e) => setConfig({ ...config, mcp: { ...config.mcp, verify_ssl: e.target.checked } }),
        className: "mr-2",
        id: "mcp-verify-ssl"
      }
    ), /* @__PURE__ */ React.createElement("label", { htmlFor: "mcp-verify-ssl", className: "text-sm text-gray-700" }, "Verify SSL Certificate")), /* @__PURE__ */ React.createElement("div", { className: "pt-3 border-t border-gray-200 space-y-2" }, /* @__PURE__ */ React.createElement(
      "button",
      {
        type: "button",
        onClick: async (event2) => {
          var _a2;
          const urlEl = document.getElementById("mcp-url");
          const tokenEl = document.getElementById("mcp-token");
          const verifySslEl = document.getElementById("mcp-verify-ssl");
          const testUrl = (urlEl == null ? void 0 : urlEl.value) || config.mcp.url;
          const testToken = (tokenEl == null ? void 0 : tokenEl.value) || config.mcp.token;
          const testVerifySsl = (_a2 = verifySslEl == null ? void 0 : verifySslEl.checked) != null ? _a2 : config.mcp.verify_ssl;
          if (!testUrl) {
            alert("Please enter an MCP URL");
            return;
          }
          const button = event2.currentTarget;
          const originalHTML2 = button.innerHTML;
          button.disabled = true;
          button.innerHTML = '<i class="fas fa-spinner fa-spin mr-2"></i>Testing...';
          try {
            const response = await fetch("/api/mcp-configs/test", {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({
                url: testUrl,
                token: testToken,
                verify_ssl: testVerifySsl
              })
            });
            const result = await response.json();
            if (result.status === "success") {
              alert("✅ " + result.message);
            } else {
              alert("⚠️ " + result.message);
            }
          } catch (error) {
            alert("❌ Test failed: " + error.message);
          } finally {
            button.disabled = false;
            button.innerHTML = originalHTML2;
          }
        },
        className: "w-full px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg font-medium shadow-md hover:shadow-lg transition-all"
      },
      /* @__PURE__ */ React.createElement("i", { className: "fas fa-network-wired mr-2" }),
      "Test Connection"
    ), loadedMCPConfigName ? /* @__PURE__ */ React.createElement(React.Fragment, null, /* @__PURE__ */ React.createElement(
      "button",
      {
        onClick: () => {
          setMCPConfigName("");
          setIsMCPSaveModalOpen(true);
        },
        className: "w-full px-4 py-2 bg-green-600 hover:bg-green-700 text-white rounded-lg font-medium shadow-md hover:shadow-lg transition-all"
      },
      /* @__PURE__ */ React.createElement("i", { className: "fas fa-plus-circle mr-2" }),
      "Save as New"
    ), /* @__PURE__ */ React.createElement(
      "button",
      {
        onClick: () => {
          setMCPConfigName(loadedMCPConfigName);
          setIsMCPSaveModalOpen(true);
        },
        className: "w-full px-4 py-2 bg-gradient-to-r from-amber-500 to-yellow-500 hover:from-amber-600 hover:to-yellow-600 text-gray-900 rounded-lg font-bold border-2 border-amber-600 shadow-md hover:shadow-lg transition-all"
      },
      /* @__PURE__ */ React.createElement("i", { className: "fas fa-sync-alt mr-2" }),
      "Update Active Configuration"
    )) : /* @__PURE__ */ React.createElement(
      "button",
      {
        onClick: () => {
          setMCPConfigName("");
          setIsMCPSaveModalOpen(true);
        },
        className: "w-full px-4 py-2 bg-gradient-to-r from-green-600 to-emerald-600 hover:from-green-700 hover:to-emerald-700 text-white rounded-lg font-bold shadow-md hover:shadow-lg transition-all"
      },
      /* @__PURE__ */ React.createElement("i", { className: "fas fa-save mr-2" }),
      "Save as New Configuration"
    )))), /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("div", { className: `rounded-lg p-6 border-2 ${isDarkTheme ? "bg-gray-800 border-purple-700" : "bg-gradient-to-r from-purple-50 to-indigo-50 border-purple-200"}` }, /* @__PURE__ */ React.createElement("div", { className: "mb-4" }, /* @__PURE__ */ React.createElement("h3", { className: "text-lg font-semibold text-gray-900 mb-2" }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-key mr-2 text-purple-600" }), "LLM Credentials"), /* @__PURE__ */ React.createElement("p", { className: "text-sm text-gray-600" }, "Manage your AI model connections")), (loadedCredentialName || (config == null ? void 0 : config.active_credential_name)) && /* @__PURE__ */ React.createElement("div", { className: "mb-4 bg-amber-50 border-l-4 border-amber-500 rounded-r-lg p-3" }, /* @__PURE__ */ React.createElement("div", { className: "flex items-center justify-between" }, /* @__PURE__ */ React.createElement("div", { className: "flex items-center gap-2" }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-check-circle text-amber-600" }), /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("p", { className: "text-sm font-semibold text-gray-900" }, "Active Connection:"), /* @__PURE__ */ React.createElement("p", { className: "text-base font-bold text-gray-800" }, loadedCredentialName || (config == null ? void 0 : config.active_credential_name)))), /* @__PURE__ */ React.createElement(
      "button",
      {
        onClick: () => {
          setLoadedCredentialName(null);
          setShowConfigForm(false);
        },
        className: "text-amber-600 hover:text-amber-800 text-sm font-medium",
        title: "Clear and close editor"
      },
      /* @__PURE__ */ React.createElement("i", { className: "fas fa-times-circle mr-1" }),
      "Close"
    ))), !showConfigForm && /* @__PURE__ */ React.createElement("div", { className: "mb-4" }, /* @__PURE__ */ React.createElement(
      "button",
      {
        onClick: () => {
          setShowConfigForm(true);
          setLoadedCredentialName(null);
          setApiKeyPlaceholder("Enter API key");
        },
        className: "w-full px-4 py-3 bg-gradient-to-r from-purple-600 to-indigo-600 hover:from-purple-700 hover:to-indigo-700 text-white rounded-lg font-bold shadow-md hover:shadow-lg transition-all transform hover:scale-[1.02]"
      },
      /* @__PURE__ */ React.createElement("i", { className: "fas fa-plus-circle mr-2" }),
      "Create New Connection"
    )), /* @__PURE__ */ React.createElement("div", { id: "credentials-list", className: "space-y-2 max-h-96 overflow-y-auto" }, /* @__PURE__ */ React.createElement("div", { className: "text-sm text-gray-500 text-center py-4 italic" }, "Loading credentials...")))), showConfigForm && /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("div", { className: "flex items-center justify-between mb-3" }, /* @__PURE__ */ React.createElement("h3", { className: "text-lg font-semibold text-gray-900" }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-brain mr-2 text-purple-600" }), loadedCredentialName ? "Edit Connection" : "New Connection"), /* @__PURE__ */ React.createElement(
      "button",
      {
        onClick: () => {
          setShowConfigForm(false);
          setLoadedCredentialName(null);
        },
        className: "px-3 py-1 text-sm text-gray-600 hover:text-gray-900 hover:bg-gray-100 rounded transition-colors"
      },
      /* @__PURE__ */ React.createElement("i", { className: "fas fa-times mr-1" }),
      "Cancel"
    )), /* @__PURE__ */ React.createElement("div", { className: "space-y-3" }, /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("label", { className: "block text-sm font-medium text-gray-700 mb-1" }, "Provider"), /* @__PURE__ */ React.createElement(
      "select",
      {
        value: selectedProvider,
        className: "w-full px-3 py-2 border border-gray-300 rounded-md",
        id: "llm-provider",
        onChange: (e) => {
          setSelectedProvider(e.target.value);
          handleSettingsChange();
        }
      },
      /* @__PURE__ */ React.createElement("option", { value: "openai" }, "OpenAI"),
      /* @__PURE__ */ React.createElement("option", { value: "azure" }, "Azure OpenAI"),
      /* @__PURE__ */ React.createElement("option", { value: "anthropic" }, "Anthropic (Claude)"),
      /* @__PURE__ */ React.createElement("option", { value: "gemini" }, "Google Gemini"),
      /* @__PURE__ */ React.createElement("option", { value: "custom" }, "Custom Endpoint")
    )), selectedProvider !== "openai" && /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("label", { className: "block text-sm font-medium text-gray-700 mb-1" }, "Endpoint URL", /* @__PURE__ */ React.createElement("span", { className: "ml-2 text-xs text-gray-500" }, "(", selectedProvider === "custom" ? "used exactly as configured" : "base URL or full API path", ")")), /* @__PURE__ */ React.createElement(
      "input",
      {
        type: "text",
        defaultValue: config.llm.endpoint_url || "",
        placeholder: selectedProvider === "azure" ? "https://YOUR-RESOURCE.openai.azure.com" : selectedProvider === "anthropic" ? "https://api.anthropic.com (optional)" : selectedProvider === "gemini" ? "https://generativelanguage.googleapis.com (optional)" : "http://localhost:8000/v1/chat/completions",
        className: "w-full px-3 py-2 border border-gray-300 rounded-md",
        id: "llm-endpoint-url",
        onChange: handleSettingsChange
      }
    ), selectedProvider === "custom" && /* @__PURE__ */ React.createElement("p", { className: "mt-1 text-xs text-gray-500" }, "✅ ", /* @__PURE__ */ React.createElement("strong", null, "Full API Path (Recommended):"), " ", /* @__PURE__ */ React.createElement("span", { className: "font-mono" }, "http://localhost:8000/v1/chat/completions"), /* @__PURE__ */ React.createElement("br", null), "⚠️ ", /* @__PURE__ */ React.createElement("strong", null, "Base URL (Slower):"), " ", /* @__PURE__ */ React.createElement("span", { className: "font-mono" }, "http://localhost:8000"), " - requires auto-detection", /* @__PURE__ */ React.createElement("br", null), /* @__PURE__ */ React.createElement("span", { className: "italic" }, "URL is used exactly as entered. No automatic path manipulation."))), /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("label", { className: "block text-sm font-medium text-gray-700 mb-1" }, "API Key", selectedProvider === "custom" && /* @__PURE__ */ React.createElement("span", { className: "ml-2 text-xs text-gray-500" }, "(Optional for local LLMs)")), /* @__PURE__ */ React.createElement(
      "input",
      {
        type: "password",
        placeholder: apiKeyPlaceholder,
        className: "w-full px-3 py-2 border border-gray-300 rounded-md",
        id: "llm-api-key",
        onChange: handleApiKeyChange
      }
    )), /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("label", { className: "block text-sm font-medium text-gray-700 mb-1" }, "Model", /* @__PURE__ */ React.createElement(
      "button",
      {
        onClick: async () => {
          var _a2;
          setIsLoadingModels(true);
          try {
            const provider = document.getElementById("llm-provider").value;
            const apiKey = document.getElementById("llm-api-key").value;
            const endpointUrl = (_a2 = document.getElementById("llm-endpoint-url")) == null ? void 0 : _a2.value;
            const response = await fetch("/api/llm/list-models", {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({
                provider,
                api_key: apiKey,
                endpoint_url: endpointUrl
              })
            });
            if (response.ok) {
              const data = await response.json();
              setAvailableModels(data.models);
              if (data.models.length > 0) {
                setSelectedModel(data.models[0]);
              }
            } else {
              const error = await response.json();
              alert("Failed to fetch models: " + error.detail);
            }
          } catch (error) {
            alert("Error fetching models: " + error.message);
          } finally {
            setIsLoadingModels(false);
          }
        },
        className: "ml-2 px-2 py-1 text-xs bg-purple-100 hover:bg-purple-200 text-purple-700 rounded disabled:opacity-50",
        disabled: isLoadingModels,
        type: "button"
      },
      /* @__PURE__ */ React.createElement("i", { className: `fas ${isLoadingModels ? "fa-spinner fa-spin" : "fa-download"}` }),
      " ",
      isLoadingModels ? "Fetching..." : "Fetch Models"
    )), availableModels.length > 0 ? /* @__PURE__ */ React.createElement(
      "select",
      {
        value: selectedModel,
        onChange: (e) => {
          setSelectedModel(e.target.value);
          handleSettingsChange();
        },
        className: "w-full px-3 py-2 border border-gray-300 rounded-md",
        id: "llm-model"
      },
      availableModels.map((model) => /* @__PURE__ */ React.createElement("option", { key: model, value: model }, model))
    ) : /* @__PURE__ */ React.createElement(
      "input",
      {
        type: "text",
        defaultValue: config.llm.model,
        placeholder: selectedProvider === "openai" ? "gpt-4o" : selectedProvider === "azure" ? "your-azure-deployment-name" : selectedProvider === "anthropic" ? "claude-3-5-sonnet-latest" : selectedProvider === "gemini" ? "gemini-1.5-pro" : "e.g., llama3.2:3b",
        className: "w-full px-3 py-2 border border-gray-300 rounded-md",
        id: "llm-model",
        onChange: (e) => {
          setSelectedModel(e.target.value);
          handleSettingsChange();
        }
      }
    ), selectedProvider !== "openai" && /* @__PURE__ */ React.createElement("p", { className: "mt-1 text-xs text-gray-500 italic" }, 'Tip: Click "Fetch Models" to query provider model/deployment inventory where supported')), /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("label", { className: "block text-sm font-medium text-gray-700 mb-1" }, "Max Tokens", /* @__PURE__ */ React.createElement(
      "button",
      {
        onClick: async (event2) => {
          var _a2, _b2, _c2, _d2;
          const btn = event2.currentTarget;
          btn.disabled = true;
          btn.innerHTML = '<i className="fas fa-spinner fa-spin"></i> Testing...';
          try {
            const provider = ((_a2 = document.getElementById("llm-provider")) == null ? void 0 : _a2.value) || selectedProvider;
            const model = ((_b2 = document.getElementById("llm-model")) == null ? void 0 : _b2.value) || selectedModel || config.llm.model;
            const apiKey = ((_c2 = document.getElementById("llm-api-key")) == null ? void 0 : _c2.value) || void 0;
            const endpointUrl = ((_d2 = document.getElementById("llm-endpoint-url")) == null ? void 0 : _d2.value) || void 0;
            const response = await fetch("/api/llm/assess-max-tokens", {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({
                llm: {
                  provider,
                  api_key: apiKey,
                  model,
                  endpoint_url: endpointUrl
                }
              })
            });
            const result = await response.json();
            if (Number.isFinite(result.recommended_max_tokens)) {
              document.getElementById("llm-max-tokens").value = result.recommended_max_tokens;
            }
            btn.innerHTML = result.applicable === false ? '<i className="fas fa-image"></i> Not Required' : '<i className="fas fa-check"></i> Done';
            setTimeout(() => {
              btn.disabled = isOpenAIImageModelSelected;
              btn.innerHTML = isOpenAIImageModelSelected ? '<i className="fas fa-image"></i> Not Used' : '<i className="fas fa-magic"></i> Auto-Assess';
            }, 2e3);
          } catch (error) {
            btn.innerHTML = '<i className="fas fa-times"></i> Failed';
            setTimeout(() => {
              btn.disabled = isOpenAIImageModelSelected;
              btn.innerHTML = isOpenAIImageModelSelected ? '<i className="fas fa-image"></i> Not Used' : '<i className="fas fa-magic"></i> Auto-Assess';
            }, 2e3);
          }
        },
        className: "ml-2 px-2 py-1 text-xs bg-indigo-100 hover:bg-indigo-200 text-indigo-700 rounded disabled:opacity-50 disabled:cursor-not-allowed",
        disabled: isOpenAIImageModelSelected
      },
      /* @__PURE__ */ React.createElement("i", { className: `fas ${isOpenAIImageModelSelected ? "fa-image" : "fa-magic"}` }),
      " ",
      isOpenAIImageModelSelected ? "Not Used" : "Auto-Assess"
    )), /* @__PURE__ */ React.createElement(
      "input",
      {
        type: "number",
        defaultValue: config.llm.max_tokens,
        className: "w-full px-3 py-2 border border-gray-300 rounded-md",
        id: "llm-max-tokens",
        onChange: handleSettingsChange,
        disabled: isOpenAIImageModelSelected
      }
    ), isOpenAIImageModelSelected && /* @__PURE__ */ React.createElement("p", { className: "mt-1 text-xs text-amber-700" }, "gpt-image-2 uses the OpenAI images API. max_tokens is ignored for summary infographic generation, and text-generation features still require a text-capable model.")), /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("label", { className: "block text-sm font-medium text-gray-700 mb-1" }, "Temperature"), /* @__PURE__ */ React.createElement(
      "input",
      {
        type: "number",
        step: "0.1",
        defaultValue: config.llm.temperature,
        className: "w-full px-3 py-2 border border-gray-300 rounded-md",
        id: "llm-temperature",
        onChange: handleSettingsChange
      }
    )), /* @__PURE__ */ React.createElement("div", { className: "pt-3 border-t border-gray-200" }, /* @__PURE__ */ React.createElement(
      "button",
      {
        onClick: async () => {
          const btn = event.target;
          const resultsDiv = document.getElementById("llm-test-results");
          btn.disabled = true;
          btn.innerHTML = '<i className="fas fa-spinner fa-spin mr-2"></i> Testing Connection...';
          resultsDiv.innerHTML = '<div className="text-blue-600"><i className="fas fa-spinner fa-spin mr-2"></i> Running tests...</div>';
          resultsDiv.style.display = "block";
          try {
            const provider = document.getElementById("llm-provider").value;
            const endpointUrlInput = document.getElementById("llm-endpoint-url");
            await fetch("/api/config", {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({
                llm: {
                  provider,
                  api_key: document.getElementById("llm-api-key").value || void 0,
                  model: document.getElementById("llm-model").value,
                  endpoint_url: provider !== "openai" && endpointUrlInput ? endpointUrlInput.value : void 0,
                  max_tokens: parseInt(document.getElementById("llm-max-tokens").value),
                  temperature: parseFloat(document.getElementById("llm-temperature").value)
                }
              })
            });
            const response = await fetch("/api/llm/test-connection", {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({
                llm: {
                  provider,
                  api_key: document.getElementById("llm-api-key").value || void 0,
                  model: document.getElementById("llm-model").value,
                  endpoint_url: provider !== "openai" && endpointUrlInput ? endpointUrlInput.value : void 0,
                  max_tokens: parseInt(document.getElementById("llm-max-tokens").value),
                  temperature: parseFloat(document.getElementById("llm-temperature").value)
                }
              })
            });
            const result = await response.json();
            let html = '<div className="space-y-2">';
            if (result.url_cleaned && result.original_endpoint) {
              html += '<div className="bg-blue-100 border border-blue-300 rounded-lg p-3 mb-2">';
              html += '<div className="font-semibold text-blue-800"><i className="fas fa-info-circle mr-2"></i>Endpoint URL Cleaned</div>';
              html += '<div className="text-xs text-blue-700 mt-1">';
              html += "Removed API path from endpoint URL for proper testing.<br>";
              html += '<span className="font-mono">From: ' + result.original_endpoint + "</span><br>";
              html += '<span className="font-mono">To: ' + result.endpoint + "</span><br>";
              html += '<span className="italic mt-1">Tip: Enter only the base URL (e.g., http://localhost:8000)</span>';
              html += "</div>";
              html += "</div>";
            }
            if (result.status === "success") {
              html += '<div className="bg-green-100 border border-green-300 rounded-lg p-3 mb-2">';
              html += '<div className="font-semibold text-green-800"><i className="fas fa-check-circle mr-2"></i>All Tests Passed!</div>';
              html += '<div className="text-sm text-green-700 mt-1">' + result.message + "</div>";
              html += "</div>";
              if (result.recommended_config && Number.isFinite(result.recommended_config.max_tokens)) {
                document.getElementById("llm-max-tokens").value = result.recommended_config.max_tokens;
              }
            } else if (result.status === "error") {
              html += '<div className="bg-red-100 border border-red-300 rounded-lg p-3 mb-2">';
              html += '<div className="font-semibold text-red-800"><i className="fas fa-times-circle mr-2"></i>Test Failed</div>';
              html += '<div className="text-sm text-red-700 mt-1">' + (result.message || result.error) + "</div>";
              html += "</div>";
            }
            html += '<div className="text-xs font-semibold text-gray-700 mb-1">Test Details:</div>';
            for (const [testName, testResult] of Object.entries(result.tests || {})) {
              const statusIcon = testResult.status === "success" ? "check" : testResult.status === "error" ? "times" : testResult.status === "warning" ? "exclamation-triangle" : "info-circle";
              const statusColor = testResult.status === "success" ? "green" : testResult.status === "error" ? "red" : testResult.status === "warning" ? "yellow" : "blue";
              html += `<div className="bg-${statusColor}-50 border border-${statusColor}-200 rounded p-2 mb-1">`;
              html += `<div className="text-xs font-medium text-${statusColor}-800">`;
              html += `<i className="fas fa-${statusIcon} mr-1"></i>${testName.charAt(0).toUpperCase() + testName.slice(1)}: ${testResult.message}`;
              html += "</div>";
              if (testResult.response_preview) {
                html += `<div className="text-xs text-gray-600 mt-1 italic">"${testResult.response_preview}"</div>`;
              }
              html += "</div>";
            }
            html += "</div>";
            resultsDiv.innerHTML = html;
            btn.innerHTML = '<i className="fas fa-check mr-2"></i> Test Complete';
            setTimeout(() => {
              btn.disabled = false;
              btn.innerHTML = '<i className="fas fa-plug mr-2"></i> Test Connection & Auto-Configure';
            }, 3e3);
          } catch (error) {
            resultsDiv.innerHTML = `<div className="bg-red-100 border border-red-300 rounded-lg p-3">
                                                                <div className="font-semibold text-red-800"><i className="fas fa-times-circle mr-2"></i>Error</div>
                                                                <div className="text-sm text-red-700 mt-1">${error.message}</div>
                                                            </div>`;
            btn.innerHTML = '<i className="fas fa-times mr-2"></i> Test Failed';
            setTimeout(() => {
              btn.disabled = false;
              btn.innerHTML = '<i className="fas fa-plug mr-2"></i> Test Connection & Auto-Configure';
            }, 3e3);
          }
        },
        className: "w-full px-4 py-2 bg-purple-600 hover:bg-purple-700 text-white rounded-lg font-medium"
      },
      /* @__PURE__ */ React.createElement("i", { className: "fas fa-plug mr-2" }),
      " Test Connection & Auto-Configure"
    ), /* @__PURE__ */ React.createElement("div", { id: "llm-test-results", className: "mt-3", style: { display: "none" } }), /* @__PURE__ */ React.createElement("div", { className: "mt-3 pt-3 border-t border-gray-200 space-y-2" }, loadedCredentialName ? /* @__PURE__ */ React.createElement(React.Fragment, null, /* @__PURE__ */ React.createElement(
      "button",
      {
        onClick: () => {
          setIsUpdateMode(false);
          setCredentialName("");
          setIsCredentialModalOpen(true);
        },
        className: "w-full px-4 py-2 bg-purple-600 hover:bg-purple-700 text-white rounded-lg font-medium shadow-md hover:shadow-lg transition-all"
      },
      /* @__PURE__ */ React.createElement("i", { className: "fas fa-plus-circle mr-2" }),
      "Save as New"
    ), /* @__PURE__ */ React.createElement(
      "button",
      {
        onClick: () => {
          setIsUpdateMode(true);
          setCredentialName(loadedCredentialName);
          setIsCredentialModalOpen(true);
        },
        className: "w-full px-4 py-2 bg-gradient-to-r from-amber-500 to-yellow-500 hover:from-amber-600 hover:to-yellow-600 text-gray-900 rounded-lg font-bold border-2 border-amber-600 shadow-md hover:shadow-lg transition-all"
      },
      /* @__PURE__ */ React.createElement("i", { className: "fas fa-sync-alt mr-2" }),
      "Update Active Connection"
    )) : /* @__PURE__ */ React.createElement(
      "button",
      {
        onClick: () => {
          setIsUpdateMode(false);
          setCredentialName("");
          setIsCredentialModalOpen(true);
        },
        className: "w-full px-4 py-2 bg-purple-600 hover:bg-purple-700 text-white rounded-lg font-medium shadow-md hover:shadow-lg transition-all"
      },
      /* @__PURE__ */ React.createElement("i", { className: "fas fa-save mr-2" }),
      "Save Connection"
    ))))))), /* @__PURE__ */ React.createElement("div", { className: `p-6 border-t ${isDarkTheme ? "border-gray-700 bg-gray-900" : "border-gray-200 bg-gray-50"}` }, /* @__PURE__ */ React.createElement("div", { className: "flex justify-between items-center" }, /* @__PURE__ */ React.createElement(
      "button",
      {
        onClick: async () => {
          try {
            const response = await fetch("/api/dependencies");
            const data = await response.json();
            const depsWindow = window.open("", "dependencies", "width=800,height=600,scrollbars=yes");
            if (depsWindow) {
              const doc = depsWindow.document;
              doc.open();
              doc.write("<html><head><title>Installed Dependencies</title>");
              doc.write("<style>body{font-family:system-ui;padding:20px;background:#f5f5f5}");
              doc.write("h1{color:#333;margin-bottom:20px}table{width:100%;border-collapse:collapse;background:white;box-shadow:0 2px 4px rgba(0,0,0,0.1)}");
              doc.write("th,td{padding:12px;text-align:left;border-bottom:1px solid #ddd}");
              doc.write("th{background:#4f46e5;color:white;font-weight:600}");
              doc.write("tr:hover{background:#f9fafb}.count{color:#666;margin-top:10px}</style></head>");
              doc.write("<body><h1>📦 Installed Python Packages</h1>");
              doc.write(`<p class="count"><strong>${data.total}</strong> packages installed</p>`);
              doc.write("<table><thead><tr><th>Package Name</th><th>Version</th></tr></thead><tbody>");
              data.packages.forEach((pkg) => {
                doc.write(`<tr><td>${pkg.name}</td><td>${pkg.version}</td></tr>`);
              });
              doc.write("</tbody></table></body></html>");
              doc.close();
            } else {
              alert("Please allow popups to view dependencies");
            }
          } catch (err) {
            alert("Failed to load dependencies: " + err.message);
          }
        },
        className: `px-4 py-2 text-sm rounded-lg font-medium ${isDarkTheme ? "bg-gray-800 hover:bg-gray-700 text-gray-200 border border-gray-600" : "bg-gray-100 hover:bg-gray-200 text-gray-700"}`
      },
      /* @__PURE__ */ React.createElement("i", { className: "fas fa-list mr-2" }),
      "View Dependencies"
    ), /* @__PURE__ */ React.createElement(
      "button",
      {
        onClick: async () => {
          const providerEl = document.getElementById("llm-provider");
          const endpointUrlInput = document.getElementById("llm-endpoint-url");
          const modelInput = document.getElementById("llm-model");
          const apiKeyEl = document.getElementById("llm-api-key");
          const maxTokensEl = document.getElementById("llm-max-tokens");
          const tempEl = document.getElementById("llm-temperature");
          const mcpUrlEl = document.getElementById("mcp-url");
          const mcpTokenEl = document.getElementById("mcp-token");
          const mcpVerifyEl = document.getElementById("mcp-verify-ssl");
          const provider = providerEl ? providerEl.value : selectedProvider;
          const mcpToken = mcpTokenEl ? mcpTokenEl.value : "";
          const mcpSettings = {
            url: mcpUrlEl ? mcpUrlEl.value : config.mcp.url,
            verify_ssl: mcpVerifyEl ? mcpVerifyEl.checked : config.mcp.verify_ssl
          };
          if (mcpToken && mcpToken.trim()) {
            mcpSettings.token = mcpToken;
          }
          const settings = {
            mcp: mcpSettings,
            llm: {
              provider,
              api_key: (apiKeyEl ? apiKeyEl.value : config.llm.api_key) || void 0,
              model: (modelInput ? modelInput.value : selectedModel) || config.llm.model,
              endpoint_url: provider !== "openai" && endpointUrlInput ? endpointUrlInput.value : void 0,
              max_tokens: maxTokensEl ? parseInt(maxTokensEl.value) : config.llm.max_tokens,
              temperature: tempEl ? parseFloat(tempEl.value) : config.llm.temperature
            },
            security: {
              ...config.security || {}
            },
            server: {
              ...config.server
            }
          };
          await saveSettings(settings);
        },
        className: "px-6 py-2 bg-indigo-600 hover:bg-indigo-700 text-white rounded-lg font-medium"
      },
      /* @__PURE__ */ React.createElement("i", { className: "fas fa-save mr-2" }),
      "Save Settings"
    ))))), renderAuthEnableInfoModal(), renderWelcomeSplashModal(), isCredentialModalOpen && /* @__PURE__ */ React.createElement("div", { className: "fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4" }, /* @__PURE__ */ React.createElement("div", { className: `rounded-xl shadow-2xl w-full max-w-md ${isDarkTheme ? "bg-gray-800 border border-gray-700" : "bg-white"}` }, /* @__PURE__ */ React.createElement("div", { className: `px-6 py-4 rounded-t-xl ${isUpdateMode ? "bg-gradient-to-r from-amber-400 to-yellow-400 text-gray-900 border-b-4 border-amber-600" : "bg-gradient-to-r from-purple-600 to-indigo-600 text-white"}` }, /* @__PURE__ */ React.createElement("div", { className: "flex items-center justify-between" }, /* @__PURE__ */ React.createElement("div", { className: "flex items-center gap-3" }, /* @__PURE__ */ React.createElement("i", { className: `text-2xl ${isUpdateMode ? "fas fa-sync-alt" : "fas fa-save"}` }), /* @__PURE__ */ React.createElement("h2", { className: "text-xl font-bold" }, isUpdateMode ? "Update" : "Save", " LLM Credential")), /* @__PURE__ */ React.createElement(
      "button",
      {
        onClick: () => {
          setIsCredentialModalOpen(false);
          setCredentialName("");
          setIsUpdateMode(false);
        },
        className: `transition-colors ${isUpdateMode ? "text-gray-900 hover:text-gray-600" : "text-white hover:text-gray-200"}`
      },
      /* @__PURE__ */ React.createElement("i", { className: "fas fa-times text-xl" })
    ))), /* @__PURE__ */ React.createElement("div", { className: "p-6" }, isUpdateMode ? /* @__PURE__ */ React.createElement("div", { className: "bg-yellow-50 border-l-4 border-yellow-600 p-4 mb-4" }, /* @__PURE__ */ React.createElement("div", { className: "flex items-start" }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-exclamation-triangle text-yellow-600 text-xl mr-3 mt-0.5" }), /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("p", { className: "text-sm font-bold text-gray-900 mb-1" }, "⚠️ Update Warning"), /* @__PURE__ */ React.createElement("p", { className: "text-sm text-gray-800" }, 'You are about to overwrite the existing credential "', /* @__PURE__ */ React.createElement("strong", { className: "text-gray-900" }, credentialName), '". This will replace all settings with your current configuration. This action cannot be undone.')))) : /* @__PURE__ */ React.createElement("p", { className: `text-sm mb-4 ${isDarkTheme ? "text-gray-300" : "text-gray-600"}` }, "Save your current LLM settings as a named credential for quick access later."), /* @__PURE__ */ React.createElement("div", { className: "mb-6" }, /* @__PURE__ */ React.createElement("label", { className: `block text-sm font-medium mb-2 ${isDarkTheme ? "text-gray-200" : "text-gray-700"}` }, "Credential Name ", /* @__PURE__ */ React.createElement("span", { className: "text-red-500" }, "*")), /* @__PURE__ */ React.createElement(
      "input",
      {
        type: "text",
        value: credentialName,
        onChange: (e) => setCredentialName(e.target.value),
        placeholder: "e.g., My OpenAI GPT-4, Local Llama Server",
        className: `w-full px-4 py-2 border rounded-lg focus:ring-2 focus:ring-purple-500 focus:border-transparent ${isDarkTheme ? "bg-gray-900 border-gray-600 text-gray-100 placeholder-gray-500" : "bg-white border-gray-300 text-gray-900 placeholder-gray-400"}`,
        disabled: isUpdateMode,
        autoFocus: !isUpdateMode
      }
    ), isUpdateMode && /* @__PURE__ */ React.createElement("p", { className: `text-xs mt-1 italic ${isDarkTheme ? "text-gray-400" : "text-gray-500"}` }, "Credential name cannot be changed when updating")), /* @__PURE__ */ React.createElement("div", { className: `rounded-lg p-4 mb-6 border ${isDarkTheme ? "bg-gray-900 border-gray-700" : "bg-gray-50 border-gray-200"}` }, /* @__PURE__ */ React.createElement("h4", { className: `text-xs font-semibold mb-2 uppercase tracking-wide ${isDarkTheme ? "text-gray-300" : "text-gray-700"}` }, "Current Settings Preview"), /* @__PURE__ */ React.createElement("div", { className: `space-y-1 text-sm ${isDarkTheme ? "text-gray-300" : "text-gray-600"}` }, /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("span", { className: "font-medium" }, "Provider:"), " ", selectedProvider), /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("span", { className: "font-medium" }, "Model:"), " ", ((_tb = document.getElementById("llm-model")) == null ? void 0 : _tb.value) || "N/A"), /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("span", { className: "font-medium" }, "Max Tokens:"), " ", ((_ub = document.getElementById("llm-max-tokens")) == null ? void 0 : _ub.value) || "N/A"), /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("span", { className: "font-medium" }, "Temperature:"), " ", ((_vb = document.getElementById("llm-temperature")) == null ? void 0 : _vb.value) || "N/A"))), /* @__PURE__ */ React.createElement("div", { className: "flex gap-3" }, /* @__PURE__ */ React.createElement(
      "button",
      {
        onClick: () => {
          setIsCredentialModalOpen(false);
          setCredentialName("");
          setIsUpdateMode(false);
        },
        className: `flex-1 px-4 py-2 rounded-lg font-medium transition-colors ${isDarkTheme ? "bg-gray-700 hover:bg-gray-600 text-gray-100" : "bg-gray-200 hover:bg-gray-300 text-gray-700"}`
      },
      "Cancel"
    ), /* @__PURE__ */ React.createElement(
      "button",
      {
        onClick: async () => {
          if (!credentialName.trim()) {
            alert("Please enter a credential name");
            return;
          }
          if (isUpdateMode) {
            const confirmed = confirm(`⚠️ Confirm Update

Are you sure you want to overwrite "${credentialName}"?

This will replace:
• Provider & Model
• API Key
• Endpoint URL
• Max Tokens & Temperature

This action cannot be undone.`);
            if (!confirmed) return;
          }
          try {
            const provider = document.getElementById("llm-provider").value;
            const endpointUrlInput = document.getElementById("llm-endpoint-url");
            const response = await fetch("/api/credentials", {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({
                name: credentialName.trim(),
                provider,
                api_key: document.getElementById("llm-api-key").value,
                model: document.getElementById("llm-model").value,
                endpoint_url: provider === "custom" && endpointUrlInput ? endpointUrlInput.value : null,
                max_tokens: parseInt(document.getElementById("llm-max-tokens").value),
                temperature: parseFloat(document.getElementById("llm-temperature").value)
              })
            });
            if (response.ok) {
              setIsCredentialModalOpen(false);
              setCredentialName("");
              const wasUpdate = isUpdateMode;
              setIsUpdateMode(false);
              await loadCredentials();
              const successDiv = document.createElement("div");
              successDiv.className = `fixed top-6 right-6 ${wasUpdate ? "bg-gradient-to-r from-amber-400 to-yellow-400 text-gray-900 border-2 border-amber-600" : "bg-green-600 text-white"} px-6 py-4 rounded-xl shadow-2xl z-50 animate-bounce`;
              successDiv.innerHTML = `
                                                            <div class="flex items-center gap-3">
                                                                <i class="fas ${wasUpdate ? "fa-sync-alt" : "fa-check-circle"} text-2xl"></i>
                                                                <div>
                                                                    <p class="font-bold text-base">Credential ${wasUpdate ? "Updated" : "Saved"}!</p>
                                                                    <p class="text-sm ${wasUpdate ? "opacity-80" : "opacity-90"}">${credentialName}</p>
                                                                </div>
                                                            </div>
                                                        `;
              document.body.appendChild(successDiv);
              setTimeout(() => {
                successDiv.style.animation = "none";
                successDiv.style.opacity = "0";
                successDiv.style.transition = "opacity 0.3s";
                setTimeout(() => successDiv.remove(), 300);
              }, 2500);
            } else {
              const error = await response.json();
              alert("Failed to save credential: " + (error.detail || "Unknown error"));
            }
          } catch (error) {
            alert("Error saving credential: " + error.message);
          }
        },
        disabled: !credentialName.trim(),
        className: `flex-1 px-4 py-2 ${isUpdateMode ? "bg-gradient-to-r from-amber-500 to-yellow-500 hover:from-amber-600 hover:to-yellow-600 text-gray-900 border-2 border-amber-600" : "bg-gradient-to-r from-purple-600 to-indigo-600 hover:from-purple-700 hover:to-indigo-700 text-white"} disabled:from-gray-400 disabled:to-gray-400 disabled:text-gray-300 rounded-lg font-bold transition-all shadow-md hover:shadow-lg disabled:cursor-not-allowed disabled:border-0`
      },
      /* @__PURE__ */ React.createElement("i", { className: `mr-2 ${isUpdateMode ? "fas fa-sync-alt" : "fas fa-save"}` }),
      isUpdateMode ? "Update Credential" : "Save Credential"
    ))))), isMCPSaveModalOpen && /* @__PURE__ */ React.createElement("div", { className: "fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4" }, /* @__PURE__ */ React.createElement("div", { className: `rounded-xl shadow-2xl w-full max-w-md ${isDarkTheme ? "bg-gray-800 border border-gray-700" : "bg-white"}` }, /* @__PURE__ */ React.createElement("div", { className: `px-6 py-4 rounded-t-xl ${loadedMCPConfigName ? "bg-gradient-to-r from-amber-400 to-yellow-400 text-gray-900 border-b-4 border-amber-600" : "bg-gradient-to-r from-green-600 to-emerald-600 text-white"}` }, /* @__PURE__ */ React.createElement("div", { className: "flex items-center justify-between" }, /* @__PURE__ */ React.createElement("div", { className: "flex items-center gap-3" }, /* @__PURE__ */ React.createElement("i", { className: `text-2xl ${loadedMCPConfigName ? "fas fa-sync-alt" : "fas fa-save"}` }), /* @__PURE__ */ React.createElement("h2", { className: "text-xl font-bold" }, loadedMCPConfigName ? "Update" : "Save", " MCP Configuration")), /* @__PURE__ */ React.createElement(
      "button",
      {
        onClick: () => {
          setIsMCPSaveModalOpen(false);
          setMCPConfigName("");
          setMCPConfigDescription("");
        },
        className: `transition-colors ${loadedMCPConfigName ? "text-gray-900 hover:text-gray-600" : "text-white hover:text-gray-200"}`
      },
      /* @__PURE__ */ React.createElement("i", { className: "fas fa-times text-xl" })
    ))), /* @__PURE__ */ React.createElement("div", { className: "p-6" }, loadedMCPConfigName ? /* @__PURE__ */ React.createElement("div", { className: "bg-yellow-50 border-l-4 border-yellow-600 p-4 mb-4" }, /* @__PURE__ */ React.createElement("div", { className: "flex items-start" }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-exclamation-triangle text-yellow-600 text-xl mr-3 mt-0.5" }), /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("p", { className: "text-sm font-bold text-gray-900 mb-1" }, "⚠️ Update Warning"), /* @__PURE__ */ React.createElement("p", { className: "text-sm text-gray-800" }, 'You are about to overwrite the existing configuration "', /* @__PURE__ */ React.createElement("strong", { className: "text-gray-900" }, mcpConfigName), '". This will replace all settings with your current configuration. This action cannot be undone.')))) : /* @__PURE__ */ React.createElement("p", { className: `text-sm mb-4 ${isDarkTheme ? "text-gray-300" : "text-gray-600"}` }, "Save your current MCP server settings as a named configuration for quick access later."), /* @__PURE__ */ React.createElement("div", { className: "mb-4" }, /* @__PURE__ */ React.createElement("label", { className: `block text-sm font-medium mb-2 ${isDarkTheme ? "text-gray-200" : "text-gray-700"}` }, "Configuration Name ", /* @__PURE__ */ React.createElement("span", { className: "text-red-500" }, "*")), /* @__PURE__ */ React.createElement(
      "input",
      {
        type: "text",
        value: mcpConfigName,
        onChange: (e) => setMCPConfigName(e.target.value),
        placeholder: "e.g., Production Splunk, Dev Environment",
        className: `w-full px-4 py-2 border rounded-lg focus:ring-2 focus:ring-green-500 focus:border-transparent ${isDarkTheme ? "bg-gray-900 border-gray-600 text-gray-100 placeholder-gray-500" : "bg-white border-gray-300 text-gray-900 placeholder-gray-400"}`,
        disabled: loadedMCPConfigName,
        autoFocus: !loadedMCPConfigName
      }
    ), loadedMCPConfigName && /* @__PURE__ */ React.createElement("p", { className: `text-xs mt-1 italic ${isDarkTheme ? "text-gray-400" : "text-gray-500"}` }, "Configuration name cannot be changed when updating")), /* @__PURE__ */ React.createElement("div", { className: "mb-6" }, /* @__PURE__ */ React.createElement("label", { className: `block text-sm font-medium mb-2 ${isDarkTheme ? "text-gray-200" : "text-gray-700"}` }, "Description (Optional)"), /* @__PURE__ */ React.createElement(
      "input",
      {
        type: "text",
        value: mcpConfigDescription,
        onChange: (e) => setMCPConfigDescription(e.target.value),
        placeholder: "e.g., Main production Splunk server",
        className: `w-full px-4 py-2 border rounded-lg focus:ring-2 focus:ring-green-500 focus:border-transparent ${isDarkTheme ? "bg-gray-900 border-gray-600 text-gray-100 placeholder-gray-500" : "bg-white border-gray-300 text-gray-900 placeholder-gray-400"}`
      }
    )), /* @__PURE__ */ React.createElement("div", { className: `rounded-lg p-4 mb-6 border ${isDarkTheme ? "bg-gray-900 border-gray-700" : "bg-gray-50 border-gray-200"}` }, /* @__PURE__ */ React.createElement("h4", { className: `text-xs font-semibold mb-2 uppercase tracking-wide ${isDarkTheme ? "text-gray-300" : "text-gray-700"}` }, "Current Settings Preview"), /* @__PURE__ */ React.createElement("div", { className: `space-y-1 text-sm ${isDarkTheme ? "text-gray-300" : "text-gray-600"}` }, /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("span", { className: "font-medium" }, "URL:"), " ", ((_wb = config == null ? void 0 : config.mcp) == null ? void 0 : _wb.url) || "N/A"), /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("span", { className: "font-medium" }, "Token:"), " ", ((_xb = config == null ? void 0 : config.mcp) == null ? void 0 : _xb.token) ? "***" : "Not set"), /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("span", { className: "font-medium" }, "Verify SSL:"), " ", ((_yb = config == null ? void 0 : config.mcp) == null ? void 0 : _yb.verify_ssl) ? "Yes" : "No"))), /* @__PURE__ */ React.createElement("div", { className: "flex gap-3" }, /* @__PURE__ */ React.createElement(
      "button",
      {
        onClick: () => {
          setIsMCPSaveModalOpen(false);
          setMCPConfigName("");
          setMCPConfigDescription("");
        },
        className: `flex-1 px-4 py-2 rounded-lg font-medium transition-colors ${isDarkTheme ? "bg-gray-700 hover:bg-gray-600 text-gray-100" : "bg-gray-200 hover:bg-gray-300 text-gray-700"}`
      },
      "Cancel"
    ), /* @__PURE__ */ React.createElement(
      "button",
      {
        onClick: async () => {
          if (!mcpConfigName.trim()) {
            alert("Please enter a configuration name");
            return;
          }
          if (loadedMCPConfigName) {
            const confirmed = confirm(`⚠️ Confirm Update

Are you sure you want to overwrite "${mcpConfigName}"?

This will replace:
• MCP URL
• Token
• SSL Settings
• Description

This action cannot be undone.`);
            if (!confirmed) return;
          }
          try {
            const response = await fetch("/api/mcp-configs", {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({
                name: mcpConfigName.trim(),
                url: document.getElementById("mcp-url").value,
                token: document.getElementById("mcp-token").value || config.mcp.token,
                verify_ssl: document.getElementById("mcp-verify-ssl").checked,
                description: mcpConfigDescription.trim() || null
              })
            });
            if (response.ok) {
              setIsMCPSaveModalOpen(false);
              const savedName = mcpConfigName.trim();
              const wasUpdate = loadedMCPConfigName;
              setMCPConfigName("");
              setMCPConfigDescription("");
              await loadMCPConfigs();
              const successDiv = document.createElement("div");
              successDiv.className = `fixed top-6 right-6 ${wasUpdate ? "bg-gradient-to-r from-amber-400 to-yellow-400 text-gray-900 border-2 border-amber-600" : "bg-green-600 text-white"} px-6 py-4 rounded-xl shadow-2xl z-50 animate-bounce`;
              successDiv.innerHTML = `
                                                            <div class="flex items-center gap-3">
                                                                <i class="fas ${wasUpdate ? "fa-sync-alt" : "fa-check-circle"} text-2xl"></i>
                                                                <div>
                                                                    <p class="font-bold text-base">Configuration ${wasUpdate ? "Updated" : "Saved"}!</p>
                                                                    <p class="text-sm ${wasUpdate ? "opacity-80" : "opacity-90"}">${savedName}</p>
                                                                </div>
                                                            </div>
                                                        `;
              document.body.appendChild(successDiv);
              setTimeout(() => {
                successDiv.style.animation = "none";
                successDiv.style.opacity = "0";
                successDiv.style.transition = "opacity 0.3s";
                setTimeout(() => successDiv.remove(), 300);
              }, 2500);
            } else {
              const error = await response.json();
              alert("Failed to save configuration: " + (error.detail || "Unknown error"));
            }
          } catch (error) {
            alert("Error saving configuration: " + error.message);
          }
        },
        disabled: !mcpConfigName.trim(),
        className: `flex-1 px-4 py-2 ${loadedMCPConfigName ? "bg-gradient-to-r from-amber-500 to-yellow-500 hover:from-amber-600 hover:to-yellow-600 text-gray-900 border-2 border-amber-600" : "bg-gradient-to-r from-green-600 to-emerald-600 hover:from-green-700 hover:to-emerald-700 text-white"} disabled:from-gray-400 disabled:to-gray-400 disabled:text-gray-300 rounded-lg font-bold transition-all shadow-md hover:shadow-lg disabled:cursor-not-allowed disabled:border-0`
      },
      /* @__PURE__ */ React.createElement("i", { className: `mr-2 ${loadedMCPConfigName ? "fas fa-sync-alt" : "fas fa-save"}` }),
      loadedMCPConfigName ? "Update Configuration" : "Save Configuration"
    ))))));
  }
  window.addEventListener("error", (event2) => {
    console.error("Global error caught:", event2.error);
    event2.preventDefault();
  });
  window.addEventListener("unhandledrejection", (event2) => {
    console.error("Unhandled promise rejection:", event2.reason);
    event2.preventDefault();
  });
  ReactDOM.render(
    /* @__PURE__ */ React.createElement(ErrorBoundary, null, isVisualizationRegressionView ? /* @__PURE__ */ React.createElement(VisualizationRegressionHarness, null) : /* @__PURE__ */ React.createElement(App, null)),
    document.getElementById("root")
  );
})();
