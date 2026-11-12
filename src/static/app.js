(() => {
  const { useState, useEffect, useRef } = React;
  const generateChatSessionId = () => {
    const now = /* @__PURE__ */ new Date();
    const stamp = now.toISOString().replace(/[-:T\.Z]/g, "").slice(0, 14);
    const rand = Math.random().toString(36).slice(2, 8);
    return `chat_${stamp}_${rand}`;
  };
  const CHAT_STATE_STORAGE_KEY = "dt4sms_chat_state_v1";
  const CHAT_MISSION_STORAGE_KEY = "dt4sms_chat_mission_v1";
  const CHAT_MISSION_MAX_CHARS = 600;
  const WELCOME_SPLASH_PREFERENCE_KEY = "dt4sms_welcome_splash_dismissed_v1";
  const THEME_PREFERENCE_OPTIONS = [
    { value: "light", label: "Light" },
    { value: "dark", label: "Dark" },
    { value: "neo", label: "Neo" },
    { value: "system", label: "System" }
  ];
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
  const loadChatMission = () => {
    try {
      if (typeof window === "undefined" || !window.localStorage) {
        return "";
      }
      const value = window.localStorage.getItem(CHAT_MISSION_STORAGE_KEY);
      return typeof value === "string" ? value.slice(0, CHAT_MISSION_MAX_CHARS) : "";
    } catch (error) {
      return "";
    }
  };
  const saveChatMission = (value) => {
    try {
      if (typeof window === "undefined" || !window.localStorage) {
        return;
      }
      if (value && value.trim()) {
        window.localStorage.setItem(CHAT_MISSION_STORAGE_KEY, value.slice(0, CHAT_MISSION_MAX_CHARS));
      } else {
        window.localStorage.removeItem(CHAT_MISSION_STORAGE_KEY);
      }
    } catch (error) {
      console.warn("Failed to save chat mission", error);
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
  const normalizeProvider = (provider, endpointUrl = "") => {
    const value = String(provider || "openai").toLowerCase().trim();
    const endpointValue = String(endpointUrl || "").toLowerCase().trim();
    if (value === "custom endpoint") return "custom";
    if (value === "azure openai") return "azure";
    if (value === "claude") return "anthropic";
    if (value === "google" || value === "google ai") return "gemini";
    if (value === "local ollama" || value === "ollama endpoint") return "ollama";
    if (value === "custom" && (endpointValue.includes("ollama") || endpointValue.includes(":11434"))) return "ollama";
    return value;
  };
  const escapeSettingsHtml = (value) => String(value != null ? value : "").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");
  const formatApiErrorDetail = (detail) => {
    if (!detail) return "Unknown error";
    if (typeof detail === "string") return detail;
    if (Array.isArray(detail)) return detail.map((item) => (item == null ? void 0 : item.msg) || JSON.stringify(item)).join("; ");
    return JSON.stringify(detail);
  };
  const readApiResponse = async (response) => {
    const text = await response.text().catch(() => "");
    let data = null;
    try {
      data = text ? JSON.parse(text) : null;
    } catch (parseError) {
      data = null;
    }
    return { data, text };
  };
  const describeApiFailure = (response, data, text) => {
    const status = response ? `HTTP ${response.status}${response.statusText ? ` ${response.statusText}` : ""}` : "No response";
    if (data && data.detail !== void 0 && data.detail !== null && data.detail !== "") {
      return `${formatApiErrorDetail(data.detail)} (${status})`;
    }
    const snippet = String(text || "").replace(/<[^>]*>/g, " ").replace(/\s+/g, " ").trim().slice(0, 200);
    return snippet ? `${status}: ${snippet}` : status;
  };
  const TROUBLESHOOT_RESTART_HINT = "Restart the app in its install folder: ./install.sh --restart (macOS/Linux) or .\\install.ps1 -Restart (Windows). Then reload this page.";
  const APP_COPY_SCAN_SPAN = 20;
  const readLlmTuningFormValues = (fallback = {}) => {
    const toPositiveInt = (element, fallbackValue) => {
      if (!element) return Number(fallbackValue) > 0 ? Number(fallbackValue) : 0;
      const parsed = parseInt(element.value || "0", 10);
      return Number.isFinite(parsed) && parsed > 0 ? parsed : 0;
    };
    const autoTuneEl = document.getElementById("llm-auto-tune");
    const effortEl = document.getElementById("llm-reasoning-effort");
    return {
      auto_tune: autoTuneEl ? autoTuneEl.checked : fallback.auto_tune !== false,
      context_window: toPositiveInt(document.getElementById("llm-context-window"), fallback.context_window),
      request_timeout: toPositiveInt(document.getElementById("llm-request-timeout"), fallback.request_timeout),
      reasoning_effort: effortEl ? effortEl.value : fallback.reasoning_effort || ""
    };
  };
  const formatTuningTokens = (value) => {
    const numeric = Number(value);
    if (!Number.isFinite(numeric) || numeric <= 0) return "n/a";
    if (numeric >= 1e3) {
      return numeric % 1024 === 0 ? `${numeric / 1024}K` : `${Math.round(numeric / 1e3)}K`;
    }
    return String(numeric);
  };
  const describeLlmTuning = (tuning) => {
    if (!tuning || typeof tuning !== "object") return "";
    const parts = [
      `${formatTuningTokens(tuning.context_window)} context`,
      `${tuning.max_tokens} max output tokens`,
      tuning.temperature === null || tuning.temperature === void 0 ? "fixed temperature" : `temperature ${tuning.temperature}`,
      `${tuning.request_timeout}s timeout`
    ];
    if (tuning.reasoning_effort) parts.push(`reasoning effort ${tuning.reasoning_effort}`);
    return parts.join(" · ");
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
    const handleSelectableKeyDown = (event, index) => {
      if (event.key === "Enter" || event.key === " ") {
        event.preventDefault();
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
            onClick: (event) => event.stopPropagation()
          },
          /* @__PURE__ */ React.createElement("div", { className: "flex items-start justify-between gap-3 px-4 pt-4" }, /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("div", { className: `text-xs uppercase tracking-wider ${mutedTextClass}` }, chartType === "line" ? "Selected trend point" : "Selected category"), /* @__PURE__ */ React.createElement("h3", { "data-testid": `${chartTestId}-selection-label`, className: `mt-1 text-sm font-semibold ${headingClass}` }, selectedPoint.fullLabel || selectedPoint.label)), /* @__PURE__ */ React.createElement(
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
          /* @__PURE__ */ React.createElement("div", { className: "px-4 pb-4" }, /* @__PURE__ */ React.createElement("div", { className: "mt-4 grid grid-cols-2 gap-2 text-xs" }, /* @__PURE__ */ React.createElement("div", { className: `rounded-lg border px-3 py-2 ${detailCardChipClass}` }, /* @__PURE__ */ React.createElement("div", { className: "uppercase tracking-wide opacity-75" }, xAxisLabel), /* @__PURE__ */ React.createElement("div", { className: "mt-1 font-semibold break-words" }, selectedPoint.fullLabel || selectedPoint.label)), /* @__PURE__ */ React.createElement("div", { className: `rounded-lg border px-3 py-2 ${detailCardChipClass}` }, /* @__PURE__ */ React.createElement("div", { className: "uppercase tracking-wide opacity-75" }, yAxisLabel), /* @__PURE__ */ React.createElement("div", { className: "mt-1 font-semibold" }, formatVisualizationNumber(selectedPoint.value)))), /* @__PURE__ */ React.createElement("div", { className: `mt-4 rounded-xl border px-3 py-3 text-xs ${isDarkTheme ? "bg-gray-950 border-gray-700 text-gray-200" : "bg-gray-50 border-gray-200 text-gray-700"}` }, /* @__PURE__ */ React.createElement("div", { className: "uppercase tracking-wider opacity-75" }, "Preview Context"), /* @__PURE__ */ React.createElement("div", { className: "mt-2" }, (spec == null ? void 0 : spec.title) || "Visualization Preview"), /* @__PURE__ */ React.createElement("div", { className: `mt-1 ${subtextClass}` }, (spec == null ? void 0 : spec.summary_text) || "Generated from chartable query results.")), sourceQueryPreview ? /* @__PURE__ */ React.createElement("div", { className: `mt-4 rounded-xl border px-3 py-3 text-xs ${isDarkTheme ? "bg-gray-950 border-gray-700 text-gray-200" : "bg-gray-50 border-gray-200 text-gray-700"}` }, /* @__PURE__ */ React.createElement("div", { className: "uppercase tracking-wider opacity-75" }, "Source SPL"), /* @__PURE__ */ React.createElement("pre", { className: "mt-2 max-h-24 overflow-auto whitespace-pre-wrap break-all font-mono text-xs" }, sourceQueryPreview)) : /* @__PURE__ */ React.createElement("div", { className: `mt-4 rounded-xl border px-3 py-3 text-xs ${isDarkTheme ? "bg-gray-950 border-gray-700 text-gray-400" : "bg-gray-50 border-gray-200 text-gray-500"}` }, "No source SPL query was attached to this visualization preview."), /* @__PURE__ */ React.createElement("div", { className: "mt-4 flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between" }, sourceQueryPreview ? renderSplQueryActionButtons(sourceQueryPreview, {
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
      return /* @__PURE__ */ React.createElement("div", { "data-testid": `${chartTestId}-root`, className: `relative mt-2 rounded-lg border p-3 ${isDarkTheme ? "bg-gray-900 border-gray-700" : "bg-white border-gray-200"}` }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-wrap items-start justify-between gap-2 mb-3" }, /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("div", { className: `text-sm font-semibold ${headingClass}` }, (spec == null ? void 0 : spec.title) || "Trend Preview"), /* @__PURE__ */ React.createElement("div", { className: `text-xs ${subtextClass}` }, (spec == null ? void 0 : spec.summary_text) || "Generated from chartable query results.")), /* @__PURE__ */ React.createElement("div", { className: "flex flex-wrap gap-2 text-xs" }, /* @__PURE__ */ React.createElement("span", { className: `inline-flex items-center rounded-full px-2 py-0.5 border ${isDarkTheme ? "bg-sky-900 text-sky-100 border-sky-700" : "bg-sky-100 text-sky-800 border-sky-300"}` }, "line"), (spec == null ? void 0 : spec.y_field) && /* @__PURE__ */ React.createElement("span", { className: `inline-flex items-center rounded-full px-2 py-0.5 border ${isDarkTheme ? "bg-gray-800 text-gray-200 border-gray-600" : "bg-gray-50 text-gray-700 border-gray-300"}` }, spec.y_field))), /* @__PURE__ */ React.createElement("div", { className: "flex flex-wrap items-center gap-2 mb-3 text-xs" }, /* @__PURE__ */ React.createElement("span", { className: `inline-flex items-center gap-2 rounded-full px-2.5 py-1 border ${isDarkTheme ? "bg-sky-950 text-sky-100 border-sky-800" : "bg-sky-50 text-sky-800 border-sky-200"}` }, /* @__PURE__ */ React.createElement("span", { className: "inline-block h-2.5 w-2.5 rounded-full", style: { backgroundColor: plotColor } }), /* @__PURE__ */ React.createElement("span", { className: "font-medium" }, yAxisLabel)), /* @__PURE__ */ React.createElement("span", { className: `inline-flex items-center rounded-full px-2.5 py-1 border ${isDarkTheme ? "bg-gray-800 text-gray-200 border-gray-600" : "bg-gray-50 text-gray-700 border-gray-300"}` }, "X-axis: ", xAxisLabel), /* @__PURE__ */ React.createElement("span", { className: `inline-flex items-center rounded-full px-2.5 py-1 border ${isDarkTheme ? "bg-gray-800 text-gray-200 border-gray-600" : "bg-gray-50 text-gray-700 border-gray-300"}` }, "Y-axis: ", yAxisLabel)), /* @__PURE__ */ React.createElement("svg", { "data-testid": `${chartTestId}-svg`, viewBox: `0 0 ${width} ${height}`, className: "w-full h-52 overflow-visible" }, yTicks.map((tick, index) => /* @__PURE__ */ React.createElement("g", { key: `line-tick-${index}` }, /* @__PURE__ */ React.createElement(
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
            onKeyDown: (event) => handleSelectableKeyDown(event, index)
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
          /* @__PURE__ */ React.createElement("div", { className: `text-xs uppercase tracking-wide ${mutedTextClass}` }, truncateVisualizationLabel(point.fullLabel || point.label, 18)),
          /* @__PURE__ */ React.createElement("div", { className: `text-xs font-semibold ${headingClass}` }, formatVisualizationNumber(point.value))
        );
      })), renderSelectionCard());
    }
    return /* @__PURE__ */ React.createElement("div", { "data-testid": `${chartTestId}-root`, className: `relative mt-2 rounded-lg border p-3 ${isDarkTheme ? "bg-gray-900 border-gray-700" : "bg-white border-gray-200"}` }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-wrap items-start justify-between gap-2 mb-3" }, /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("div", { className: `text-sm font-semibold ${headingClass}` }, (spec == null ? void 0 : spec.title) || "Breakdown Preview"), /* @__PURE__ */ React.createElement("div", { className: `text-xs ${subtextClass}` }, (spec == null ? void 0 : spec.summary_text) || "Generated from chartable query results.")), /* @__PURE__ */ React.createElement("div", { className: "flex flex-wrap gap-2 text-xs" }, /* @__PURE__ */ React.createElement("span", { className: `inline-flex items-center rounded-full px-2 py-0.5 border ${isDarkTheme ? "bg-cyan-900 text-cyan-100 border-cyan-700" : "bg-cyan-100 text-cyan-800 border-cyan-300"}` }, "bar"), (spec == null ? void 0 : spec.y_field) && /* @__PURE__ */ React.createElement("span", { className: `inline-flex items-center rounded-full px-2 py-0.5 border ${isDarkTheme ? "bg-gray-800 text-gray-200 border-gray-600" : "bg-gray-50 text-gray-700 border-gray-300"}` }, spec.y_field))), /* @__PURE__ */ React.createElement("div", { className: "flex flex-wrap items-center gap-2 mb-3 text-xs" }, /* @__PURE__ */ React.createElement("span", { className: `inline-flex items-center gap-2 rounded-full px-2.5 py-1 border ${isDarkTheme ? "bg-cyan-950 text-cyan-100 border-cyan-800" : "bg-cyan-50 text-cyan-800 border-cyan-200"}` }, /* @__PURE__ */ React.createElement("span", { className: "inline-block h-2.5 w-2.5 rounded-sm", style: { backgroundColor: plotColor } }), /* @__PURE__ */ React.createElement("span", { className: "font-medium" }, yAxisLabel)), /* @__PURE__ */ React.createElement("span", { className: `inline-flex items-center rounded-full px-2.5 py-1 border ${isDarkTheme ? "bg-gray-800 text-gray-200 border-gray-600" : "bg-gray-50 text-gray-700 border-gray-300"}` }, "X-axis: ", xAxisLabel), /* @__PURE__ */ React.createElement("span", { className: `inline-flex items-center rounded-full px-2.5 py-1 border ${isDarkTheme ? "bg-gray-800 text-gray-200 border-gray-600" : "bg-gray-50 text-gray-700 border-gray-300"}` }, "Y-axis: ", yAxisLabel)), /* @__PURE__ */ React.createElement("svg", { "data-testid": `${chartTestId}-svg`, viewBox: `0 0 ${width} ${height}`, className: "w-full h-52 overflow-visible" }, yTicks.map((tick, index) => /* @__PURE__ */ React.createElement("g", { key: `bar-tick-${index}` }, /* @__PURE__ */ React.createElement(
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
          onKeyDown: (event) => handleSelectableKeyDown(event, index)
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
        /* @__PURE__ */ React.createElement("div", { className: `text-xs uppercase tracking-wide ${mutedTextClass}` }, truncateVisualizationLabel(point.fullLabel || point.label, 18)),
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
    return /* @__PURE__ */ React.createElement("div", { "data-theme": regressionTheme, "data-testid": "visualization-regression-root", className: isDarkTheme ? "min-h-screen bg-gray-950 text-gray-100" : "min-h-screen bg-gray-100 text-gray-900" }, /* @__PURE__ */ React.createElement("div", { className: "max-w-6xl mx-auto px-6 py-8" }, /* @__PURE__ */ React.createElement("div", { className: `rounded-2xl border p-6 shadow-sm ${isDarkTheme ? "bg-gray-900 border-gray-700" : "bg-white border-gray-200"}` }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-col gap-2 mb-6" }, /* @__PURE__ */ React.createElement("div", { className: "text-xs font-semibold uppercase tracking-wider text-cyan-600" }, "Browser Regression Harness"), /* @__PURE__ */ React.createElement("h1", { className: `text-2xl font-bold ${headingClass}` }, "Visualization Preview Layout"), /* @__PURE__ */ React.createElement("p", { className: `text-sm ${subtextClass}` }, "Fixed sample data for catching collapsed bars, missing SVG geometry, and unreadable dense category labels.")), /* @__PURE__ */ React.createElement("div", { className: "grid grid-cols-1 gap-6" }, /* @__PURE__ */ React.createElement(
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
  const countLabel = (value, singular, plural = `${singular}s`) => {
    const numericValue = Number(value);
    const count = Number.isFinite(numericValue) ? numericValue : 0;
    return `${count.toLocaleString()} ${count === 1 ? singular : plural}`;
  };
  const formatDurationWords = (value) => {
    let totalSeconds = Number(value);
    if (!Number.isFinite(totalSeconds) && typeof value === "string") {
      const parts = value.trim().split(":").map((part) => Number(part));
      if (parts.length >= 2 && parts.length <= 3 && parts.every((part) => Number.isFinite(part))) {
        totalSeconds = parts.reduce((sum, part) => sum * 60 + part, 0);
      }
    }
    if (!Number.isFinite(totalSeconds) || totalSeconds < 0) {
      return null;
    }
    const rounded = Math.round(totalSeconds);
    const hours = Math.floor(rounded / 3600);
    const minutes = Math.floor(rounded % 3600 / 60);
    const seconds = rounded % 60;
    if (hours > 0) {
      return minutes > 0 ? `${hours} hr ${minutes} min` : `${hours} hr`;
    }
    if (minutes > 0) {
      return seconds > 0 && minutes < 10 ? `${minutes} min ${seconds} sec` : `${minutes} min`;
    }
    return `${seconds} sec`;
  };
  const formatByteSize = (value) => {
    const bytes = Number(value);
    if (!Number.isFinite(bytes) || bytes < 0) {
      return "Unknown";
    }
    if (bytes < 1024) {
      return `${bytes} B`;
    }
    if (bytes < 1024 * 1024) {
      return `${(bytes / 1024).toFixed(1)} KB`;
    }
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  };
  const PROVIDER_NAMES = {
    openai: "OpenAI",
    azure: "Azure OpenAI",
    anthropic: "Anthropic (Claude)",
    gemini: "Google Gemini",
    ollama: "Ollama",
    custom: "Custom endpoint"
  };
  const formatProviderName = (value) => {
    const rawValue = String(value || "").trim();
    return PROVIDER_NAMES[rawValue.toLowerCase()] || rawValue || "Not configured";
  };
  const TABLIST_NAVIGATION_KEYS = ["ArrowLeft", "ArrowRight", "Home", "End"];
  const handleTablistKeyDown = (event) => {
    if (!TABLIST_NAVIGATION_KEYS.includes(event.key)) {
      return;
    }
    const tabs = Array.from(event.currentTarget.querySelectorAll('[role="tab"]')).filter((tab) => !tab.disabled);
    const currentIndex = tabs.indexOf(document.activeElement);
    if (currentIndex === -1) {
      return;
    }
    event.preventDefault();
    let nextIndex = currentIndex;
    if (event.key === "ArrowRight") nextIndex = (currentIndex + 1) % tabs.length;
    if (event.key === "ArrowLeft") nextIndex = (currentIndex - 1 + tabs.length) % tabs.length;
    if (event.key === "Home") nextIndex = 0;
    if (event.key === "End") nextIndex = tabs.length - 1;
    tabs[nextIndex].focus();
    tabs[nextIndex].click();
  };
  function App() {
    var _a, _b, _c, _d, _e, _f, _g, _h, _i, _j, _k, _l, _m, _n, _o, _p, _q, _r, _s, _t, _u, _v, _w, _x, _y, _z, _A, _B, _C, _D, _E, _F, _G, _H, _I, _J, _K, _L, _M, _N, _O, _P, _Q, _R, _S, _T, _U, _V, _W, _X, _Y, _Z, __, _$, _aa, _ba, _ca, _da, _ea, _fa, _ga, _ha, _ia, _ja, _ka, _la, _ma, _na, _oa, _pa, _qa, _ra, _sa, _ta, _ua, _va, _wa, _xa, _ya, _za, _Aa, _Ba, _Ca, _Da, _Ea, _Fa, _Ga, _Ha, _Ia, _Ja;
    const THEME_PREFERENCE_KEY = "dt4sms_theme_preference";
    const OPERATOR_VOICE_PREFERENCE_KEY = "dt4sms_operator_voice";
    const OPERATOR_VOICE_OPTIONS = [
      { value: "direct", label: "Direct", description: "Short and to the point, focused on the next step." },
      { value: "evidence", label: "Evidence-led", description: "Focused on the evidence and how to verify it." },
      { value: "executive", label: "Executive", description: "Focused on risk, business impact, and cost." }
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
    const [m2614Profile, setM2614Profile] = useState({ has_data: false, message: "Loading M-26-14 readiness..." });
    const [m2614Compare, setM2614Compare] = useState({ has_data: false, message: "Choose two runs, then select Compare." });
    const [m2614ValidationCatalog, setM2614ValidationCatalog] = useState({
      status: "idle",
      capability: null,
      packs: [],
      error: ""
    });
    const [m2614ValidationSelection, setM2614ValidationSelection] = useState({
      packId: "",
      earliest: "-30d",
      latest: "now"
    });
    const [m2614ValidationState, setM2614ValidationState] = useState({ status: "idle", error: "" });
    const [m2614ValidationResult, setM2614ValidationResult] = useState(null);
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
    const [chatMission, setChatMission] = useState(() => loadChatMission());
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
    const [troubleshootKind, setTroubleshootKind] = useState("mcp");
    const [troubleshootDrafts, setTroubleshootDrafts] = useState({ mcp: null, llm: null });
    const [troubleshootOptions, setTroubleshootOptions] = useState({ check_save: true, check_connection: true });
    const [troubleshootRunning, setTroubleshootRunning] = useState(false);
    const [troubleshootResult, setTroubleshootResult] = useState(null);
    const [troubleshootCopied, setTroubleshootCopied] = useState("");
    const [serverCodeStatus, setServerCodeStatus] = useState(null);
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
    const [modelRanking, setModelRanking] = useState([]);
    const [llmAutoTune, setLlmAutoTune] = useState(true);
    const [llmTuningSummary, setLlmTuningSummary] = useState(null);
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
    const [capabilityActionStartedAt, setCapabilityActionStartedAt] = useState({});
    const [capabilityActionTick, setCapabilityActionTick] = useState(() => Date.now());
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
    const [knowledgeLibrary, setKnowledgeLibrary] = useState({ status: "idle", data: null, error: "", action: "", message: null });
    const [showAllLibraryGaps, setShowAllLibraryGaps] = useState(false);
    const libraryPackInputRef = useRef(null);
    const [headerHeight, setHeaderHeight] = useState(88);
    const [savedMCPConfigs, setSavedMCPConfigs] = useState({});
    const [loadedMCPConfigName, setLoadedMCPConfigName] = useState(null);
    const [isMCPSaveModalOpen, setIsMCPSaveModalOpen] = useState(false);
    const [mcpConfigName, setMCPConfigName] = useState("");
    const [mcpConfigDescription, setMCPConfigDescription] = useState("");
    const [mcpSaveDraft, setMCPSaveDraft] = useState(null);
    const [showMCPConfigForm, setShowMCPConfigForm] = useState(false);
    const [mcpTokenPlaceholder, setMCPTokenPlaceholder] = useState("Enter token");
    const [showSuggestedQueries, setShowSuggestedQueries] = useState(false);
    const [isWelcomeSplashOpen, setIsWelcomeSplashOpen] = useState(() => !initialWelcomeSplashDismissed);
    const [hasDismissedWelcomeSplash, setHasDismissedWelcomeSplash] = useState(() => initialWelcomeSplashDismissed);
    const [welcomeSplashDoNotShowAgain, setWelcomeSplashDoNotShowAgain] = useState(() => initialWelcomeSplashDismissed);
    const [themePreference, setThemePreference] = useState(() => {
      try {
        const savedTheme = localStorage.getItem(THEME_PREFERENCE_KEY);
        if (THEME_PREFERENCE_OPTIONS.some((option) => option.value === savedTheme)) {
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
    const currentAuthUser = (authStatus == null ? void 0 : authStatus.user) || null;
    const authAccountsEnabled = !!(authStatus == null ? void 0 : authStatus.auth_enabled);
    const headerAuthVisible = authAccountsEnabled && !!currentAuthUser && !!(authStatus == null ? void 0 : authStatus.authenticated);
    const headerAuthProviderLabel = (authStatus == null ? void 0 : authStatus.auth_provider) === "oidc" ? "OpenID Connect" : "Local account";
    const headerAuthRoleLabel = (currentAuthUser == null ? void 0 : currentAuthUser.role) ? `${currentAuthUser.role} access` : "Authenticated";
    const headerAuthAssignmentLabel = (currentAuthUser == null ? void 0 : currentAuthUser.mcp_config_name) ? `MCP ${currentAuthUser.mcp_config_name}` : "";
    const isMissionTab = workspaceTab === "mission";
    const isIntelligenceTab = workspaceTab === "intelligence";
    const isM2614Tab = workspaceTab === "m26-14";
    const isArtifactsTab = workspaceTab === "artifacts";
    const isCapabilitiesTab = workspaceTab === "capabilities";
    const isChatTab = isChatFullscreen && workspaceTab === "chat";
    const isSummaryTab = isSummaryFullscreen && workspaceTab === "summary-workspace";
    const operatorVoiceDefinition = OPERATOR_VOICE_OPTIONS.find((option) => option.value === operatorVoice) || OPERATOR_VOICE_OPTIONS[0];
    const isCapabilitiesOverview = isCapabilitiesTab && capabilitiesView === "overview";
    const isCapabilitiesRagView = isCapabilitiesTab && capabilitiesView === "rag";
    const isNeoTheme = resolvedTheme === "neo";
    const isDarkTheme = resolvedTheme === "dark" || isNeoTheme;
    const normalizedSelectedModel = (selectedModel || ((_c = config == null ? void 0 : config.llm) == null ? void 0 : _c.model) || "").trim().toLowerCase();
    const isOpenAIImageModelSelected = selectedProvider === "openai" && normalizedSelectedModel.startsWith("gpt-image-");
    const recommendedModelEntry = modelRanking.find((item) => item && item.recommended) || null;
    const selectedModelRanking = modelRanking.find((item) => {
      var _a2;
      return item && item.model === (selectedModel || ((_a2 = config == null ? void 0 : config.llm) == null ? void 0 : _a2.model));
    }) || null;
    const configAutoTune = (_d = config == null ? void 0 : config.llm) == null ? void 0 : _d.auto_tune;
    useEffect(() => {
      setLlmAutoTune(configAutoTune !== false);
    }, [configAutoTune]);
    const activeLlmTuning = llmTuningSummary || (config == null ? void 0 : config.llm_effective_tuning) || null;
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
    const workspaceShellClass = showWorkspaceRail ? "grid grid-cols-1 gap-6 lg:grid-cols-[minmax(0,1fr),280px] xl:grid-cols-[minmax(0,1fr),320px] 2xl:grid-cols-[minmax(0,1fr),360px]" : "grid grid-cols-1 gap-6";
    const workspaceMainClass = "min-w-0";
    const workspaceRailClass = showWorkspaceRail ? "min-w-0 lg:sticky lg:top-24 lg:self-start" : "min-w-0";
    const workspaceRailPanelClass = showWorkspaceRail ? "lg:flex lg:max-h-[calc(100vh-8.5rem)] lg:flex-col" : "";
    const workspaceRailListClass = showWorkspaceRail ? "lg:flex-1 lg:overflow-y-auto" : "";
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
    const capabilityCountSummary = (() => {
      const onCount = capabilityList.filter((capability) => capability.installed && capability.enabled && !capability.restart_required).length;
      const offCount = capabilityList.filter((capability) => capability.installed && !capability.enabled && !capability.restart_required).length;
      const restartCount = capabilityList.filter((capability) => capability.installed && capability.restart_required).length;
      const notInstalledCount = capabilityList.filter((capability) => capability.runtime_available && !capability.installed).length;
      const plannedCount = capabilityList.filter((capability) => !capability.runtime_available).length;
      const parts = [
        `${onCount} on`,
        offCount > 0 ? `${offCount} off` : null,
        restartCount > 0 ? `${restartCount} waiting for a restart` : null,
        notInstalledCount > 0 ? `${notInstalledCount} not installed` : null,
        plannedCount > 0 ? `${plannedCount} planned` : null
      ].filter(Boolean);
      return `${countLabel(capabilityList.length, "capability", "capabilities")}: ${parts.join(", ")}.`;
    })();
    const deeplinkCapability = ((_e = capabilitiesData == null ? void 0 : capabilitiesData.capabilities) == null ? void 0 : _e.splunk_deeplink_tools) || null;
    const exportCapability = ((_f = capabilitiesData == null ? void 0 : capabilitiesData.capabilities) == null ? void 0 : _f.export_tools) || null;
    const ragCapability = ((_g = capabilitiesData == null ? void 0 : capabilitiesData.capabilities) == null ? void 0 : _g.rag_chromadb) || null;
    const selectedCapabilityDetail = selectedCapabilityDetailName ? ((_h = capabilitiesData == null ? void 0 : capabilitiesData.capabilities) == null ? void 0 : _h[selectedCapabilityDetailName]) || null : null;
    const ragIndexSummary = (ragCapability == null ? void 0 : ragCapability.index_summary) && typeof ragCapability.index_summary === "object" ? ragCapability.index_summary : null;
    const ragIndexedDocumentCount = Number((ragIndexSummary == null ? void 0 : ragIndexSummary.document_count) || 0);
    const ragKnowledgeAssetSummary = (ragCapability == null ? void 0 : ragCapability.knowledge_asset_summary) && typeof (ragCapability == null ? void 0 : ragCapability.knowledge_asset_summary) === "object" ? ragCapability.knowledge_asset_summary : null;
    const ragIndexSourceTypes = (ragIndexSummary == null ? void 0 : ragIndexSummary.source_type_counts) && typeof ragIndexSummary.source_type_counts === "object" ? Object.entries(ragIndexSummary.source_type_counts) : [];
    const ragKnowledgeAssetTypeCounts = Object.entries(((_i = ragAssetWorkspace.summary) == null ? void 0 : _i.asset_type_counts) || (ragKnowledgeAssetSummary == null ? void 0 : ragKnowledgeAssetSummary.asset_type_counts) || {});
    const ragDisplayedAssets = Array.isArray(ragAssetWorkspace.assets) ? ragAssetWorkspace.assets : [];
    const ragDisplayedAssetCount = (_l = (_k = (_j = ragAssetWorkspace.summary) == null ? void 0 : _j.asset_count) != null ? _k : ragKnowledgeAssetSummary == null ? void 0 : ragKnowledgeAssetSummary.asset_count) != null ? _l : 0;
    const ragDisplayedAssetDir = ((_m = ragAssetWorkspace.summary) == null ? void 0 : _m.asset_dir) || (ragKnowledgeAssetSummary == null ? void 0 : ragKnowledgeAssetSummary.asset_dir) || "output/rag/assets";
    const ragSplLibraryAssetCount = ragDisplayedAssets.filter((asset) => String((asset == null ? void 0 : asset.asset_type) || "").toLowerCase() === SPL_LIBRARY_ASSET_TYPE).length;
    const m2614AdvisorCapability = ((_n = capabilitiesData == null ? void 0 : capabilitiesData.capabilities) == null ? void 0 : _n.m26_14_advisor) || null;
    const showM2614WorkspaceTab = !!((m2614AdvisorCapability == null ? void 0 : m2614AdvisorCapability.installed) && (m2614AdvisorCapability == null ? void 0 : m2614AdvisorCapability.enabled));
    const m2614PriorityObjectives = Object.values((m2614Profile == null ? void 0 : m2614Profile.priority_objectives) || {}).filter((item) => item && typeof item === "object");
    const m2614MaturityElements = Array.isArray(m2614Profile == null ? void 0 : m2614Profile.maturity_elements) ? m2614Profile.maturity_elements.filter((item) => item && typeof item === "object") : [];
    const m2614ValidationPacks = Array.isArray(m2614ValidationCatalog == null ? void 0 : m2614ValidationCatalog.packs) && m2614ValidationCatalog.packs.length > 0 ? m2614ValidationCatalog.packs : Array.isArray(m2614Profile == null ? void 0 : m2614Profile.validation_packs) ? m2614Profile.validation_packs : [];
    const selectedM2614ValidationPack = m2614ValidationPacks.find((pack) => (pack == null ? void 0 : pack.id) === m2614ValidationSelection.packId) || m2614ValidationPacks[0] || null;
    const m2614RecommendedPackIds = Array.isArray((_o = m2614Profile == null ? void 0 : m2614Profile.live_validation) == null ? void 0 : _o.recommended_pack_ids) ? m2614Profile.live_validation.recommended_pack_ids : [];
    const m2614RecommendedPacks = m2614ValidationPacks.filter((pack) => m2614RecommendedPackIds.includes(pack == null ? void 0 : pack.id));
    const canRunM2614Validation = !authAccountsEnabled || ["admin", "analyst"].includes(String((currentAuthUser == null ? void 0 : currentAuthUser.role) || "").trim().toLowerCase());
    const m2614ValidationSummary = ((_p = m2614ValidationResult == null ? void 0 : m2614ValidationResult.result) == null ? void 0 : _p.summary) && typeof m2614ValidationResult.result.summary === "object" ? m2614ValidationResult.result.summary : null;
    const m2614ValidationRows = Array.isArray((_q = m2614ValidationResult == null ? void 0 : m2614ValidationResult.result) == null ? void 0 : _q.rows) ? m2614ValidationResult.result.rows : [];
    const m2614ValidationAdvisory = (m2614ValidationResult == null ? void 0 : m2614ValidationResult.advisory) && typeof m2614ValidationResult.advisory === "object" ? m2614ValidationResult.advisory : null;
    const m2614ValidationProfileSnapshot = (m2614ValidationAdvisory == null ? void 0 : m2614ValidationAdvisory.profile_snapshot) && typeof m2614ValidationAdvisory.profile_snapshot === "object" ? m2614ValidationAdvisory.profile_snapshot : null;
    const m2614ValidationRagContext = (m2614ValidationAdvisory == null ? void 0 : m2614ValidationAdvisory.rag_context) && typeof m2614ValidationAdvisory.rag_context === "object" ? m2614ValidationAdvisory.rag_context : null;
    const m2614ValidationReusableQueries = Array.isArray(m2614ValidationRagContext == null ? void 0 : m2614ValidationRagContext.reusable_spl_queries) ? m2614ValidationRagContext.reusable_spl_queries.filter((candidate) => typeof (candidate == null ? void 0 : candidate.query) === "string" && candidate.query.trim()).slice(0, 3) : [];
    const m2614ValidationLlmAnalysis = (m2614ValidationAdvisory == null ? void 0 : m2614ValidationAdvisory.llm_analysis) && typeof m2614ValidationAdvisory.llm_analysis === "object" ? m2614ValidationAdvisory.llm_analysis : null;
    const ragLibraryStatusCounts = ((_r = ragAssetWorkspace.summary) == null ? void 0 : _r.library_status_counts) && typeof ragAssetWorkspace.summary.library_status_counts === "object" ? ragAssetWorkspace.summary.library_status_counts : (ragKnowledgeAssetSummary == null ? void 0 : ragKnowledgeAssetSummary.library_status_counts) && typeof ragKnowledgeAssetSummary.library_status_counts === "object" ? ragKnowledgeAssetSummary.library_status_counts : { checked_in: 0, checked_out: 0 };
    const ragCheckedInAssetCount = (_u = (_t = (_s = ragAssetWorkspace.summary) == null ? void 0 : _s.checked_in_asset_count) != null ? _t : ragKnowledgeAssetSummary == null ? void 0 : ragKnowledgeAssetSummary.checked_in_asset_count) != null ? _u : ragDisplayedAssets.filter((asset) => String((asset == null ? void 0 : asset.library_status) || "checked_in").toLowerCase() !== "checked_out").length;
    const ragCheckedOutAssetCount = (_x = (_w = (_v = ragAssetWorkspace.summary) == null ? void 0 : _v.checked_out_asset_count) != null ? _w : ragKnowledgeAssetSummary == null ? void 0 : ragKnowledgeAssetSummary.checked_out_asset_count) != null ? _x : ragDisplayedAssets.filter((asset) => String((asset == null ? void 0 : asset.library_status) || "").toLowerCase() === "checked_out").length;
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
    const canReindexRag = !!(ragCapability == null ? void 0 : ragCapability.installed) && !(ragCapability == null ? void 0 : ragCapability.restart_required);
    const ragInstallGuidance = (ragCapability == null ? void 0 : ragCapability.install_guidance) && typeof ragCapability.install_guidance === "object" ? ragCapability.install_guidance : null;
    const ragInstallPreflightWarning = typeof (ragInstallGuidance == null ? void 0 : ragInstallGuidance.preflight_warning) === "string" ? ragInstallGuidance.preflight_warning.trim() : "";
    const ragInstallPreflightReason = typeof (ragInstallGuidance == null ? void 0 : ragInstallGuidance.preflight_reason) === "string" ? ragInstallGuidance.preflight_reason.trim() : "";
    const ragInstallAlternativeMethods = Array.isArray(ragInstallGuidance == null ? void 0 : ragInstallGuidance.alternative_methods) ? ragInstallGuidance.alternative_methods : [];
    const ragPreferredInstallAlternativeMethod = ragInstallAlternativeMethods.find((method) => (method == null ? void 0 : method.app_action_supported) && typeof (method == null ? void 0 : method.strategy) === "string") || null;
    const ragInstallPackageIndexes = Array.isArray(ragInstallGuidance == null ? void 0 : ragInstallGuidance.package_indexes) ? ragInstallGuidance.package_indexes : [];
    const ragInstallStartedAt = (capabilityActionStartedAt == null ? void 0 : capabilityActionStartedAt.rag_chromadb) || 0;
    const ragInstallElapsedSeconds = ragActionInProgress === "install" && ragInstallStartedAt ? Math.max(0, Math.floor((capabilityActionTick - ragInstallStartedAt) / 1e3)) : 0;
    const headerMcpConnected = !!((_y = connectionInfo == null ? void 0 : connectionInfo.mcp) == null ? void 0 : _y.configured);
    const headerLlmDisplayLabel = String(((_z = connectionInfo == null ? void 0 : connectionInfo.llm) == null ? void 0 : _z.display_label) || "").trim() || "Not configured";
    const connectionInfoStatus = String((connectionInfo == null ? void 0 : connectionInfo.status) || "disconnected").toLowerCase();
    const canUseSplunkDeeplinks = !!(deeplinkCapability == null ? void 0 : deeplinkCapability.installed) && !!(deeplinkCapability == null ? void 0 : deeplinkCapability.enabled) && !(deeplinkCapability == null ? void 0 : deeplinkCapability.restart_required) && String((deeplinkCapability == null ? void 0 : deeplinkCapability.health_status) || "").toLowerCase() === "ready";
    const canUseExportTools = !!(exportCapability == null ? void 0 : exportCapability.installed) && !!(exportCapability == null ? void 0 : exportCapability.enabled) && !(exportCapability == null ? void 0 : exportCapability.restart_required) && String((exportCapability == null ? void 0 : exportCapability.health_status) || "").toLowerCase() === "ready";
    useEffect(() => {
      if (ragActionInProgress !== "install") {
        return void 0;
      }
      setCapabilityActionTick(Date.now());
      const intervalId = window.setInterval(() => {
        setCapabilityActionTick(Date.now());
      }, 1e3);
      return () => window.clearInterval(intervalId);
    }, [ragActionInProgress]);
    const formatCapabilityActionElapsed = (totalSeconds) => {
      const safeSeconds = Math.max(0, Number(totalSeconds) || 0);
      const minutes = Math.floor(safeSeconds / 60);
      const seconds = safeSeconds % 60;
      if (minutes > 0) {
        return `${minutes}m ${String(seconds).padStart(2, "0")}s`;
      }
      return `${seconds}s`;
    };
    const getRagInstallProgressMeta = (elapsedSeconds, installGuidance = null) => {
      const expectedDurationLabel = (installGuidance == null ? void 0 : installGuidance.expected_duration_label) || "This install can take a few minutes.";
      if (elapsedSeconds < 12) {
        return {
          title: "Preparing the Python environment",
          detail: "Checking Python and starting the ChromaDB install.",
          stageLabel: "Preparing install",
          notes: Array.isArray(installGuidance == null ? void 0 : installGuidance.operator_notes) ? installGuidance.operator_notes.slice(0, 2) : [],
          expectedDurationLabel
        };
      }
      if (elapsedSeconds < 45) {
        return {
          title: "Downloading ChromaDB dependencies",
          detail: "pip is downloading the packages ChromaDB needs.",
          stageLabel: "Downloading packages",
          notes: Array.isArray(installGuidance == null ? void 0 : installGuidance.operator_notes) ? installGuidance.operator_notes.slice(0, 2) : [],
          expectedDurationLabel
        };
      }
      if (elapsedSeconds < 120) {
        return {
          title: "Installing and verifying packages",
          detail: "Still installing. First installs on Windows often take longer.",
          stageLabel: "Installing packages",
          notes: Array.isArray(installGuidance == null ? void 0 : installGuidance.operator_notes) ? installGuidance.operator_notes.slice(0, 3) : [],
          expectedDurationLabel
        };
      }
      return {
        title: "Still working on the first-time install",
        detail: "The installer is still running. pip may still be building or unpacking large packages.",
        stageLabel: "Still installing",
        notes: Array.isArray(installGuidance == null ? void 0 : installGuidance.next_steps) ? installGuidance.next_steps.slice(0, 3) : [],
        expectedDurationLabel
      };
    };
    const getCapabilityActionError = (result, fallbackMessage) => {
      const detailPayload = (result == null ? void 0 : result.detail) && typeof result.detail === "object" ? result.detail : null;
      const details = (result == null ? void 0 : result.details) || (detailPayload == null ? void 0 : detailPayload.details) || null;
      const message = (detailPayload == null ? void 0 : detailPayload.message) || (result == null ? void 0 : result.message) || (result == null ? void 0 : result.detail) || fallbackMessage;
      return {
        message,
        details,
        result: detailPayload || result || null
      };
    };
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
      return parsedValue ? parsedValue.toLocaleString(void 0, { dateStyle: "medium", timeStyle: "short" }) : fallback;
    };
    const formatMissionSessionSelectionLabel = (value) => {
      const normalizedValue = String(value || "").trim();
      if (!normalizedValue || normalizedValue === "latest") {
        return "Latest run";
      }
      if (normalizedValue === "previous") {
        return "Previous run";
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
          label: "Run time unknown",
          ageLabel: "age unavailable",
          ageHours: null,
          badgeClass: isDarkTheme ? "bg-gray-900 text-gray-200 border border-gray-700" : "bg-gray-100 text-gray-700 border border-gray-200",
          summary: "These results come from the latest saved discovery run. Its run time was not recorded."
        };
      }
      const ageHours = Math.max(0, Math.floor((Date.now() - parsedValue.getTime()) / 36e5));
      const ageDays = Math.floor(ageHours / 24);
      const ageLabel = ageDays >= 1 ? `${ageDays} day${ageDays === 1 ? "" : "s"} old` : `${ageHours} hour${ageHours === 1 ? "" : "s"} old`;
      if (ageHours >= 72) {
        return {
          label: "Out of date",
          ageLabel,
          ageHours,
          badgeClass: isDarkTheme ? "bg-amber-950 text-amber-100 border border-amber-700" : "bg-amber-50 text-amber-800 border border-amber-200",
          summary: `The latest discovery run is ${ageLabel}. Run discovery again before you act on these results.`
        };
      }
      if (ageHours >= 24) {
        return {
          label: "Over a day old",
          ageLabel,
          ageHours,
          badgeClass: isDarkTheme ? "bg-blue-950 text-blue-100 border border-blue-700" : "bg-blue-50 text-blue-800 border border-blue-200",
          summary: `The latest discovery run is ${ageLabel}. Run discovery again for a more current picture.`
        };
      }
      return {
        label: "Up to date",
        ageLabel,
        ageHours,
        badgeClass: isDarkTheme ? "bg-emerald-950 text-emerald-100 border border-emerald-700" : "bg-emerald-50 text-emerald-800 border border-emerald-200",
        summary: `The latest discovery run is ${ageLabel}, so these results are current.`
      };
    };
    const discoveryStatusNormalized = normalizeDiscoveryStatusValue(discoveryStatus);
    const discoveryProgressPercent = Math.round(Math.max(0, Math.min(100, Number((progress == null ? void 0 : progress.percentage) || 0))));
    const discoveryEtaMethodLabel = String((progress == null ? void 0 : progress.eta_method) || "").trim() === "stage_calibrated" ? "Time left (estimate)" : "Time left";
    const discoveryEtaLabel = (progress == null ? void 0 : progress.eta_seconds) != null ? formatDiscoveryRuntimeDuration(progress.eta_seconds, "Calculating") : isMissionDiscoveryActive ? "Calibrating" : "Not active";
    const discoveryUpdatedLabel = discoveryLastUpdatedAt ? formatMissionDateTime(discoveryLastUpdatedAt, "Waiting for an update") : isMissionDiscoveryActive ? "Waiting for an update" : "No recent run";
    const discoveryCompletedLabel = discoveryCompletedAt ? formatMissionDateTime(discoveryCompletedAt, "Not completed yet") : discoveryStatusNormalized === "completed" ? "Completed now" : "Not completed yet";
    const discoveryResultSessionLabel = discoveryResultTimestamp ? formatMissionSessionSelectionLabel(discoveryResultTimestamp) : "No finished run";
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
    const discoveryPhaseLeadTitle = (discoveryActivePhase == null ? void 0 : discoveryActivePhase.title) || discoveryCurrentPhaseTitle || (discoveryLastRunOutcome == null ? void 0 : discoveryLastRunOutcome.phase_title) || "Not started";
    const discoveryStatusMeta = (() => {
      switch (discoveryStatusNormalized) {
        case "starting":
          return {
            label: "Starting discovery",
            shortValue: "Starting",
            bannerTitle: "Discovery is starting",
            statusBadgeClass: isDarkTheme ? "bg-amber-950 text-amber-100 border border-amber-700" : "bg-amber-50 text-amber-800 border border-amber-200",
            tonePanelClass: isDarkTheme ? "bg-amber-950/40 border-amber-700" : "bg-amber-50 border-amber-200",
            toneTextClass: isDarkTheme ? "text-amber-100" : "text-amber-900",
            dotClass: "bg-amber-500",
            progressFillClass: "bg-amber-500"
          };
        case "running":
          return {
            label: "Discovery running",
            shortValue: "Running",
            bannerTitle: "Discovery is running",
            statusBadgeClass: isDarkTheme ? "bg-indigo-950 text-indigo-100 border border-indigo-700" : "bg-indigo-50 text-indigo-800 border border-indigo-200",
            tonePanelClass: isDarkTheme ? "bg-indigo-950/50 border-indigo-700" : "bg-indigo-50 border-indigo-200",
            toneTextClass: isDarkTheme ? "text-indigo-100" : "text-indigo-950",
            dotClass: "bg-indigo-500",
            progressFillClass: "bg-indigo-600"
          };
        case "completed":
          return {
            label: "Discovery complete",
            shortValue: "Done",
            bannerTitle: "Reports are ready",
            statusBadgeClass: isDarkTheme ? "bg-emerald-950 text-emerald-100 border border-emerald-700" : "bg-emerald-50 text-emerald-800 border border-emerald-200",
            tonePanelClass: isDarkTheme ? "bg-emerald-950/45 border-emerald-700" : "bg-emerald-50 border-emerald-200",
            toneTextClass: isDarkTheme ? "text-emerald-100" : "text-emerald-900",
            dotClass: "bg-emerald-500",
            progressFillClass: "bg-emerald-600"
          };
        case "error":
          return {
            label: "Discovery issue",
            shortValue: "Issue",
            bannerTitle: "Discovery stopped with an error",
            statusBadgeClass: isDarkTheme ? "bg-rose-950 text-rose-100 border border-rose-700" : "bg-rose-50 text-rose-800 border border-rose-200",
            tonePanelClass: isDarkTheme ? "bg-rose-950/45 border-rose-700" : "bg-rose-50 border-rose-200",
            toneTextClass: isDarkTheme ? "text-rose-100" : "text-rose-900",
            dotClass: "bg-rose-500",
            progressFillClass: "bg-rose-600"
          };
        case "aborted":
          return {
            label: "Discovery stopped",
            shortValue: "Stopped",
            bannerTitle: "Discovery was stopped",
            statusBadgeClass: isDarkTheme ? "bg-orange-950 text-orange-100 border border-orange-700" : "bg-orange-50 text-orange-800 border border-orange-200",
            tonePanelClass: isDarkTheme ? "bg-orange-950/45 border-orange-700" : "bg-orange-50 border-orange-200",
            toneTextClass: isDarkTheme ? "text-orange-100" : "text-orange-900",
            dotClass: "bg-orange-500",
            progressFillClass: "bg-orange-600"
          };
        case "idle":
        default:
          return {
            label: "Discovery ready",
            shortValue: "Ready",
            bannerTitle: "Ready to run discovery",
            statusBadgeClass: isDarkTheme ? "bg-gray-900 text-gray-100 border border-gray-700" : "bg-gray-50 text-gray-800 border border-gray-200",
            tonePanelClass: isDarkTheme ? "bg-gray-900 border-gray-700" : "bg-gray-50 border-gray-200",
            toneTextClass: isDarkTheme ? "text-gray-100" : "text-gray-900",
            dotClass: "bg-gray-400",
            progressFillClass: "bg-slate-500"
          };
      }
    })();
    const discoveryNarrative = (() => {
      if (isMissionDiscoveryActive) {
        return discoveryActivePhase ? `${discoveryActivePhase.label}: ${progress.description || discoveryActivePhase.description || "in progress."}` : progress.description || "Discovery is running.";
      }
      if (discoveryStatusNormalized === "completed") {
        return discoveryReportCount > 0 ? `${countLabel(discoveryReportCount, "report")}${discoveryResultTimestamp ? ` from the ${discoveryResultSessionLabel} run` : ""} ${discoveryReportCount === 1 ? "is" : "are"} ready.` : "Discovery finished.";
      }
      if (discoveryStatusNormalized === "error") {
        return discoveryErrorMessage || "Discovery failed before it finished building reports.";
      }
      if (discoveryStatusNormalized === "aborted") {
        return "Discovery was stopped before it finished. Check the log or start a new run.";
      }
      return "Start a run here. You can switch tabs while it runs.";
    })();
    const missionDiscoveryMonitorCard = (() => {
      if (isMissionDiscoveryActive) {
        return {
          title: `${(discoveryActivePhase == null ? void 0 : discoveryActivePhase.label) || "Discovery"} in progress`,
          summary: progress.description || "Discovery is running.",
          detailLabel: discoveryEtaMethodLabel,
          detail: discoveryEtaLabel,
          ctaLabel: "Open Discovery"
        };
      }
      if (discoveryLastRunOutcome) {
        const outcomeTimestamp = discoveryLastRunOutcome.completed_at || discoveryLastRunOutcome.result_timestamp || discoveryCompletedAt;
        return {
          title: discoveryLastRunOutcome.title || "Last discovery run",
          summary: discoveryLastRunOutcome.summary || "Result of the most recent discovery run.",
          detailLabel: "Finished",
          detail: outcomeTimestamp ? formatMissionDateTime(outcomeTimestamp, "Time not recorded") : "Time not recorded",
          ctaLabel: "Review Discovery"
        };
      }
      return {
        title: "No discovery run yet",
        summary: "Run discovery from the Discovery tab. Its progress and results appear here.",
        detailLabel: "Finished",
        detail: "Not run yet",
        ctaLabel: "Open Discovery"
      };
    })();
    const selectedPackageSessionLabel = formatMissionSessionSelectionLabel(compareSelection.current);
    const activePackageBundle = exportBuildState.bundle || (exportCapability == null ? void 0 : exportCapability.latest_bundle) || null;
    const hasFreshPackageBuild = !!exportBuildState.bundle;
    const packageCardTitle = hasFreshPackageBuild ? "New report package" : "Last report package";
    const downloadPackageLabel = hasFreshPackageBuild ? "Download Package" : "Download Last Package";
    const packagePersonaLabel = workflowTab ? `${workflowTab.charAt(0).toUpperCase()}${workflowTab.slice(1)}` : "Persona";
    const packageTargetLabel = `${selectedPackageSessionLabel} reports, ${packagePersonaLabel} runbook, ${operatorVoiceDefinition.label} style`;
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
    const OPERATOR_VOICE_ADMIN_PREFIXES = {
      evidence: { summary: "", meta: "How to verify: " },
      executive: { summary: "Risk if ignored: ", meta: "Decision needed: " },
      direct: { summary: "", meta: "Next step: " }
    };
    const OPERATOR_VOICE_ANALYST_PREFIXES = {
      evidence: { summary: "", meta: "Proof: " },
      executive: { summary: "If confirmed: ", meta: "Why it matters: " },
      direct: { summary: "Check: ", meta: "Done when: " }
    };
    const buildOperatorVoiceAdminCard = (action, voice) => {
      const prefixes = OPERATOR_VOICE_ADMIN_PREFIXES[voice] || OPERATOR_VOICE_ADMIN_PREFIXES.direct;
      const why = getNormalizedLine(action == null ? void 0 : action.why);
      const nextStep = getNormalizedLine(action == null ? void 0 : action.next_step);
      const effort = getNormalizedLine(action == null ? void 0 : action.effort);
      return {
        title: getNormalizedLine(action == null ? void 0 : action.title, "Admin follow-up"),
        summary: why ? `${prefixes.summary}${why}` : "",
        meta: nextStep ? `${prefixes.meta}${nextStep}` : "",
        badge: effort && effort.toLowerCase() !== "unknown" ? `Effort: ${effort}` : ""
      };
    };
    const buildOperatorVoiceAnalystCard = (track, voice) => {
      const prefixes = OPERATOR_VOICE_ANALYST_PREFIXES[voice] || OPERATOR_VOICE_ANALYST_PREFIXES.direct;
      const question = getNormalizedLine(track == null ? void 0 : track.question);
      const successMetric = getNormalizedLine(track == null ? void 0 : track.success_metric);
      return {
        title: getNormalizedLine(track == null ? void 0 : track.title, "Investigation track"),
        summary: question ? `${prefixes.summary}${question}` : "",
        meta: successMetric ? `${prefixes.meta}${successMetric}` : ""
      };
    };
    const summarizeFindingEntry = (entry) => {
      const findings = Array.isArray(entry == null ? void 0 : entry.findings) ? entry.findings.filter(Boolean) : [];
      return getNormalizedLine(findings[0], "See the evidence entry for details.");
    };
    const latestMissionSession = (discoveryDashboard == null ? void 0 : discoveryDashboard.latest) || null;
    const missionOverview = (latestMissionSession == null ? void 0 : latestMissionSession.overview) || {};
    const missionStats = (latestMissionSession == null ? void 0 : latestMissionSession.stats) || {};
    const missionFreshness = getMissionFreshnessMeta((latestMissionSession == null ? void 0 : latestMissionSession.created_at) || (latestMissionSession == null ? void 0 : latestMissionSession.timestamp));
    const missionHasPreviousSession = !!(discoveryDashboard == null ? void 0 : discoveryDashboard.previous);
    const missionExecutiveHeadline = ((_B = (_A = latestMissionSession == null ? void 0 : latestMissionSession.personas) == null ? void 0 : _A.executive) == null ? void 0 : _B.headline) || `Readiness score is ${formatMissionMetricValue((_C = discoveryDashboard == null ? void 0 : discoveryDashboard.kpis) == null ? void 0 : _C.readiness_score)} out of 100, with ${countLabel((_D = discoveryDashboard == null ? void 0 : discoveryDashboard.kpis) == null ? void 0 : _D.recommendation_count, "recommendation")} to follow up.`;
    const workspaceMetricTone = {
      shellClass: isDarkTheme ? "bg-gray-900 border-gray-700" : "bg-white border-gray-200",
      labelClass: mutedTextClass,
      valueClass: headingClass
    };
    const describeMissionChange = (delta) => missionHasPreviousSession ? `${formatMissionTrendValue(delta)} since the previous run.` : "";
    const missionStatCards = [
      {
        label: "Readiness",
        value: `${formatMissionMetricValue((_E = discoveryDashboard == null ? void 0 : discoveryDashboard.kpis) == null ? void 0 : _E.readiness_score)}/100`,
        detail: describeMissionChange((_F = discoveryDashboard == null ? void 0 : discoveryDashboard.trends) == null ? void 0 : _F.readiness_delta),
        ...workspaceMetricTone
      },
      {
        label: "Hosts",
        value: formatMissionMetricValue(missionOverview.total_hosts),
        detail: `${countLabel(missionOverview.total_sources, "source")}.`,
        ...workspaceMetricTone
      },
      {
        label: "Indexes",
        value: formatMissionMetricValue((_G = discoveryDashboard == null ? void 0 : discoveryDashboard.kpis) == null ? void 0 : _G.total_indexes),
        detail: describeMissionChange((_H = discoveryDashboard == null ? void 0 : discoveryDashboard.trends) == null ? void 0 : _H.indexes_delta),
        ...workspaceMetricTone
      },
      {
        label: "Sourcetypes",
        value: formatMissionMetricValue((_I = discoveryDashboard == null ? void 0 : discoveryDashboard.kpis) == null ? void 0 : _I.total_sourcetypes),
        detail: describeMissionChange((_J = discoveryDashboard == null ? void 0 : discoveryDashboard.trends) == null ? void 0 : _J.sourcetypes_delta),
        ...workspaceMetricTone
      },
      {
        label: "Data in last 24 hours",
        value: missionOverview.data_volume_24h || "Unknown",
        detail: missionOverview.splunk_version ? `Splunk ${missionOverview.splunk_version}${missionOverview.license_state ? `, license ${missionOverview.license_state}` : ""}.` : "Splunk version was not recorded.",
        ...workspaceMetricTone
      },
      {
        label: "Recommendations",
        value: formatMissionMetricValue(missionStats.recommendation_count || ((_K = discoveryDashboard == null ? void 0 : discoveryDashboard.kpis) == null ? void 0 : _K.recommendation_count)),
        detail: describeMissionChange((_L = discoveryDashboard == null ? void 0 : discoveryDashboard.trends) == null ? void 0 : _L.recommendations_delta),
        ...workspaceMetricTone
      }
    ];
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
    const intelligenceHeadline = (() => {
      if (operatorVoice === "evidence") {
        return `${countLabel(intelligenceGapCount, "coverage gap")}, ${countLabel(intelligenceUseCaseCount, "investigation")}, and ${countLabel(intelligenceFindingCount, "evidence entry", "evidence entries")} to verify.`;
      }
      if (operatorVoice === "executive") {
        return `${countLabel(intelligenceGapCount, "coverage gap")} and ${countLabel(intelligenceUseCaseCount, "suggested investigation")} to weigh for funding.`;
      }
      return `${countLabel(intelligenceGapCount, "coverage gap")} and ${countLabel(intelligenceUseCaseCount, "investigation")} ready to act on.`;
    })();
    const intelligenceWhyNow = (() => {
      if (operatorVoice === "evidence") {
        return `Check the gaps, confirm the strongest evidence, and decide which investigations deserve analyst time. ${missionFreshness.summary}`;
      }
      if (operatorVoice === "executive") {
        return `Decide which gaps carry the most risk and which investigations to fund. ${missionFreshness.summary}`;
      }
      return `Start with the top gap and the top investigation below. ${missionFreshness.summary}`;
    })();
    const intelligenceSummaryCards = [
      {
        label: "Coverage gaps",
        value: formatMissionMetricValue(intelligenceGapCount),
        detail: (intelligenceTopGap == null ? void 0 : intelligenceTopGap.gap) ? `Top gap: ${intelligenceTopGap.gap}` : "No high-priority gaps found.",
        ...workspaceMetricTone
      },
      {
        label: "Investigations",
        value: formatMissionMetricValue(intelligenceUseCaseCount),
        detail: (intelligenceTopUseCase == null ? void 0 : intelligenceTopUseCase.title) ? `Top: ${intelligenceTopUseCase.title}` : "No investigations suggested.",
        ...workspaceMetricTone
      },
      {
        label: "Evidence entries",
        value: formatMissionMetricValue(intelligenceFindingCount),
        detail: (intelligenceTopFinding == null ? void 0 : intelligenceTopFinding.title) ? `First: ${intelligenceTopFinding.title}` : "No evidence recorded.",
        ...workspaceMetricTone
      },
      {
        label: "Hosts",
        value: formatMissionMetricValue(v2Overview.total_hosts),
        detail: `${formatMissionMetricValue(v2Overview.total_indexes)} indexes, ${formatMissionMetricValue(v2Overview.total_sourcetypes)} sourcetypes, ${formatMissionMetricValue(v2Overview.total_sources)} sources.`,
        ...workspaceMetricTone
      }
    ];
    const getFirstNormalizedLine = (value) => {
      const entries = Array.isArray(value) ? value : [value];
      for (const entry of entries) {
        const text = entry && typeof entry === "object" ? entry.action || entry.step || entry.title || entry.description : entry;
        const normalized = getNormalizedLine(text);
        if (normalized) {
          return normalized;
        }
      }
      return "";
    };
    const v2RiskRegister = Array.isArray(v2Blueprint == null ? void 0 : v2Blueprint.risk_register) ? v2Blueprint.risk_register : [];
    const findingsAdminItems = v2CoverageGaps.map((gap, idx) => {
      const title = getNormalizedLine(gap == null ? void 0 : gap.gap, `Coverage gap ${idx + 1}`);
      const matchingRisk = v2RiskRegister.find((entry) => getNormalizedLine(entry == null ? void 0 : entry.risk) === title) || null;
      const card = buildOperatorVoiceAdminCard({
        title,
        why: gap == null ? void 0 : gap.why_it_matters,
        next_step: getFirstNormalizedLine(matchingRisk == null ? void 0 : matchingRisk.mitigation)
      }, operatorVoice);
      return {
        title: card.title,
        summary: card.summary,
        meta: card.meta,
        badge: `${formatOperatorPriorityLabel(gap == null ? void 0 : gap.priority)} priority`,
        badgeClass: getOperatorPriorityClasses(gap == null ? void 0 : gap.priority)
      };
    });
    const findingsAnalystItems = v2UseCases.map((useCase, idx) => {
      const successMetric = getFirstNormalizedLine(useCase == null ? void 0 : useCase.success_metrics) || getNormalizedLine(useCase == null ? void 0 : useCase.business_value);
      const card = buildOperatorVoiceAnalystCard({
        title: getNormalizedLine((useCase == null ? void 0 : useCase.title) || (useCase == null ? void 0 : useCase.name), `Investigation ${idx + 1}`),
        question: (useCase == null ? void 0 : useCase.description) || (useCase == null ? void 0 : useCase.scenario) || (useCase == null ? void 0 : useCase.use_case),
        success_metric: successMetric
      }, operatorVoice);
      const complexity = getNormalizedLine(useCase == null ? void 0 : useCase.implementation_complexity).toLowerCase();
      return {
        ...card,
        badge: complexity ? `${complexity.charAt(0).toUpperCase()}${complexity.slice(1)} effort` : "",
        badgeClass: `${panelMutedClass} ${mutedTextClass}`
      };
    });
    const findingsExecutiveItems = (() => {
      const businessValueItems = v2UseCases.map((useCase, idx) => ({
        title: getNormalizedLine((useCase == null ? void 0 : useCase.title) || (useCase == null ? void 0 : useCase.name), `Investigation ${idx + 1}`),
        summary: getNormalizedLine(useCase == null ? void 0 : useCase.business_value)
      })).filter((item) => item.summary);
      if (businessValueItems.length > 0) {
        return businessValueItems;
      }
      return intelligenceNotablePatterns.map((pattern, idx) => ({
        title: formatIntelligencePatternLabel((pattern == null ? void 0 : pattern.title) || (pattern == null ? void 0 : pattern.category), `Pattern ${idx + 1}`),
        summary: getNormalizedLine((pattern == null ? void 0 : pattern.description) || (pattern == null ? void 0 : pattern.signal))
      })).filter((item) => item.summary);
    })();
    const findingsExecutiveNextStep = findingsExecutiveItems.find((item) => {
      var _a2;
      return item.title !== ((_a2 = findingsAnalystItems[0]) == null ? void 0 : _a2.title);
    }) || findingsExecutiveItems[0] || null;
    const findingsNextSteps = [
      findingsAdminItems[0] ? { ...findingsAdminItems[0], audience: "Admin" } : null,
      findingsAnalystItems[0] ? { ...findingsAnalystItems[0], audience: "Analyst" } : null,
      findingsExecutiveNextStep ? { ...findingsExecutiveNextStep, audience: "Executive" } : null
    ].filter(Boolean);
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
      "Suggest a weekly check we can run to catch drift, anomalies, and hidden failures.",
      "Translate the discovery output into executive-ready priorities with business impact and verification steps."
    ];
    const handleSettingsChange = () => {
    };
    const getApiKeyPlaceholderForProvider = (provider, hasStoredKey = false) => {
      if (hasStoredKey) {
        return "(Already Configured)";
      }
      const normalizedProvider = normalizeProvider(provider);
      if (normalizedProvider === "ollama") {
        return "Optional for secured or proxied Ollama";
      }
      if (normalizedProvider === "custom") {
        return "Optional for local LLMs";
      }
      return "Enter API key";
    };
    const handleApiKeyChange = () => {
      setApiKeyPlaceholder(getApiKeyPlaceholderForProvider(selectedProvider));
      handleSettingsChange();
    };
    const SECURITY_ROLE_OPTIONS = ["admin", "analyst", "viewer"];
    const SECURITY_TOKEN_SCOPE_OPTIONS = {
      external_api: [
        {
          value: "rag:search",
          label: "Knowledge Base Search",
          description: "Search the Knowledge Base (read-only)."
        },
        {
          value: "rag:assets:read",
          label: "Knowledge Base Read",
          description: "Read the index summary, the item list, and item details."
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
      { id: "access", label: "Security", icon: "fa-key" },
      { id: "appearance", label: "Appearance", icon: "fa-adjust" },
      { id: "troubleshoot", label: "Troubleshoot", icon: "fa-stethoscope" }
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
        warning: "bg-amber-500 text-gray-900",
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
    const handleKeyActivate = (event, callback) => {
      if (event.key === "Enter" || event.key === " ") {
        event.preventDefault();
        callback();
      }
    };
    const handleDialogKeyDown = (event, onClose) => {
      if (event.key === "Escape") {
        event.preventDefault();
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
      (_M = config == null ? void 0 : config.llm) == null ? void 0 : _M.provider,
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
      document.documentElement.setAttribute("data-color-scheme", resolvedTheme === "light" ? "light" : "dark");
    }, [resolvedTheme]);
    const syncWelcomeSplashPreference = (dismissed) => {
      const shouldDismiss = !!dismissed;
      setHasDismissedWelcomeSplash(shouldDismiss);
      persistWelcomeSplashDismissed(shouldDismiss);
    };
    const applyThemePreference = (nextTheme) => {
      setThemePreference(nextTheme);
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
    const [isDiscoveryRunDetailsOpen, setIsDiscoveryRunDetailsOpen] = useState(false);
    const wsRef = useRef(null);
    const headerRef = useRef(null);
    const discoveryLogContainerRef = useRef(null);
    const discoveryReportViewerRef = useRef(null);
    const discoveryViewerScrollPendingRef = useRef(false);
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
      const status = normalizeDiscoveryStatusValue(discoveryStatus);
      setIsDiscoveryRunDetailsOpen(status === "starting" || status === "running" || status === "error" || status === "aborted");
    }, [discoveryStatus]);
    const handleDiscoveryRunDetailsToggle = (event) => {
      const isOpen = event.currentTarget.open;
      setIsDiscoveryRunDetailsOpen(isOpen);
      if (isOpen) {
        window.requestAnimationFrame(() => scrollDiscoveryLogToBottom("auto"));
      }
    };
    useEffect(() => {
      if (!discoveryHasFocusedReport || !discoveryViewerScrollPendingRef.current) {
        return;
      }
      discoveryViewerScrollPendingRef.current = false;
      const viewer = discoveryReportViewerRef.current;
      if (viewer && window.matchMedia && window.matchMedia("(max-width: 1023px)").matches) {
        viewer.scrollIntoView({ behavior: "smooth", block: "start" });
      }
    }, [discoveryHasFocusedReport, selectedReport, reportContent]);
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
      saveChatMission(chatMission);
    }, [chatMission]);
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
      loadAuthStatus();
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
      if (isM2614Tab) {
        refreshM2614Workspace();
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
      if (isCapabilitiesRagView) {
        loadKnowledgeLibrary();
      }
    }, [isCapabilitiesRagView]);
    useEffect(() => {
      var _a2, _b2;
      if (!isCapabilitiesRagView || ((_b2 = (_a2 = knowledgeLibrary.data) == null ? void 0 : _a2.refresh) == null ? void 0 : _b2.state) !== "running") {
        return void 0;
      }
      const timer = setTimeout(() => loadKnowledgeLibrary({ silent: true }), 3e3);
      return () => clearTimeout(timer);
    }, [isCapabilitiesRagView, knowledgeLibrary.data]);
    useEffect(() => {
      if (!showM2614WorkspaceTab && workspaceTab === "m26-14") {
        setWorkspaceTab("mission");
      }
    }, [showM2614WorkspaceTab, workspaceTab]);
    useEffect(() => {
      if (m2614ValidationPacks.length === 0) {
        return;
      }
      const hasSelectedPack = m2614ValidationPacks.some((pack) => (pack == null ? void 0 : pack.id) === m2614ValidationSelection.packId);
      if (!hasSelectedPack) {
        setM2614ValidationSelection((prev) => {
          var _a2;
          return {
            ...prev,
            packId: ((_a2 = m2614ValidationPacks[0]) == null ? void 0 : _a2.id) || ""
          };
        });
      }
    }, [m2614ValidationPacks, m2614ValidationSelection.packId]);
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
      wsRef.current.onmessage = (event) => {
        const message = JSON.parse(event.data);
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
              setDiscoveryErrorMessage("You stopped discovery.");
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
          eyebrow: "Local AI model",
          title: "Run discovery with a local AI model?",
          summary: "Your AI model runs locally, so discovery will be slower than with a hosted provider.",
          details: [
            "It can take several minutes, depending on the model and your hardware.",
            "You can switch tabs while it runs. The Discovery tab shows progress.",
            "You can stop the run at any time from the Discovery tab."
          ],
          confirmLabel: "Run Discovery",
          cancelLabel: "Cancel"
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
          addMessage("warning", { message: "⚠️ Discovery stopped" });
          if (result == null ? void 0 : result.discovery) {
            applyDiscoveryRuntimeSnapshot(result.discovery);
          } else {
            setDiscoveryStatus("aborted");
            setDiscoveryErrorMessage("You stopped discovery.");
            setDiscoveryCompletedAt((/* @__PURE__ */ new Date()).toISOString());
            setDiscoveryStartTime(null);
            setElapsedTime(0);
          }
        }
      } catch (error) {
        addMessage("error", { message: `Could not stop discovery: ${error.message}` });
      }
    };
    const abortDiscovery = async () => {
      setDiscoveryActionDialog({
        action: "abort",
        tone: "rose",
        icon: "fa-stop-circle",
        eyebrow: "Stop discovery",
        title: "Stop the current discovery run?",
        summary: "Discovery stops now. The log and the finished stages stay on screen so you can review them.",
        details: [
          "The run is marked as stopped.",
          "No more reports are created for this run."
        ],
        confirmLabel: "Stop Discovery",
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
    const openM2614Workspace = () => {
      setWorkspaceTab("m26-14");
      refreshM2614Workspace();
    };
    const openFindingsWorkspace = () => {
      setWorkspaceTab("intelligence");
      refreshIntelligenceWorkspace();
    };
    const MODULE_WORKSPACE_OPENERS = {
      "m26-14": openM2614Workspace
    };
    const moduleWorkspaceTabs = Object.values((capabilitiesData == null ? void 0 : capabilitiesData.capabilities) || {}).filter((capability) => {
      var _a2;
      return (capability == null ? void 0 : capability.installed) && (capability == null ? void 0 : capability.enabled) && ((_a2 = capability == null ? void 0 : capability.workspace) == null ? void 0 : _a2.id);
    }).map((capability) => {
      const workspaceId = String(capability.workspace.id);
      const open = MODULE_WORKSPACE_OPENERS[workspaceId];
      if (!open) {
        return null;
      }
      return {
        id: workspaceId,
        label: String(capability.workspace.label || capability.title || workspaceId),
        description: String(capability.workspace.description || ""),
        isActive: workspaceTab === workspaceId,
        open
      };
    }).filter(Boolean);
    const headerButtonClass = isDarkTheme ? "border-gray-600 bg-gray-800 text-gray-100 hover:bg-gray-700" : "border-gray-300 bg-white text-gray-700 hover:bg-gray-100";
    const secondaryButtonClass = headerButtonClass;
    const headerConnectionMeta = (() => {
      if (connectionInfoStatus === "connected") {
        return {
          label: "Connected",
          summary: "The Splunk MCP server and AI model are set up.",
          dotClass: "bg-green-500"
        };
      }
      if (connectionInfoStatus === "partial") {
        return {
          label: "Setup incomplete",
          summary: headerMcpConnected ? "The Splunk MCP server is set up. Add an AI model in Settings." : "The AI model is set up. Add a Splunk MCP server in Settings.",
          dotClass: "bg-amber-500"
        };
      }
      if (connectionInfoStatus === "error") {
        return {
          label: "Status unavailable",
          summary: "The app could not read its connection settings.",
          dotClass: "bg-red-500"
        };
      }
      return {
        label: "Not connected",
        summary: "Add your Splunk MCP server and AI model in Settings.",
        dotClass: "bg-red-500"
      };
    })();
    const headerAuthSummary = headerAuthVisible ? `Signed in as ${currentAuthUser.username}. ${headerAuthRoleLabel}. ${headerAuthProviderLabel}.${headerAuthAssignmentLabel ? ` ${headerAuthAssignmentLabel}.` : ""}` : "";
    const getWorkspaceTabClass = (isActive) => `dt4sms-shell-tab inline-flex flex-shrink-0 items-center gap-2 whitespace-nowrap border-b-2 px-3 py-2.5 text-sm transition-colors ${isActive ? isDarkTheme ? "border-indigo-300 text-white font-semibold" : "border-indigo-600 text-indigo-700 font-semibold" : isDarkTheme ? "border-transparent text-gray-300 hover:text-white hover:border-gray-500" : "border-transparent text-gray-600 hover:text-gray-900 hover:border-gray-300"}`;
    const discoveryTabIndicator = (() => {
      if (isMissionDiscoveryActive) {
        const percent = Math.max(discoveryProgressPercent, 1);
        return {
          text: `${percent}%`,
          textClass: isDarkTheme ? "text-amber-200" : "text-amber-800",
          srText: `discovery is running, ${percent}% done`
        };
      }
      if (discoveryStatusNormalized === "error") {
        return {
          text: "Failed",
          textClass: isDarkTheme ? "text-red-300" : "text-red-700",
          srText: "the last discovery run failed"
        };
      }
      return null;
    })();
    const renderOperatorVoiceSelect = () => /* @__PURE__ */ React.createElement(
      "label",
      {
        className: `dt4sms-voice-control inline-flex items-center gap-2 rounded-lg border px-2.5 py-1 text-sm ${isDarkTheme ? "border-gray-600 bg-gray-800 text-gray-100" : "border-gray-300 bg-white text-gray-900"}`,
        title: operatorVoiceDefinition.description
      },
      /* @__PURE__ */ React.createElement("span", { className: `text-xs font-semibold ${mutedTextClass}` }, "Style"),
      /* @__PURE__ */ React.createElement(
        "select",
        {
          "data-testid": "workspace-operator-voice-select",
          value: operatorVoice,
          onChange: (event) => setOperatorVoice(event.target.value),
          className: `rounded border px-2 py-1 text-xs ${isDarkTheme ? "border-gray-600 bg-gray-900 text-gray-100" : "border-gray-300 bg-white text-gray-900"}`,
          "aria-label": "Wording style"
        },
        OPERATOR_VOICE_OPTIONS.map((option) => /* @__PURE__ */ React.createElement("option", { key: option.value, value: option.value }, option.label))
      )
    );
    const renderWorkspaceRefreshButton = (onRefresh, label) => /* @__PURE__ */ React.createElement(
      "button",
      {
        type: "button",
        onClick: onRefresh,
        className: `dt4sms-shell-action inline-flex items-center gap-2 rounded-lg border px-3 py-1.5 text-sm font-medium transition-colors ${headerButtonClass}`,
        title: label,
        "aria-label": label
      },
      /* @__PURE__ */ React.createElement("i", { className: "fas fa-sync", "aria-hidden": "true" }),
      /* @__PURE__ */ React.createElement("span", null, "Refresh")
    );
    const renderWorkspaceMetricCard = (card) => /* @__PURE__ */ React.createElement("div", { key: card.label, className: `dt4sms-neo-metric rounded-xl border px-4 py-4 ${card.shellClass}` }, /* @__PURE__ */ React.createElement("div", { className: `text-xs uppercase tracking-wide ${card.labelClass}` }, card.label), /* @__PURE__ */ React.createElement("div", { className: `mt-2 text-2xl font-semibold ${card.valueClass}` }, card.value), card.detail && /* @__PURE__ */ React.createElement("div", { className: `mt-2 text-xs leading-5 ${subtextClass}` }, card.detail));
    const renderFindingsList = ({ key, icon, iconClass, title, audience, items, emptyText }) => /* @__PURE__ */ React.createElement(
      "section",
      {
        key,
        "data-testid": `findings-list-${key}`,
        "aria-labelledby": `findings-list-${key}-heading`,
        className: `dt4sms-neo-section rounded-xl border p-4 ${isDarkTheme ? "bg-gray-950 border-gray-800" : "bg-white border-gray-200"}`
      },
      /* @__PURE__ */ React.createElement("div", { className: "flex items-start justify-between gap-2 mb-3" }, /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("div", { className: "flex items-center gap-2" }, /* @__PURE__ */ React.createElement("i", { className: `fas ${icon} ${iconClass}`, "aria-hidden": "true" }), /* @__PURE__ */ React.createElement("h3", { id: `findings-list-${key}-heading`, className: `text-sm font-semibold ${headingClass}` }, title)), /* @__PURE__ */ React.createElement("p", { className: `mt-1 text-xs ${mutedTextClass}` }, audience)), items.length > 0 && /* @__PURE__ */ React.createElement("span", { className: `rounded-full px-2 py-0.5 border text-xs ${panelMutedClass} ${mutedTextClass}` }, items.length)),
      items.length === 0 ? /* @__PURE__ */ React.createElement("div", { className: `text-xs ${mutedTextClass}` }, emptyText) : /* @__PURE__ */ React.createElement("ul", { className: "space-y-2 text-xs" }, items.map((item, idx) => /* @__PURE__ */ React.createElement("li", { key: `findings-${key}-${idx}`, "data-testid": `findings-list-${key}-item`, className: `dt4sms-neo-item ${isDarkTheme ? "bg-gray-900 border-gray-800" : "bg-gray-50 border-gray-200"} border rounded-lg px-3 py-3` }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-wrap items-start justify-between gap-2" }, /* @__PURE__ */ React.createElement("div", { "data-testid": "findings-item-title", className: `font-medium ${headingClass}` }, item.title), item.badge && /* @__PURE__ */ React.createElement("span", { className: `rounded-full px-2 py-0.5 border text-xs ${item.badgeClass}` }, item.badge)), item.summary && /* @__PURE__ */ React.createElement("div", { className: `mt-1 leading-5 ${subtextClass}` }, item.summary), item.meta && /* @__PURE__ */ React.createElement("div", { className: `mt-2 ${mutedTextClass}` }, item.meta))))
    );
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
          error: error.message || "Could not load the library."
        }));
      }
    };
    const LIBRARY_SOURCE_LABELS = {
      security_content: "Splunk Security Content",
      splunkbase: "Splunkbase",
      help_docs: "help.splunk.com"
    };
    const getLibraryErrorMessage = (result, fallback) => {
      if (typeof (result == null ? void 0 : result.detail) === "string" && result.detail) {
        return result.detail;
      }
      if (typeof (result == null ? void 0 : result.message) === "string" && result.message) {
        return result.message;
      }
      return fallback;
    };
    const loadKnowledgeLibrary = async (options = {}) => {
      if (!options.silent) {
        setKnowledgeLibrary((prev) => ({ ...prev, status: "loading", error: "" }));
      }
      try {
        const response = await fetch("/api/knowledge-library/status");
        const result = await response.json().catch(() => ({}));
        if (!response.ok) {
          throw new Error(getLibraryErrorMessage(result, `HTTP ${response.status}`));
        }
        setKnowledgeLibrary((prev) => ({ ...prev, status: "success", data: result, error: "" }));
      } catch (error) {
        console.error("Failed to load library health:", error);
        setKnowledgeLibrary((prev) => ({ ...prev, status: "error", error: error.message || "Could not check library health." }));
      }
    };
    const runKnowledgeLibraryRequest = async (action, url, options = {}) => {
      setKnowledgeLibrary((prev) => ({ ...prev, action, message: null }));
      try {
        const response = await fetch(url, options);
        const result = await response.json().catch(() => ({}));
        if (!response.ok) {
          throw new Error(getLibraryErrorMessage(result, `HTTP ${response.status}`));
        }
        setKnowledgeLibrary((prev) => ({ ...prev, status: "success", data: result, error: "", action: "" }));
        return result;
      } catch (error) {
        console.error(`Library request failed (${action}):`, error);
        setKnowledgeLibrary((prev) => ({
          ...prev,
          action: "",
          message: { type: "error", text: error.message || "That did not work. Try again." }
        }));
        return null;
      }
    };
    const setKnowledgeLibraryOnline = (allowOnline) => runKnowledgeLibraryRequest("settings", "/api/knowledge-library/settings", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ allow_online_sources: !!allowOnline })
    });
    const refreshKnowledgeLibrarySources = () => runKnowledgeLibraryRequest("refresh", "/api/knowledge-library/refresh", { method: "POST" });
    const importKnowledgeLibraryPack = async (file) => {
      var _a2;
      if (!file) {
        return;
      }
      const formData = new FormData();
      formData.append("file", file);
      const result = await runKnowledgeLibraryRequest("import", "/api/knowledge-library/pack/import", { method: "POST", body: formData });
      const imported = Array.isArray((_a2 = result == null ? void 0 : result.import_result) == null ? void 0 : _a2.imported) ? result.import_result.imported : [];
      if (imported.length > 0) {
        setKnowledgeLibrary((prev) => ({
          ...prev,
          message: { type: "success", text: `Imported ${imported.map((name) => LIBRARY_SOURCE_LABELS[name] || name).join(", ")}.` }
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
    const getM2614StatusClasses = (status) => {
      switch (String(status || "").toLowerCase()) {
        case "ready":
        case "observed":
          return isDarkTheme ? "bg-emerald-900 text-emerald-100 border border-emerald-700" : "bg-emerald-100 text-emerald-800 border border-emerald-300";
        case "partial":
        case "warn":
        case "degraded":
          return isDarkTheme ? "bg-amber-900 text-amber-100 border border-amber-700" : "bg-amber-100 text-amber-900 border border-amber-300";
        case "gap":
          return isDarkTheme ? "bg-rose-900 text-rose-100 border border-rose-700" : "bg-rose-100 text-rose-900 border border-rose-300";
        case "unknown":
        default:
          return isDarkTheme ? "bg-slate-800 text-slate-100 border border-slate-600" : "bg-slate-100 text-slate-800 border border-slate-300";
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
        case "disabled":
          return "Off";
        case "restart-required":
          return "Restart required";
        case "unavailable":
          return "Planned";
        default:
          return formatTokenLabel(status) || "Unknown";
      }
    };
    const formatM2614StatusLabel = (status) => {
      switch (String(status || "").toLowerCase()) {
        case "very_low":
          return "Very low";
        default:
          return formatTokenLabel(status) || "Unknown";
      }
    };
    const formatCapabilityCategoryLabel = (category) => {
      switch (String(category || "").toLowerCase()) {
        case "rag":
          return "Search";
        case "tool_pack":
          return "Tools";
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
          return "Monitored System Notes";
        case "connected_system_context":
          return "Connected System Notes";
        case "integration_context":
          return "Integration Notes";
        case "runbook_context":
          return "Runbook Notes";
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
      const match = basename.match(/^dt4sms_(?:export|report_package)_(\d{8})_(\d{6})_([a-z]+)(?:_([a-z]+))?(?:_.+)?$/i);
      if (!match) {
        return formatTokenLabel(basename.replace(/bundle/gi, "package")) || raw;
      }
      const [, datePart, timePart, persona, voice] = match;
      const voiceOption = OPERATOR_VOICE_OPTIONS.find((option) => option.value === String(voice || "").toLowerCase());
      const audienceLabel = `${formatTokenLabel(persona) || "Admin"} runbook`;
      const styleLabel = voiceOption ? `, ${voiceOption.label} style` : "";
      return `${audienceLabel}${styleLabel}, run of ${formatMissionSessionSelectionLabel(`${datePart}_${timePart}`)}`;
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
    const getCapabilityDisplayTitle = (name) => {
      var _a2, _b2;
      return ((_b2 = (_a2 = capabilitiesData == null ? void 0 : capabilitiesData.capabilities) == null ? void 0 : _a2[name]) == null ? void 0 : _b2.title) || formatTokenLabel(name) || "Capability";
    };
    const describeCapabilityActionSuccess = (name, action, result) => {
      const title = getCapabilityDisplayTitle(name);
      switch (action) {
        case "disable":
          return `${title} is off.`;
        case "uninstall":
          return `${title} was removed. Its settings are kept if you install it again.`;
        case "config":
          return `Saved settings for ${title}.`;
        default:
          return (result == null ? void 0 : result.message) || `${title} updated.`;
      }
    };
    const runCapabilityAction = async (name, action, payload = null) => {
      var _a2;
      setCapabilityNotice(null);
      setCapabilityActionState((prev) => ({
        ...prev,
        [name]: action
      }));
      setCapabilityActionStartedAt((prev) => ({
        ...prev,
        [name]: Date.now()
      }));
      try {
        const response = await fetch(`/api/capabilities/${name}/${action}`, {
          method: "POST",
          headers: payload ? { "Content-Type": "application/json" } : void 0,
          body: payload ? JSON.stringify(payload) : void 0
        });
        const result = await response.json();
        if (!response.ok) {
          const capabilityError = getCapabilityActionError(result, `${action} failed`);
          const requestError = new Error(capabilityError.message || `${action} failed`);
          requestError.details = capabilityError.details;
          requestError.result = capabilityError.result;
          throw requestError;
        }
        setCapabilityNotice({
          type: "success",
          capability: name,
          action,
          message: describeCapabilityActionSuccess(name, action, result),
          details: (result == null ? void 0 : result.details) || null
        });
        await loadCapabilities();
      } catch (error) {
        console.error(`Capability action failed (${name}/${action}):`, error);
        setCapabilityNotice({
          type: "error",
          capability: name,
          action,
          message: error.message || "That did not work. Try again.",
          details: (error == null ? void 0 : error.details) || ((_a2 = error == null ? void 0 : error.result) == null ? void 0 : _a2.details) || null
        });
        await loadCapabilities();
      } finally {
        setCapabilityActionState((prev) => {
          const next = { ...prev };
          delete next[name];
          return next;
        });
        setCapabilityActionStartedAt((prev) => {
          const next = { ...prev };
          delete next[name];
          return next;
        });
        if (action !== "install") {
          setTimeout(() => setCapabilityNotice(null), 3500);
        }
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
        const launchedWindow = window.open("", "_blank");
        if (launchedWindow && !launchedWindow.closed) {
          try {
            launchedWindow.opener = null;
          } catch (error) {
            console.debug("Unable to clear opener for Splunk window:", error);
          }
          launchedWindow.location.href = directUrl;
        } else {
          const fallbackWindow = window.open(directUrl, "_blank", "noopener,noreferrer");
          if (!fallbackWindow) {
            setCapabilityNotice({
              type: "error",
              message: "Unable to open Splunk in a new tab. Allow pop-ups for this site and retry."
            });
            setTimeout(() => setCapabilityNotice(null), 3500);
          }
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
      return /* @__PURE__ */ React.createElement("div", { "data-testid": buildTestId("intelligence-panel"), className: "mt-3 space-y-2" }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-wrap gap-2 text-xs" }, fitStatus && /* @__PURE__ */ React.createElement("span", { "data-testid": buildTestId("fit-status"), className: `rounded-full px-2 py-0.5 border ${getSplEnvironmentFitClasses(fitStatus)}` }, "Environment Fit: ", formatSplIntelligenceLabel(fitStatus, "Unknown")), validationStatus && /* @__PURE__ */ React.createElement("span", { "data-testid": buildTestId("validation-status"), className: `rounded-full px-2 py-0.5 border ${getSplValidationClasses(validationStatus)}` }, "Validation: ", formatSplIntelligenceLabel(validationStatus, "Unknown")), (reuseTier || knownGood) && /* @__PURE__ */ React.createElement("span", { "data-testid": buildTestId("reuse-tier"), className: `rounded-full px-2 py-0.5 border ${getSplReuseTierClasses(reuseTier, knownGood)}` }, "Reuse: ", knownGood ? "Known Good" : formatSplIntelligenceLabel(reuseTier, "Candidate")), (executionCount > 0 || successCount > 0 || failureCount > 0) && /* @__PURE__ */ React.createElement("span", { "data-testid": buildTestId("feedback-counts"), className: `rounded-full px-2 py-0.5 border ${isDarkTheme ? "bg-gray-900 border-gray-700 text-gray-200" : "bg-white border-gray-300 text-gray-700"}` }, "Observed Runs: ", successCount, " success / ", failureCount, " failure")), (fitReason || reuseGuidance) && /* @__PURE__ */ React.createElement("div", { "data-testid": buildTestId("intelligence-notes"), className: `text-xs ${subtextClass}` }, [fitReason, reuseGuidance].filter(Boolean).join(" ")));
    };
    const importKnowledgeAssetToLibrary = async (payload, options = {}) => {
      var _a2;
      if (!payload || typeof payload !== "object") {
        return null;
      }
      const fallbackSuccessMessage = String(options.successMessage || "Saved to the Knowledge Base.").trim();
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
        successMessage: "SPL query saved to the Knowledge Base.",
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
      const splActionClass = "inline-flex items-center rounded-md border px-2 py-1 text-xs font-medium transition-colors";
      return /* @__PURE__ */ React.createElement("div", { className: `flex flex-wrap items-center gap-2 ${options.className || ""}` }, canUseSplunkDeeplinks && /* @__PURE__ */ React.createElement(
        "button",
        {
          type: "button",
          onClick: () => openSplunkSearch(trimmedQuery, deeplinkOptions),
          className: `${splActionClass} ${secondaryButtonClass}`,
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
          className: `${splActionClass} ${!isRagBusy ? secondaryButtonClass : `cursor-not-allowed border-transparent ${isDarkTheme ? "bg-gray-700 text-gray-400" : "bg-gray-200 text-gray-600"}`}`,
          title: "Save this query to the SPL Library in the Knowledge Base"
        },
        /* @__PURE__ */ React.createElement("i", { className: "fas fa-bookmark mr-1" }),
        ragActionInProgress === "import-asset" ? "Saving..." : "Save to Library"
      ), options.allowUseInChat !== false && /* @__PURE__ */ React.createElement(
        "button",
        {
          type: "button",
          onClick: () => useSplQueryInChat(trimmedQuery, options),
          className: `${splActionClass} ${secondaryButtonClass}`,
          title: "Bring this query into Chat"
        },
        /* @__PURE__ */ React.createElement("i", { className: "fas fa-comments mr-1" }),
        "Use in Chat"
      ), options.allowCopy !== false && /* @__PURE__ */ React.createElement(
        "button",
        {
          type: "button",
          onClick: () => copyToClipboard(trimmedQuery),
          className: `${splActionClass} ${secondaryButtonClass}`,
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
      return /* @__PURE__ */ React.createElement("div", { className: "space-y-2 mt-3", "data-testid": "chat-capability-reusable-query-list" }, /* @__PURE__ */ React.createElement("div", { className: `text-xs font-semibold uppercase tracking-wider ${mutedTextClass}` }, "Reusable SPL Candidates"), reusableQueries.map((candidate, candidateIdx) => {
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
        })), /* @__PURE__ */ React.createElement("div", { className: "mt-2 flex flex-wrap gap-2 text-xs" }, (reuseTier || knownGood) && /* @__PURE__ */ React.createElement("span", { "data-testid": "chat-capability-reusable-query-reuse-tier", className: `rounded-full px-2 py-0.5 border ${getSplReuseTierClasses(reuseTier, knownGood)}` }, "Reuse: ", knownGood ? "Known Good" : formatSplIntelligenceLabel(reuseTier, "Candidate")), fitStatus && /* @__PURE__ */ React.createElement("span", { "data-testid": "chat-capability-reusable-query-fit-status", className: `rounded-full px-2 py-0.5 border ${getSplEnvironmentFitClasses(fitStatus)}` }, "Environment Fit: ", formatSplIntelligenceLabel(fitStatus, "Unknown")), validationStatus && /* @__PURE__ */ React.createElement("span", { "data-testid": "chat-capability-reusable-query-validation-status", className: `rounded-full px-2 py-0.5 border ${getSplValidationClasses(validationStatus)}` }, "Validation: ", formatSplIntelligenceLabel(validationStatus, "Unknown")), (successCount > 0 || failureCount > 0) && /* @__PURE__ */ React.createElement("span", { "data-testid": "chat-capability-reusable-query-feedback-counts", className: `rounded-full px-2 py-0.5 border ${isDarkTheme ? "bg-gray-800 border-gray-600 text-gray-200" : "bg-gray-100 border-gray-300 text-gray-700"}` }, "Observed Runs: ", successCount, " success / ", failureCount, " failure")), /* @__PURE__ */ React.createElement("pre", { "data-testid": "chat-capability-reusable-query", className: `mt-2 max-h-32 overflow-auto rounded-lg border px-3 py-3 text-xs whitespace-pre-wrap font-mono ${isDarkTheme ? "bg-gray-950 border-gray-700 text-gray-100" : "bg-gray-50 border-gray-200 text-gray-900"}` }, query));
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
          capability: name,
          action: "config",
          message: "Settings must be valid JSON before you save them."
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
    const loadM2614Profile = async (timestamp = compareSelection.current || "latest") => {
      try {
        const params = new URLSearchParams();
        if (timestamp) params.set("timestamp", timestamp);
        const response = await fetch(`/api/discovery/m26-14/profile?${params.toString()}`);
        const result = await response.json();
        if (!response.ok) {
          throw new Error((result == null ? void 0 : result.detail) || (result == null ? void 0 : result.message) || `HTTP ${response.status}`);
        }
        setM2614Profile(result);
        return result;
      } catch (error) {
        console.error("Failed to load M-26-14 profile:", error);
        const fallbackResult = { has_data: false, message: error.message || "Failed to load M-26-14 profile." };
        setM2614Profile(fallbackResult);
        return fallbackResult;
      }
    };
    const loadM2614Compare = async (current = compareSelection.current || "latest", baseline = compareSelection.baseline || "previous") => {
      try {
        const params = new URLSearchParams();
        if (current) params.set("current", current);
        if (baseline) params.set("baseline", baseline);
        const response = await fetch(`/api/discovery/m26-14/compare?${params.toString()}`);
        const result = await response.json();
        if (!response.ok) {
          throw new Error((result == null ? void 0 : result.detail) || (result == null ? void 0 : result.message) || `HTTP ${response.status}`);
        }
        setM2614Compare(result);
        return result;
      } catch (error) {
        console.error("Failed to load M-26-14 compare:", error);
        const fallbackResult = { has_data: false, message: error.message || "Failed to load M-26-14 compare." };
        setM2614Compare(fallbackResult);
        return fallbackResult;
      }
    };
    const loadM2614ValidationPacks = async () => {
      try {
        const response = await fetch("/api/discovery/m26-14/validation-packs");
        const result = await response.json();
        if (!response.ok) {
          throw new Error((result == null ? void 0 : result.detail) || (result == null ? void 0 : result.message) || `HTTP ${response.status}`);
        }
        setM2614ValidationCatalog({
          status: "success",
          capability: (result == null ? void 0 : result.capability) || null,
          packs: Array.isArray(result == null ? void 0 : result.packs) ? result.packs : [],
          error: ""
        });
        return result;
      } catch (error) {
        console.error("Failed to load M-26-14 validation packs:", error);
        setM2614ValidationCatalog({
          status: "error",
          capability: null,
          packs: [],
          error: error.message || "Failed to load M-26-14 validation packs."
        });
        return { status: "error", packs: [], message: error.message || "Failed to load M-26-14 validation packs." };
      }
    };
    const refreshM2614Workspace = (options = {}) => {
      const current = options.current || compareSelection.current || "latest";
      const baseline = options.baseline || compareSelection.baseline || "previous";
      loadM2614Profile(current);
      loadM2614Compare(current, baseline);
      loadM2614ValidationPacks();
    };
    const runM2614Validation = async () => {
      if (!(selectedM2614ValidationPack == null ? void 0 : selectedM2614ValidationPack.id)) {
        setM2614ValidationState({ status: "error", error: "Choose a check before you run it." });
        return;
      }
      setM2614ValidationState({ status: "loading", error: "" });
      try {
        const response = await fetch("/api/discovery/m26-14/validate", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            pack_id: selectedM2614ValidationPack.id,
            timestamp: compareSelection.current || "latest",
            earliest: m2614ValidationSelection.earliest,
            latest: m2614ValidationSelection.latest
          })
        });
        const result = await response.json();
        if (!response.ok) {
          throw new Error((result == null ? void 0 : result.detail) || (result == null ? void 0 : result.message) || `HTTP ${response.status}`);
        }
        setM2614ValidationResult(result);
        setM2614ValidationState({ status: "success", error: "" });
      } catch (error) {
        console.error("Failed to run M-26-14 validation:", error);
        setM2614ValidationState({ status: "error", error: error.message || "The check could not run." });
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
    const refreshM2614CompareSelection = () => {
      refreshM2614Workspace({ current: compareSelection.current, baseline: compareSelection.baseline });
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
          throw new Error((result == null ? void 0 : result.detail) || (result == null ? void 0 : result.message) || "Could not load item details.");
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
          detailError: error.message || "Could not load item details."
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
          message: "Add a title for the pasted text."
        });
        setTimeout(() => setCapabilityNotice(null), 3500);
        return;
      }
      if (!usingFileUpload && !trimmedContent) {
        setCapabilityNotice({
          type: "error",
          message: "Paste some text or choose a supported file to import."
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
        const confirmed = window.confirm(`Check out "${assetTitle || "this item"}"? It stays stored, but chat and previews will ignore it until you check it back in.`);
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
          message: "Enter a question before building a preview."
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
          throw new Error((result == null ? void 0 : result.detail) || (result == null ? void 0 : result.message) || "Could not build the preview.");
        }
        setRagAssetWorkspace((prev) => ({
          ...prev,
          contextPreview: (result == null ? void 0 : result.details) || null,
          error: ""
        }));
        setCapabilityNotice({
          type: "success",
          message: (result == null ? void 0 : result.message) || "Preview ready."
        });
      } catch (error) {
        console.error("Failed to build RAG context preview:", error);
        setCapabilityNotice({
          type: "error",
          message: error.message || "Could not build the preview."
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
      if (isCapabilitiesRagView) {
        loadKnowledgeLibrary({ silent: true });
      }
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
        return /* @__PURE__ */ React.createElement("div", { className: `rounded-xl border p-4 ${panelMutedClass}` }, /* @__PURE__ */ React.createElement("div", { className: `text-xs uppercase tracking-wider ${mutedTextClass}` }, "Current Setup"), /* @__PURE__ */ React.createElement("div", { className: `mt-2 text-sm font-semibold ${headingClass}` }, "Local Search Profile"), /* @__PURE__ */ React.createElement("div", { className: `grid grid-cols-1 gap-3 mt-3 text-sm sm:grid-cols-2 ${subtextClass}` }, /* @__PURE__ */ React.createElement("div", null, "Source directory: ", ((_a2 = capability == null ? void 0 : capability.config) == null ? void 0 : _a2.source_dir) || "output"), /* @__PURE__ */ React.createElement("div", null, "Max files scanned: ", ((_b2 = capability == null ? void 0 : capability.config) == null ? void 0 : _b2.max_files) || 8), /* @__PURE__ */ React.createElement("div", null, "Max scan characters: ", ((_c2 = capability == null ? void 0 : capability.config) == null ? void 0 : _c2.max_scan_chars) || 12e3), /* @__PURE__ */ React.createElement("div", null, "Snippet size: ", ((_d2 = capability == null ? void 0 : capability.config) == null ? void 0 : _d2.max_block_chars) || 420)), /* @__PURE__ */ React.createElement("div", { className: `mt-3 text-xs ${mutedTextClass}` }, "Allowed file types: ", Array.isArray((_e2 = capability == null ? void 0 : capability.config) == null ? void 0 : _e2.allowed_extensions) && capability.config.allowed_extensions.length > 0 ? capability.config.allowed_extensions.join(", ") : ".md, .txt, .json"));
      }
      if (capability.name === "rag_chromadb") {
        const indexSummary = (capability == null ? void 0 : capability.index_summary) && typeof capability.index_summary === "object" ? capability.index_summary : null;
        const knowledgeAssetSummary = (capability == null ? void 0 : capability.knowledge_asset_summary) && typeof capability.knowledge_asset_summary === "object" ? capability.knowledge_asset_summary : null;
        const indexSourceTypes = (indexSummary == null ? void 0 : indexSummary.source_type_counts) && typeof indexSummary.source_type_counts === "object" ? Object.entries(indexSummary.source_type_counts) : [];
        const knowledgeAssetTypes = (knowledgeAssetSummary == null ? void 0 : knowledgeAssetSummary.asset_type_counts) && typeof knowledgeAssetSummary.asset_type_counts === "object" ? Object.entries(knowledgeAssetSummary.asset_type_counts) : [];
        return /* @__PURE__ */ React.createElement("div", { className: `rounded-xl border p-4 ${panelMutedClass}` }, /* @__PURE__ */ React.createElement("div", { className: `text-xs uppercase tracking-wider ${mutedTextClass}` }, "Current Setup"), /* @__PURE__ */ React.createElement("div", { className: `mt-2 text-sm font-semibold ${headingClass}` }, "Knowledge Base"), /* @__PURE__ */ React.createElement("div", { className: `grid grid-cols-1 gap-3 mt-3 text-sm sm:grid-cols-2 ${subtextClass}` }, /* @__PURE__ */ React.createElement("div", null, "Indexed documents: ", (indexSummary == null ? void 0 : indexSummary.document_count) || 0), /* @__PURE__ */ React.createElement("div", null, "Source files indexed: ", (indexSummary == null ? void 0 : indexSummary.source_file_count) || 0), /* @__PURE__ */ React.createElement("div", null, "Imported items: ", (knowledgeAssetSummary == null ? void 0 : knowledgeAssetSummary.asset_count) || 0), /* @__PURE__ */ React.createElement("div", null, "Imported files folder: ", (knowledgeAssetSummary == null ? void 0 : knowledgeAssetSummary.asset_dir) || ((_f2 = capability == null ? void 0 : capability.config) == null ? void 0 : _f2.asset_dir) || "output/rag/assets")), /* @__PURE__ */ React.createElement("div", { className: `mt-3 text-xs ${mutedTextClass}` }, "Index folder: ", ((_g2 = capability == null ? void 0 : capability.config) == null ? void 0 : _g2.storage_dir) || "output/rag/chromadb"), (indexSummary == null ? void 0 : indexSummary.last_indexed_at) && /* @__PURE__ */ React.createElement("div", { className: `mt-1 text-xs ${mutedTextClass}` }, "Last indexed: ", formatMissionDateTime(indexSummary.last_indexed_at)), (indexSourceTypes.length > 0 || knowledgeAssetTypes.length > 0) && /* @__PURE__ */ React.createElement("div", { className: "grid grid-cols-1 gap-3 mt-4 lg:grid-cols-2" }, /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("div", { className: `text-xs font-medium mb-2 ${headingClass}` }, "Indexed by Source"), /* @__PURE__ */ React.createElement("div", { className: "flex flex-wrap gap-2 text-xs" }, indexSourceTypes.length > 0 ? indexSourceTypes.map(([sourceType, count]) => /* @__PURE__ */ React.createElement("span", { key: sourceType, className: `rounded-full px-2 py-0.5 border ${isDarkTheme ? "bg-gray-800 text-gray-200 border-gray-600" : "bg-white text-gray-700 border-gray-300"}` }, formatCapabilitySourceTypeLabel(sourceType), ": ", count)) : /* @__PURE__ */ React.createElement("span", { className: mutedTextClass }, "Nothing indexed yet."))), /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("div", { className: `text-xs font-medium mb-2 ${headingClass}` }, "Imported by Type"), /* @__PURE__ */ React.createElement("div", { className: "flex flex-wrap gap-2 text-xs" }, knowledgeAssetTypes.length > 0 ? knowledgeAssetTypes.map(([assetType, count]) => /* @__PURE__ */ React.createElement("span", { key: assetType, className: `rounded-full px-2 py-0.5 border ${isDarkTheme ? "bg-gray-800 text-gray-200 border-gray-600" : "bg-white text-gray-700 border-gray-300"}` }, formatKnowledgeAssetTypeLabel(assetType), ": ", count)) : /* @__PURE__ */ React.createElement("span", { className: mutedTextClass }, "Nothing imported yet.")))));
      }
      if (capability.name === "splunk_deeplink_tools") {
        return /* @__PURE__ */ React.createElement("div", { className: `rounded-xl border p-4 ${panelMutedClass}` }, /* @__PURE__ */ React.createElement("div", { className: `text-xs uppercase tracking-wider ${mutedTextClass}` }, "Current Setup"), /* @__PURE__ */ React.createElement("div", { className: `mt-2 text-sm font-semibold ${headingClass}` }, "Splunk Web Address"), /* @__PURE__ */ React.createElement("div", { className: `grid grid-cols-1 gap-3 mt-3 text-sm sm:grid-cols-2 ${subtextClass}` }, /* @__PURE__ */ React.createElement("div", null, "Splunk Web address: ", capability.resolved_web_base_url || "Not found"), /* @__PURE__ */ React.createElement("div", null, "Found from: ", formatTokenLabel(capability.base_url_source) || "Not found"), /* @__PURE__ */ React.createElement("div", null, "Default app: ", capability.default_app || ((_h2 = capability == null ? void 0 : capability.config) == null ? void 0 : _h2.default_app) || "search"), /* @__PURE__ */ React.createElement("div", null, "Default time range starts: ", ((_i2 = capability == null ? void 0 : capability.config) == null ? void 0 : _i2.default_earliest) || "-24h")), capability.sample_search_url && /* @__PURE__ */ React.createElement("div", { className: "mt-3" }, /* @__PURE__ */ React.createElement(
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
        return /* @__PURE__ */ React.createElement("div", { className: `rounded-xl border p-4 ${panelMutedClass}` }, /* @__PURE__ */ React.createElement("div", { className: `text-xs uppercase tracking-wider ${mutedTextClass}` }, "Current Setup"), /* @__PURE__ */ React.createElement("div", { className: `mt-2 text-sm font-semibold ${headingClass}` }, "Chart Settings"), /* @__PURE__ */ React.createElement("div", { className: `grid grid-cols-1 gap-3 mt-3 text-sm sm:grid-cols-2 ${subtextClass}` }, /* @__PURE__ */ React.createElement("div", null, "Charts in chat: ", capability.preview_enabled ? "On" : "Off"), /* @__PURE__ */ React.createElement("div", null, "Max points per chart: ", capability.max_preview_points || ((_j2 = capability == null ? void 0 : capability.config) == null ? void 0 : _j2.max_preview_points) || 8), /* @__PURE__ */ React.createElement("div", null, "Chart types: ", Array.isArray(capability.supported_chart_types) && capability.supported_chart_types.length > 0 ? capability.supported_chart_types.join(", ") : "line, bar"), /* @__PURE__ */ React.createElement("div", null, "Result types: ", Array.isArray(capability.supported_query_shapes) && capability.supported_query_shapes.length > 0 ? capability.supported_query_shapes.map((shape) => formatTokenLabel(shape)).join(", ") : "Time Series, Aggregation")));
      }
      if (capability.name === "export_tools") {
        return /* @__PURE__ */ React.createElement("div", { className: `rounded-xl border p-4 ${panelMutedClass}` }, /* @__PURE__ */ React.createElement("div", { className: `text-xs uppercase tracking-wider ${mutedTextClass}` }, "Current Setup"), /* @__PURE__ */ React.createElement("div", { className: `mt-2 text-sm font-semibold ${headingClass}` }, "Report Package Settings"), /* @__PURE__ */ React.createElement("div", { className: `grid grid-cols-1 gap-3 mt-3 text-sm sm:grid-cols-2 ${subtextClass}` }, /* @__PURE__ */ React.createElement("div", null, "Reports folder: ", capability.output_dir || ((_k2 = capability == null ? void 0 : capability.config) == null ? void 0 : _k2.source_dir) || "output"), /* @__PURE__ */ React.createElement("div", null, "Packages folder: ", capability.export_dir || ((_l2 = capability == null ? void 0 : capability.config) == null ? void 0 : _l2.export_dir) || "output/exports"), /* @__PURE__ */ React.createElement("div", null, "Runs available: ", capability.available_session_count || 0), /* @__PURE__ */ React.createElement("div", null, "Packages built: ", capability.bundle_count || 0)), /* @__PURE__ */ React.createElement("div", { className: `mt-3 text-xs ${mutedTextClass}` }, "Package contents: ", Array.isArray(capability.supported_outputs) && capability.supported_outputs.length > 0 ? capability.supported_outputs.map((output) => formatExportOutputLabel(output)).join(", ") : "ZIP Package, Manifest, Summary Note"), /* @__PURE__ */ React.createElement("div", { className: `mt-1 text-xs ${mutedTextClass}` }, "Max files per package: ", capability.max_bundle_files || ((_m2 = capability == null ? void 0 : capability.config) == null ? void 0 : _m2.max_bundle_files) || 12), ((_n2 = capability.latest_bundle) == null ? void 0 : _n2.name) && /* @__PURE__ */ React.createElement("div", { className: "mt-3" }, /* @__PURE__ */ React.createElement(
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
      const restartNote = capability.restart_required ? "Restart the app to finish turning this on." : !capability.installed && capability.requires_restart_on_install ? "After you install this, restart the app before you turn it on." : "";
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
            onClick: (event) => event.stopPropagation(),
            onKeyDown: (event) => handleDialogKeyDown(event, closeCapabilityDetail),
            tabIndex: -1
          },
          /* @__PURE__ */ React.createElement("div", { className: `flex-shrink-0 flex items-start justify-between gap-4 border-b px-4 py-4 sm:px-6 sm:py-5 ${isDarkTheme ? "border-gray-700" : "border-gray-200"}` }, /* @__PURE__ */ React.createElement("div", { className: "min-w-0" }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-wrap items-center gap-2" }, /* @__PURE__ */ React.createElement("span", { className: `inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium ${getCapabilityStatusClasses(capability.health_status || "unknown")}` }, formatCapabilityStatusLabel(capability.health_status || "unknown")), /* @__PURE__ */ React.createElement("span", { className: `inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium ${isDarkTheme ? "bg-gray-800 text-gray-200 border border-gray-600" : "bg-gray-100 text-gray-700 border border-gray-300"}` }, formatCapabilityCategoryLabel(capability.category || "capability")), /* @__PURE__ */ React.createElement("span", { className: `inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium ${isDarkTheme ? "bg-sky-950 text-sky-100 border border-sky-800" : "bg-sky-50 text-sky-800 border border-sky-200"}` }, availabilityLabel)), /* @__PURE__ */ React.createElement("h3", { id: "capability-detail-title", className: `mt-3 text-lg font-semibold sm:text-xl ${headingClass}` }, capability.title || capability.name), /* @__PURE__ */ React.createElement("p", { className: `mt-2 text-sm ${subtextClass}` }, capability.description || "Optional feature.")), /* @__PURE__ */ React.createElement(
            "button",
            {
              type: "button",
              onClick: closeCapabilityDetail,
              className: `inline-flex items-center gap-2 rounded-lg border px-3 py-1.5 text-sm font-medium ${isDarkTheme ? "border-gray-600 bg-gray-800 text-gray-100 hover:bg-gray-700" : "border-gray-300 bg-white text-gray-800 hover:bg-gray-50"}`
            },
            /* @__PURE__ */ React.createElement("i", { className: "fa-solid fa-xmark", "aria-hidden": "true" }),
            /* @__PURE__ */ React.createElement("span", null, "Close")
          )),
          /* @__PURE__ */ React.createElement("div", { className: "min-h-0 flex-1 overflow-y-auto px-4 py-4 sm:px-6 sm:py-5" }, /* @__PURE__ */ React.createElement("div", { className: "grid grid-cols-1 gap-4 xl:grid-cols-[minmax(0,1.15fr),minmax(280px,0.85fr)]" }, /* @__PURE__ */ React.createElement("div", { className: "space-y-4" }, /* @__PURE__ */ React.createElement("div", { className: "grid grid-cols-1 gap-4 lg:grid-cols-2" }, /* @__PURE__ */ React.createElement("div", { className: `rounded-xl border p-4 ${panelMutedClass}` }, /* @__PURE__ */ React.createElement("div", { className: `text-xs uppercase tracking-wider ${mutedTextClass}` }, "What It Does"), /* @__PURE__ */ React.createElement("div", { className: `mt-2 text-sm leading-6 ${subtextClass}` }, capability.purpose || capability.description || "Optional add-on for Splunk Discovery Tool.")), /* @__PURE__ */ React.createElement("div", { className: `rounded-xl border p-4 ${panelMutedClass}` }, /* @__PURE__ */ React.createElement("div", { className: `text-xs uppercase tracking-wider ${mutedTextClass}` }, "Why Use It"), /* @__PURE__ */ React.createElement("div", { className: `mt-2 text-sm leading-6 ${subtextClass}` }, capability.intent || "Turn it on when you need it."))), /* @__PURE__ */ React.createElement("div", { className: `rounded-xl border p-4 ${panelMutedClass}` }, /* @__PURE__ */ React.createElement("div", { className: `text-xs uppercase tracking-wider ${mutedTextClass}` }, "Features"), capabilitySet.length > 0 ? /* @__PURE__ */ React.createElement("ul", { className: `mt-3 space-y-2 text-sm ${subtextClass}` }, capabilitySet.map((item, itemIndex) => /* @__PURE__ */ React.createElement("li", { key: `${capability.name}-capability-set-${itemIndex}`, className: "flex items-start gap-2" }, /* @__PURE__ */ React.createElement("span", { className: `mt-1 h-1.5 w-1.5 rounded-full ${isDarkTheme ? "bg-sky-300" : "bg-sky-600"}` }), /* @__PURE__ */ React.createElement("span", null, item)))) : /* @__PURE__ */ React.createElement("div", { className: `mt-3 text-sm ${mutedTextClass}` }, "No feature list yet.")), renderCapabilityRuntimeSnapshot(capability)), /* @__PURE__ */ React.createElement("div", { className: "space-y-4" }, /* @__PURE__ */ React.createElement("div", { className: `rounded-xl border p-4 ${panelMutedClass}` }, /* @__PURE__ */ React.createElement("div", { className: `text-xs uppercase tracking-wider ${mutedTextClass}` }, "Status"), /* @__PURE__ */ React.createElement("div", { className: "grid grid-cols-3 gap-3 mt-3" }, /* @__PURE__ */ React.createElement("div", { className: `rounded-lg border px-3 py-2 ${isDarkTheme ? "bg-gray-900 border-gray-700" : "bg-white border-gray-300"}` }, /* @__PURE__ */ React.createElement("div", { className: `text-xs uppercase tracking-wide ${mutedTextClass}` }, "Setup"), /* @__PURE__ */ React.createElement("div", { className: `mt-1 text-sm font-semibold ${headingClass}` }, formatCapabilityInstallMethodLabel(capability.install_method || "unknown"))), /* @__PURE__ */ React.createElement("div", { className: `rounded-lg border px-3 py-2 ${isDarkTheme ? "bg-gray-900 border-gray-700" : "bg-white border-gray-300"}` }, /* @__PURE__ */ React.createElement("div", { className: `text-xs uppercase tracking-wide ${mutedTextClass}` }, "Installed"), /* @__PURE__ */ React.createElement("div", { className: `mt-1 text-sm font-semibold ${headingClass}` }, capability.installed ? "Yes" : "No")), /* @__PURE__ */ React.createElement("div", { className: `rounded-lg border px-3 py-2 ${isDarkTheme ? "bg-gray-900 border-gray-700" : "bg-white border-gray-300"}` }, /* @__PURE__ */ React.createElement("div", { className: `text-xs uppercase tracking-wide ${mutedTextClass}` }, "Enabled"), /* @__PURE__ */ React.createElement("div", { className: `mt-1 text-sm font-semibold ${headingClass}` }, capability.enabled ? "Yes" : "No")))), /* @__PURE__ */ React.createElement("div", { className: `rounded-xl border p-4 ${panelMutedClass}` }, /* @__PURE__ */ React.createElement("div", { className: `text-xs uppercase tracking-wider ${mutedTextClass}` }, "Health"), /* @__PURE__ */ React.createElement("div", { className: "mt-3 flex flex-wrap items-center gap-2" }, /* @__PURE__ */ React.createElement("span", { className: `inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium ${getCapabilityStatusClasses(capability.health_status || "unknown")}` }, formatCapabilityStatusLabel(capability.health_status || "unknown")), capability.version && /* @__PURE__ */ React.createElement("span", { className: `inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium ${isDarkTheme ? "bg-gray-800 text-gray-200 border border-gray-600" : "bg-white text-gray-700 border border-gray-300"}` }, "Version ", capability.version)), /* @__PURE__ */ React.createElement("div", { className: `mt-3 text-sm leading-6 ${subtextClass}` }, capability.health_message || "Not tested yet."), capability.last_tested_at && /* @__PURE__ */ React.createElement("div", { className: `mt-2 text-xs ${mutedTextClass}` }, "Last checked: ", formatMissionDateTime(capability.last_tested_at)), capability.last_error && /* @__PURE__ */ React.createElement("div", { className: `mt-3 rounded-lg border px-3 py-2 text-xs ${isDarkTheme ? "bg-red-950 border-red-800 text-red-100" : "bg-red-50 border-red-200 text-red-800"}` }, capability.last_error)), /* @__PURE__ */ React.createElement("div", { className: `rounded-xl border p-4 ${panelMutedClass}` }, /* @__PURE__ */ React.createElement("div", { className: `text-xs uppercase tracking-wider ${mutedTextClass}` }, "Dependencies"), dependencyPackages.length > 0 ? /* @__PURE__ */ React.createElement("div", { className: "flex flex-wrap gap-2 mt-3 text-xs" }, dependencyPackages.map((pkg) => /* @__PURE__ */ React.createElement("span", { key: pkg, className: `rounded-full px-2 py-0.5 border ${isDarkTheme ? "bg-gray-800 text-gray-200 border-gray-600" : "bg-white text-gray-700 border-gray-300"}` }, pkg))) : /* @__PURE__ */ React.createElement("div", { className: `mt-3 text-sm ${mutedTextClass}` }, "No extra packages needed.")), restartNote && /* @__PURE__ */ React.createElement("div", { className: `rounded-xl border px-4 py-3 text-sm ${isDarkTheme ? "bg-amber-950 border-amber-800 text-amber-100" : "bg-amber-50 border-amber-200 text-amber-800"}` }, restartNote))))
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
          eyebrow: "Option 1",
          title: "Local passwords",
          shellClass: isDarkTheme ? "bg-indigo-950 border-indigo-800" : "bg-indigo-50 border-indigo-200",
          eyebrowClass: isDarkTheme ? "text-indigo-200" : "text-indigo-800",
          titleClass: isDarkTheme ? "text-indigo-50" : "text-indigo-950",
          bullets: [
            "Splunk Discovery Tool keeps user accounts and passwords in its own database.",
            "You create users, assign roles and MCP connections, and can require a password change at first sign-in.",
            "Use this if you do not have single sign-on, or want this install to manage its own users."
          ]
        },
        {
          eyebrow: "Option 2",
          title: "Single sign-on (OIDC)",
          shellClass: isDarkTheme ? "bg-sky-950 border-sky-800" : "bg-sky-50 border-sky-200",
          eyebrowClass: isDarkTheme ? "text-sky-200" : "text-sky-800",
          titleClass: isDarkTheme ? "text-sky-50" : "text-sky-950",
          bullets: [
            "Users sign in through your identity provider, such as Okta, Microsoft Entra ID, or Keycloak.",
            "Claims from the provider set each user's name, email, default role, and MCP connection.",
            "Use this if your organization already manages sign-in centrally."
          ]
        }
      ];
      const authGuideSettings = [
        ["Sign-in Method", "Choose local passwords or single sign-on (OIDC)."],
        ["Session Timeout", "How long a sign-in lasts before users must sign in again."],
        ["Minimum Password Length", "The shortest password allowed for local accounts."],
        ["Require Password Change on First Sign-in", "New local users must change their password the first time they sign in."],
        ["Enable External REST API", "Lets other programs use the REST API with an access token."],
        ["Enable External MCP", "Lets MCP clients use this tool's read-only MCP endpoint with an access token."],
        ["OIDC Provider Fields", "Issuer URL, client ID and secret, scopes, and claim mapping for single sign-on."]
      ];
      const authGuideChecklist = [
        authProviderSelection === "oidc" ? oidcCanEnableAuth ? "Your OIDC settings are complete enough to turn on sign-in." : "OIDC still needs an issuer URL, client ID, and client secret." : "Local passwords work right away.",
        "After you turn on authentication, everyone must sign in to use the app.",
        "The external REST API and MCP endpoint stay off until you turn them on and issue tokens.",
        "If you continue, the Enable Authentication checkbox unlocks for this session."
      ];
      const authGuideCurrentReadiness = authProviderSelection === "oidc" ? oidcCanEnableAuth ? "Ready" : "Setup needed" : "Ready";
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
            onClick: (event) => event.stopPropagation(),
            onKeyDown: (event) => handleDialogKeyDown(event, () => {
              setIsAuthEnableInfoModalOpen(false);
              setPendingAuthEnableReview(false);
            }),
            tabIndex: -1,
            "data-testid": "auth-enable-info-modal"
          },
          /* @__PURE__ */ React.createElement("div", { className: `flex-shrink-0 flex items-start justify-between gap-4 border-b px-4 py-4 sm:px-6 sm:py-5 ${isDarkTheme ? "border-gray-700 bg-sky-950/30" : "border-gray-200 bg-sky-50"}` }, /* @__PURE__ */ React.createElement("div", { className: "min-w-0" }, /* @__PURE__ */ React.createElement("div", { className: `text-xs uppercase tracking-wider ${mutedTextClass}` }, "Authentication guide"), /* @__PURE__ */ React.createElement("h3", { id: "auth-enable-info-title", className: `mt-3 text-lg font-semibold sm:text-xl ${headingClass}` }, "Before you turn on sign-in"), /* @__PURE__ */ React.createElement("p", { className: `mt-2 text-sm ${subtextClass}` }, "How sign-in works, what each setting does, and what changes when you turn it on.")), /* @__PURE__ */ React.createElement(
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
          /* @__PURE__ */ React.createElement("div", { className: "min-h-0 flex-1 overflow-y-auto px-4 py-4 sm:px-6 sm:py-5" }, /* @__PURE__ */ React.createElement("div", { className: "grid grid-cols-1 gap-4 xl:grid-cols-[minmax(0,1.1fr),minmax(300px,0.9fr)]" }, /* @__PURE__ */ React.createElement("div", { className: "space-y-4" }, /* @__PURE__ */ React.createElement("div", { className: "grid grid-cols-1 gap-4 lg:grid-cols-2" }, authGuideMethods.map((method) => /* @__PURE__ */ React.createElement("div", { key: method.title, className: `rounded-xl border p-4 ${method.shellClass}` }, /* @__PURE__ */ React.createElement("div", { className: `text-xs uppercase tracking-wider ${method.eyebrowClass}` }, method.eyebrow), /* @__PURE__ */ React.createElement("div", { className: `mt-2 text-base font-semibold ${method.titleClass}` }, method.title), /* @__PURE__ */ React.createElement("ul", { className: `mt-3 space-y-2 text-sm ${subtextClass}` }, method.bullets.map((bullet, bulletIdx) => /* @__PURE__ */ React.createElement("li", { key: `${method.title}-bullet-${bulletIdx}`, className: "flex items-start gap-2" }, /* @__PURE__ */ React.createElement("span", { className: `mt-1 h-1.5 w-1.5 rounded-full ${isDarkTheme ? "bg-sky-300" : "bg-sky-600"}` }), /* @__PURE__ */ React.createElement("span", null, bullet))))))), /* @__PURE__ */ React.createElement("div", { className: `rounded-xl border p-4 ${panelMutedClass}` }, /* @__PURE__ */ React.createElement("div", { className: `text-xs uppercase tracking-wider ${mutedTextClass}` }, "Settings in this section"), /* @__PURE__ */ React.createElement("div", { className: "grid grid-cols-1 gap-3 mt-3 sm:grid-cols-2 xl:grid-cols-3" }, authGuideSettings.map(([title, description]) => /* @__PURE__ */ React.createElement("div", { key: title, className: `rounded-lg border px-3 py-3 ${isDarkTheme ? "bg-gray-900 border-gray-700" : "bg-white border-gray-300"}` }, /* @__PURE__ */ React.createElement("div", { className: `text-sm font-semibold ${headingClass}` }, title), /* @__PURE__ */ React.createElement("div", { className: `mt-2 text-xs leading-5 ${subtextClass}` }, description))))), /* @__PURE__ */ React.createElement("div", { className: `rounded-xl border p-4 ${panelMutedClass}` }, /* @__PURE__ */ React.createElement("div", { className: `text-xs uppercase tracking-wider ${mutedTextClass}` }, "What changes when you turn on sign-in"), /* @__PURE__ */ React.createElement("div", { className: `mt-3 grid grid-cols-1 gap-3 text-sm ${subtextClass} lg:grid-cols-2` }, /* @__PURE__ */ React.createElement("div", { className: `rounded-lg border px-3 py-3 ${isDarkTheme ? "bg-gray-900 border-gray-700" : "bg-white border-gray-300"}` }, "Everyone must sign in to use the app, and each user's role controls what they can do."), /* @__PURE__ */ React.createElement("div", { className: `rounded-lg border px-3 py-3 ${isDarkTheme ? "bg-gray-900 border-gray-700" : "bg-white border-gray-300"}` }, "With local passwords, this app manages users, password resets, tokens, and MCP connections."), /* @__PURE__ */ React.createElement("div", { className: `rounded-lg border px-3 py-3 ${isDarkTheme ? "bg-gray-900 border-gray-700" : "bg-white border-gray-300"}` }, "With OIDC, users sign in through your identity provider, and this app still applies roles and MCP connections."), /* @__PURE__ */ React.createElement("div", { className: `rounded-lg border px-3 py-3 ${isDarkTheme ? "bg-gray-900 border-gray-700" : "bg-white border-gray-300"}` }, "This does not turn on the external REST API or MCP endpoint. They need their own settings and tokens.")))), /* @__PURE__ */ React.createElement("div", { className: "space-y-4" }, /* @__PURE__ */ React.createElement("div", { className: `rounded-xl border p-4 ${panelMutedClass}` }, /* @__PURE__ */ React.createElement("div", { className: `text-xs uppercase tracking-wider ${mutedTextClass}` }, "Current status"), /* @__PURE__ */ React.createElement("div", { className: "mt-3 flex flex-wrap gap-2 text-xs font-medium" }, /* @__PURE__ */ React.createElement("span", { className: `inline-flex items-center rounded-full px-2 py-1 ${securityConfig.auth_enabled ? "bg-emerald-50 text-gray-900" : "bg-gray-100 text-gray-700"}` }, securityConfig.auth_enabled ? "Sign-in is on" : "Sign-in is off"), /* @__PURE__ */ React.createElement("span", { className: `inline-flex items-center rounded-full px-2 py-1 ${authProviderSelection === "oidc" ? "bg-sky-50 text-gray-900" : "bg-indigo-50 text-gray-900"}` }, "Method: ", authProviderSelection === "oidc" ? "OIDC" : "Local passwords"), /* @__PURE__ */ React.createElement("span", { className: `inline-flex items-center rounded-full px-2 py-1 ${authGuideCurrentReadiness === "Provider ready" || authGuideCurrentReadiness === "Ready now" ? "bg-emerald-50 text-gray-900" : "bg-amber-50 text-gray-900"}` }, authGuideCurrentReadiness)), /* @__PURE__ */ React.createElement("div", { className: `mt-3 text-sm leading-6 ${subtextClass}` }, authProviderSelection === "oidc" ? "Enter the OIDC settings in this panel, and check the issuer, client, scopes, and claim mapping before you turn on sign-in." : "Local passwords can be turned on now. Plan how you will create users and handle the first admin password change.")), /* @__PURE__ */ React.createElement("div", { className: `rounded-xl border p-4 ${panelMutedClass}` }, /* @__PURE__ */ React.createElement("div", { className: `text-xs uppercase tracking-wider ${mutedTextClass}` }, "Before you continue"), /* @__PURE__ */ React.createElement("ul", { className: `mt-3 space-y-2 text-sm ${subtextClass}` }, authGuideChecklist.map((item, itemIdx) => /* @__PURE__ */ React.createElement("li", { key: `auth-guide-check-${itemIdx}`, className: "flex items-start gap-2" }, /* @__PURE__ */ React.createElement("span", { className: `mt-1 h-1.5 w-1.5 rounded-full ${isDarkTheme ? "bg-emerald-300" : "bg-emerald-600"}` }), /* @__PURE__ */ React.createElement("span", null, item))))), /* @__PURE__ */ React.createElement("div", { className: `rounded-xl border px-4 py-3 text-sm ${pendingAuthEnableReview && !securityConfig.auth_enabled ? isDarkTheme ? "bg-indigo-950 border-indigo-800 text-indigo-100" : "bg-indigo-50 border-indigo-200 text-indigo-900" : isDarkTheme ? "bg-gray-900 border-gray-700 text-gray-200" : "bg-gray-50 border-gray-200 text-gray-700"}` }, pendingAuthEnableReview && !securityConfig.auth_enabled ? "Continue to enable checks the Enable Authentication box. Sign-in starts after you save settings." : "Mark as reviewed unlocks the Enable Authentication checkbox for this session.")))),
          /* @__PURE__ */ React.createElement("div", { className: `flex-shrink-0 flex items-center justify-end gap-3 border-t px-4 py-4 sm:px-6 ${isDarkTheme ? "border-gray-700 bg-gray-900/90" : "border-gray-200 bg-white"}` }, /* @__PURE__ */ React.createElement(
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
      const splashSteps = [
        {
          title: "Connect",
          description: "In Settings, add the URL and token for your Splunk MCP server and an AI model, such as OpenAI or a local Ollama model."
        },
        {
          title: "Run discovery",
          description: "Start a run from the Discovery tab. It surveys your indexes, sourcetypes, hosts, and settings, and saves reports."
        },
        {
          title: "Review and act",
          description: "Overview shows the next steps, Findings lists coverage gaps and evidence, and Chat answers follow-up questions."
        }
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
        ), /* @__PURE__ */ React.createElement("div", { className: "relative w-full max-w-3xl" }, /* @__PURE__ */ React.createElement(
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
            onClick: (event) => event.stopPropagation(),
            onKeyDown: (event) => handleDialogKeyDown(event, closeWelcomeSplash),
            tabIndex: -1,
            "data-testid": "welcome-splash-modal"
          },
          /* @__PURE__ */ React.createElement("div", { className: "min-h-0 flex-1 overflow-y-auto px-5 py-6 sm:px-8 sm:py-8" }, /* @__PURE__ */ React.createElement("h2", { id: "welcome-splash-title", className: `text-2xl font-semibold sm:text-3xl ${headingClass}` }, "Welcome to Splunk Discovery Tool"), /* @__PURE__ */ React.createElement("p", { className: `mt-3 text-sm leading-6 sm:text-base ${subtextClass}` }, "This tool surveys your Splunk environment, explains what it found, and suggests what to do next."), /* @__PURE__ */ React.createElement("ol", { "data-testid": "welcome-splash-steps", className: "mt-6 space-y-5" }, splashSteps.map((step, stepIdx) => /* @__PURE__ */ React.createElement("li", { key: step.title, className: "flex items-start gap-4" }, /* @__PURE__ */ React.createElement("span", { "aria-hidden": "true", className: `flex-shrink-0 inline-flex h-8 w-8 items-center justify-center rounded-full text-sm font-semibold ${isDarkTheme ? "bg-indigo-900 text-indigo-100" : "bg-indigo-50 text-indigo-700"}` }, stepIdx + 1), /* @__PURE__ */ React.createElement("div", { className: "min-w-0" }, /* @__PURE__ */ React.createElement("h3", { className: `text-base font-semibold ${headingClass}` }, step.title), /* @__PURE__ */ React.createElement("p", { className: `mt-1 text-sm leading-6 ${subtextClass}` }, step.description))))), /* @__PURE__ */ React.createElement("p", { className: `mt-6 text-sm ${mutedTextClass}` }, "Optional features, such as the Knowledge Base, are on the Capabilities tab.")),
          /* @__PURE__ */ React.createElement("div", { className: `flex-shrink-0 border-t px-5 py-4 sm:px-8 ${isDarkTheme ? "border-gray-700 bg-gray-900" : "border-gray-200 bg-gray-50"}` }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between" }, /* @__PURE__ */ React.createElement("label", { className: `inline-flex items-start gap-3 text-sm ${subtextClass}` }, /* @__PURE__ */ React.createElement(
            "input",
            {
              type: "checkbox",
              "data-testid": "welcome-splash-dismiss-checkbox",
              checked: welcomeSplashDoNotShowAgain,
              onChange: (event) => setWelcomeSplashDoNotShowAgain(event.target.checked),
              className: "mt-0.5 h-4 w-4 flex-shrink-0 rounded border-gray-300"
            }
          ), /* @__PURE__ */ React.createElement("span", null, "Don't show this again on this browser.", /* @__PURE__ */ React.createElement("span", { className: `block text-xs ${mutedTextClass}` }, "You can turn it back on in Appearance settings."))), /* @__PURE__ */ React.createElement("div", { className: "flex flex-col-reverse gap-2 sm:flex-row sm:justify-end" }, connectionInfoStatus !== "connected" && /* @__PURE__ */ React.createElement(
            "button",
            {
              type: "button",
              "data-testid": "welcome-splash-open-settings",
              onClick: () => {
                closeWelcomeSplash();
                openSettings();
              },
              className: `rounded-lg border px-4 py-2 text-sm font-medium ${secondaryButtonClass}`
            },
            "Set Up Connections"
          ), /* @__PURE__ */ React.createElement(
            "button",
            {
              type: "button",
              onClick: closeWelcomeSplash,
              className: "rounded-lg px-4 py-2 text-sm font-medium text-white bg-indigo-600 hover:bg-indigo-700"
            },
            "Get Started"
          ))))
        )))
      );
    };
    const CAPABILITY_ACTION_LABELS = {
      install: { idle: "Install", busy: "Installing...", notice: "Install" },
      enable: { idle: "Turn On", busy: "Turning On...", notice: "Turn on" },
      disable: { idle: "Turn Off", busy: "Turning Off...", notice: "Turn off" },
      uninstall: { idle: "Remove", busy: "Removing...", notice: "Remove" },
      test: { idle: "Test", busy: "Testing...", notice: "Test" },
      reindex: { idle: "Reindex", busy: "Reindexing...", notice: "Reindex" },
      config: { idle: "Save Settings", busy: "Saving...", notice: "Save settings" }
    };
    const getCapabilityLifecycleState = (capability) => {
      if (!(capability == null ? void 0 : capability.runtime_available)) return "planned";
      if (!capability.installed) return "not_installed";
      if (capability.restart_required) return "restart_required";
      return capability.enabled ? "on" : "off";
    };
    const CAPABILITY_LIFECYCLE_ACTIONS = {
      planned: [],
      not_installed: [{ action: "install", primary: true }],
      restart_required: [{ action: "uninstall" }],
      off: [{ action: "enable", primary: true }, { action: "uninstall" }],
      on: [{ action: "test" }, { action: "disable" }]
    };
    const getCapabilityActionButtonClass = (primary, isBusy) => {
      const base = "inline-flex items-center rounded-lg border px-3 py-1.5 text-sm font-medium transition-colors";
      if (isBusy) {
        return `${base} cursor-not-allowed border-transparent ${isDarkTheme ? "bg-gray-700 text-gray-300" : "bg-gray-200 text-gray-600"}`;
      }
      return primary ? `${base} border-transparent bg-indigo-600 hover:bg-indigo-700 text-white` : `${base} ${secondaryButtonClass}`;
    };
    const renderCapabilityLifecycleActions = (capability, extraButtons = null) => {
      if (!capability) return null;
      const name = capability.name;
      const title = capability.title || formatTokenLabel(name);
      const actionInProgress = (capabilityActionState == null ? void 0 : capabilityActionState[name]) || "";
      const isBusy = !!actionInProgress;
      const lifecycle = getCapabilityLifecycleState(capability);
      const actions = CAPABILITY_LIFECYCLE_ACTIONS[lifecycle] || [];
      const actionHints = {
        disable: `Turn off ${title}. You can turn it back on at any time.`,
        uninstall: `Turn off ${title} and mark it not installed. Its settings and data are kept.`,
        test: `Check that ${title} is working.`
      };
      return /* @__PURE__ */ React.createElement("div", { "data-testid": `capability-actions-${name}`, className: "flex flex-wrap items-center gap-2" }, lifecycle === "planned" && /* @__PURE__ */ React.createElement("span", { className: `text-xs ${mutedTextClass}` }, "Coming in a later release."), lifecycle === "restart_required" && /* @__PURE__ */ React.createElement("span", { className: `text-xs ${mutedTextClass}` }, "Restart Splunk Discovery Tool to finish installing."), actions.map(({ action, primary }) => {
        const labels = CAPABILITY_ACTION_LABELS[action];
        const busyLabel = action === "install" && name === "rag_chromadb" ? `Installing... ${formatCapabilityActionElapsed(ragInstallElapsedSeconds)}` : labels.busy;
        return /* @__PURE__ */ React.createElement(
          "button",
          {
            key: action,
            type: "button",
            "data-capability-action": action,
            onClick: () => runCapabilityAction(name, action),
            disabled: isBusy,
            title: actionHints[action],
            className: getCapabilityActionButtonClass(primary, isBusy)
          },
          actionInProgress === action ? busyLabel : labels.idle,
          /* @__PURE__ */ React.createElement("span", { className: "sr-only" }, " ", title)
        );
      }), extraButtons);
    };
    const renderCapabilityNotice = () => {
      var _a2;
      const showRagInstallProgress = ragActionInProgress === "install";
      const progressMeta = showRagInstallProgress ? getRagInstallProgressMeta(ragInstallElapsedSeconds, ragInstallGuidance) : null;
      const activeNotice = capabilityNotice;
      if (!activeNotice && !showRagInstallProgress) {
        return null;
      }
      if (!activeNotice && showRagInstallProgress) {
        return /* @__PURE__ */ React.createElement("div", { className: `mt-4 rounded-xl border p-4 ${isDarkTheme ? "bg-sky-950 border-sky-800 text-sky-100" : "bg-sky-50 border-sky-200 text-sky-900"}` }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between" }, /* @__PURE__ */ React.createElement("div", { className: "min-w-0 flex-1" }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-wrap items-center gap-2" }, /* @__PURE__ */ React.createElement("span", { className: `inline-flex items-center rounded-full px-2.5 py-1 text-xs font-semibold ${isDarkTheme ? "bg-sky-900 text-sky-100 border border-sky-700" : "bg-white text-sky-800 border border-sky-200"}` }, "Installing ChromaDB runtime"), /* @__PURE__ */ React.createElement("span", { className: `inline-flex items-center rounded-full px-2.5 py-1 text-xs font-medium ${isDarkTheme ? "bg-slate-900 text-slate-100 border border-slate-700" : "bg-white text-slate-700 border border-slate-200"}` }, (progressMeta == null ? void 0 : progressMeta.stageLabel) || "In progress"), /* @__PURE__ */ React.createElement("span", { className: `inline-flex items-center rounded-full px-2.5 py-1 text-xs font-medium ${isDarkTheme ? "bg-indigo-950 text-indigo-100 border border-indigo-800" : "bg-indigo-50 text-indigo-700 border border-indigo-200"}` }, "Elapsed ", formatCapabilityActionElapsed(ragInstallElapsedSeconds))), /* @__PURE__ */ React.createElement("div", { className: `mt-3 text-sm font-semibold ${headingClass}` }, (progressMeta == null ? void 0 : progressMeta.title) || "Installing the Knowledge Base"), /* @__PURE__ */ React.createElement("div", { className: `mt-1 text-sm ${subtextClass}` }, progressMeta == null ? void 0 : progressMeta.detail), /* @__PURE__ */ React.createElement("div", { className: `mt-2 text-xs ${mutedTextClass}` }, progressMeta == null ? void 0 : progressMeta.expectedDurationLabel), Array.isArray(progressMeta == null ? void 0 : progressMeta.notes) && progressMeta.notes.length > 0 && /* @__PURE__ */ React.createElement("ul", { className: `mt-3 space-y-2 text-xs ${subtextClass}` }, progressMeta.notes.map((item, index) => /* @__PURE__ */ React.createElement("li", { key: `rag-install-progress-note-${index}`, className: "flex items-start gap-2" }, /* @__PURE__ */ React.createElement("span", { className: `mt-1 h-1.5 w-1.5 rounded-full ${isDarkTheme ? "bg-sky-300" : "bg-sky-600"}` }), /* @__PURE__ */ React.createElement("span", null, item))))), /* @__PURE__ */ React.createElement("div", { className: `min-w-[240px] rounded-xl border p-3 ${isDarkTheme ? "bg-slate-950 border-sky-900" : "bg-white border-sky-200"}` }, /* @__PURE__ */ React.createElement("div", { className: `text-xs uppercase tracking-wide ${mutedTextClass}` }, "Dependency Set"), /* @__PURE__ */ React.createElement("div", { className: "mt-2 flex flex-wrap gap-2 text-xs" }, (Array.isArray(ragCapability == null ? void 0 : ragCapability.dependency_packages) ? ragCapability.dependency_packages : ["chromadb"]).map((pkg) => /* @__PURE__ */ React.createElement("span", { key: pkg, className: `rounded-full px-2 py-0.5 border ${isDarkTheme ? "bg-gray-900 text-gray-200 border-gray-700" : "bg-sky-50 text-sky-800 border-sky-200"}` }, pkg))), /* @__PURE__ */ React.createElement("div", { className: `mt-3 text-xs ${subtextClass}` }, "When the install finishes, restart Splunk Discovery Tool, then select Turn On and Reindex."))), /* @__PURE__ */ React.createElement("div", { className: `mt-4 h-2 overflow-hidden rounded-full ${isDarkTheme ? "bg-slate-900" : "bg-sky-100"}` }, /* @__PURE__ */ React.createElement("div", { className: `h-full w-1/3 rounded-full ${isDarkTheme ? "bg-sky-400" : "bg-sky-500"} animate-pulse` })));
      }
      const noticeToneClass = activeNotice.type === "error" ? isDarkTheme ? "bg-red-950 border-red-800 text-red-100" : "bg-red-50 border-red-200 text-red-900" : isDarkTheme ? "bg-emerald-950 border-emerald-800 text-emerald-100" : "bg-emerald-50 border-emerald-200 text-emerald-900";
      const noticeDetails = (activeNotice == null ? void 0 : activeNotice.details) && typeof activeNotice.details === "object" ? activeNotice.details : null;
      const installGuidance = (noticeDetails == null ? void 0 : noticeDetails.install_guidance) && typeof noticeDetails.install_guidance === "object" ? noticeDetails.install_guidance : null;
      const nextSteps = Array.isArray(installGuidance == null ? void 0 : installGuidance.next_steps) ? installGuidance.next_steps : [];
      const installCommands = Array.isArray(installGuidance == null ? void 0 : installGuidance.install_commands) ? installGuidance.install_commands : [];
      const diagnosticExcerpt = (installGuidance == null ? void 0 : installGuidance.diagnostic_excerpt) || (noticeDetails == null ? void 0 : noticeDetails.stderr) || (noticeDetails == null ? void 0 : noticeDetails.error) || "";
      const likelyIssue = (installGuidance == null ? void 0 : installGuidance.likely_issue) || "";
      return /* @__PURE__ */ React.createElement("div", { className: `mt-4 rounded-xl border p-4 ${noticeToneClass}` }, /* @__PURE__ */ React.createElement("div", { className: "flex items-start justify-between gap-3" }, /* @__PURE__ */ React.createElement("div", { className: "min-w-0 flex-1" }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-wrap items-center gap-2" }, activeNotice.capability && /* @__PURE__ */ React.createElement("span", { className: `inline-flex items-center rounded-full px-2.5 py-1 text-xs font-semibold ${activeNotice.type === "error" ? isDarkTheme ? "bg-red-900 text-red-100 border border-red-700" : "bg-white text-red-700 border border-red-200" : isDarkTheme ? "bg-emerald-900 text-emerald-100 border border-emerald-700" : "bg-white text-emerald-700 border border-emerald-200"}` }, getCapabilityDisplayTitle(activeNotice.capability)), activeNotice.action && /* @__PURE__ */ React.createElement("span", { className: `inline-flex items-center rounded-full px-2.5 py-1 text-xs font-medium ${isDarkTheme ? "bg-slate-950 text-slate-100 border border-slate-700" : "bg-white text-slate-700 border border-slate-200"}` }, ((_a2 = CAPABILITY_ACTION_LABELS[activeNotice.action]) == null ? void 0 : _a2.notice) || formatTokenLabel(activeNotice.action))), /* @__PURE__ */ React.createElement("div", { className: `mt-3 text-sm font-semibold ${headingClass}` }, activeNotice.message), (installGuidance == null ? void 0 : installGuidance.summary) && /* @__PURE__ */ React.createElement("div", { className: `mt-1 text-sm ${subtextClass}` }, installGuidance.summary), likelyIssue && /* @__PURE__ */ React.createElement("div", { className: `mt-3 rounded-lg border px-3 py-2 text-xs ${activeNotice.type === "error" ? isDarkTheme ? "bg-red-900/60 border-red-800 text-red-100" : "bg-white border-red-200 text-red-800" : isDarkTheme ? "bg-emerald-900/60 border-emerald-800 text-emerald-100" : "bg-white border-emerald-200 text-emerald-800"}` }, likelyIssue)), /* @__PURE__ */ React.createElement(
        "button",
        {
          type: "button",
          onClick: () => setCapabilityNotice(null),
          className: `inline-flex items-center rounded-lg border px-2 py-1 text-xs font-medium ${isDarkTheme ? "border-gray-700 bg-slate-950 text-gray-100 hover:bg-slate-900" : "border-gray-300 bg-white text-gray-700 hover:bg-gray-50"}`
        },
        "Dismiss"
      )), nextSteps.length > 0 && /* @__PURE__ */ React.createElement("div", { className: "mt-4" }, /* @__PURE__ */ React.createElement("div", { className: `text-xs font-semibold uppercase tracking-wide ${mutedTextClass}` }, "Next Steps"), /* @__PURE__ */ React.createElement("ul", { className: `mt-2 space-y-2 text-sm ${subtextClass}` }, nextSteps.map((step, index) => /* @__PURE__ */ React.createElement("li", { key: `capability-notice-step-${index}`, className: "flex items-start gap-2" }, /* @__PURE__ */ React.createElement("span", { className: `mt-1 h-1.5 w-1.5 rounded-full ${activeNotice.type === "error" ? isDarkTheme ? "bg-red-300" : "bg-red-600" : isDarkTheme ? "bg-emerald-300" : "bg-emerald-600"}` }), /* @__PURE__ */ React.createElement("span", null, step))))), installCommands.length > 0 && /* @__PURE__ */ React.createElement("div", { className: "mt-4" }, /* @__PURE__ */ React.createElement("div", { className: `text-xs font-semibold uppercase tracking-wide ${mutedTextClass}` }, "Install Commands"), /* @__PURE__ */ React.createElement("div", { className: "mt-2 space-y-2" }, installCommands.map((command, index) => /* @__PURE__ */ React.createElement("pre", { key: `capability-notice-command-${index}`, className: `overflow-x-auto rounded-lg border px-3 py-2 text-xs ${isDarkTheme ? "bg-slate-950 border-slate-800 text-slate-100" : "bg-white border-slate-200 text-slate-800"}` }, command)))), diagnosticExcerpt && /* @__PURE__ */ React.createElement("div", { className: "mt-4" }, /* @__PURE__ */ React.createElement("div", { className: `text-xs font-semibold uppercase tracking-wide ${mutedTextClass}` }, "Diagnostic Excerpt"), /* @__PURE__ */ React.createElement("pre", { className: `mt-2 max-h-56 overflow-auto rounded-lg border px-3 py-2 text-xs whitespace-pre-wrap break-words ${isDarkTheme ? "bg-slate-950 border-slate-800 text-slate-100" : "bg-white border-slate-200 text-slate-800"}` }, diagnosticExcerpt)));
    };
    const renderRagOverviewCard = () => {
      const lastIndexedLabel = formatMissionDateTime(ragIndexSummary == null ? void 0 : ragIndexSummary.last_indexed_at, "Not indexed yet");
      const ragLifecycle = getCapabilityLifecycleState(ragCapability);
      const ragIsInstalled = !!(ragCapability == null ? void 0 : ragCapability.installed);
      const ragTileClass = `rounded-lg p-3 border ${isDarkTheme ? "bg-gray-900 border-gray-700" : "bg-gray-50 border-gray-200"}`;
      return /* @__PURE__ */ React.createElement("section", { "data-testid": "rag-overview-card", "aria-labelledby": "rag-overview-title", className: `rounded-lg shadow-sm p-6 border ${panelClass}` }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-col xl:flex-row xl:items-start xl:justify-between gap-4" }, /* @__PURE__ */ React.createElement("div", { className: "max-w-3xl" }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-wrap items-center gap-2" }, /* @__PURE__ */ React.createElement("h3", { id: "rag-overview-title", className: `text-lg font-semibold ${headingClass}` }, (ragCapability == null ? void 0 : ragCapability.title) || "Knowledge Base"), /* @__PURE__ */ React.createElement("span", { className: `inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-medium ${getCapabilityStatusClasses(ragStatusLabel)}` }, formatCapabilityStatusLabel(ragStatusLabel))), /* @__PURE__ */ React.createElement("p", { className: `mt-2 text-sm ${subtextClass}` }, (ragCapability == null ? void 0 : ragCapability.description) || "Indexes your reports and imported documents so the AI assistant can find relevant context."), ragLifecycle === "not_installed" && (ragCapability == null ? void 0 : ragCapability.install_method) === "pip" && /* @__PURE__ */ React.createElement("p", { className: `mt-2 text-xs ${mutedTextClass}` }, "Installing downloads extra Python packages, which can take a few minutes."), ragIsInstalled && /* @__PURE__ */ React.createElement("p", { className: `mt-2 text-xs break-all ${mutedTextClass}` }, "Files stored in: ", ragDisplayedAssetDir)), /* @__PURE__ */ React.createElement("div", { className: "flex flex-wrap items-center gap-2 xl:justify-end" }, /* @__PURE__ */ React.createElement(
        "button",
        {
          type: "button",
          onClick: () => openCapabilityDetail("rag_chromadb"),
          "aria-label": "View details for Knowledge Base",
          title: "View details",
          className: `inline-flex h-9 w-9 flex-shrink-0 items-center justify-center rounded-full border ${isDarkTheme ? "border-gray-600 bg-gray-800 text-sky-200 hover:bg-gray-700" : "border-gray-300 bg-white text-sky-700 hover:bg-sky-50"}`
        },
        /* @__PURE__ */ React.createElement("i", { className: "fa-solid fa-circle-info text-sm", "aria-hidden": "true" })
      ), ragIsInstalled && /* @__PURE__ */ React.createElement(
        "button",
        {
          type: "button",
          onClick: openRagCapabilitiesWorkspace,
          className: getCapabilityActionButtonClass(true, false)
        },
        "Open Knowledge Base"
      ), renderCapabilityLifecycleActions(ragCapability, canReindexRag ? /* @__PURE__ */ React.createElement(
        "button",
        {
          type: "button",
          onClick: () => runCapabilityAction("rag_chromadb", "reindex"),
          disabled: isRagBusy,
          className: getCapabilityActionButtonClass(false, isRagBusy)
        },
        ragActionInProgress === "reindex" ? "Reindexing..." : "Reindex"
      ) : null))), ragIsInstalled && /* @__PURE__ */ React.createElement("div", { className: "grid grid-cols-2 xl:grid-cols-4 gap-3 mt-5" }, /* @__PURE__ */ React.createElement("div", { className: ragTileClass }, /* @__PURE__ */ React.createElement("div", { className: `text-xs uppercase tracking-wide ${mutedTextClass}` }, "Indexed Documents"), /* @__PURE__ */ React.createElement("div", { className: `text-2xl font-semibold mt-1 ${headingClass}` }, ragIndexedDocumentCount)), /* @__PURE__ */ React.createElement("div", { className: ragTileClass }, /* @__PURE__ */ React.createElement("div", { className: `text-xs uppercase tracking-wide ${mutedTextClass}` }, "Source Files"), /* @__PURE__ */ React.createElement("div", { className: `text-2xl font-semibold mt-1 ${headingClass}` }, (ragIndexSummary == null ? void 0 : ragIndexSummary.source_file_count) || 0)), /* @__PURE__ */ React.createElement("div", { className: ragTileClass }, /* @__PURE__ */ React.createElement("div", { className: `text-xs uppercase tracking-wide ${mutedTextClass}` }, "Imported Items"), /* @__PURE__ */ React.createElement("div", { className: `text-2xl font-semibold mt-1 ${headingClass}` }, ragDisplayedAssetCount)), /* @__PURE__ */ React.createElement("div", { className: ragTileClass }, /* @__PURE__ */ React.createElement("div", { className: `text-xs uppercase tracking-wide ${mutedTextClass}` }, "Ready for Chat"), /* @__PURE__ */ React.createElement("div", { className: `text-sm font-semibold mt-2 ${headingClass}` }, canUseRagContextPreview ? "Yes" : "Not yet"), /* @__PURE__ */ React.createElement("div", { className: `mt-1 text-xs ${mutedTextClass}` }, "Last indexed: ", lastIndexedLabel))), ragIsInstalled && (ragIndexSourceTypes.length > 0 || ragKnowledgeAssetTypeCounts.length > 0) && /* @__PURE__ */ React.createElement("div", { className: "grid grid-cols-1 xl:grid-cols-2 gap-3 mt-4" }, /* @__PURE__ */ React.createElement("div", { className: `rounded-lg border px-3 py-3 ${panelMutedClass}` }, /* @__PURE__ */ React.createElement("div", { className: `text-xs font-medium mb-2 ${headingClass}` }, "Indexed by Source"), /* @__PURE__ */ React.createElement("div", { className: "flex flex-wrap gap-2 text-xs" }, ragIndexSourceTypes.length > 0 ? ragIndexSourceTypes.map(([sourceType, count]) => /* @__PURE__ */ React.createElement("span", { key: sourceType, className: `rounded-full px-2 py-0.5 border ${isDarkTheme ? "bg-gray-800 text-gray-200 border-gray-600" : "bg-white text-gray-700 border-gray-300"}` }, formatCapabilitySourceTypeLabel(sourceType), ": ", count)) : /* @__PURE__ */ React.createElement("span", { className: mutedTextClass }, "Nothing indexed yet."))), /* @__PURE__ */ React.createElement("div", { className: `rounded-lg border px-3 py-3 ${panelMutedClass}` }, /* @__PURE__ */ React.createElement("div", { className: `text-xs font-medium mb-2 ${headingClass}` }, "Imported by Type"), /* @__PURE__ */ React.createElement("div", { className: "flex flex-wrap gap-2 text-xs" }, ragKnowledgeAssetTypeCounts.length > 0 ? ragKnowledgeAssetTypeCounts.map(([assetType, count]) => /* @__PURE__ */ React.createElement("span", { key: assetType, className: `rounded-full px-2 py-0.5 border ${isDarkTheme ? "bg-gray-800 text-gray-200 border-gray-600" : "bg-white text-gray-700 border-gray-300"}` }, formatKnowledgeAssetTypeLabel(assetType), ": ", count)) : /* @__PURE__ */ React.createElement("span", { className: mutedTextClass }, "Nothing imported yet.")))));
    };
    const M2614_OBJECTIVE_NAMES = {
      CEM: "Continuous Event Monitoring (CEM)",
      THIRF: "Threat Hunting, Investigation, Response, and Forensics (THIRF)"
    };
    const formatM2614ObjectiveName = (value) => {
      const raw = String(value || "").trim();
      return M2614_OBJECTIVE_NAMES[raw.toUpperCase()] || raw || "Objective";
    };
    const formatM2614Delta = (value) => {
      if (value == null || value === "") return "Unknown";
      const numeric = Number(value);
      if (!Number.isFinite(numeric)) return String(value);
      return numeric > 0 ? `+${numeric}` : String(numeric);
    };
    const formatM2614Level = (value) => value == null ? "Unknown" : `Level ${value}`;
    const renderM2614WorkspaceView = () => {
      var _a2, _b2, _c2, _d2, _e2, _f2, _g2, _h2, _i2, _j2;
      const m2614IconClass = isDarkTheme ? "text-indigo-300" : "text-indigo-600";
      const m2614SectionClass = `rounded-lg shadow-sm p-6 border ${panelClass}`;
      const m2614CardClass = `rounded-lg border p-4 ${panelMutedClass}`;
      const m2614PillClass = `inline-flex items-center rounded-full border px-2 py-0.5 text-xs font-medium ${isDarkTheme ? "bg-gray-800 text-gray-200 border-gray-600" : "bg-white text-gray-700 border-gray-300"}`;
      const m2614InputClass = `w-full rounded-md border px-3 py-2 text-sm ${isDarkTheme ? "border-gray-600 bg-gray-900 text-gray-100" : "border-gray-300 bg-white text-gray-900"}`;
      const m2614LabelClass = `block text-sm font-medium mb-1 ${headingClass}`;
      const m2614CodeClass = `overflow-x-auto rounded-md border p-3 text-xs font-mono whitespace-pre-wrap ${isDarkTheme ? "bg-gray-950 border-gray-700 text-gray-100" : "bg-gray-50 border-gray-200 text-gray-900"}`;
      const m2614BulletClass = `mt-1.5 h-1.5 w-1.5 flex-shrink-0 rounded-full ${isDarkTheme ? "bg-gray-400" : "bg-gray-500"}`;
      const m2614NoticeClass = `rounded-md border px-3 py-2 text-sm ${isDarkTheme ? "border-red-800 bg-red-950 text-red-100" : "border-red-200 bg-red-50 text-red-800"}`;
      const canStartM2614Validation = !!selectedM2614ValidationPack && canRunM2614Validation && m2614ValidationState.status !== "loading";
      const renderSectionHeader = (icon, title, description, id) => /* @__PURE__ */ React.createElement("div", { className: "mb-4" }, /* @__PURE__ */ React.createElement("h3", { id, className: `flex items-center gap-2 text-base font-semibold ${headingClass}` }, /* @__PURE__ */ React.createElement("i", { className: `fas ${icon} text-sm ${m2614IconClass}`, "aria-hidden": "true" }), title), description && /* @__PURE__ */ React.createElement("p", { className: `mt-1 text-sm ${subtextClass}` }, description));
      const renderLabeledLine = (label, value, toneClass = subtextClass) => value ? /* @__PURE__ */ React.createElement("div", { className: `text-sm ${toneClass}` }, /* @__PURE__ */ React.createElement("dt", { className: "inline font-semibold" }, label), " ", /* @__PURE__ */ React.createElement("dd", { className: "inline" }, value)) : null;
      const renderBulletList = (items, keyPrefix) => /* @__PURE__ */ React.createElement("ul", { className: `space-y-1.5 text-sm ${subtextClass}` }, items.map((item, itemIdx) => /* @__PURE__ */ React.createElement("li", { key: `${keyPrefix}-${itemIdx}`, className: "flex items-start gap-2" }, /* @__PURE__ */ React.createElement("span", { "aria-hidden": "true", className: m2614BulletClass }), /* @__PURE__ */ React.createElement("span", null, item))));
      const firstItem = (value) => Array.isArray(value) && value.length > 0 ? value[0] : "";
      const sourceSummary = (m2614Profile == null ? void 0 : m2614Profile.source_summary) || {};
      return /* @__PURE__ */ React.createElement(React.Fragment, null, /* @__PURE__ */ React.createElement("section", { "aria-labelledby": "m2614-page-title", className: m2614SectionClass }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-col gap-4 xl:flex-row xl:items-start xl:justify-between" }, /* @__PURE__ */ React.createElement("div", { className: "max-w-3xl" }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-wrap items-center gap-2" }, /* @__PURE__ */ React.createElement("h2", { id: "m2614-page-title", className: `text-lg font-semibold ${headingClass}` }, "M-26-14 Readiness"), /* @__PURE__ */ React.createElement("span", { className: `inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-medium ${getCapabilityStatusClasses((m2614AdvisorCapability == null ? void 0 : m2614AdvisorCapability.health_status) || "unknown")}` }, formatCapabilityStatusLabel((m2614AdvisorCapability == null ? void 0 : m2614AdvisorCapability.health_status) || "unknown")), headerAuthVisible && /* @__PURE__ */ React.createElement("span", { className: m2614PillClass }, headerAuthRoleLabel)), /* @__PURE__ */ React.createElement("p", { className: `mt-2 text-sm leading-6 ${subtextClass}` }, "Estimates how ready this Splunk environment is for the logging requirements in OMB memo M-26-14. It uses your discovery results, shows where the evidence is thin, and runs read-only searches to check monitoring, investigation, retention, and log management."), /* @__PURE__ */ React.createElement("p", { className: `mt-2 text-sm ${mutedTextClass}` }, /* @__PURE__ */ React.createElement("span", { className: "font-semibold" }, "Advisory only."), " These are estimates to guide your review, not a compliance decision.", " ", canRunM2614Validation ? "You can run live checks while the Splunk MCP server is connected." : "You can review results. Only analysts and admins can run live checks.")), /* @__PURE__ */ React.createElement("div", { className: "flex flex-wrap items-center gap-2" }, renderWorkspaceRefreshButton(() => refreshM2614Workspace(), "Refresh M-26-14 readiness"), /* @__PURE__ */ React.createElement(
        "button",
        {
          type: "button",
          onClick: openCapabilitiesOverview,
          className: `inline-flex items-center gap-2 rounded-lg border px-3 py-1.5 text-sm font-medium transition-colors ${secondaryButtonClass}`
        },
        /* @__PURE__ */ React.createElement("i", { className: "fas fa-sliders-h", "aria-hidden": "true" }),
        "Capability Settings"
      ))), !m2614Profile || !m2614Profile.has_data ? /* @__PURE__ */ React.createElement("div", { className: `mt-6 rounded-lg border px-4 py-4 text-sm ${panelMutedClass} ${mutedTextClass}` }, (m2614Profile == null ? void 0 : m2614Profile.message) || "No readiness estimate yet. Run discovery to create one.") : /* @__PURE__ */ React.createElement("dl", { className: "mt-6 grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-4" }, /* @__PURE__ */ React.createElement("div", { className: m2614CardClass }, /* @__PURE__ */ React.createElement("dt", { className: `text-xs uppercase tracking-wide ${mutedTextClass}` }, "Readiness estimate"), /* @__PURE__ */ React.createElement("dd", { className: `mt-2 text-2xl font-semibold ${headingClass}` }, formatMissionMetricValue(m2614Profile == null ? void 0 : m2614Profile.readiness_estimate), "/100"), /* @__PURE__ */ React.createElement("dd", { className: `mt-1 text-sm ${subtextClass}` }, "From the run on ", formatMissionSessionSelectionLabel((m2614Profile == null ? void 0 : m2614Profile.timestamp) || compareSelection.current))), /* @__PURE__ */ React.createElement("div", { className: m2614CardClass }, /* @__PURE__ */ React.createElement("dt", { className: `text-xs uppercase tracking-wide ${mutedTextClass}` }, "Confidence"), /* @__PURE__ */ React.createElement("dd", { className: `mt-2 text-2xl font-semibold ${headingClass}` }, formatM2614StatusLabel(m2614Profile == null ? void 0 : m2614Profile.confidence)), /* @__PURE__ */ React.createElement("dd", { className: `mt-1 text-sm ${subtextClass}` }, "How strongly the evidence supports this estimate. Live checks can raise it.")), /* @__PURE__ */ React.createElement("div", { className: m2614CardClass }, /* @__PURE__ */ React.createElement("dt", { className: `text-xs uppercase tracking-wide ${mutedTextClass}` }, "Maturity floor"), /* @__PURE__ */ React.createElement("dd", { className: `mt-2 text-2xl font-semibold ${headingClass}` }, formatM2614Level((_a2 = m2614Profile == null ? void 0 : m2614Profile.maturity_floor) == null ? void 0 : _a2.level)), /* @__PURE__ */ React.createElement("dd", { className: `mt-1 text-sm ${subtextClass}` }, ((_b2 = m2614Profile == null ? void 0 : m2614Profile.maturity_floor) == null ? void 0 : _b2.explanation) || "The lowest maturity level the evidence supports. Not enough evidence yet.")), /* @__PURE__ */ React.createElement("div", { className: m2614CardClass }, /* @__PURE__ */ React.createElement("dt", { className: `text-xs uppercase tracking-wide ${mutedTextClass}` }, "What discovery saw"), /* @__PURE__ */ React.createElement("dd", { className: `mt-2 text-lg font-semibold ${headingClass}` }, countLabel(Number(sourceSummary.total_indexes) || 0, "index", "indexes"), ", ", countLabel(Number(sourceSummary.total_hosts) || 0, "host")), /* @__PURE__ */ React.createElement("dd", { className: `mt-1 text-sm ${subtextClass}` }, countLabel(Number(sourceSummary.security_source_count) || 0, "security source"), ", ", countLabel(Number(sourceSummary.compliance_source_count) || 0, "compliance source"))))), (m2614Profile == null ? void 0 : m2614Profile.has_data) && /* @__PURE__ */ React.createElement(React.Fragment, null, /* @__PURE__ */ React.createElement("section", { "aria-labelledby": "m2614-objectives-title", className: m2614SectionClass }, renderSectionHeader("fa-bullseye", "Priority Objectives", "M-26-14 organizes logging around two objectives. Each status starts from discovery results and gets stronger as live checks confirm it.", "m2614-objectives-title"), m2614PriorityObjectives.length > 0 ? /* @__PURE__ */ React.createElement("div", { className: "grid grid-cols-1 gap-3 md:grid-cols-2" }, m2614PriorityObjectives.map((objective) => /* @__PURE__ */ React.createElement("div", { key: objective.objective || objective.status, className: m2614CardClass }, /* @__PURE__ */ React.createElement("div", { className: "flex items-start justify-between gap-3" }, /* @__PURE__ */ React.createElement("h4", { className: `text-sm font-semibold ${headingClass}` }, formatM2614ObjectiveName(objective.objective)), /* @__PURE__ */ React.createElement("span", { className: `inline-flex flex-shrink-0 items-center rounded-full px-2.5 py-0.5 text-xs font-medium ${getM2614StatusClasses(objective.status)}` }, formatM2614StatusLabel(objective.status))), /* @__PURE__ */ React.createElement("p", { className: `mt-2 text-sm ${subtextClass}` }, firstItem(objective.notes) || "No notes for this objective yet."), firstItem(objective.evidence) && /* @__PURE__ */ React.createElement("dl", { className: "mt-2" }, renderLabeledLine("Evidence:", firstItem(objective.evidence), mutedTextClass))))) : /* @__PURE__ */ React.createElement("div", { className: `rounded-lg border px-4 py-4 text-sm ${panelMutedClass} ${mutedTextClass}` }, "No objective status is available for this run.")), sessionCatalog.length >= 2 && /* @__PURE__ */ React.createElement("section", { "aria-labelledby": "m2614-compare-title", className: m2614SectionClass }, renderSectionHeader("fa-code-compare", "Compare Runs", "See how readiness changed between two discovery runs.", "m2614-compare-title"), /* @__PURE__ */ React.createElement("div", { className: "flex flex-wrap items-end gap-3 mb-4" }, /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("label", { htmlFor: "m2614-compare-current", className: m2614LabelClass }, "Run"), /* @__PURE__ */ React.createElement(
        "select",
        {
          id: "m2614-compare-current",
          value: compareSelection.current,
          onChange: (e) => setCompareSelection((prev) => ({ ...prev, current: e.target.value })),
          "data-testid": "m2614-compare-current-select",
          className: m2614InputClass
        },
        /* @__PURE__ */ React.createElement("option", { value: "latest" }, "Latest run"),
        sessionCatalog.map((session) => /* @__PURE__ */ React.createElement("option", { key: `m2614-current-${session.timestamp}`, value: session.timestamp }, formatMissionSessionSelectionLabel(session.timestamp)))
      )), /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("label", { htmlFor: "m2614-compare-baseline", className: m2614LabelClass }, "Compared with"), /* @__PURE__ */ React.createElement(
        "select",
        {
          id: "m2614-compare-baseline",
          value: compareSelection.baseline,
          onChange: (e) => setCompareSelection((prev) => ({ ...prev, baseline: e.target.value })),
          "data-testid": "m2614-compare-baseline-select",
          className: m2614InputClass
        },
        /* @__PURE__ */ React.createElement("option", { value: "previous" }, "Previous run"),
        sessionCatalog.map((session) => /* @__PURE__ */ React.createElement("option", { key: `m2614-baseline-${session.timestamp}`, value: session.timestamp }, formatMissionSessionSelectionLabel(session.timestamp)))
      )), /* @__PURE__ */ React.createElement(
        "button",
        {
          type: "button",
          onClick: refreshM2614CompareSelection,
          "data-testid": "m2614-compare-submit",
          className: `inline-flex items-center rounded-md border px-3 py-2 text-sm font-medium transition-colors ${secondaryButtonClass}`
        },
        "Compare"
      )), !m2614Compare || !m2614Compare.has_data ? /* @__PURE__ */ React.createElement("div", { className: `rounded-lg border px-4 py-4 text-sm ${panelMutedClass} ${mutedTextClass}` }, (m2614Compare == null ? void 0 : m2614Compare.message) || "Run discovery at least twice to compare runs.") : /* @__PURE__ */ React.createElement("dl", { className: "grid grid-cols-1 gap-3 sm:grid-cols-3" }, /* @__PURE__ */ React.createElement("div", { className: m2614CardClass }, /* @__PURE__ */ React.createElement("dt", { className: `text-xs uppercase tracking-wide ${mutedTextClass}` }, "Readiness change"), /* @__PURE__ */ React.createElement("dd", { "data-testid": "m2614-compare-readiness-delta", className: `mt-1 text-lg font-semibold ${headingClass}` }, formatM2614Delta((_d2 = (_c2 = m2614Compare == null ? void 0 : m2614Compare.comparison) == null ? void 0 : _c2.readiness_delta) != null ? _d2 : 0))), /* @__PURE__ */ React.createElement("div", { className: m2614CardClass }, /* @__PURE__ */ React.createElement("dt", { className: `text-xs uppercase tracking-wide ${mutedTextClass}` }, "Maturity floor change"), /* @__PURE__ */ React.createElement("dd", { className: `mt-1 text-lg font-semibold ${headingClass}` }, formatM2614Delta((_e2 = m2614Compare == null ? void 0 : m2614Compare.comparison) == null ? void 0 : _e2.maturity_floor_delta))), /* @__PURE__ */ React.createElement("div", { className: m2614CardClass }, /* @__PURE__ */ React.createElement("dt", { className: `text-xs uppercase tracking-wide ${mutedTextClass}` }, "Suggested checks"), /* @__PURE__ */ React.createElement("dd", { className: `mt-1 text-lg font-semibold ${headingClass}` }, Array.isArray((_f2 = m2614Compare == null ? void 0 : m2614Compare.comparison) == null ? void 0 : _f2.recommended_pack_ids) ? m2614Compare.comparison.recommended_pack_ids.length : 0)))), /* @__PURE__ */ React.createElement("section", { "aria-labelledby": "m2614-elements-title", className: m2614SectionClass }, renderSectionHeader("fa-layer-group", "Maturity Elements", "Each area shows what discovery found, what is missing, and what to do next.", "m2614-elements-title"), /* @__PURE__ */ React.createElement("div", { className: "grid grid-cols-1 gap-3 xl:grid-cols-2" }, m2614MaturityElements.map((element) => /* @__PURE__ */ React.createElement("div", { key: element.id || element.label, className: m2614CardClass }, /* @__PURE__ */ React.createElement("div", { className: "flex items-start justify-between gap-3" }, /* @__PURE__ */ React.createElement("h4", { className: `text-sm font-semibold ${headingClass}` }, element.label || element.id || "Element"), /* @__PURE__ */ React.createElement("span", { className: `inline-flex flex-shrink-0 items-center rounded-full px-2.5 py-0.5 text-xs font-medium ${getM2614StatusClasses(element.status)}` }, formatM2614StatusLabel(element.status))), /* @__PURE__ */ React.createElement("div", { className: "mt-2 flex flex-wrap items-center gap-2" }, /* @__PURE__ */ React.createElement("span", { className: m2614PillClass }, "Confidence: ", formatM2614StatusLabel(element.confidence)), /* @__PURE__ */ React.createElement("span", { className: m2614PillClass }, "Maturity floor: ", formatM2614Level(element.estimated_level_floor))), /* @__PURE__ */ React.createElement("dl", { className: "mt-3 space-y-1.5" }, renderLabeledLine("Found:", firstItem(element.evidence)), renderLabeledLine("Missing:", firstItem(element.gaps)), renderLabeledLine("Not yet known:", firstItem(element.unknowns), mutedTextClass), renderLabeledLine("Next step:", firstItem(element.remediation), mutedTextClass)))))), /* @__PURE__ */ React.createElement("section", { "aria-labelledby": "m2614-checks-title", className: m2614SectionClass }, renderSectionHeader("fa-vial", "Live Checks", "Run a prepared, read-only Splunk search. You can review the exact search before it runs.", "m2614-checks-title"), m2614ValidationCatalog.status === "error" && /* @__PURE__ */ React.createElement("div", { role: "alert", className: `mb-4 ${m2614NoticeClass}` }, m2614ValidationCatalog.error), /* @__PURE__ */ React.createElement("div", { className: "grid grid-cols-1 gap-6 lg:grid-cols-2" }, /* @__PURE__ */ React.createElement("div", { className: "space-y-4" }, /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("label", { htmlFor: "m2614-validation-pack", className: m2614LabelClass }, "Check"), /* @__PURE__ */ React.createElement(
        "select",
        {
          id: "m2614-validation-pack",
          value: m2614ValidationSelection.packId || (selectedM2614ValidationPack == null ? void 0 : selectedM2614ValidationPack.id) || "",
          onChange: (e) => {
            const nextPackId = e.target.value;
            setM2614ValidationSelection((prev) => ({ ...prev, packId: nextPackId }));
            setM2614ValidationResult(null);
            setM2614ValidationState({ status: "idle", error: "" });
          },
          "data-testid": "m2614-validation-pack-select",
          className: m2614InputClass
        },
        m2614ValidationPacks.map((pack) => /* @__PURE__ */ React.createElement("option", { key: pack.id, value: pack.id }, pack.title))
      )), m2614RecommendedPacks.length > 0 && /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("div", { id: "m2614-suggested-checks-label", className: `text-sm font-medium mb-2 ${headingClass}` }, "Suggested checks"), /* @__PURE__ */ React.createElement("div", { role: "group", "aria-labelledby": "m2614-suggested-checks-label", className: "flex flex-wrap gap-2" }, m2614RecommendedPacks.map((pack) => {
        const isSelected = (selectedM2614ValidationPack == null ? void 0 : selectedM2614ValidationPack.id) === pack.id;
        return /* @__PURE__ */ React.createElement(
          "button",
          {
            key: `m2614-recommended-${pack.id}`,
            type: "button",
            "aria-pressed": isSelected,
            onClick: () => setM2614ValidationSelection((prev) => ({ ...prev, packId: pack.id })),
            className: `rounded-full border px-3 py-1 text-xs font-medium transition-colors ${isSelected ? "bg-indigo-600 text-white border-indigo-600" : secondaryButtonClass}`
          },
          pack.title
        );
      }))), /* @__PURE__ */ React.createElement("div", { className: "grid grid-cols-1 gap-3 sm:grid-cols-2" }, /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("label", { htmlFor: "m2614-validation-earliest", className: m2614LabelClass }, "From"), /* @__PURE__ */ React.createElement(
        "input",
        {
          id: "m2614-validation-earliest",
          type: "text",
          "aria-describedby": "m2614-validation-time-hint",
          value: m2614ValidationSelection.earliest,
          onChange: (e) => setM2614ValidationSelection((prev) => ({ ...prev, earliest: e.target.value })),
          className: m2614InputClass
        }
      )), /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("label", { htmlFor: "m2614-validation-latest", className: m2614LabelClass }, "To"), /* @__PURE__ */ React.createElement(
        "input",
        {
          id: "m2614-validation-latest",
          type: "text",
          "aria-describedby": "m2614-validation-time-hint",
          value: m2614ValidationSelection.latest,
          onChange: (e) => setM2614ValidationSelection((prev) => ({ ...prev, latest: e.target.value })),
          className: m2614InputClass
        }
      ))), /* @__PURE__ */ React.createElement("p", { id: "m2614-validation-time-hint", className: `text-xs ${mutedTextClass}` }, "Use Splunk time values, such as -30d for 30 days ago or now."), !canRunM2614Validation && /* @__PURE__ */ React.createElement("div", { className: `rounded-md border px-3 py-2 text-sm ${isDarkTheme ? "border-amber-700 bg-amber-950 text-amber-100" : "border-amber-200 bg-amber-50 text-amber-900"}` }, "Only analysts and admins can run live checks. Sign in with one of those roles to run this search."), /* @__PURE__ */ React.createElement(
        "button",
        {
          type: "button",
          onClick: runM2614Validation,
          disabled: !canStartM2614Validation,
          "data-testid": "m2614-run-validation-button",
          className: `inline-flex items-center gap-2 rounded-md px-4 py-2 text-sm font-medium transition-colors ${canStartM2614Validation ? "bg-indigo-600 hover:bg-indigo-700 text-white" : isDarkTheme ? "bg-gray-700 text-gray-300 cursor-not-allowed" : "bg-gray-200 text-gray-600 cursor-not-allowed"}`
        },
        /* @__PURE__ */ React.createElement("i", { className: `fas ${m2614ValidationState.status === "loading" ? "fa-spinner fa-spin" : "fa-play"}`, "aria-hidden": "true" }),
        m2614ValidationState.status === "loading" ? "Running Check..." : "Run Check"
      )), selectedM2614ValidationPack && /* @__PURE__ */ React.createElement("div", { className: m2614CardClass }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-wrap items-center gap-2 mb-2" }, selectedM2614ValidationPack.control_area && /* @__PURE__ */ React.createElement("span", { className: m2614PillClass }, formatTokenLabel(selectedM2614ValidationPack.control_area)), selectedM2614ValidationPack.priority_objective && /* @__PURE__ */ React.createElement("span", { className: m2614PillClass, title: formatM2614ObjectiveName(selectedM2614ValidationPack.priority_objective) }, String(selectedM2614ValidationPack.priority_objective).toUpperCase()), selectedM2614ValidationPack.required_role && /* @__PURE__ */ React.createElement("span", { className: m2614PillClass }, formatTokenLabel(selectedM2614ValidationPack.required_role), " role")), /* @__PURE__ */ React.createElement("h4", { className: `text-sm font-semibold ${headingClass}` }, selectedM2614ValidationPack.title), selectedM2614ValidationPack.description && /* @__PURE__ */ React.createElement("p", { className: `mt-1 text-sm leading-6 ${subtextClass}` }, selectedM2614ValidationPack.description), /* @__PURE__ */ React.createElement("details", { className: "mt-3", open: true }, /* @__PURE__ */ React.createElement("summary", { className: `cursor-pointer text-sm font-medium ${headingClass}` }, "Search that will run"), /* @__PURE__ */ React.createElement("pre", { className: `mt-2 ${m2614CodeClass}` }, selectedM2614ValidationPack.query))))), (m2614ValidationState.status === "error" || m2614ValidationResult) && /* @__PURE__ */ React.createElement("section", { "data-testid": "m2614-validation-result", "aria-labelledby": "m2614-result-title", className: m2614SectionClass }, renderSectionHeader("fa-clipboard-check", "Check Result", "", "m2614-result-title"), m2614ValidationState.status === "error" ? /* @__PURE__ */ React.createElement("div", { role: "alert", className: m2614NoticeClass }, m2614ValidationState.error) : /* @__PURE__ */ React.createElement("div", { className: "space-y-4" }, /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("div", { className: "flex flex-wrap items-center gap-2 mb-2" }, /* @__PURE__ */ React.createElement("span", { className: `inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-medium ${getM2614StatusClasses((m2614ValidationSummary == null ? void 0 : m2614ValidationSummary.status) || "unknown")}` }, formatM2614StatusLabel((m2614ValidationSummary == null ? void 0 : m2614ValidationSummary.status) || "unknown")), /* @__PURE__ */ React.createElement("span", { className: m2614PillClass }, countLabel((m2614ValidationSummary == null ? void 0 : m2614ValidationSummary.row_count) || m2614ValidationRows.length, "row"))), /* @__PURE__ */ React.createElement("p", { "data-testid": "m2614-validation-summary-headline", className: `text-sm font-semibold ${headingClass}` }, (m2614ValidationSummary == null ? void 0 : m2614ValidationSummary.headline) || "The check finished."), Array.isArray(m2614ValidationSummary == null ? void 0 : m2614ValidationSummary.findings) && m2614ValidationSummary.findings.length > 0 && /* @__PURE__ */ React.createElement("div", { className: "mt-3" }, renderBulletList(m2614ValidationSummary.findings, "m2614-finding")), Array.isArray(m2614ValidationSummary == null ? void 0 : m2614ValidationSummary.sample_rows) && m2614ValidationSummary.sample_rows.length > 0 && /* @__PURE__ */ React.createElement("details", { className: "mt-3" }, /* @__PURE__ */ React.createElement("summary", { className: `cursor-pointer text-sm font-medium ${headingClass}` }, "Show sample rows"), /* @__PURE__ */ React.createElement("pre", { className: `mt-2 ${m2614CodeClass}` }, JSON.stringify(m2614ValidationSummary.sample_rows, null, 2)))), m2614ValidationProfileSnapshot && /* @__PURE__ */ React.createElement("div", { "data-testid": "m2614-validation-grounding-panel", className: m2614CardClass }, /* @__PURE__ */ React.createElement("h4", { className: `text-sm font-semibold mb-2 ${headingClass}` }, "What Discovery Found"), m2614ValidationProfileSnapshot.has_data ? /* @__PURE__ */ React.createElement(React.Fragment, null, /* @__PURE__ */ React.createElement("div", { className: "flex flex-wrap gap-2 mb-2" }, /* @__PURE__ */ React.createElement("span", { className: m2614PillClass }, "Readiness ", formatMissionMetricValue(m2614ValidationProfileSnapshot.readiness_estimate), "/100"), /* @__PURE__ */ React.createElement("span", { className: m2614PillClass }, "Confidence: ", formatM2614StatusLabel(m2614ValidationProfileSnapshot.confidence || "unknown")), /* @__PURE__ */ React.createElement("span", { className: m2614PillClass }, "Run: ", formatMissionSessionSelectionLabel(m2614ValidationProfileSnapshot.timestamp || compareSelection.current))), /* @__PURE__ */ React.createElement("dl", { className: "space-y-1.5" }, renderLabeledLine("Objective:", ((_g2 = m2614ValidationProfileSnapshot.priority_objective) == null ? void 0 : _g2.objective) ? formatM2614ObjectiveName(m2614ValidationProfileSnapshot.priority_objective.objective) : ""), renderLabeledLine("Current state:", firstItem((_h2 = m2614ValidationProfileSnapshot.priority_objective) == null ? void 0 : _h2.notes)), renderLabeledLine("Gap to watch:", firstItem((_i2 = m2614ValidationProfileSnapshot.maturity_element) == null ? void 0 : _i2.gaps)), renderLabeledLine("Suggested next step:", firstItem((_j2 = m2614ValidationProfileSnapshot.maturity_element) == null ? void 0 : _j2.remediation), mutedTextClass))) : /* @__PURE__ */ React.createElement("p", { className: `text-sm ${mutedTextClass}` }, m2614ValidationProfileSnapshot.message || "No discovery results are available for this check yet.")), m2614ValidationRagContext && /* @__PURE__ */ React.createElement("div", { "data-testid": "m2614-validation-rag-panel", className: m2614CardClass }, /* @__PURE__ */ React.createElement("h4", { className: `text-sm font-semibold mb-2 ${headingClass}` }, "Related Context"), m2614ValidationRagContext.operator_brief && /* @__PURE__ */ React.createElement("p", { className: `text-sm ${subtextClass}` }, m2614ValidationRagContext.operator_brief), Array.isArray(m2614ValidationRagContext.recommended_uses) && m2614ValidationRagContext.recommended_uses.length > 0 && /* @__PURE__ */ React.createElement("div", { className: "mt-3" }, renderBulletList(m2614ValidationRagContext.recommended_uses.slice(0, 3), "m2614-rag-use")), firstItem(m2614ValidationRagContext.coverage_gaps) && /* @__PURE__ */ React.createElement("dl", { className: "mt-3" }, renderLabeledLine("Missing context:", firstItem(m2614ValidationRagContext.coverage_gaps), mutedTextClass)), m2614ValidationReusableQueries.length > 0 && /* @__PURE__ */ React.createElement("div", { className: "mt-4 space-y-3" }, /* @__PURE__ */ React.createElement("h5", { className: `text-xs font-semibold uppercase tracking-wider ${mutedTextClass}` }, "Searches you can reuse"), m2614ValidationReusableQueries.map((candidate, candidateIdx) => {
        const query = String(candidate.query || "").trim();
        const reuseTier = String(candidate.reuse_tier || "").trim().toLowerCase();
        const fitStatus = String(candidate.environment_fit_status || "").trim().toLowerCase();
        const validationStatus = String(candidate.validation_status || "").trim().toLowerCase();
        const knownGood = Boolean(candidate.known_good) || validationStatus === "known_good";
        return /* @__PURE__ */ React.createElement("div", { key: `m2614-validation-reuse-${candidateIdx}`, "data-testid": "m2614-validation-reusable-query-card", className: `rounded-lg border p-3 ${isDarkTheme ? "bg-gray-900 border-gray-700" : "bg-white border-gray-200"}` }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-col gap-2 sm:flex-row sm:items-start sm:justify-between" }, /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("div", { className: `text-sm font-medium ${headingClass}` }, candidate.title || "Reusable search"), candidate.why_reuse && /* @__PURE__ */ React.createElement("div", { className: `mt-1 text-sm ${subtextClass}` }, candidate.why_reuse)), renderSplQueryActionButtons2(query, {
          allowSave: false,
          originKind: "m2614_validation_reuse",
          originLabel: candidate.title || (selectedM2614ValidationPack == null ? void 0 : selectedM2614ValidationPack.title) || "M-26-14 reusable SPL candidate",
          sourceLabel: "M-26-14 Advisory",
          contextExcerpt: candidate.why_reuse || m2614ValidationRagContext.operator_brief || "",
          className: "sm:justify-end"
        })), /* @__PURE__ */ React.createElement("div", { className: "mt-2 flex flex-wrap gap-2 text-xs" }, (reuseTier || knownGood) && /* @__PURE__ */ React.createElement("span", { className: `rounded-full px-2 py-0.5 border ${getSplReuseTierClasses(reuseTier, knownGood)}` }, "Reuse: ", knownGood ? "Known Good" : formatSplIntelligenceLabel(reuseTier, "Candidate")), fitStatus && /* @__PURE__ */ React.createElement("span", { className: `rounded-full px-2 py-0.5 border ${getSplEnvironmentFitClasses(fitStatus)}` }, "Environment Fit: ", formatSplIntelligenceLabel(fitStatus, "Unknown")), validationStatus && /* @__PURE__ */ React.createElement("span", { className: `rounded-full px-2 py-0.5 border ${getSplValidationClasses(validationStatus)}` }, "Validation: ", formatSplIntelligenceLabel(validationStatus, "Unknown"))), /* @__PURE__ */ React.createElement("pre", { className: `mt-2 max-h-32 overflow-auto ${m2614CodeClass}` }, query));
      }))), m2614ValidationLlmAnalysis && /* @__PURE__ */ React.createElement("div", { "data-testid": "m2614-validation-advisory-panel", className: m2614CardClass }, /* @__PURE__ */ React.createElement("h4", { className: `text-sm font-semibold mb-2 ${headingClass}` }, "AI Review"), m2614ValidationLlmAnalysis.message && m2614ValidationLlmAnalysis.status !== "ready" && /* @__PURE__ */ React.createElement("p", { className: `mb-2 text-sm ${mutedTextClass}` }, m2614ValidationLlmAnalysis.message), m2614ValidationLlmAnalysis.summary && /* @__PURE__ */ React.createElement("p", { className: `text-sm leading-6 ${subtextClass}` }, m2614ValidationLlmAnalysis.summary), /* @__PURE__ */ React.createElement("dl", { className: "mt-2 space-y-1.5" }, renderLabeledLine("Why this matters here:", m2614ValidationLlmAnalysis.environment_relevance)), Array.isArray(m2614ValidationLlmAnalysis.recommended_adjustments) && m2614ValidationLlmAnalysis.recommended_adjustments.length > 0 && /* @__PURE__ */ React.createElement("div", { className: "mt-3" }, /* @__PURE__ */ React.createElement("h5", { className: `mb-2 text-xs font-semibold uppercase tracking-wider ${mutedTextClass}` }, "Suggested changes"), renderBulletList(m2614ValidationLlmAnalysis.recommended_adjustments.slice(0, 4), "m2614-adjustment")), /* @__PURE__ */ React.createElement("dl", { className: "mt-3 space-y-1.5" }, renderLabeledLine("Follow-up:", firstItem(m2614ValidationLlmAnalysis.suggested_follow_ups)), renderLabeledLine("Missing evidence:", firstItem(m2614ValidationLlmAnalysis.evidence_gaps), mutedTextClass), renderLabeledLine("Confidence note:", firstItem(m2614ValidationLlmAnalysis.confidence_notes), mutedTextClass)))))));
    };
    const getLibraryScoreClass = (score) => {
      if (typeof score !== "number") {
        return mutedTextClass;
      }
      if (score >= 80) {
        return isDarkTheme ? "text-emerald-300" : "text-emerald-700";
      }
      if (score >= 50) {
        return isDarkTheme ? "text-amber-300" : "text-amber-700";
      }
      return isDarkTheme ? "text-rose-300" : "text-rose-700";
    };
    const getLibraryPriorityClass = (priority) => {
      switch (priority) {
        case "high":
          return isDarkTheme ? "bg-rose-950 text-rose-100 border border-rose-800" : "bg-rose-50 text-rose-700 border border-rose-200";
        case "medium":
          return isDarkTheme ? "bg-amber-900 text-amber-100 border border-amber-700" : "bg-amber-50 text-amber-800 border border-amber-200";
        default:
          return isDarkTheme ? "bg-slate-800 text-slate-200 border border-slate-600" : "bg-slate-100 text-slate-700 border border-slate-300";
      }
    };
    const LIBRARY_DIMENSION_STATUS_LABELS = {
      needs_sources: "Needs sources",
      needs_discovery: "Run discovery again",
      not_applicable: "Not applicable",
      unavailable: "Unavailable"
    };
    const describeLibraryRefresh = (refresh) => {
      if (!refresh || !refresh.state || refresh.state === "idle") {
        return "";
      }
      if (refresh.state === "running") {
        const stage = LIBRARY_SOURCE_LABELS[refresh.stage] || "sources";
        const progress2 = refresh.total ? ` (${refresh.done || 0} of ${refresh.total})` : "";
        return `Refreshing ${stage}${progress2}. This can take a few minutes.`;
      }
      const label = {
        completed: "Last refresh finished",
        partial: "Last refresh finished with errors",
        failed: "Last refresh failed"
      }[refresh.state] || "Last refresh";
      return refresh.finished_at ? `${label} ${formatMissionDateTime(refresh.finished_at)}.` : `${label}.`;
    };
    const isSafeLibraryLink = (url) => typeof url === "string" && url.startsWith("https://");
    const renderKnowledgeLibraryPanel = () => {
      var _a2, _b2, _c2;
      const data = knowledgeLibrary.data;
      const tileClass = `rounded-lg p-3 border ${isDarkTheme ? "bg-gray-900 border-gray-700" : "bg-gray-50 border-gray-200"}`;
      const linkClass = isDarkTheme ? "text-indigo-300 hover:text-indigo-200 underline" : "text-indigo-700 hover:text-indigo-900 underline";
      if (!data) {
        return /* @__PURE__ */ React.createElement("section", { "data-testid": "knowledge-library-panel", "aria-labelledby": "knowledge-library-title", className: `rounded-lg shadow-sm p-6 border ${panelClass}` }, /* @__PURE__ */ React.createElement("h3", { id: "knowledge-library-title", className: `text-base font-semibold ${headingClass}` }, "Library health"), knowledgeLibrary.status === "error" ? /* @__PURE__ */ React.createElement("div", { className: "mt-2 flex flex-wrap items-center gap-3" }, /* @__PURE__ */ React.createElement("p", { className: `text-sm ${isDarkTheme ? "text-red-300" : "text-red-700"}` }, knowledgeLibrary.error || "Could not check library health."), /* @__PURE__ */ React.createElement("button", { type: "button", onClick: () => loadKnowledgeLibrary(), className: getCapabilityActionButtonClass(false, false) }, "Try again")) : /* @__PURE__ */ React.createElement("p", { className: `mt-2 text-sm ${subtextClass}` }, "Checking library health..."));
      }
      const scorecard = data.scorecard || {};
      const profile = data.profile || {};
      const splunk = profile.splunk || {};
      const apps = profile.apps || {};
      const refresh = data.refresh || {};
      const settings = data.settings || {};
      const isRefreshing = refresh.state === "running";
      const busyAction = knowledgeLibrary.action;
      const canManage = !!data.can_manage;
      const allowOnline = !!settings.allow_online_sources;
      const dimensions = Array.isArray(scorecard.dimensions) ? scorecard.dimensions : [];
      const gaps = Array.isArray(scorecard.gaps) ? scorecard.gaps : [];
      const gapCounts = scorecard.gap_counts || {};
      const visibleGaps = showAllLibraryGaps ? gaps : gaps.slice(0, 6);
      const sources = Array.isArray(data.sources) ? data.sources : [];
      const anySourceLoaded = sources.some((source) => source.available);
      const platformDocs = ((_a2 = data.catalog) == null ? void 0 : _a2.platform_docs) || {};
      const docLinks = [
        ...Array.isArray(platformDocs.manuals) ? platformDocs.manuals : [],
        ...Array.isArray((_b2 = data.catalog) == null ? void 0 : _b2.app_docs) ? data.catalog.app_docs : []
      ].filter((entry) => isSafeLibraryLink(entry == null ? void 0 : entry.url));
      const deploymentLabel = { cloud: "Splunk Cloud Platform", enterprise: "Splunk Enterprise" }[splunk.deployment_type] || "Splunk";
      const refreshText = describeLibraryRefresh(refresh);
      const failedResults = isRefreshing ? [] : Object.entries(refresh.results || {}).filter(([, result]) => (result == null ? void 0 : result.status) === "error");
      const profileFacts = profile.available ? [
        `${deploymentLabel}${splunk.version ? ` ${splunk.version}` : ""}`,
        apps.collected ? `${apps.total || 0} apps (${apps.addons || 0} not built in)` : null,
        `${profile.sourcetype_count || 0} sourcetypes`,
        ((_c2 = profile.discovery) == null ? void 0 : _c2.generated_at) ? `Discovery ${formatMissionDateTime(profile.discovery.generated_at)}` : null
      ].filter(Boolean) : [];
      return /* @__PURE__ */ React.createElement("section", { "data-testid": "knowledge-library-panel", "aria-labelledby": "knowledge-library-title", className: `rounded-lg shadow-sm p-6 border ${panelClass}` }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-col lg:flex-row lg:items-start lg:justify-between gap-4" }, /* @__PURE__ */ React.createElement("div", { className: "min-w-0 max-w-3xl" }, /* @__PURE__ */ React.createElement("h3", { id: "knowledge-library-title", className: `text-base font-semibold ${headingClass}` }, "Library health"), /* @__PURE__ */ React.createElement("p", { className: `mt-1 text-sm ${subtextClass}` }, "How well the reference library covers the Splunk environment from your latest discovery, and what to fix first."), profileFacts.length > 0 && /* @__PURE__ */ React.createElement("p", { "data-testid": "knowledge-library-profile", className: `mt-1 text-xs ${mutedTextClass}` }, profileFacts.join(" · "))), /* @__PURE__ */ React.createElement("div", { className: "lg:flex-shrink-0 lg:text-right" }, /* @__PURE__ */ React.createElement("div", { className: `text-xs uppercase tracking-wide ${mutedTextClass}` }, "Overall score"), /* @__PURE__ */ React.createElement("div", { "data-testid": "knowledge-library-score", className: `text-3xl font-semibold mt-1 ${getLibraryScoreClass(scorecard.overall_score)}` }, typeof scorecard.overall_score === "number" ? `${scorecard.overall_score}%` : "Not scored"))), dimensions.length > 0 && /* @__PURE__ */ React.createElement("div", { "data-testid": "knowledge-library-dimensions", className: "grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-3 gap-3 mt-5" }, dimensions.map((dimension) => /* @__PURE__ */ React.createElement("div", { key: dimension.key, className: tileClass }, /* @__PURE__ */ React.createElement("div", { className: `text-xs uppercase tracking-wide ${mutedTextClass}` }, dimension.label), /* @__PURE__ */ React.createElement("div", { className: `mt-1 ${typeof dimension.score === "number" ? `text-2xl font-semibold ${getLibraryScoreClass(dimension.score)}` : `text-sm font-semibold ${headingClass}`}` }, typeof dimension.score === "number" ? `${dimension.score}%` : LIBRARY_DIMENSION_STATUS_LABELS[dimension.status] || "Not scored"), dimension.basis && /* @__PURE__ */ React.createElement("div", { className: `mt-1 text-xs ${subtextClass}` }, dimension.basis)))), /* @__PURE__ */ React.createElement("div", { className: "mt-5" }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-wrap items-center gap-2" }, /* @__PURE__ */ React.createElement("h4", { className: `text-sm font-semibold ${headingClass}` }, "What to fix"), gaps.length > 0 && /* @__PURE__ */ React.createElement("span", { className: `text-xs ${mutedTextClass}` }, gapCounts.high || 0, " high, ", gapCounts.medium || 0, " medium, ", gapCounts.low || 0, " low")), gaps.length === 0 ? /* @__PURE__ */ React.createElement("p", { className: `mt-2 text-sm ${subtextClass}` }, "Nothing to fix right now.") : /* @__PURE__ */ React.createElement("ul", { "data-testid": "knowledge-library-gaps", className: "mt-2 space-y-2" }, visibleGaps.map((gap) => /* @__PURE__ */ React.createElement("li", { key: gap.id, className: `rounded-lg border px-3 py-3 ${panelMutedClass}` }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-wrap items-center gap-2" }, /* @__PURE__ */ React.createElement("span", { className: `inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium ${getLibraryPriorityClass(gap.priority)}` }, gap.priority === "high" ? "High" : gap.priority === "medium" ? "Medium" : "Low"), /* @__PURE__ */ React.createElement("span", { className: `text-sm font-medium break-words ${headingClass}` }, gap.title)), gap.detail && /* @__PURE__ */ React.createElement("div", { className: `mt-1 text-xs break-words ${subtextClass}` }, gap.detail), gap.action && /* @__PURE__ */ React.createElement("div", { className: `mt-1 text-xs font-medium break-words ${headingClass}` }, gap.action), isSafeLibraryLink(gap.url) && /* @__PURE__ */ React.createElement("a", { href: gap.url, target: "_blank", rel: "noopener noreferrer", className: `mt-1 inline-block text-xs ${linkClass}` }, "Open on Splunkbase")))), gaps.length > 6 && /* @__PURE__ */ React.createElement(
        "button",
        {
          type: "button",
          onClick: () => setShowAllLibraryGaps((prev) => !prev),
          className: `mt-2 text-xs font-medium ${linkClass}`
        },
        showAllLibraryGaps ? "Show fewer" : `Show all ${gaps.length}`
      )), docLinks.length > 0 && /* @__PURE__ */ React.createElement("div", { className: "mt-5" }, /* @__PURE__ */ React.createElement("h4", { className: `text-sm font-semibold ${headingClass}` }, "Documentation for your environment"), /* @__PURE__ */ React.createElement("p", { className: `mt-1 text-xs ${mutedTextClass}` }, platformDocs.doc_version ? `${platformDocs.product_title || deploymentLabel} ${platformDocs.doc_version} manuals on help.splunk.com.` : "Manuals on help.splunk.com."), /* @__PURE__ */ React.createElement("ul", { "data-testid": "knowledge-library-docs", className: "mt-2 grid grid-cols-1 xl:grid-cols-2 gap-2" }, docLinks.map((entry) => /* @__PURE__ */ React.createElement("li", { key: entry.entry_id || entry.url, className: `rounded-lg border px-3 py-2 ${panelMutedClass}` }, /* @__PURE__ */ React.createElement("a", { href: entry.url, target: "_blank", rel: "noopener noreferrer", className: `text-sm font-medium ${linkClass}` }, entry.title), /* @__PURE__ */ React.createElement("div", { className: `mt-0.5 text-xs ${subtextClass}` }, [entry.reason, entry.version ? `Version ${entry.version}` : null, entry.page_count ? `${Number(entry.page_count).toLocaleString()} pages` : null].filter(Boolean).join(" · ")))))), /* @__PURE__ */ React.createElement("div", { className: "mt-5" }, /* @__PURE__ */ React.createElement("h4", { className: `text-sm font-semibold ${headingClass}` }, "Sources"), /* @__PURE__ */ React.createElement("div", { "data-testid": "knowledge-library-sources", className: "mt-2 grid grid-cols-1 xl:grid-cols-3 gap-3" }, sources.map((source) => /* @__PURE__ */ React.createElement("div", { key: source.name, className: tileClass }, /* @__PURE__ */ React.createElement("div", { className: `text-sm font-medium ${headingClass}` }, source.title), /* @__PURE__ */ React.createElement("div", { className: `mt-1 text-xs ${source.available ? subtextClass : mutedTextClass}` }, source.available ? [
        source.fetched_at ? `Updated ${formatMissionDateTime(source.fetched_at)}` : "Loaded",
        typeof source.count === "number" ? `${source.count.toLocaleString()} ${source.name === "help_docs" ? "pages" : source.name === "splunkbase" ? "apps" : "data sources"}` : null,
        source.version ? `Release ${source.version}` : null
      ].filter(Boolean).join(" · ") : "Not loaded"), source.available && /* @__PURE__ */ React.createElement("div", { className: `mt-1 text-xs ${mutedTextClass}` }, source.origin === "pack" ? `From a library pack${source.pack_created_at ? ` created ${formatMissionDateTime(source.pack_created_at)}` : ""}` : "Downloaded online"), /* @__PURE__ */ React.createElement("div", { className: `mt-1 text-xs ${mutedTextClass}` }, source.license)))), canManage ? /* @__PURE__ */ React.createElement("div", { className: "mt-4 space-y-3" }, /* @__PURE__ */ React.createElement("label", { className: "flex items-start gap-2 text-sm cursor-pointer" }, /* @__PURE__ */ React.createElement(
        "input",
        {
          type: "checkbox",
          "data-testid": "knowledge-library-online-toggle",
          checked: allowOnline,
          disabled: !!busyAction,
          onChange: (event) => setKnowledgeLibraryOnline(event.target.checked),
          className: "mt-1"
        }
      ), /* @__PURE__ */ React.createElement("span", null, /* @__PURE__ */ React.createElement("span", { className: `font-medium ${headingClass}` }, "Download sources from the internet"), /* @__PURE__ */ React.createElement("span", { className: `block text-xs ${subtextClass}` }, "Connects only to ", (Array.isArray(settings.online_hosts) ? settings.online_hosts : []).join(", "), ". Sources download when you turn this on and update every ", settings.auto_refresh_days || 7, " days. On networks without internet access, leave this off and import a library pack."))), /* @__PURE__ */ React.createElement("div", { className: "flex flex-wrap items-center gap-2" }, /* @__PURE__ */ React.createElement(
        "button",
        {
          type: "button",
          "data-testid": "knowledge-library-refresh-button",
          onClick: refreshKnowledgeLibrarySources,
          disabled: !allowOnline || isRefreshing || !!busyAction,
          title: allowOnline ? void 0 : "Turn on internet downloads first.",
          className: getCapabilityActionButtonClass(true, !allowOnline || isRefreshing || !!busyAction)
        },
        isRefreshing || busyAction === "refresh" ? "Refreshing..." : "Refresh sources"
      ), /* @__PURE__ */ React.createElement(
        "button",
        {
          type: "button",
          "data-testid": "knowledge-library-import-button",
          onClick: () => {
            var _a3;
            return (_a3 = libraryPackInputRef.current) == null ? void 0 : _a3.click();
          },
          disabled: isRefreshing || !!busyAction,
          className: getCapabilityActionButtonClass(false, isRefreshing || !!busyAction)
        },
        busyAction === "import" ? "Importing..." : "Import library pack"
      ), /* @__PURE__ */ React.createElement(
        "input",
        {
          ref: libraryPackInputRef,
          type: "file",
          accept: ".zip,application/zip",
          className: "hidden",
          "data-testid": "knowledge-library-import-input",
          onChange: (event) => {
            const file = event.target.files && event.target.files[0];
            event.target.value = "";
            importKnowledgeLibraryPack(file);
          }
        }
      ), anySourceLoaded && /* @__PURE__ */ React.createElement("a", { href: "/api/knowledge-library/pack/export", download: true, "data-testid": "knowledge-library-export-link", className: getCapabilityActionButtonClass(false, false) }, "Export library pack"))) : /* @__PURE__ */ React.createElement("div", { className: "mt-4 flex flex-wrap items-center gap-3" }, /* @__PURE__ */ React.createElement("p", { className: `text-xs ${subtextClass}` }, "Only admins can change library sources."), anySourceLoaded && /* @__PURE__ */ React.createElement("a", { href: "/api/knowledge-library/pack/export", download: true, "data-testid": "knowledge-library-export-link", className: getCapabilityActionButtonClass(false, false) }, "Export library pack")), refreshText && /* @__PURE__ */ React.createElement("p", { "data-testid": "knowledge-library-refresh-status", className: `mt-3 text-xs ${isRefreshing ? headingClass : mutedTextClass}` }, refreshText), failedResults.length > 0 && /* @__PURE__ */ React.createElement("ul", { className: `mt-1 space-y-1 text-xs ${isDarkTheme ? "text-amber-200" : "text-amber-800"}` }, failedResults.map(([name, result]) => /* @__PURE__ */ React.createElement("li", { key: name, className: "break-words" }, LIBRARY_SOURCE_LABELS[name] || "Refresh", ": ", result.error || "failed"))), knowledgeLibrary.message && /* @__PURE__ */ React.createElement(
        "p",
        {
          "data-testid": "knowledge-library-message",
          role: knowledgeLibrary.message.type === "error" ? "alert" : "status",
          className: `mt-3 text-sm ${knowledgeLibrary.message.type === "error" ? isDarkTheme ? "text-red-300" : "text-red-700" : isDarkTheme ? "text-emerald-300" : "text-emerald-700"}`
        },
        knowledgeLibrary.message.text
      )));
    };
    const renderRagWorkspaceView = () => {
      var _a2, _b2, _c2, _d2, _e2, _f2, _g2, _h2;
      if (!ragCapability) {
        return /* @__PURE__ */ React.createElement("div", { "data-testid": "context-library-detail-panel", className: `rounded-lg shadow-sm p-6 border ${panelClass}` }, /* @__PURE__ */ React.createElement("h3", { className: `text-lg font-semibold ${headingClass}` }, "Knowledge Base"), /* @__PURE__ */ React.createElement("p", { className: `mt-2 text-sm ${subtextClass}` }, "The Knowledge Base is not available on this server."));
      }
      return /* @__PURE__ */ React.createElement(React.Fragment, null, /* @__PURE__ */ React.createElement("div", { "data-testid": "rag-workspace-status", className: `rounded-lg shadow-sm p-6 border ${panelClass}` }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-col lg:flex-row lg:items-start lg:justify-between gap-4" }, /* @__PURE__ */ React.createElement("div", { className: "min-w-0 max-w-3xl" }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-wrap items-center gap-2" }, /* @__PURE__ */ React.createElement("h3", { className: `text-base font-semibold ${headingClass}` }, "Status"), /* @__PURE__ */ React.createElement("span", { className: `inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium ${getCapabilityStatusClasses(ragStatusLabel)}` }, formatCapabilityStatusLabel(ragStatusLabel))), ragCapability.installed && ragCapability.health_message && /* @__PURE__ */ React.createElement("p", { className: `mt-2 text-sm ${subtextClass}` }, ragCapability.health_message), !ragCapability.installed && /* @__PURE__ */ React.createElement("p", { className: `mt-2 text-sm ${subtextClass}` }, "You can import documents now. Install the Knowledge Base and turn it on so chat can search them."), ragCapability.installed && (ragCapability.last_tested_at || ragCapability.version && ragCapability.version !== "bundled") && /* @__PURE__ */ React.createElement("p", { className: `mt-1 text-xs ${mutedTextClass}` }, [
        ragCapability.last_tested_at ? `Last checked ${formatMissionDateTime(ragCapability.last_tested_at)}` : null,
        ragCapability.version && ragCapability.version !== "bundled" ? `Version ${ragCapability.version}` : null
      ].filter(Boolean).join(" · "))), /* @__PURE__ */ React.createElement("div", { className: "lg:flex-shrink-0" }, renderCapabilityLifecycleActions(ragCapability, canReindexRag ? /* @__PURE__ */ React.createElement(
        "button",
        {
          type: "button",
          onClick: () => runCapabilityAction("rag_chromadb", "reindex"),
          disabled: isRagBusy,
          className: getCapabilityActionButtonClass(false, isRagBusy)
        },
        ragActionInProgress === "reindex" ? "Reindexing..." : "Reindex"
      ) : null))), ragCapability.installed && /* @__PURE__ */ React.createElement("div", { className: "grid grid-cols-2 xl:grid-cols-4 gap-3 mt-5" }, /* @__PURE__ */ React.createElement("div", { className: `rounded-lg p-3 border ${isDarkTheme ? "bg-gray-900 border-gray-700" : "bg-gray-50 border-gray-200"}` }, /* @__PURE__ */ React.createElement("div", { className: `text-xs uppercase tracking-wide ${mutedTextClass}` }, "Documents Indexed"), /* @__PURE__ */ React.createElement("div", { className: `text-2xl font-semibold mt-1 ${headingClass}` }, ragIndexedDocumentCount)), /* @__PURE__ */ React.createElement("div", { className: `rounded-lg p-3 border ${isDarkTheme ? "bg-gray-900 border-gray-700" : "bg-gray-50 border-gray-200"}` }, /* @__PURE__ */ React.createElement("div", { className: `text-xs uppercase tracking-wide ${mutedTextClass}` }, "Source Files"), /* @__PURE__ */ React.createElement("div", { className: `text-2xl font-semibold mt-1 ${headingClass}` }, (ragIndexSummary == null ? void 0 : ragIndexSummary.source_file_count) || 0)), /* @__PURE__ */ React.createElement("div", { className: `rounded-lg p-3 border ${isDarkTheme ? "bg-gray-900 border-gray-700" : "bg-gray-50 border-gray-200"}` }, /* @__PURE__ */ React.createElement("div", { className: `text-xs uppercase tracking-wide ${mutedTextClass}` }, "Imported Items"), /* @__PURE__ */ React.createElement("div", { className: `text-2xl font-semibold mt-1 ${headingClass}` }, ragDisplayedAssetCount)), /* @__PURE__ */ React.createElement("div", { className: `rounded-lg p-3 border ${isDarkTheme ? "bg-gray-900 border-gray-700" : "bg-gray-50 border-gray-200"}` }, /* @__PURE__ */ React.createElement("div", { className: `text-xs uppercase tracking-wide ${mutedTextClass}` }, "Ready for Chat"), /* @__PURE__ */ React.createElement("div", { className: `text-sm font-semibold mt-2 ${headingClass}` }, canUseRagContextPreview ? "Yes" : !ragCapability.enabled ? "Not yet. Turn it on." : "Not yet. Select Reindex."))), canInstallRag && ragInstallPreflightWarning && /* @__PURE__ */ React.createElement("div", { "data-testid": "rag-install-preflight-warning", className: `mt-4 rounded-xl border p-4 ${isDarkTheme ? "bg-amber-950 border-amber-800 text-amber-100" : "bg-amber-50 border-amber-200 text-amber-900"}` }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-col gap-4 xl:flex-row xl:items-start xl:justify-between" }, /* @__PURE__ */ React.createElement("div", { className: "min-w-0 flex-1" }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-wrap items-center gap-2" }, /* @__PURE__ */ React.createElement("span", { className: `inline-flex items-center rounded-full px-2.5 py-1 text-xs font-semibold ${isDarkTheme ? "bg-amber-900 text-amber-100 border border-amber-700" : "bg-white text-amber-800 border border-amber-200"}` }, "Before You Install"), /* @__PURE__ */ React.createElement("span", { className: `inline-flex items-center rounded-full px-2.5 py-1 text-xs font-medium ${isDarkTheme ? "bg-rose-950 text-rose-100 border border-rose-800" : "bg-rose-50 text-rose-700 border border-rose-200"}` }, "Install will likely fail with the current package source")), /* @__PURE__ */ React.createElement("div", { className: `mt-3 text-sm font-semibold break-words ${headingClass}` }, ragInstallPreflightWarning), ragInstallPreflightReason && /* @__PURE__ */ React.createElement("div", { className: `mt-1 text-sm break-words ${subtextClass}` }, ragInstallPreflightReason), ragInstallPackageIndexes.length > 0 && /* @__PURE__ */ React.createElement("div", { className: "mt-3 flex flex-wrap gap-2 text-xs" }, ragInstallPackageIndexes.map((pkgIndex) => /* @__PURE__ */ React.createElement("span", { key: pkgIndex, className: `max-w-full break-all rounded-full px-2 py-0.5 border ${isDarkTheme ? "bg-gray-900 text-gray-200 border-gray-700" : "bg-white text-gray-700 border-gray-300"}` }, pkgIndex)))), /* @__PURE__ */ React.createElement("div", { className: `min-w-[240px] rounded-xl border p-3 ${isDarkTheme ? "bg-slate-950 border-amber-900" : "bg-white border-amber-200"}` }, /* @__PURE__ */ React.createElement("div", { className: `text-xs uppercase tracking-wide ${mutedTextClass}` }, "Try This First"), /* @__PURE__ */ React.createElement("div", { className: `mt-2 text-xs ${subtextClass}` }, "This machine uses a filtered or private package source. Try the alternate install method first."), ragPreferredInstallAlternativeMethod && /* @__PURE__ */ React.createElement(React.Fragment, null, /* @__PURE__ */ React.createElement(
        "button",
        {
          type: "button",
          "data-testid": "rag-install-alternate-method-button",
          onClick: () => runCapabilityAction("rag_chromadb", "install", { strategy: ragPreferredInstallAlternativeMethod.strategy }),
          disabled: isRagBusy,
          className: `mt-3 w-full px-3 py-2 rounded text-sm font-semibold ${!isRagBusy ? "bg-amber-500 hover:bg-amber-600 text-gray-950" : isDarkTheme ? "bg-gray-700 text-gray-400 cursor-not-allowed" : "bg-gray-200 text-gray-500 cursor-not-allowed"}`
        },
        ragActionInProgress === "install" ? `Trying alternate method... ${formatCapabilityActionElapsed(ragInstallElapsedSeconds)}` : ragPreferredInstallAlternativeMethod.app_action_label || "Try Alternate Method"
      ), /* @__PURE__ */ React.createElement("div", { className: `mt-2 text-xs ${mutedTextClass}` }, ragPreferredInstallAlternativeMethod.label || "Force public PyPI for the active environment")))), ragInstallAlternativeMethods.length > 0 && /* @__PURE__ */ React.createElement("div", { className: "mt-4 grid grid-cols-1 xl:grid-cols-2 gap-3" }, ragInstallAlternativeMethods.map((method, index) => /* @__PURE__ */ React.createElement("div", { key: `rag-install-alt-method-${index}`, className: `rounded-xl border p-3 ${panelMutedClass}` }, /* @__PURE__ */ React.createElement("div", { className: `text-sm font-semibold ${headingClass}` }, (method == null ? void 0 : method.label) || "Alternate install method"), (method == null ? void 0 : method.description) && /* @__PURE__ */ React.createElement("div", { className: `mt-1 text-xs ${subtextClass}` }, method.description), Array.isArray(method == null ? void 0 : method.commands) && method.commands.length > 0 && /* @__PURE__ */ React.createElement("div", { className: "mt-3 space-y-2" }, method.commands.map((command, commandIndex) => /* @__PURE__ */ React.createElement("pre", { key: `rag-install-alt-command-${index}-${commandIndex}`, className: `max-w-full overflow-x-auto whitespace-pre-wrap break-all rounded-lg border px-3 py-2 text-xs ${isDarkTheme ? "bg-slate-950 border-slate-800 text-slate-100" : "bg-white border-slate-200 text-slate-800"}` }, command))))))), ragCapability.installed && /* @__PURE__ */ React.createElement("div", { className: "grid grid-cols-1 xl:grid-cols-2 gap-3 mt-4" }, /* @__PURE__ */ React.createElement("div", { className: `rounded-lg border px-3 py-3 ${panelMutedClass}` }, /* @__PURE__ */ React.createElement("div", { className: `text-xs font-medium mb-1 ${headingClass}` }, "Index Status"), /* @__PURE__ */ React.createElement("div", { className: `text-xs ${subtextClass}` }, "Last indexed: ", formatMissionDateTime(ragIndexSummary == null ? void 0 : ragIndexSummary.last_indexed_at, "Not indexed yet")), Array.isArray(ragIndexSummary == null ? void 0 : ragIndexSummary.sample_sources) && ragIndexSummary.sample_sources.length > 0 && /* @__PURE__ */ React.createElement("div", { className: `mt-2 text-xs ${mutedTextClass}` }, "Sample sources: ", ragIndexSummary.sample_sources.join(", "))), /* @__PURE__ */ React.createElement("div", { className: `rounded-lg border px-3 py-3 ${panelMutedClass}` }, /* @__PURE__ */ React.createElement("div", { className: `text-xs font-medium mb-1 ${headingClass}` }, "Imported Items"), /* @__PURE__ */ React.createElement("div", { className: `text-xs ${subtextClass}` }, "Stored in: ", ragDisplayedAssetDir), /* @__PURE__ */ React.createElement("div", { className: `mt-1 text-xs ${subtextClass}` }, "Checked in: ", ragCheckedInAssetCount, ". Checked out: ", ragCheckedOutAssetCount, "."), /* @__PURE__ */ React.createElement("div", { className: `mt-1 text-xs ${subtextClass}` }, canUseRagContextPreview ? "Checked-in items are ready for chat." : "Chat can use imports after the Knowledge Base is turned on and reindexed."))), (Array.isArray(ragCapability.dependency_packages) && ragCapability.dependency_packages.length > 0 || ragIndexSourceTypes.length > 0 || ragKnowledgeAssetTypeCounts.length > 0) && /* @__PURE__ */ React.createElement("div", { className: "space-y-3 mt-4" }, Array.isArray(ragCapability.dependency_packages) && ragCapability.dependency_packages.length > 0 && /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("div", { className: `text-xs font-medium mb-1 ${headingClass}` }, "Dependencies"), /* @__PURE__ */ React.createElement("div", { className: "flex flex-wrap gap-2 text-xs" }, ragCapability.dependency_packages.map((pkg) => /* @__PURE__ */ React.createElement("span", { key: pkg, className: `rounded-full px-2 py-0.5 border ${isDarkTheme ? "bg-gray-800 text-gray-200 border-gray-600" : "bg-gray-50 text-gray-700 border-gray-300"}` }, pkg)))), ragIndexSourceTypes.length > 0 && /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("div", { className: `text-xs font-medium mb-1 ${headingClass}` }, "Indexed by Source"), /* @__PURE__ */ React.createElement("div", { className: "flex flex-wrap gap-2 text-xs" }, ragIndexSourceTypes.map(([sourceType, count]) => /* @__PURE__ */ React.createElement("span", { key: sourceType, className: `rounded-full px-2 py-0.5 border ${isDarkTheme ? "bg-gray-800 text-gray-200 border-gray-600" : "bg-gray-50 text-gray-700 border-gray-300"}` }, formatCapabilitySourceTypeLabel(sourceType), ": ", count)))), ragKnowledgeAssetTypeCounts.length > 0 && /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("div", { className: `text-xs font-medium mb-1 ${headingClass}` }, "Imported by Type"), /* @__PURE__ */ React.createElement("div", { className: "flex flex-wrap gap-2 text-xs" }, ragKnowledgeAssetTypeCounts.map(([assetType, count]) => /* @__PURE__ */ React.createElement("span", { key: assetType, className: `rounded-full px-2 py-0.5 border ${isDarkTheme ? "bg-gray-800 text-gray-200 border-gray-600" : "bg-gray-50 text-gray-700 border-gray-300"}` }, formatKnowledgeAssetTypeLabel(assetType), ": ", count)))))), renderKnowledgeLibraryPanel(), /* @__PURE__ */ React.createElement("div", { className: "grid grid-cols-1 xl:grid-cols-2 gap-6" }, /* @__PURE__ */ React.createElement("div", { className: "space-y-6" }, /* @__PURE__ */ React.createElement("div", { className: `rounded-lg shadow-sm p-6 border ${panelClass}` }, /* @__PURE__ */ React.createElement("div", { className: `text-sm font-semibold mb-2 ${headingClass}` }, "Import a Document"), /* @__PURE__ */ React.createElement("p", { className: `text-xs mb-3 ${subtextClass}` }, "Add documentation, environment notes, or runbook steps the assistant should know about. New imports are checked in, so chat can use them."), /* @__PURE__ */ React.createElement("div", { className: "grid grid-cols-1 sm:grid-cols-2 gap-2 mb-2" }, /* @__PURE__ */ React.createElement(
        "input",
        {
          value: ragAssetDraft.title || "",
          onChange: (event) => updateRagAssetDraft("title", event.target.value),
          placeholder: "Title",
          className: `rounded-lg border px-3 py-2 text-xs ${isDarkTheme ? "bg-gray-900 border-gray-700 text-gray-100" : "bg-white border-gray-300 text-gray-900"}`
        }
      ), /* @__PURE__ */ React.createElement(
        "select",
        {
          value: ragAssetDraft.asset_type || "reference_document",
          onChange: (event) => updateRagAssetDraft("asset_type", event.target.value),
          className: `rounded-lg border px-3 py-2 text-xs ${isDarkTheme ? "bg-gray-900 border-gray-700 text-gray-100" : "bg-white border-gray-300 text-gray-900"}`
        },
        /* @__PURE__ */ React.createElement("option", { value: SPL_LIBRARY_ASSET_TYPE }, "SPL Library Query"),
        /* @__PURE__ */ React.createElement("option", { value: "reference_document" }, "Reference Document"),
        /* @__PURE__ */ React.createElement("option", { value: "splunk_documentation" }, "Splunk Documentation"),
        /* @__PURE__ */ React.createElement("option", { value: "monitored_system_context" }, "Monitored System Notes"),
        /* @__PURE__ */ React.createElement("option", { value: "connected_system_context" }, "Connected System Notes"),
        /* @__PURE__ */ React.createElement("option", { value: "integration_context" }, "Integration Notes"),
        /* @__PURE__ */ React.createElement("option", { value: "runbook_context" }, "Runbook Notes")
      ), /* @__PURE__ */ React.createElement(
        "input",
        {
          value: ragAssetDraft.source_label || "",
          onChange: (event) => updateRagAssetDraft("source_label", event.target.value),
          placeholder: "Source label, system, or owner",
          className: `rounded-lg border px-3 py-2 text-xs ${isDarkTheme ? "bg-gray-900 border-gray-700 text-gray-100" : "bg-white border-gray-300 text-gray-900"}`
        }
      ), /* @__PURE__ */ React.createElement(
        "input",
        {
          value: ragAssetDraft.tags || "",
          onChange: (event) => updateRagAssetDraft("tags", event.target.value),
          placeholder: "Tags, comma separated",
          className: `rounded-lg border px-3 py-2 text-xs ${isDarkTheme ? "bg-gray-900 border-gray-700 text-gray-100" : "bg-white border-gray-300 text-gray-900"}`
        }
      )), /* @__PURE__ */ React.createElement(
        "textarea",
        {
          value: ragAssetDraft.description || "",
          onChange: (event) => updateRagAssetDraft("description", event.target.value),
          rows: 2,
          placeholder: "What questions this should help answer (optional)",
          className: `w-full rounded-lg border px-3 py-2 text-xs mb-2 ${isDarkTheme ? "bg-gray-900 border-gray-700 text-gray-100" : "bg-white border-gray-300 text-gray-900"}`
        }
      ), /* @__PURE__ */ React.createElement(
        "textarea",
        {
          value: ragAssetDraft.content || "",
          onChange: (event) => updateRagAssetDraft("content", event.target.value),
          rows: 8,
          placeholder: "Paste documentation, system notes, runbook steps, or other reference text",
          className: `w-full rounded-lg border px-3 py-2 text-xs font-mono ${isDarkTheme ? "bg-gray-900 border-gray-700 text-gray-100" : "bg-white border-gray-300 text-gray-900"}`
        }
      ), /* @__PURE__ */ React.createElement("div", { className: "mt-2" }, /* @__PURE__ */ React.createElement("label", { className: `block text-xs font-medium mb-1 ${headingClass}` }, "Or upload a file"), /* @__PURE__ */ React.createElement(
        "input",
        {
          ref: ragAssetFileInputRef,
          type: "file",
          accept: ".md,.txt,.json,.log,.csv,.pdf,.docx",
          onChange: (event) => {
            var _a3;
            return setRagAssetUploadFile(((_a3 = event.target.files) == null ? void 0 : _a3[0]) || null);
          },
          className: `block w-full text-xs ${subtextClass}`
        }
      ), ragAssetUploadFile && /* @__PURE__ */ React.createElement("div", { className: `mt-1 ${mutedTextClass}` }, "Selected file: ", ragAssetUploadFile.name)), /* @__PURE__ */ React.createElement("div", { className: "flex flex-wrap gap-2 mt-3" }, /* @__PURE__ */ React.createElement(
        "button",
        {
          type: "button",
          onClick: importRagKnowledgeAsset,
          disabled: isRagBusy,
          className: getCapabilityActionButtonClass(true, isRagBusy)
        },
        ragActionInProgress === "import-asset" ? "Importing..." : ragAssetUploadFile ? "Upload File" : "Import"
      ), /* @__PURE__ */ React.createElement(
        "button",
        {
          type: "button",
          onClick: clearRagAssetDraft,
          disabled: isRagBusy,
          className: getCapabilityActionButtonClass(false, isRagBusy)
        },
        "Clear"
      )), /* @__PURE__ */ React.createElement("div", { className: `mt-2 text-xs ${mutedTextClass}` }, "Supported files: .md, .txt, .json, .log, .csv, .pdf, and .docx. If you choose a file, it is imported instead of the pasted text."))), /* @__PURE__ */ React.createElement("div", { className: "space-y-6" }, /* @__PURE__ */ React.createElement("div", { className: `rounded-lg shadow-sm p-6 border ${panelClass}` }, /* @__PURE__ */ React.createElement("div", { className: "mb-3" }, /* @__PURE__ */ React.createElement("div", { className: `text-sm font-semibold ${headingClass}` }, "Preview Chat Context"), /* @__PURE__ */ React.createElement("div", { className: `text-xs ${subtextClass}` }, "See which passages the assistant would use to answer a question."), !canUseRagContextPreview && /* @__PURE__ */ React.createElement("div", { "data-testid": "rag-context-preview-unavailable", className: `mt-2 text-xs ${mutedTextClass}` }, !ragCapability.installed ? "Available after you install the Knowledge Base, turn it on, and reindex." : !ragCapability.enabled ? "Available after you turn on the Knowledge Base and reindex." : "Available after you reindex.")), /* @__PURE__ */ React.createElement("div", { className: "grid grid-cols-1 sm:grid-cols-[minmax(0,1fr),140px] gap-2" }, /* @__PURE__ */ React.createElement(
        "input",
        {
          value: ragContextQuery || "",
          onChange: (event) => setRagContextQuery(event.target.value),
          placeholder: "What should the assistant know about our Splunk indexer cluster dependencies?",
          className: `rounded-lg border px-3 py-2 text-xs ${isDarkTheme ? "bg-gray-900 border-gray-700 text-gray-100" : "bg-white border-gray-300 text-gray-900"}`
        }
      ), /* @__PURE__ */ React.createElement(
        "select",
        {
          value: ragContextLimit,
          onChange: (event) => setRagContextLimit(Number(event.target.value) || 4),
          className: `rounded-lg border px-3 py-2 text-xs ${isDarkTheme ? "bg-gray-900 border-gray-700 text-gray-100" : "bg-white border-gray-300 text-gray-900"}`
        },
        /* @__PURE__ */ React.createElement("option", { value: 2 }, "2 passages"),
        /* @__PURE__ */ React.createElement("option", { value: 3 }, "3 passages"),
        /* @__PURE__ */ React.createElement("option", { value: 4 }, "4 passages"),
        /* @__PURE__ */ React.createElement("option", { value: 5 }, "5 passages"),
        /* @__PURE__ */ React.createElement("option", { value: 6 }, "6 passages")
      )), /* @__PURE__ */ React.createElement("div", { className: "flex flex-wrap gap-2 mt-3" }, /* @__PURE__ */ React.createElement(
        "button",
        {
          type: "button",
          onClick: buildRagContextPreview,
          disabled: !canUseRagContextPreview || isRagBusy,
          className: getCapabilityActionButtonClass(true, !canUseRagContextPreview || isRagBusy)
        },
        ragActionInProgress === "build-context" ? "Building Preview..." : "Build Preview"
      ), ragAssetWorkspace.contextPreview && /* @__PURE__ */ React.createElement(
        "button",
        {
          type: "button",
          onClick: () => setRagAssetWorkspace((prev) => ({ ...prev, contextPreview: null })),
          disabled: isRagBusy,
          className: getCapabilityActionButtonClass(false, isRagBusy)
        },
        "Clear Preview"
      )), ((_a2 = ragAssetWorkspace.contextPreview) == null ? void 0 : _a2.message) && /* @__PURE__ */ React.createElement("div", { className: `mt-3 text-xs rounded-lg border px-3 py-2 ${panelMutedClass} ${subtextClass}` }, ragAssetWorkspace.contextPreview.message), ((_b2 = ragAssetWorkspace.contextPreview) == null ? void 0 : _b2.operator_brief) && /* @__PURE__ */ React.createElement("div", { className: `mt-3 rounded-lg border px-3 py-3 ${isDarkTheme ? "bg-gray-900 border-gray-700" : "bg-white border-gray-300"}` }, /* @__PURE__ */ React.createElement("div", { className: `text-sm font-medium mb-2 ${headingClass}` }, "Context Summary"), /* @__PURE__ */ React.createElement("pre", { className: `text-xs whitespace-pre-wrap font-mono ${isDarkTheme ? "text-gray-100" : "text-gray-900"}` }, ragAssetWorkspace.contextPreview.operator_brief)), Array.isArray((_c2 = ragAssetWorkspace.contextPreview) == null ? void 0 : _c2.matched_assets) && ragAssetWorkspace.contextPreview.matched_assets.length > 0 && /* @__PURE__ */ React.createElement("div", { className: "space-y-2 mt-3" }, ragAssetWorkspace.contextPreview.matched_assets.map((asset) => /* @__PURE__ */ React.createElement("div", { key: asset.asset_id || `${asset.title}-${asset.asset_type}`, className: `rounded-lg border px-3 py-3 text-xs ${isDarkTheme ? "bg-gray-900 border-gray-700 text-gray-100" : "bg-white border-gray-300 text-gray-800"}` }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-col sm:flex-row sm:items-start sm:justify-between gap-2" }, /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("div", { className: "flex flex-wrap items-center gap-2" }, /* @__PURE__ */ React.createElement("span", { className: `font-medium ${headingClass}` }, asset.title || "Matched asset"), /* @__PURE__ */ React.createElement("span", { className: `rounded-full px-2 py-0.5 border text-xs ${isDarkTheme ? "bg-sky-950 border-sky-800 text-sky-100" : "bg-sky-50 border-sky-200 text-sky-800"}` }, formatKnowledgeAssetTypeLabel(asset.asset_type))), asset.source_label && /* @__PURE__ */ React.createElement("div", { className: `mt-1 ${mutedTextClass}` }, "Source: ", asset.source_label)), /* @__PURE__ */ React.createElement("div", { className: "flex flex-wrap items-center gap-2" }, asset.match_score != null && /* @__PURE__ */ React.createElement("span", { className: `rounded-full px-2 py-0.5 border text-xs ${isDarkTheme ? "bg-violet-950 border-violet-800 text-violet-100" : "bg-violet-50 border-violet-200 text-violet-800"}` }, "score ", asset.match_score), asset.asset_id && /* @__PURE__ */ React.createElement(
        "button",
        {
          type: "button",
          onClick: () => loadRagAssetDetail(asset.asset_id, { force: true }),
          disabled: ragAssetWorkspace.detailStatus === "loading",
          className: `px-2.5 py-1 rounded text-xs font-medium ${ragAssetWorkspace.detailStatus !== "loading" ? "bg-slate-700 hover:bg-slate-800 text-white" : isDarkTheme ? "bg-gray-700 text-gray-400 cursor-not-allowed" : "bg-gray-200 text-gray-500 cursor-not-allowed"}`
        },
        ragAssetWorkspace.detailStatus === "loading" && ragAssetWorkspace.detailAssetId === asset.asset_id ? "Loading Detail..." : "Inspect Asset"
      ))), asset.why_matched && /* @__PURE__ */ React.createElement("div", { className: `mt-2 ${subtextClass}` }, asset.why_matched), asset.best_excerpt && /* @__PURE__ */ React.createElement("div", { className: `mt-2 ${subtextClass}` }, asset.best_excerpt), Array.isArray(asset.matched_chunks) && asset.matched_chunks.length > 0 && /* @__PURE__ */ React.createElement("div", { className: "flex flex-wrap gap-2 mt-2 text-xs" }, asset.matched_chunks.slice(0, 4).map((matchedChunk, matchedChunkIndex) => /* @__PURE__ */ React.createElement(
        "span",
        {
          key: `${asset.asset_id || asset.title}-${matchedChunk.document_id || matchedChunkIndex}`,
          className: `rounded-full px-2 py-0.5 border ${isDarkTheme ? "bg-emerald-950 border-emerald-800 text-emerald-100" : "bg-emerald-50 border-emerald-200 text-emerald-800"}`
        },
        matchedChunk.section || `Matched chunk ${matchedChunkIndex + 1}`,
        matchedChunk.score != null ? ` · ${matchedChunk.score}` : ""
      ))), Array.isArray(asset.focus_terms) && asset.focus_terms.length > 0 && /* @__PURE__ */ React.createElement("div", { className: "flex flex-wrap gap-2 mt-2 text-xs" }, asset.focus_terms.slice(0, 8).map((term) => /* @__PURE__ */ React.createElement("span", { key: `${asset.asset_id || asset.title}-${term}`, className: `rounded-full px-2 py-0.5 border ${isDarkTheme ? "bg-gray-800 border-gray-600 text-gray-200" : "bg-gray-100 border-gray-300 text-gray-700"}` }, term))), Array.isArray(asset.key_points) && asset.key_points.length > 0 && /* @__PURE__ */ React.createElement("ul", { className: `mt-2 list-disc pl-4 space-y-1 ${subtextClass}` }, asset.key_points.slice(0, 2).map((point, pointIndex) => /* @__PURE__ */ React.createElement("li", { key: `${asset.asset_id || asset.title}-${pointIndex}` }, point)))))), ((_d2 = ragAssetWorkspace.contextPreview) == null ? void 0 : _d2.context_text) && /* @__PURE__ */ React.createElement("pre", { className: `mt-3 rounded-lg border px-3 py-3 text-xs whitespace-pre-wrap font-mono ${isDarkTheme ? "bg-gray-900 border-gray-700 text-gray-100" : "bg-white border-gray-300 text-gray-900"}` }, ragAssetWorkspace.contextPreview.context_text), Array.isArray((_e2 = ragAssetWorkspace.contextPreview) == null ? void 0 : _e2.chunks) && ragAssetWorkspace.contextPreview.chunks.length > 0 && /* @__PURE__ */ React.createElement("div", { className: "space-y-2 mt-3" }, ragAssetWorkspace.contextPreview.chunks.map((chunk, chunkIndex) => /* @__PURE__ */ React.createElement("div", { key: `${chunk.source || "chunk"}-${chunkIndex}`, className: `rounded-lg border px-3 py-2 text-xs ${isDarkTheme ? "bg-gray-900 border-gray-700 text-gray-100" : "bg-white border-gray-300 text-gray-800"}` }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-wrap items-center gap-2 mb-1" }, /* @__PURE__ */ React.createElement("span", { className: `font-medium ${headingClass}` }, chunk.source || `Chunk ${chunkIndex + 1}`), chunk.score != null && /* @__PURE__ */ React.createElement("span", { className: `rounded-full px-2 py-0.5 border ${isDarkTheme ? "bg-violet-950 border-violet-800 text-violet-100" : "bg-violet-50 border-violet-200 text-violet-800"}` }, "score ", chunk.score)), /* @__PURE__ */ React.createElement("div", { className: subtextClass }, chunk.snippet || "No snippet returned."))))), (ragAssetWorkspace.detailAssetId || ragAssetWorkspace.assetDetail) && /* @__PURE__ */ React.createElement("div", { className: `rounded-lg shadow-sm p-6 border ${panelClass}` }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-col sm:flex-row sm:items-start sm:justify-between gap-2 mb-3" }, /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("div", { className: `text-sm font-semibold ${headingClass}` }, "Item Details"), /* @__PURE__ */ React.createElement("div", { className: `text-xs ${subtextClass}` }, "The stored sections of this item and how the index splits them for search.")), /* @__PURE__ */ React.createElement(
        "button",
        {
          type: "button",
          onClick: clearRagAssetDetail,
          className: `px-3 py-1.5 rounded text-sm font-medium ${isDarkTheme ? "bg-gray-700 hover:bg-gray-600 text-white" : "bg-gray-100 hover:bg-gray-200 text-gray-800 border border-gray-300"}`
        },
        "Close Detail"
      )), ragAssetWorkspace.detailStatus === "loading" ? /* @__PURE__ */ React.createElement("div", { className: `text-xs rounded-lg border px-3 py-3 ${panelMutedClass} ${subtextClass}` }, "Loading item details.") : ragAssetWorkspace.detailStatus === "error" ? /* @__PURE__ */ React.createElement("div", { className: `text-xs rounded-lg border px-3 py-3 ${isDarkTheme ? "bg-red-950 border-red-800 text-red-100" : "bg-red-50 border-red-200 text-red-800"}` }, ragAssetWorkspace.detailError || "Could not load item details.") : ((_f2 = ragAssetWorkspace.assetDetail) == null ? void 0 : _f2.asset) ? /* @__PURE__ */ React.createElement(React.Fragment, null, /* @__PURE__ */ React.createElement("div", { className: `rounded-lg border px-3 py-3 mb-3 ${isDarkTheme ? "bg-gray-900 border-gray-700" : "bg-white border-gray-300"}` }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-col sm:flex-row sm:items-start sm:justify-between gap-2" }, /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("div", { className: "flex flex-wrap items-center gap-2" }, /* @__PURE__ */ React.createElement("span", { className: `text-sm font-medium ${headingClass}` }, ragAssetWorkspace.assetDetail.asset.title || "Knowledge Asset"), /* @__PURE__ */ React.createElement("span", { className: `rounded-full px-2 py-0.5 border text-xs ${isDarkTheme ? "bg-sky-950 border-sky-800 text-sky-100" : "bg-sky-50 border-sky-200 text-sky-800"}` }, formatKnowledgeAssetTypeLabel(ragAssetWorkspace.assetDetail.asset.asset_type))), ragAssetWorkspace.assetDetail.asset.source_label && /* @__PURE__ */ React.createElement("div", { className: `mt-1 text-xs ${mutedTextClass}` }, "Source: ", ragAssetWorkspace.assetDetail.asset.source_label)), /* @__PURE__ */ React.createElement("div", { className: `text-xs ${mutedTextClass}` }, "Stored as: ", ragAssetWorkspace.assetDetail.stored_path || ragAssetWorkspace.assetDetail.asset.content_path || "managed asset")), /* @__PURE__ */ React.createElement("div", { className: "grid grid-cols-2 sm:grid-cols-4 gap-2 mt-3 text-xs" }, /* @__PURE__ */ React.createElement("div", { className: mutedTextClass }, "Stored sections: ", Array.isArray(ragAssetWorkspace.assetDetail.stored_sections) ? ragAssetWorkspace.assetDetail.stored_sections.length : 0), /* @__PURE__ */ React.createElement("div", { className: mutedTextClass }, "Chunk sections: ", ragAssetWorkspace.assetDetail.chunk_count || 0), /* @__PURE__ */ React.createElement("div", { className: mutedTextClass }, "Context characters: ", ragAssetWorkspace.assetDetail.context_character_count || 0), /* @__PURE__ */ React.createElement("div", { className: mutedTextClass }, "Imported: ", ragAssetWorkspace.assetDetail.asset.created_at ? formatMissionDateTime(ragAssetWorkspace.assetDetail.asset.created_at) : "Unknown"))), (() => {
        const detailAttributes = getKnowledgeAssetAttributes(ragAssetWorkspace.assetDetail.asset);
        const detailSplQuery = String(detailAttributes.spl_query || "").trim();
        if (!detailSplQuery) {
          return null;
        }
        return /* @__PURE__ */ React.createElement("div", { "data-testid": "context-library-detail-spl-query", className: `rounded-lg border px-3 py-3 mb-3 ${isDarkTheme ? "bg-gray-900 border-gray-700" : "bg-white border-gray-300"}` }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-col gap-2 sm:flex-row sm:items-start sm:justify-between" }, /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("div", { className: `text-sm font-medium ${headingClass}` }, "Saved SPL Query"), /* @__PURE__ */ React.createElement("div", { className: `mt-1 text-xs ${subtextClass}` }, "Run this search in Splunk Web, reuse it in chat, or keep it in the library.")), renderSplQueryActionButtons2(detailSplQuery, {
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
      })(), /* @__PURE__ */ React.createElement("div", { className: "grid grid-cols-1 2xl:grid-cols-2 gap-3" }, /* @__PURE__ */ React.createElement("div", { className: `rounded-lg border px-3 py-3 ${isDarkTheme ? "bg-gray-900 border-gray-700" : "bg-white border-gray-300"}` }, /* @__PURE__ */ React.createElement("div", { className: `text-sm font-medium mb-2 ${headingClass}` }, "Stored Sections"), /* @__PURE__ */ React.createElement("div", { className: "space-y-2 max-h-96 overflow-y-auto pr-1" }, Array.isArray(ragAssetWorkspace.assetDetail.stored_sections) && ragAssetWorkspace.assetDetail.stored_sections.length > 0 ? ragAssetWorkspace.assetDetail.stored_sections.map((section, sectionIndex) => /* @__PURE__ */ React.createElement("details", { key: `${section.title || "section"}-${sectionIndex}`, open: section.title !== "Context", className: `rounded border px-3 py-2 ${isDarkTheme ? "border-gray-700 bg-gray-950" : "border-gray-200 bg-gray-50"}` }, /* @__PURE__ */ React.createElement("summary", { className: `cursor-pointer text-xs font-medium ${headingClass}` }, section.title || `Section ${sectionIndex + 1}`, " (", section.character_count || 0, " chars)"), Array.isArray(section.items) && section.items.length > 0 ? /* @__PURE__ */ React.createElement("ul", { className: `mt-2 list-disc pl-4 space-y-1 text-xs ${subtextClass}` }, section.items.map((item, itemIndex) => /* @__PURE__ */ React.createElement("li", { key: `${section.title || "section"}-${itemIndex}` }, item))) : /* @__PURE__ */ React.createElement("pre", { className: `mt-2 text-xs whitespace-pre-wrap font-mono ${subtextClass}` }, section.content || "No section content available."))) : /* @__PURE__ */ React.createElement("div", { className: `text-xs rounded-lg border px-3 py-3 ${panelMutedClass} ${mutedTextClass}` }, "This item has no stored sections."))), /* @__PURE__ */ React.createElement("div", { className: `rounded-lg border px-3 py-3 ${isDarkTheme ? "bg-gray-900 border-gray-700" : "bg-white border-gray-300"}` }, /* @__PURE__ */ React.createElement("div", { className: `text-sm font-medium mb-2 ${headingClass}` }, "Index Passages"), /* @__PURE__ */ React.createElement("div", { className: `text-xs mb-2 ${subtextClass}` }, "How the index splits this item into searchable passages."), activeDetailPreviewTrace.matchedChunkIds.length > 0 && /* @__PURE__ */ React.createElement("div", { className: `text-xs rounded-lg border px-3 py-2 mb-2 ${isDarkTheme ? "bg-sky-950 border-sky-800 text-sky-100" : "bg-sky-50 border-sky-200 text-sky-800"}` }, "The preview matched ", countLabel(activeDetailPreviewTrace.matchedChunkIds.length, "passage"), " in this item, highlighted below."), /* @__PURE__ */ React.createElement("div", { className: "space-y-2 max-h-96 overflow-y-auto pr-1" }, Array.isArray(ragAssetWorkspace.assetDetail.chunk_sections) && ragAssetWorkspace.assetDetail.chunk_sections.length > 0 ? ragAssetWorkspace.assetDetail.chunk_sections.map((section, sectionIndex) => {
        const isPreviewMatched = activeDetailPreviewTrace.matchedChunkIds.includes(section.document_id);
        return /* @__PURE__ */ React.createElement("details", { key: section.document_id || `${section.section || "chunk"}-${sectionIndex}`, open: isPreviewMatched || sectionIndex === 0, className: `rounded border px-3 py-2 ${isPreviewMatched ? isDarkTheme ? "border-sky-700 bg-sky-950/40" : "border-sky-300 bg-sky-50" : isDarkTheme ? "border-gray-700 bg-gray-950" : "border-gray-200 bg-gray-50"}` }, /* @__PURE__ */ React.createElement("summary", { className: `cursor-pointer text-xs font-medium ${headingClass}` }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-wrap items-center gap-2" }, /* @__PURE__ */ React.createElement("span", null, section.section || `Chunk ${sectionIndex + 1}`, " (", section.character_count || 0, " chars)"), isPreviewMatched && /* @__PURE__ */ React.createElement("span", { className: `rounded-full px-2 py-0.5 border text-xs ${isDarkTheme ? "bg-sky-900 border-sky-700 text-sky-100" : "bg-sky-100 border-sky-300 text-sky-800"}` }, "Matched in Preview"))), /* @__PURE__ */ React.createElement("pre", { className: `mt-2 text-xs whitespace-pre-wrap font-mono ${subtextClass}` }, section.content || "No passage text available."));
      }) : /* @__PURE__ */ React.createElement("div", { className: `text-xs rounded-lg border px-3 py-3 ${panelMutedClass} ${mutedTextClass}` }, "The index produced no passages for this item."))))) : null), /* @__PURE__ */ React.createElement("div", { className: `rounded-lg shadow-sm p-6 border ${panelClass}` }, /* @__PURE__ */ React.createElement("details", { className: `rounded-lg border ${isDarkTheme ? "border-gray-700 bg-gray-900" : "border-gray-200 bg-gray-50"}` }, /* @__PURE__ */ React.createElement("summary", { className: `cursor-pointer px-3 py-2 text-sm font-medium ${headingClass}` }, "Advanced settings"), /* @__PURE__ */ React.createElement("div", { className: "px-3 py-3" }, /* @__PURE__ */ React.createElement(
        "textarea",
        {
          "aria-label": "Knowledge Base settings (JSON)",
          value: capabilityDrafts.rag_chromadb || "{}",
          onChange: (event) => updateCapabilityDraft("rag_chromadb", event.target.value),
          rows: 10,
          className: `w-full rounded-lg border px-3 py-2 text-xs font-mono ${isDarkTheme ? "bg-gray-900 border-gray-700 text-gray-100" : "bg-white border-gray-300 text-gray-900"}`
        }
      ), /* @__PURE__ */ React.createElement("div", { className: `mt-2 text-xs ${mutedTextClass}` }, "Install, restart the app if asked, then turn it on and reindex before chat or previews can use it."), /* @__PURE__ */ React.createElement("div", { className: "flex flex-wrap gap-2 mt-3" }, /* @__PURE__ */ React.createElement(
        "button",
        {
          type: "button",
          onClick: () => saveCapabilityConfig("rag_chromadb"),
          disabled: isRagBusy,
          className: getCapabilityActionButtonClass(true, isRagBusy)
        },
        ragActionInProgress === "config" ? "Saving..." : "Save Settings"
      ))))))), /* @__PURE__ */ React.createElement("div", { className: `rounded-lg shadow-sm p-6 border ${panelClass} mt-6` }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-col lg:flex-row lg:items-start lg:justify-between gap-3 mb-3" }, /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("div", { className: `text-sm font-semibold ${headingClass}` }, "Library"), /* @__PURE__ */ React.createElement("div", { className: `text-xs ${subtextClass}` }, "New imports are checked in. Check an item out to keep it stored but hide it from chat until you check it back in.")), /* @__PURE__ */ React.createElement("div", { className: "grid grid-cols-3 gap-2 min-w-[280px] text-xs" }, /* @__PURE__ */ React.createElement("div", { className: `rounded-lg border px-3 py-2 ${panelMutedClass}` }, /* @__PURE__ */ React.createElement("div", { className: mutedTextClass }, "Total"), /* @__PURE__ */ React.createElement("div", { className: `mt-1 font-semibold ${headingClass}` }, ragDisplayedAssetCount)), /* @__PURE__ */ React.createElement("div", { className: `rounded-lg border px-3 py-2 ${panelMutedClass}` }, /* @__PURE__ */ React.createElement("div", { className: mutedTextClass }, "Checked In"), /* @__PURE__ */ React.createElement("div", { className: `mt-1 font-semibold ${headingClass}` }, ragCheckedInAssetCount)), /* @__PURE__ */ React.createElement("div", { className: `rounded-lg border px-3 py-2 ${panelMutedClass}` }, /* @__PURE__ */ React.createElement("div", { className: mutedTextClass }, "Checked Out"), /* @__PURE__ */ React.createElement("div", { className: `mt-1 font-semibold ${headingClass}` }, ragCheckedOutAssetCount)))), /* @__PURE__ */ React.createElement("div", { className: "flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2 mb-3" }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-wrap gap-2" }, [
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
      })), /* @__PURE__ */ React.createElement("div", { className: `text-xs ${mutedTextClass}` }, countLabel(ragLibraryAssetCount, "item"), " shown")), ragAssetWorkspace.status === "loading" ? /* @__PURE__ */ React.createElement("div", { className: `text-xs rounded-lg border px-3 py-3 ${panelMutedClass} ${subtextClass}` }, "Loading the library.") : ragAssetWorkspace.status === "error" ? /* @__PURE__ */ React.createElement("div", { className: `text-xs rounded-lg border px-3 py-2 ${isDarkTheme ? "bg-red-950 border-red-800 text-red-100" : "bg-red-50 border-red-200 text-red-800"}` }, ragAssetWorkspace.error || "Could not load the library.") : ragLibraryAssets.length === 0 ? /* @__PURE__ */ React.createElement("div", { className: `text-xs rounded-lg border px-3 py-3 ${panelMutedClass} ${mutedTextClass}` }, ragLibraryFilter === "spl_library" ? "No saved searches yet." : ragLibraryFilter === "checked_in" ? "No checked-in items." : ragLibraryFilter === "checked_out" ? "No checked-out items." : "Nothing imported yet.") : /* @__PURE__ */ React.createElement("div", { className: "space-y-2 max-h-[42rem] overflow-y-auto pr-1" }, ragLibraryAssets.map((asset) => {
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
        return /* @__PURE__ */ React.createElement("div", { key: asset.asset_id || asset.content_path || asset.title, "data-testid": savedSplQuery ? "context-library-spl-asset-card" : "context-library-asset-card", className: `rounded-lg border px-3 py-3 ${isDarkTheme ? "bg-gray-900 border-gray-700" : "bg-white border-gray-300"}` }, isSplLibraryOnlyView ? /* @__PURE__ */ React.createElement("div", { className: "space-y-3" }, /* @__PURE__ */ React.createElement("div", { "data-testid": "context-library-spl-query-card", className: `rounded-lg border px-3 py-3 ${isDarkTheme ? "bg-gray-950 border-gray-700" : "bg-gray-50 border-gray-200"}` }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-col gap-2 sm:flex-row sm:items-start sm:justify-between" }, /* @__PURE__ */ React.createElement("div", { className: `text-xs font-semibold uppercase tracking-wide ${mutedTextClass}` }, "Saved SPL Query"), renderSplQueryActionButtons2(savedSplQuery, splQueryActionOptions)), /* @__PURE__ */ React.createElement("pre", { "data-testid": "context-library-spl-only-query", className: `mt-2 max-h-[26rem] overflow-auto rounded-lg border px-3 py-3 text-xs whitespace-pre-wrap font-mono ${isDarkTheme ? "bg-gray-900 border-gray-700 text-gray-100" : "bg-white border-gray-300 text-gray-900"}` }, savedSplQuery), splIntelligenceSummary), /* @__PURE__ */ React.createElement("div", { className: "flex flex-wrap gap-2" }, /* @__PURE__ */ React.createElement(
          "button",
          {
            type: "button",
            "data-testid": "context-library-view-spl-details",
            onClick: () => loadRagAssetDetail(asset.asset_id),
            disabled: ragAssetWorkspace.detailStatus === "loading" || !asset.asset_id,
            className: `px-3 py-1.5 rounded text-sm font-medium ${ragAssetWorkspace.detailStatus !== "loading" && asset.asset_id ? "bg-slate-700 hover:bg-slate-800 text-white" : isDarkTheme ? "bg-gray-700 text-gray-400 cursor-not-allowed" : "bg-gray-200 text-gray-500 cursor-not-allowed"}`
          },
          ragAssetWorkspace.detailStatus === "loading" && ragAssetWorkspace.detailAssetId === asset.asset_id ? "Loading Detail..." : ((_b3 = (_a3 = ragAssetWorkspace.assetDetail) == null ? void 0 : _a3.asset) == null ? void 0 : _b3.asset_id) === asset.asset_id ? "Hide Details" : "View Details"
        ), /* @__PURE__ */ React.createElement(
          "button",
          {
            type: "button",
            onClick: () => setRagKnowledgeAssetLibraryStatus(asset.asset_id, asset.title, isAssetCheckedOut ? "checked_in" : "checked_out"),
            disabled: isRagBusy || !asset.asset_id,
            className: `px-3 py-1.5 rounded text-sm font-medium ${!isRagBusy && asset.asset_id ? isAssetCheckedOut ? "bg-emerald-600 hover:bg-emerald-700 text-white" : "bg-amber-600 hover:bg-amber-700 text-white" : isDarkTheme ? "bg-gray-700 text-gray-400 cursor-not-allowed" : "bg-gray-200 text-gray-500 cursor-not-allowed"}`
          },
          ragActionInProgress === libraryActionKey ? isAssetCheckedOut ? "Checking In..." : "Checking Out..." : isAssetCheckedOut ? "Check In" : "Check Out"
        ), /* @__PURE__ */ React.createElement(
          "button",
          {
            type: "button",
            onClick: () => deleteRagKnowledgeAsset(asset.asset_id, asset.title),
            disabled: isRagBusy,
            className: `px-3 py-1.5 rounded text-sm font-medium ${!isRagBusy ? "bg-rose-600 hover:bg-rose-700 text-white" : isDarkTheme ? "bg-gray-700 text-gray-400 cursor-not-allowed" : "bg-gray-200 text-gray-500 cursor-not-allowed"}`
          },
          ragActionInProgress === "delete-asset" ? "Removing..." : "Remove"
        )), isAssetCheckedOut && /* @__PURE__ */ React.createElement("div", { className: `text-xs rounded-lg border px-3 py-2 ${isDarkTheme ? "bg-amber-950 border-amber-800 text-amber-100" : "bg-amber-50 border-amber-200 text-amber-800"}` }, "Checked out. Chat and previews ignore this item until you check it back in.")) : /* @__PURE__ */ React.createElement(React.Fragment, null, /* @__PURE__ */ React.createElement("div", { className: "flex flex-col sm:flex-row sm:items-start sm:justify-between gap-2" }, /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("div", { className: "flex flex-wrap items-center gap-2" }, /* @__PURE__ */ React.createElement("div", { className: `text-sm font-medium ${headingClass}` }, asset.title || "Knowledge Asset"), /* @__PURE__ */ React.createElement("span", { className: `rounded-full px-2 py-0.5 border text-xs ${isDarkTheme ? "bg-sky-950 border-sky-800 text-sky-100" : "bg-sky-50 border-sky-200 text-sky-800"}` }, formatKnowledgeAssetTypeLabel(asset.asset_type)), /* @__PURE__ */ React.createElement("span", { className: `rounded-full px-2 py-0.5 border text-xs ${isDarkTheme ? "bg-gray-800 border-gray-600 text-gray-200" : "bg-gray-100 border-gray-300 text-gray-700"}` }, formatKnowledgeAssetImportMethodLabel(asset.import_method)), /* @__PURE__ */ React.createElement("span", { className: `rounded-full px-2 py-0.5 border text-xs ${getKnowledgeAssetLibraryStatusClasses(assetLibraryStatus)}` }, formatKnowledgeAssetLibraryStatusLabel(assetLibraryStatus))), asset.source_label && /* @__PURE__ */ React.createElement("div", { className: `mt-1 text-xs ${mutedTextClass}` }, "Source: ", asset.source_label)), /* @__PURE__ */ React.createElement("div", { className: "flex flex-wrap gap-2" }, /* @__PURE__ */ React.createElement(
          "button",
          {
            type: "button",
            "data-testid": savedSplQuery ? "context-library-view-spl-details" : void 0,
            onClick: () => loadRagAssetDetail(asset.asset_id),
            disabled: ragAssetWorkspace.detailStatus === "loading" || !asset.asset_id,
            className: `px-3 py-1.5 rounded text-sm font-medium ${ragAssetWorkspace.detailStatus !== "loading" && asset.asset_id ? "bg-slate-700 hover:bg-slate-800 text-white" : isDarkTheme ? "bg-gray-700 text-gray-400 cursor-not-allowed" : "bg-gray-200 text-gray-500 cursor-not-allowed"}`
          },
          ragAssetWorkspace.detailStatus === "loading" && ragAssetWorkspace.detailAssetId === asset.asset_id ? "Loading Detail..." : ((_d3 = (_c3 = ragAssetWorkspace.assetDetail) == null ? void 0 : _c3.asset) == null ? void 0 : _d3.asset_id) === asset.asset_id ? "Hide Details" : "View Details"
        ), /* @__PURE__ */ React.createElement(
          "button",
          {
            type: "button",
            onClick: () => setRagKnowledgeAssetLibraryStatus(asset.asset_id, asset.title, isAssetCheckedOut ? "checked_in" : "checked_out"),
            disabled: isRagBusy || !asset.asset_id,
            className: `px-3 py-1.5 rounded text-sm font-medium ${!isRagBusy && asset.asset_id ? isAssetCheckedOut ? "bg-emerald-600 hover:bg-emerald-700 text-white" : "bg-amber-600 hover:bg-amber-700 text-white" : isDarkTheme ? "bg-gray-700 text-gray-400 cursor-not-allowed" : "bg-gray-200 text-gray-500 cursor-not-allowed"}`
          },
          ragActionInProgress === libraryActionKey ? isAssetCheckedOut ? "Checking In..." : "Checking Out..." : isAssetCheckedOut ? "Check In" : "Check Out"
        ), /* @__PURE__ */ React.createElement(
          "button",
          {
            type: "button",
            onClick: () => deleteRagKnowledgeAsset(asset.asset_id, asset.title),
            disabled: isRagBusy,
            className: `px-3 py-1.5 rounded text-sm font-medium ${!isRagBusy ? "bg-rose-600 hover:bg-rose-700 text-white" : isDarkTheme ? "bg-gray-700 text-gray-400 cursor-not-allowed" : "bg-gray-200 text-gray-500 cursor-not-allowed"}`
          },
          ragActionInProgress === "delete-asset" ? "Removing..." : "Remove"
        ))), /* @__PURE__ */ React.createElement("div", { className: `mt-2 text-xs ${subtextClass}` }, asset.summary || asset.preview || "No summary available."), savedSplQuery && /* @__PURE__ */ React.createElement("div", { "data-testid": "context-library-spl-query-card", className: `mt-3 rounded-lg border px-3 py-3 ${isDarkTheme ? "bg-gray-950 border-gray-700" : "bg-gray-50 border-gray-200"}` }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-col gap-2 sm:flex-row sm:items-start sm:justify-between" }, /* @__PURE__ */ React.createElement("div", { className: `text-xs font-semibold uppercase tracking-wide ${mutedTextClass}` }, "Saved SPL Query"), renderSplQueryActionButtons2(savedSplQuery, splQueryActionOptions)), /* @__PURE__ */ React.createElement("pre", { className: `mt-2 max-h-32 overflow-auto rounded-lg border px-3 py-3 text-xs whitespace-pre-wrap font-mono ${isDarkTheme ? "bg-gray-900 border-gray-700 text-gray-100" : "bg-white border-gray-300 text-gray-900"}` }, savedSplQuery), splIntelligenceSummary), isAssetCheckedOut && /* @__PURE__ */ React.createElement("div", { className: `mt-2 text-xs rounded-lg border px-3 py-2 ${isDarkTheme ? "bg-amber-950 border-amber-800 text-amber-100" : "bg-amber-50 border-amber-200 text-amber-800"}` }, "Checked out. Chat and previews ignore this item until you check it back in."), asset.description && /* @__PURE__ */ React.createElement("div", { className: `mt-2 text-xs ${mutedTextClass}` }, "Purpose: ", asset.description), Array.isArray(asset.tags) && asset.tags.length > 0 && /* @__PURE__ */ React.createElement("div", { className: "flex flex-wrap gap-2 mt-2 text-xs" }, asset.tags.map((tag) => /* @__PURE__ */ React.createElement("span", { key: `${asset.asset_id || asset.title}-${tag}`, className: `rounded-full px-2 py-0.5 border ${isDarkTheme ? "bg-gray-800 border-gray-600 text-gray-200" : "bg-gray-100 border-gray-300 text-gray-700"}` }, tag))), Array.isArray(asset.focus_terms) && asset.focus_terms.length > 0 && /* @__PURE__ */ React.createElement("div", { className: "flex flex-wrap gap-2 mt-2 text-xs" }, asset.focus_terms.slice(0, 8).map((term) => /* @__PURE__ */ React.createElement("span", { key: `${asset.asset_id || asset.title}-focus-${term}`, className: `rounded-full px-2 py-0.5 border ${isDarkTheme ? "bg-sky-950 border-sky-800 text-sky-100" : "bg-sky-50 border-sky-200 text-sky-800"}` }, term))), Array.isArray(asset.key_points) && asset.key_points.length > 0 && /* @__PURE__ */ React.createElement("ul", { className: `mt-2 list-disc pl-4 space-y-1 text-xs ${subtextClass}` }, asset.key_points.slice(0, 2).map((point, pointIndex) => /* @__PURE__ */ React.createElement("li", { key: `${asset.asset_id || asset.title}-point-${pointIndex}` }, point))), Array.isArray(asset.usage_guidance) && asset.usage_guidance.length > 0 && /* @__PURE__ */ React.createElement("div", { className: `mt-2 text-xs ${mutedTextClass}` }, "Best used for: ", asset.usage_guidance[0]), /* @__PURE__ */ React.createElement("div", { className: "grid grid-cols-2 gap-2 mt-3 text-xs" }, /* @__PURE__ */ React.createElement("div", { className: mutedTextClass }, "Words: ", asset.word_count || 0), /* @__PURE__ */ React.createElement("div", { className: mutedTextClass }, "Characters: ", asset.text_char_count || 0), /* @__PURE__ */ React.createElement("div", { className: mutedTextClass }, "Imported: ", asset.created_at ? formatMissionDateTime(asset.created_at) : "Unknown"), /* @__PURE__ */ React.createElement("div", { className: mutedTextClass }, "Last checked in: ", asset.last_checked_in_at ? formatMissionDateTime(asset.last_checked_in_at) : "Not recorded")), asset.checked_out_at ? /* @__PURE__ */ React.createElement("div", { className: `mt-1 text-xs ${mutedTextClass}` }, "Checked out: ", formatMissionDateTime(asset.checked_out_at)) : /* @__PURE__ */ React.createElement("div", { className: `mt-1 text-xs ${mutedTextClass}` }, "Chat and previews can use this item while it is checked in."), /* @__PURE__ */ React.createElement("div", { className: `mt-1 text-xs ${mutedTextClass}` }, "Stored as: ", asset.content_path || "managed asset")));
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
        checkServerCodeStatus();
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
        setSelectedProvider(normalizeProvider(data.llm.provider || "openai", data.llm.endpoint_url));
        setSelectedModel(data.llm.model || "");
        setApiKeyPlaceholder(getApiKeyPlaceholderForProvider(data.llm.provider, data.llm.api_key === "***"));
        setMCPTokenPlaceholder(data.mcp.token === "***" ? "(Already Configured)" : "Enter token");
        if (data.active_mcp_config_name) {
          setLoadedMCPConfigName(data.active_mcp_config_name);
        }
      } catch (error) {
        console.error("Failed to load config:", error);
      } finally {
        await loadConnectionInfo();
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
    const handleAuthLogout = async () => {
      try {
        const response = await fetch("/api/auth/logout", { method: "POST" });
        const result = await response.json();
        if (!response.ok) {
          throw new Error(result.detail || "Failed to sign out");
        }
        setAuthStatus((current) => current ? { ...current, authenticated: false, user: null } : null);
        closeSettings();
        const providerLogout = result.provider_logout || {};
        if (providerLogout.supported && providerLogout.mode === "front_channel_redirect" && providerLogout.url) {
          window.location.assign(providerLogout.url);
          return;
        }
        window.location.assign("/");
      } catch (error) {
        alert(`Failed to sign out: ${error.message}`);
      }
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

This deletes the token. Anything using it loses access.`);
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
                                <p class="text-base font-bold text-gray-700 mb-2">No AI models saved yet</p>
                                <p class="text-sm text-gray-500 mb-4">Save an AI model connection so Chat and summaries can use it.</p>
                                <p class="text-xs text-gray-400 italic">Click "Add AI Model" above.</p>
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
          const provider = normalizeProvider(cred.provider, cred.endpoint_url);
          const providerIcon = provider === "openai" ? "fa-openai" : provider === "azure" ? "fa-cloud" : provider === "anthropic" ? "fa-robot" : provider === "gemini" ? "fa-gem" : provider === "custom" ? "fa-server" : "fa-brain";
          const providerColor = provider === "openai" ? "text-green-600" : provider === "azure" ? "text-blue-600" : provider === "anthropic" ? "text-orange-600" : provider === "gemini" ? "text-indigo-600" : "text-purple-600";
          const isActive = cred.name === activeCredName;
          return `
                            <div class="group bg-white rounded-lg p-4 border-2 ${isActive ? "border-amber-500 shadow-lg" : "border-gray-200 hover:border-purple-400"} hover:shadow-lg transition-all">
                                <div class="flex items-start justify-between gap-4">
                                    <div class="flex-1 min-w-0">
                                        <div class="flex items-center gap-2 mb-2">
                                            <i class="fab ${providerIcon} ${providerColor} text-lg"></i>
                                            <h5 class="text-base font-bold text-gray-900 truncate">${escapeSettingsHtml(cred.name)}</h5>
                                            ${isActive ? '<span class="ml-2 px-2 py-0.5 bg-amber-500 text-gray-900 text-xs font-bold rounded-full uppercase">Active</span>' : ""}
                                        </div>
                                        <div class="text-sm text-gray-600 space-y-1.5 pl-1">
                                            <div class="flex items-center gap-2">
                                                <i class="fas fa-cog w-4 text-gray-400"></i>
                                                <span><span class="font-semibold text-gray-700">Provider:</span> ${escapeSettingsHtml(provider)}</span>
                                            </div>
                                            <div class="flex items-center gap-2">
                                                <i class="fas fa-brain w-4 text-gray-400"></i>
                                                <span><span class="font-semibold text-gray-700">Model:</span> ${escapeSettingsHtml(cred.model)}</span>
                                            </div>
                                            ${cred.endpoint_url ? `
                                            <div class="flex items-center gap-2">
                                                <i class="fas fa-link w-4 text-gray-400"></i>
                                                <span class="truncate"><span class="font-semibold text-gray-700">Endpoint:</span> <code class="text-xs bg-gray-100 px-1 rounded">${escapeSettingsHtml(cred.endpoint_url)}</code></span>
                                            </div>` : ""}
                                            <div class="flex items-center gap-2">
                                                <i class="fas fa-sliders-h w-4 text-gray-400"></i>
                                                <span><span class="font-semibold text-gray-700">Settings:</span> ${cred.auto_tune === false ? `${escapeSettingsHtml(cred.max_tokens)} tokens, ${escapeSettingsHtml(cred.temperature)} temp` : "Auto-tuned for the model"}</span>
                                            </div>
                                        </div>
                                    </div>
                                    <div class="flex flex-col gap-2 flex-shrink-0">
                                        <button
                                            data-credential-name="${escapeSettingsHtml(cred.name)}" onclick="loadCredentialIntoSettings(this.dataset.credentialName)"
                                            class="px-4 py-2 bg-indigo-600 hover:bg-indigo-700 active:bg-indigo-800 text-white rounded-lg text-sm font-semibold transition-colors"
                                            title="Load this credential into the settings form above"
                                        >
                                            <i class="fas fa-download mr-2"></i>Load
                                        </button>
                                        <button
                                            data-credential-name="${escapeSettingsHtml(cred.name)}" onclick="deleteCredential(this.dataset.credentialName)"
                                            class="px-4 py-2 bg-red-600 hover:bg-red-700 active:bg-red-800 text-white rounded-lg text-sm font-semibold transition-colors"
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
                                <p class="text-sm text-gray-500 mt-2">${escapeSettingsHtml(name)}</p>
                            </div>
                        `;
        }
        const response = await fetch(`/api/credentials/${encodeURIComponent(name)}/load`, { method: "POST" });
        const result = await response.json();
        if (response.ok) {
          const newConfig = result.config;
          setConfig(newConfig);
          setSelectedProvider(normalizeProvider(newConfig.llm.provider, newConfig.llm.endpoint_url));
          setLoadedCredentialName(name);
          setApiKeyPlaceholder(getApiKeyPlaceholderForProvider(newConfig.llm.provider, true));
          setShowConfigForm(true);
          setSelectedModel(newConfig.llm.model);
          setAvailableModels([]);
          setModelRanking([]);
          setLlmTuningSummary(null);
          setLlmAutoTune(newConfig.llm.auto_tune !== false);
          setTimeout(() => {
            const normalizedProvider = normalizeProvider(newConfig.llm.provider, newConfig.llm.endpoint_url);
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
            const contextWindowInput = document.getElementById("llm-context-window");
            if (contextWindowInput) {
              contextWindowInput.value = newConfig.llm.context_window || 0;
            }
            const requestTimeoutInput = document.getElementById("llm-request-timeout");
            if (requestTimeoutInput) {
              requestTimeoutInput.value = newConfig.llm.request_timeout || 0;
            }
            const reasoningEffortInput = document.getElementById("llm-reasoning-effort");
            if (reasoningEffortInput) {
              reasoningEffortInput.value = newConfig.llm.reasoning_effort || "";
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
        const response = await fetch(`/api/credentials/${encodeURIComponent(name)}`, { method: "DELETE" });
        if (response.ok) {
          await loadCredentials();
          const successDiv = document.createElement("div");
          successDiv.className = "fixed top-6 right-6 bg-red-600 text-white px-6 py-4 rounded-xl shadow-2xl z-50";
          successDiv.innerHTML = `
                            <div class="flex items-center gap-3">
                                <i class="fas fa-trash-alt text-2xl"></i>
                                <div>
                                    <p class="font-bold text-base">Credential Deleted</p>
                                    <p class="text-sm opacity-90">${escapeSettingsHtml(name)}</p>
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
    const openMCPSaveModal = (profileName) => {
      var _a2, _b2, _c2, _d2;
      const urlEl = document.getElementById("mcp-url");
      const tokenEl = document.getElementById("mcp-token");
      const verifySslEl = document.getElementById("mcp-verify-ssl");
      const caBundleEl = document.getElementById("mcp-ca-bundle");
      const name = String(profileName || "");
      setMCPSaveDraft({
        mode: name ? "update" : "new",
        url: String((urlEl == null ? void 0 : urlEl.value) || ((_a2 = config == null ? void 0 : config.mcp) == null ? void 0 : _a2.url) || "").trim(),
        token: (tokenEl == null ? void 0 : tokenEl.value) || "",
        verify_ssl: verifySslEl ? verifySslEl.checked : Boolean((_b2 = config == null ? void 0 : config.mcp) == null ? void 0 : _b2.verify_ssl),
        ca_bundle_path: String(caBundleEl ? caBundleEl.value : ((_c2 = config == null ? void 0 : config.mcp) == null ? void 0 : _c2.ca_bundle_path) || "").trim()
      });
      setMCPConfigName(name);
      setMCPConfigDescription(name ? ((_d2 = savedMCPConfigs == null ? void 0 : savedMCPConfigs[name]) == null ? void 0 : _d2.description) || "" : "");
      setIsMCPSaveModalOpen(true);
    };
    const describeMCPDraftToken = (draft, profileName) => {
      var _a2, _b2, _c2;
      if (!draft) return "Not set";
      if (draft.token) return "New token entered";
      if ((_a2 = savedMCPConfigs == null ? void 0 : savedMCPConfigs[String(profileName || "").trim()]) == null ? void 0 : _a2.token) return "Keep saved token";
      const normalizeUrl = (value) => String(value || "").trim().replace(/\/+$/, "").toLowerCase();
      if (((_b2 = config == null ? void 0 : config.mcp) == null ? void 0 : _b2.token) && normalizeUrl(draft.url) === normalizeUrl((_c2 = config == null ? void 0 : config.mcp) == null ? void 0 : _c2.url)) return "Use current token";
      return "Not set";
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
                                <p class="text-base font-bold text-gray-700 mb-2">No MCP servers saved yet</p>
                                <p class="text-sm text-gray-500 mb-4">Save MCP server settings so you can switch between them.</p>
                                <p class="text-xs text-gray-400 italic">Click "Add MCP Server" above.</p>
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
                                        <h5 class="text-base font-bold text-gray-900 truncate">${escapeSettingsHtml(mcp.name)}</h5>
                                        ${mcp.name === activeMCPName ? '<span class="px-2 py-0.5 bg-green-100 text-green-700 text-xs font-bold rounded-full">ACTIVE</span>' : ""}
                                        ${mcp.token ? "" : '<span class="px-2 py-0.5 bg-amber-100 text-amber-800 text-xs font-bold rounded-full" title="Load this configuration, enter the token, and update it">NO TOKEN</span>'}
                                    </div>
                                    ${mcp.description ? `<p class="text-sm text-gray-600 mb-2 pl-1">${escapeSettingsHtml(mcp.description)}</p>` : ""}
                                    <div class="text-sm text-gray-600 space-y-1.5 pl-1">
                                        <div class="flex items-center gap-2">
                                            <i class="fas fa-link w-4 text-gray-400"></i>
                                            <span><span class="font-semibold text-gray-700">URL:</span> ${escapeSettingsHtml(mcp.url)}</span>
                                        </div>
                                        <div class="flex items-center gap-2">
                                            <i class="fas fa-shield-alt w-4 text-gray-400"></i>
                                            <span><span class="font-semibold text-gray-700">SSL:</span> ${mcp.verify_ssl ? "Enabled" : "Disabled"}</span>
                                        </div>
                                    </div>
                                </div>
                                <div class="flex flex-col gap-2 flex-shrink-0">
                                    <button
                                        data-mcp-name="${escapeSettingsHtml(mcp.name)}" onclick="testMCPConfig(this.dataset.mcpName)"
                                        class="px-4 py-2 bg-indigo-600 hover:bg-indigo-700 active:bg-indigo-800 text-white rounded-lg text-sm font-semibold transition-colors"
                                        title="Test connection to this MCP server"
                                    >
                                        <i class="fas fa-network-wired mr-2"></i>Test
                                    </button>
                                    <button
                                        data-mcp-name="${escapeSettingsHtml(mcp.name)}" onclick="loadMCPConfigIntoSettings(this.dataset.mcpName)"
                                        class="px-4 py-2 bg-indigo-600 hover:bg-indigo-700 active:bg-indigo-800 text-white rounded-lg text-sm font-semibold transition-colors"
                                        title="Load this configuration into active settings"
                                    >
                                        <i class="fas fa-download mr-2"></i>Load
                                    </button>
                                    <button
                                        data-mcp-name="${escapeSettingsHtml(mcp.name)}" onclick="deleteMCPConfig(this.dataset.mcpName)"
                                        class="px-4 py-2 bg-red-600 hover:bg-red-700 active:bg-red-800 text-white rounded-lg text-sm font-semibold transition-colors"
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
      var _a2;
      try {
        const mcpList = document.getElementById("mcp-configs-list");
        const originalHTML2 = mcpList.innerHTML;
        mcpList.innerHTML = `
                        <div class="text-center py-10">
                            <i class="fas fa-spinner fa-spin text-green-600 text-4xl mb-4"></i>
                            <p class="text-base font-semibold text-gray-700">Loading configuration...</p>
                            <p class="text-sm text-gray-500 mt-2">${escapeSettingsHtml(name)}</p>
                        </div>
                    `;
        const response = await fetch(`/api/mcp-configs/${encodeURIComponent(name)}/load`, { method: "POST" });
        if (response.ok) {
          const result = await response.json();
          const newConfig = result.config;
          setConfig(newConfig);
          setLoadedMCPConfigName(name);
          setShowMCPConfigForm(true);
          setMCPTokenPlaceholder(((_a2 = newConfig == null ? void 0 : newConfig.mcp) == null ? void 0 : _a2.token) === "***" ? "(Already Configured)" : "Enter token");
          setTimeout(() => {
            const mcpUrlInput = document.getElementById("mcp-url");
            const mcpTokenInput = document.getElementById("mcp-token");
            const mcpCaBundleInput = document.getElementById("mcp-ca-bundle");
            if (mcpUrlInput) mcpUrlInput.value = newConfig.mcp.url;
            if (mcpTokenInput) mcpTokenInput.value = "";
            if (mcpCaBundleInput) mcpCaBundleInput.value = newConfig.mcp.ca_bundle_path || "";
          }, 50);
          await loadConfig();
          await loadMCPConfigs();
          const successDiv = document.createElement("div");
          successDiv.className = "fixed top-6 right-6 bg-green-600 text-white px-6 py-4 rounded-xl shadow-2xl z-50";
          successDiv.innerHTML = `
                            <div class="flex items-center gap-3">
                                <i class="fas fa-check-circle text-2xl"></i>
                                <div>
                                    <p class="font-bold text-base">Configuration Loaded!</p>
                                    <p class="text-sm opacity-90">${escapeSettingsHtml(name)}</p>
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
          alert(`Failed to load configuration: ${formatApiErrorDetail(result.detail)}`);
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
        const response = await fetch(`/api/mcp-configs/${encodeURIComponent(name)}`, { method: "DELETE" });
        if (response.ok) {
          await loadMCPConfigs();
          const successDiv = document.createElement("div");
          successDiv.className = "fixed top-6 right-6 bg-red-600 text-white px-6 py-4 rounded-xl shadow-2xl z-50";
          successDiv.innerHTML = `
                            <div class="flex items-center gap-3">
                                <i class="fas fa-trash-alt text-2xl"></i>
                                <div>
                                    <p class="font-bold text-base">Configuration Deleted</p>
                                    <p class="text-sm opacity-90">${escapeSettingsHtml(name)}</p>
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
                                <p class="text-sm opacity-90">${escapeSettingsHtml(name)}</p>
                            </div>
                        </div>
                    `;
        document.body.appendChild(testingDiv);
        const response = await fetch(`/api/mcp-configs/${encodeURIComponent(name)}/test`, { method: "POST" });
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
                                <p class="text-sm opacity-90">${escapeSettingsHtml(result.message)}</p>
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
    const TROUBLESHOOT_STATUS_STYLES = {
      pass: { icon: "fa-check-circle", tone: "text-green-700", badge: "bg-green-50 text-green-800 border-green-300", label: "Passed" },
      warn: { icon: "fa-exclamation-triangle", tone: "text-amber-700", badge: "bg-amber-50 text-amber-900 border-amber-300", label: "Warning" },
      fail: { icon: "fa-times-circle", tone: "text-red-700", badge: "bg-red-50 text-red-800 border-red-300", label: "Problem found" },
      info: { icon: "fa-info-circle", tone: "text-blue-700", badge: "bg-blue-50 text-blue-800 border-blue-300", label: "Info" },
      skip: { icon: "fa-minus-circle", tone: "text-gray-500", badge: "bg-gray-50 text-gray-600 border-gray-300", label: "Skipped" }
    };
    const buildTroubleshootDraftFromSettings = (kind) => {
      var _a2, _b2, _c2, _d2, _e2, _f2, _g2;
      if (kind === "mcp") {
        return {
          name: loadedMCPConfigName || (config == null ? void 0 : config.active_mcp_config_name) || "",
          url: ((_a2 = config == null ? void 0 : config.mcp) == null ? void 0 : _a2.url) || "",
          token: "",
          verify_ssl: Boolean((_b2 = config == null ? void 0 : config.mcp) == null ? void 0 : _b2.verify_ssl),
          ca_bundle_path: ((_c2 = config == null ? void 0 : config.mcp) == null ? void 0 : _c2.ca_bundle_path) || ""
        };
      }
      return {
        name: loadedCredentialName || (config == null ? void 0 : config.active_credential_name) || "",
        provider: normalizeProvider((_d2 = config == null ? void 0 : config.llm) == null ? void 0 : _d2.provider, (_e2 = config == null ? void 0 : config.llm) == null ? void 0 : _e2.endpoint_url),
        endpoint_url: ((_f2 = config == null ? void 0 : config.llm) == null ? void 0 : _f2.endpoint_url) || "",
        api_key: "",
        model: ((_g2 = config == null ? void 0 : config.llm) == null ? void 0 : _g2.model) || ""
      };
    };
    const readTroubleshootDraftFromForm = (kind) => {
      var _a2, _b2, _c2, _d2, _e2, _f2, _g2, _h2;
      const base = buildTroubleshootDraftFromSettings(kind);
      const field = (id) => document.getElementById(id);
      if (kind === "mcp") {
        const urlEl = field("mcp-url");
        if (!urlEl) return base;
        const verifyEl = field("mcp-verify-ssl");
        return {
          ...base,
          name: loadedMCPConfigName || "",
          url: String(urlEl.value || "").trim(),
          token: ((_a2 = field("mcp-token")) == null ? void 0 : _a2.value) || "",
          verify_ssl: verifyEl ? verifyEl.checked : base.verify_ssl,
          ca_bundle_path: String((_c2 = (_b2 = field("mcp-ca-bundle")) == null ? void 0 : _b2.value) != null ? _c2 : base.ca_bundle_path).trim()
        };
      }
      const providerEl = field("llm-provider");
      if (!providerEl) return base;
      const provider = providerEl.value || base.provider;
      const endpointEl = field("llm-endpoint-url");
      const draft = {
        ...base,
        name: loadedCredentialName || "",
        provider,
        endpoint_url: provider !== "openai" && endpointEl ? endpointEl.value : "",
        api_key: ((_d2 = field("llm-api-key")) == null ? void 0 : _d2.value) || "",
        model: (_f2 = (_e2 = field("llm-model")) == null ? void 0 : _e2.value) != null ? _f2 : base.model,
        ...readLlmTuningFormValues((config == null ? void 0 : config.llm) || {})
      };
      const maxTokens = parseInt(((_g2 = field("llm-max-tokens")) == null ? void 0 : _g2.value) || "", 10);
      const temperature = parseFloat(((_h2 = field("llm-temperature")) == null ? void 0 : _h2.value) || "");
      if (Number.isFinite(maxTokens)) draft.max_tokens = maxTokens;
      if (Number.isFinite(temperature)) draft.temperature = temperature;
      return draft;
    };
    const updateTroubleshootDraft = (kind, key, value) => {
      setTroubleshootDrafts((current) => ({
        ...current,
        [kind]: { ...current[kind] || buildTroubleshootDraftFromSettings(kind), [key]: value }
      }));
    };
    const hideUrlCredentials = (value) => String(value || "").replace(/\/\/[^/@\s]+@/, "//[hidden]@");
    const buildBrowserTroubleshootResult = (kind, draft, response, data, text) => {
      let title;
      let detail;
      let fix;
      if (!response) {
        title = "Couldn't reach the app server";
        detail = text ? `The browser reported: ${text}` : "";
        fix = "Check that the app is still running (./install.sh --status or .\\install.ps1 -Status) and that this page uses the address the app printed when it started.";
      } else if (response.status === 404 || response.status === 405) {
        const currentCopy = ((serverCodeStatus == null ? void 0 : serverCodeStatus.other_copies) || []).find((copy) => copy.state === "current");
        title = "The running app is older than this page";
        detail = `The server on port ${pagePort()} doesn't know the troubleshooting request (${describeApiFailure(response, data, text)}). This happens when the files were updated, for example with git pull, but this copy of the app wasn't restarted, or when an older copy installed in another folder still holds this port. The old server code can also make saves fail in ways the update already fixes.`;
        fix = currentCopy ? `${TROUBLESHOOT_RESTART_HINT} Or open the up-to-date copy at ${currentCopy.origin} and stop this one with ./install.sh --stop in its folder.` : `${TROUBLESHOOT_RESTART_HINT} If you installed the app again in a new folder, stop this older copy with ./install.sh --stop in its old folder and open the address the new install printed.`;
      } else if (response.status === 401) {
        title = "You are signed out";
        detail = describeApiFailure(response, data, text);
        fix = "Sign in again, then run the checks again.";
      } else {
        title = `The troubleshooting request failed (HTTP ${response.status})`;
        detail = describeApiFailure(response, data, text);
        fix = response.status >= 500 ? "Look for the error in the app log (dt4sms.log in the install folder)." : "";
      }
      const target = kind === "mcp" ? hideUrlCredentials(draft == null ? void 0 : draft.url) : [draft == null ? void 0 : draft.provider, draft == null ? void 0 : draft.model].filter(Boolean).join(" ");
      const checkedAt = /* @__PURE__ */ new Date();
      const lines = [
        `Splunk Discovery Tool troubleshooting report: ${kind === "mcp" ? "MCP server" : "AI provider"}`,
        `Checked: ${formatMissionDateTime(checkedAt)}`,
        `Target: ${target || "(none entered)"}`,
        `Result: FAIL - ${title}`,
        `Browser: ${navigator.userAgent}`,
        "",
        "Browser and app server: FAIL",
        `  [fail] ${title}`
      ];
      if (detail) lines.push(`         ${detail}`);
      if (fix) lines.push(`         Fix: ${fix}`);
      return {
        kind,
        target,
        status: "fail",
        summary: title,
        summary_fix: fix,
        checked_at: checkedAt.toISOString(),
        stages: [{ id: "browser", title: "Browser and app server", status: "fail", checks: [{ id: "request", title, status: "fail", detail, fix }] }],
        report: lines.join("\n")
      };
    };
    const runSettingsTroubleshooter = async (kind, draftOverride) => {
      const draft = draftOverride || troubleshootDrafts[kind] || buildTroubleshootDraftFromSettings(kind);
      setTroubleshootRunning(true);
      setTroubleshootResult(null);
      setTroubleshootCopied("");
      try {
        const response = await fetch(`/api/troubleshoot/${kind}`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ ...draft, ...troubleshootOptions })
        });
        const { data, text } = await readApiResponse(response);
        if (response.ok && data && Array.isArray(data.stages)) {
          setTroubleshootResult(data);
        } else {
          setTroubleshootResult(buildBrowserTroubleshootResult(kind, draft, response, data, text));
        }
      } catch (error) {
        setTroubleshootResult(buildBrowserTroubleshootResult(kind, draft, null, null, (error == null ? void 0 : error.message) || String(error)));
      } finally {
        setTroubleshootRunning(false);
      }
    };
    const openSettingsTroubleshooter = (kind, draft, options = {}) => {
      const nextDraft = draft || buildTroubleshootDraftFromSettings(kind);
      setTroubleshootKind(kind);
      setTroubleshootDrafts((current) => ({ ...current, [kind]: nextDraft }));
      setTroubleshootResult(null);
      setTroubleshootCopied("");
      setActiveSettingsTab("troubleshoot");
      if (options.autoRun) {
        runSettingsTroubleshooter(kind, nextDraft);
      }
    };
    const offerTroubleshootAfterSaveFailure = (kind, message, draft, closeSaveDialog) => {
      if (!confirm(`${message}

Open Troubleshoot to find out why it can't be saved?`)) {
        return;
      }
      if (closeSaveDialog) closeSaveDialog();
      openSettingsTroubleshooter(kind, draft, { autoRun: true });
    };
    const copyTroubleshootReport = async (reportText) => {
      let copied = false;
      try {
        if (navigator.clipboard && window.isSecureContext) {
          await navigator.clipboard.writeText(reportText);
          copied = true;
        }
      } catch (clipboardError) {
        copied = false;
      }
      if (!copied) {
        const area = document.createElement("textarea");
        area.value = reportText;
        area.setAttribute("readonly", "");
        area.style.position = "fixed";
        area.style.opacity = "0";
        document.body.appendChild(area);
        area.select();
        try {
          copied = document.execCommand("copy");
        } catch (copyError) {
          copied = false;
        }
        area.remove();
      }
      setTroubleshootCopied(copied ? "copied" : "failed");
    };
    const pagePort = () => Number(window.location.port) || (window.location.protocol === "https:" ? 443 : 80);
    const probeAppCopy = async (port) => {
      const origin = `${window.location.protocol}//${window.location.hostname}:${port}`;
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 1500);
      const request = (route) => fetch(`${origin}${route}`, { mode: "cors", credentials: "omit", cache: "no-store", signal: controller.signal });
      try {
        const response = await request("/api/troubleshoot/server-status");
        if (response.ok) {
          const data = await response.json().catch(() => null);
          if (!data || typeof data !== "object" || !("stale" in data)) {
            return null;
          }
          return { port, origin, state: data.stale ? "stale" : "current", commit: data.running_commit || null };
        }
        if (![401, 403, 404].includes(response.status)) {
          return null;
        }
        const authData = await (await request("/api/auth/status")).json().catch(() => null);
        if (!authData || typeof authData !== "object" || !("demo_mode" in authData)) {
          return null;
        }
        return { port, origin, state: response.status === 404 ? "old" : "signin" };
      } catch (error) {
        return null;
      } finally {
        clearTimeout(timer);
      }
    };
    const findOtherAppCopies = async () => {
      var _a2;
      const preferred = Number((_a2 = config == null ? void 0 : config.server) == null ? void 0 : _a2.port) || 8003;
      const own = pagePort();
      const ports = [];
      for (let port = preferred; port <= preferred + APP_COPY_SCAN_SPAN; port += 1) {
        if (port !== own) {
          ports.push(port);
        }
      }
      return (await Promise.all(ports.map(probeAppCopy))).filter(Boolean);
    };
    const checkServerCodeStatus = async () => {
      let status = null;
      try {
        const response = await fetch("/api/troubleshoot/server-status");
        if (response.status === 404) {
          status = { stale: true, outdated_server: true, restart_hint: TROUBLESHOOT_RESTART_HINT };
        } else if (response.ok) {
          const data = await response.json();
          status = data && typeof data === "object" ? data : null;
        }
      } catch (error) {
        status = null;
      }
      setServerCodeStatus(status);
      if (status == null ? void 0 : status.stale) {
        const otherCopies = await findOtherAppCopies();
        setServerCodeStatus((current) => current === status ? { ...status, other_copies: otherCopies } : current);
      }
    };
    const restartCommandFor = (folder) => /^[A-Za-z]:[\\/]/.test(folder) ? `cd "${folder}"; .\\install.ps1 -Restart` : `cd "${folder}" && ./install.sh --restart`;
    const renderServerCodeBanner = () => {
      if (!(serverCodeStatus == null ? void 0 : serverCodeStatus.stale)) {
        return null;
      }
      const port = pagePort();
      const copies = Array.isArray(serverCodeStatus.other_copies) ? serverCodeStatus.other_copies : [];
      const currentCopy = copies.find((copy) => copy.state === "current");
      const otherCopies = copies.filter((copy) => copy !== currentCopy);
      const folder = String(serverCodeStatus.install_dir || "");
      let fix;
      if (serverCodeStatus.outdated_server && currentCopy) {
        fix = `Use the up-to-date copy, and stop the older ones so bookmarks for port ${port} don't reach old code: run ./install.sh --stop (or .\\install.ps1 -Stop on Windows) in each older copy's folder. On the app's computer, ./install.sh --status in the up-to-date copy's folder lists the copies still running.`;
      } else if (serverCodeStatus.outdated_server) {
        fix = `${TROUBLESHOOT_RESTART_HINT} If you installed the app again in a new folder, this is the older copy: stop it with ./install.sh --stop (or .\\install.ps1 -Stop) in its old folder, then open the address the new install printed.`;
      } else if (folder) {
        fix = `Restart it: ${restartCommandFor(folder)}. Then reload this page.`;
      } else {
        fix = serverCodeStatus.restart_hint || TROUBLESHOOT_RESTART_HINT;
      }
      return /* @__PURE__ */ React.createElement("div", { "data-testid": "settings-server-stale-banner", className: "rounded-lg border-2 border-amber-400 bg-amber-50 p-4 text-sm text-amber-900" }, /* @__PURE__ */ React.createElement("div", { className: "font-semibold" }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-exclamation-triangle mr-2" }), serverCodeStatus.outdated_server ? `The server on port ${port} is running an older version of the app` : `The server on port ${port} is still running the code it had before an update`), /* @__PURE__ */ React.createElement("div", { className: "mt-1" }, serverCodeStatus.outdated_server ? "This page is newer than the server behind it, usually because the files were updated (for example with git pull) after this copy started. Until this copy restarts, saving and testing can fail in ways the update already fixes. Restarting a copy installed in another folder does not change this one." : `Files in ${folder || "its install folder"} changed after it started. Until it restarts, saving and testing can fail in ways the update already fixes.`), currentCopy && /* @__PURE__ */ React.createElement("div", { className: "mt-2", "data-testid": "settings-server-current-copy" }, "An up-to-date copy of the app is running on port ", currentCopy.port, currentCopy.commit ? ` (commit ${String(currentCopy.commit).slice(0, 7)})` : "", ".", " ", /* @__PURE__ */ React.createElement("a", { href: `${currentCopy.origin}/`, "data-testid": "settings-server-current-copy-link", className: "font-semibold underline" }, "Open ", currentCopy.origin)), otherCopies.length > 0 && /* @__PURE__ */ React.createElement("div", { className: "mt-2", "data-testid": "settings-server-other-copies" }, "Other copies of the app are also running on ", otherCopies.length > 1 ? "ports" : "port", " ", otherCopies.map((copy) => copy.port).join(", "), otherCopies.some((copy) => copy.state === "old" || copy.state === "stale") ? ", at least one with older code" : "", "."), /* @__PURE__ */ React.createElement("div", { className: "mt-2" }, fix), /* @__PURE__ */ React.createElement("button", { type: "button", onClick: checkServerCodeStatus, className: "mt-2 text-xs font-medium underline" }, "Check again"));
    };
    const renderTroubleshootResult = (result, panelClass2) => {
      const overall = TROUBLESHOOT_STATUS_STYLES[result.status] || TROUBLESHOOT_STATUS_STYLES.info;
      const passText = result.kind === "mcp" ? "These MCP settings should save and connect." : "These AI provider settings should save and connect.";
      return /* @__PURE__ */ React.createElement("div", { "data-testid": "troubleshoot-results", "data-status": result.status, className: "mt-4 space-y-3" }, /* @__PURE__ */ React.createElement("div", { "data-testid": "troubleshoot-summary", className: `rounded-lg border-2 p-4 ${overall.badge}` }, /* @__PURE__ */ React.createElement("div", { className: "font-semibold" }, /* @__PURE__ */ React.createElement("i", { className: `fas ${overall.icon} mr-2` }), result.status === "pass" ? "All checks passed" : result.summary), result.status === "pass" && /* @__PURE__ */ React.createElement("div", { className: "mt-1 text-sm" }, passText), result.status !== "pass" && result.summary_fix && /* @__PURE__ */ React.createElement("div", { className: "mt-1 text-sm" }, /* @__PURE__ */ React.createElement("span", { className: "font-semibold" }, "What to do:"), " ", result.summary_fix)), (result.stages || []).map((stage) => {
        const stageStyle = TROUBLESHOOT_STATUS_STYLES[stage.status] || TROUBLESHOOT_STATUS_STYLES.info;
        return /* @__PURE__ */ React.createElement("div", { key: `troubleshoot-stage-${stage.id}`, "data-testid": `troubleshoot-stage-${stage.id}`, "data-status": stage.status, className: panelClass2 }, /* @__PURE__ */ React.createElement("div", { className: "flex items-center justify-between gap-2 mb-2" }, /* @__PURE__ */ React.createElement("h4", { className: "text-sm font-semibold text-gray-900" }, stage.title), /* @__PURE__ */ React.createElement("span", { className: `rounded-full border px-2 py-0.5 text-xs font-medium ${stageStyle.badge}` }, stageStyle.label)), /* @__PURE__ */ React.createElement("ul", { className: "space-y-2" }, (stage.checks || []).map((check, index) => {
          const checkStyle = TROUBLESHOOT_STATUS_STYLES[check.status] || TROUBLESHOOT_STATUS_STYLES.info;
          return /* @__PURE__ */ React.createElement("li", { key: `troubleshoot-check-${stage.id}-${check.id}-${index}`, "data-testid": `troubleshoot-check-${check.id}`, "data-status": check.status, className: "text-sm" }, /* @__PURE__ */ React.createElement("div", { className: `font-medium ${checkStyle.tone}` }, /* @__PURE__ */ React.createElement("i", { className: `fas ${checkStyle.icon} mr-2` }), check.title), check.detail && /* @__PURE__ */ React.createElement("div", { className: "ml-6 text-xs text-gray-600 whitespace-pre-wrap break-words" }, check.detail), check.fix && /* @__PURE__ */ React.createElement("div", { className: "ml-6 mt-1 text-xs text-gray-800 break-words" }, /* @__PURE__ */ React.createElement("span", { className: "font-semibold" }, "Fix:"), " ", check.fix));
        })));
      }), /* @__PURE__ */ React.createElement("div", { className: "flex flex-wrap items-center gap-3" }, /* @__PURE__ */ React.createElement(
        "button",
        {
          type: "button",
          "data-testid": "troubleshoot-copy-report",
          onClick: () => copyTroubleshootReport(result.report || ""),
          className: `rounded-lg px-3 py-2 text-xs font-medium ${isDarkTheme ? "bg-gray-800 text-gray-100 border border-gray-700 hover:bg-gray-700" : "bg-white text-gray-700 border border-gray-300 hover:bg-gray-50"}`
        },
        /* @__PURE__ */ React.createElement("i", { className: "fas fa-copy mr-2" }),
        "Copy Report"
      ), troubleshootCopied === "copied" && /* @__PURE__ */ React.createElement("span", { "data-testid": "troubleshoot-copy-status", className: "text-xs text-green-700" }, "Copied. Tokens and keys are hidden, so the report is safe to share with support."), troubleshootCopied === "failed" && /* @__PURE__ */ React.createElement("span", { "data-testid": "troubleshoot-copy-status", className: "text-xs text-amber-700" }, "Couldn't copy automatically. Open the report text below and copy it.")), /* @__PURE__ */ React.createElement("details", { className: "text-xs" }, /* @__PURE__ */ React.createElement("summary", { className: "cursor-pointer font-medium text-gray-700" }, "Show report text"), /* @__PURE__ */ React.createElement("pre", { "data-testid": "troubleshoot-report-text", className: `mt-2 max-h-64 overflow-auto whitespace-pre-wrap rounded-lg border p-3 ${isDarkTheme ? "bg-gray-950 border-gray-700 text-gray-200" : "bg-gray-50 border-gray-200 text-gray-800"}` }, result.report)));
    };
    const renderSettingsTroubleshooter = () => {
      if (activeSettingsTab !== "troubleshoot") {
        return null;
      }
      const kind = troubleshootKind;
      const draft = troubleshootDrafts[kind] || buildTroubleshootDraftFromSettings(kind);
      const panelClass2 = `rounded-xl border p-4 ${isDarkTheme ? "bg-gray-900 border-gray-700" : "bg-white border-gray-200"}`;
      const inputClass = "w-full px-3 py-2 border border-gray-300 rounded-md";
      const labelClass = "block text-sm font-medium text-gray-700 mb-1";
      const savedNames = Object.keys((kind === "mcp" ? savedMCPConfigs : savedCredentials) || {}).sort();
      const secretLabel = kind === "mcp" ? "token" : "API key";
      const nothingToCheck = !troubleshootOptions.check_save && !troubleshootOptions.check_connection;
      const kindButton = (value, label, icon) => /* @__PURE__ */ React.createElement(
        "button",
        {
          key: `troubleshoot-kind-${value}`,
          type: "button",
          "data-testid": `troubleshoot-kind-${value}`,
          onClick: () => {
            setTroubleshootKind(value);
            setTroubleshootResult(null);
            setTroubleshootCopied("");
          },
          className: `flex-1 rounded-lg px-4 py-2 text-sm font-medium ${kind === value ? "bg-amber-600 text-white shadow-sm" : isDarkTheme ? "bg-gray-800 text-gray-200 hover:bg-gray-700" : "bg-white text-gray-700 border border-gray-200 hover:bg-gray-100"}`,
          "aria-pressed": kind === value
        },
        /* @__PURE__ */ React.createElement("i", { className: `fas ${icon} mr-2` }),
        label
      );
      return /* @__PURE__ */ React.createElement("div", { "data-testid": "settings-troubleshooter" }, /* @__PURE__ */ React.createElement("div", { className: `rounded-lg p-6 border ${isDarkTheme ? "bg-gray-800 border-gray-700" : "bg-white border-gray-200"}` }, /* @__PURE__ */ React.createElement("div", { className: "mb-4" }, /* @__PURE__ */ React.createElement("h3", { className: "text-lg font-semibold text-gray-900 mb-2" }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-stethoscope mr-2 text-indigo-600", "aria-hidden": "true" }), "Troubleshoot a Connection"), /* @__PURE__ */ React.createElement("p", { className: "text-sm text-gray-600" }, "Enter the settings that won't connect or won't save. The checks look at the app itself, the values you entered, saving, the network, and the server's reply, and explain what to fix. Nothing is saved.")), /* @__PURE__ */ React.createElement("div", { className: "flex gap-2 mb-4" }, kindButton("mcp", "MCP Server", "fa-server"), kindButton("llm", "AI Provider", "fa-brain")), /* @__PURE__ */ React.createElement("div", { className: panelClass2 }, /* @__PURE__ */ React.createElement("div", { className: "space-y-3" }, /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("label", { className: labelClass, htmlFor: "troubleshoot-name" }, kind === "mcp" ? "Configuration name" : "Credential name", /* @__PURE__ */ React.createElement("span", { className: "ml-2 text-xs text-gray-500" }, "(optional; a blank ", secretLabel, " uses the one saved under this name)")), /* @__PURE__ */ React.createElement(
        "input",
        {
          id: "troubleshoot-name",
          "data-testid": "troubleshoot-name",
          type: "text",
          list: "troubleshoot-saved-names",
          className: inputClass,
          value: draft.name || "",
          onChange: (e) => updateTroubleshootDraft(kind, "name", e.target.value)
        }
      ), /* @__PURE__ */ React.createElement("datalist", { id: "troubleshoot-saved-names" }, savedNames.map((savedName) => /* @__PURE__ */ React.createElement("option", { key: `troubleshoot-saved-${savedName}`, value: savedName })))), kind === "mcp" ? /* @__PURE__ */ React.createElement(React.Fragment, null, /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("label", { className: labelClass, htmlFor: "troubleshoot-mcp-url" }, "MCP URL"), /* @__PURE__ */ React.createElement(
        "input",
        {
          id: "troubleshoot-mcp-url",
          "data-testid": "troubleshoot-mcp-url",
          type: "text",
          placeholder: "https://splunk.example.com:8089/services/mcp",
          className: inputClass,
          value: draft.url || "",
          onChange: (e) => updateTroubleshootDraft("mcp", "url", e.target.value)
        }
      )), /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("label", { className: labelClass, htmlFor: "troubleshoot-mcp-token" }, "Token"), /* @__PURE__ */ React.createElement(
        "input",
        {
          id: "troubleshoot-mcp-token",
          "data-testid": "troubleshoot-mcp-token",
          type: "password",
          autoComplete: "off",
          placeholder: "Leave blank to use the saved token",
          className: inputClass,
          value: draft.token || "",
          onChange: (e) => updateTroubleshootDraft("mcp", "token", e.target.value)
        }
      )), /* @__PURE__ */ React.createElement("div", { className: "flex items-center" }, /* @__PURE__ */ React.createElement(
        "input",
        {
          id: "troubleshoot-mcp-verify-ssl",
          "data-testid": "troubleshoot-mcp-verify-ssl",
          type: "checkbox",
          className: "mr-2",
          checked: Boolean(draft.verify_ssl),
          onChange: (e) => updateTroubleshootDraft("mcp", "verify_ssl", e.target.checked)
        }
      ), /* @__PURE__ */ React.createElement("label", { htmlFor: "troubleshoot-mcp-verify-ssl", className: "text-sm text-gray-700" }, "Verify SSL Certificate")), /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("label", { className: labelClass, htmlFor: "troubleshoot-mcp-ca-bundle" }, "CA bundle file", /* @__PURE__ */ React.createElement("span", { className: "ml-2 text-xs text-gray-500" }, "(optional; a .pem file on the app server that trusts your Splunk certificate)")), /* @__PURE__ */ React.createElement(
        "input",
        {
          id: "troubleshoot-mcp-ca-bundle",
          "data-testid": "troubleshoot-mcp-ca-bundle",
          type: "text",
          className: inputClass,
          value: draft.ca_bundle_path || "",
          onChange: (e) => updateTroubleshootDraft("mcp", "ca_bundle_path", e.target.value)
        }
      ))) : /* @__PURE__ */ React.createElement(React.Fragment, null, /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("label", { className: labelClass, htmlFor: "troubleshoot-llm-provider" }, "Provider"), /* @__PURE__ */ React.createElement(
        "select",
        {
          id: "troubleshoot-llm-provider",
          "data-testid": "troubleshoot-llm-provider",
          className: inputClass,
          value: draft.provider || "openai",
          onChange: (e) => updateTroubleshootDraft("llm", "provider", e.target.value)
        },
        /* @__PURE__ */ React.createElement("option", { value: "openai" }, "OpenAI"),
        /* @__PURE__ */ React.createElement("option", { value: "azure" }, "Azure OpenAI"),
        /* @__PURE__ */ React.createElement("option", { value: "anthropic" }, "Anthropic (Claude)"),
        /* @__PURE__ */ React.createElement("option", { value: "gemini" }, "Google Gemini"),
        /* @__PURE__ */ React.createElement("option", { value: "ollama" }, "Ollama"),
        /* @__PURE__ */ React.createElement("option", { value: "custom" }, "Custom Endpoint")
      )), draft.provider !== "openai" && /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("label", { className: labelClass, htmlFor: "troubleshoot-llm-endpoint" }, "Endpoint URL"), /* @__PURE__ */ React.createElement(
        "input",
        {
          id: "troubleshoot-llm-endpoint",
          "data-testid": "troubleshoot-llm-endpoint",
          type: "text",
          placeholder: draft.provider === "ollama" ? "http://localhost:11434" : "Leave blank for the provider default",
          className: inputClass,
          value: draft.endpoint_url || "",
          onChange: (e) => updateTroubleshootDraft("llm", "endpoint_url", e.target.value)
        }
      )), /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("label", { className: labelClass, htmlFor: "troubleshoot-llm-api-key" }, "API Key"), /* @__PURE__ */ React.createElement(
        "input",
        {
          id: "troubleshoot-llm-api-key",
          "data-testid": "troubleshoot-llm-api-key",
          type: "password",
          autoComplete: "off",
          placeholder: "Leave blank to use the saved key",
          className: inputClass,
          value: draft.api_key || "",
          onChange: (e) => updateTroubleshootDraft("llm", "api_key", e.target.value)
        }
      )), /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("label", { className: labelClass, htmlFor: "troubleshoot-llm-model" }, "Model"), /* @__PURE__ */ React.createElement(
        "input",
        {
          id: "troubleshoot-llm-model",
          "data-testid": "troubleshoot-llm-model",
          type: "text",
          className: inputClass,
          value: draft.model || "",
          onChange: (e) => updateTroubleshootDraft("llm", "model", e.target.value)
        }
      ))), /* @__PURE__ */ React.createElement("div", { className: "flex flex-wrap gap-4 pt-1" }, /* @__PURE__ */ React.createElement("label", { className: "flex items-center text-sm text-gray-700" }, /* @__PURE__ */ React.createElement(
        "input",
        {
          type: "checkbox",
          "data-testid": "troubleshoot-check-save",
          className: "mr-2",
          checked: troubleshootOptions.check_save,
          onChange: (e) => setTroubleshootOptions((current) => ({ ...current, check_save: e.target.checked }))
        }
      ), "Check that it can be saved"), /* @__PURE__ */ React.createElement("label", { className: "flex items-center text-sm text-gray-700" }, /* @__PURE__ */ React.createElement(
        "input",
        {
          type: "checkbox",
          "data-testid": "troubleshoot-check-connection",
          className: "mr-2",
          checked: troubleshootOptions.check_connection,
          onChange: (e) => setTroubleshootOptions((current) => ({ ...current, check_connection: e.target.checked }))
        }
      ), "Test the connection")), /* @__PURE__ */ React.createElement("div", { className: "flex flex-wrap gap-2 pt-3 border-t border-gray-200" }, /* @__PURE__ */ React.createElement(
        "button",
        {
          type: "button",
          "data-testid": "troubleshoot-run",
          disabled: troubleshootRunning || nothingToCheck,
          onClick: () => runSettingsTroubleshooter(kind, draft),
          className: "flex-1 px-4 py-2 bg-amber-600 hover:bg-amber-700 text-white rounded-lg font-medium shadow-md transition-all disabled:opacity-60 disabled:cursor-not-allowed"
        },
        troubleshootRunning ? /* @__PURE__ */ React.createElement(React.Fragment, null, /* @__PURE__ */ React.createElement("i", { className: "fas fa-spinner fa-spin mr-2" }), "Running checks...") : /* @__PURE__ */ React.createElement(React.Fragment, null, /* @__PURE__ */ React.createElement("i", { className: "fas fa-stethoscope mr-2" }), "Run Checks")
      ), /* @__PURE__ */ React.createElement(
        "button",
        {
          type: "button",
          "data-testid": "troubleshoot-use-current",
          onClick: () => {
            setTroubleshootDrafts((current) => ({ ...current, [kind]: readTroubleshootDraftFromForm(kind) }));
            setTroubleshootResult(null);
          },
          className: `px-4 py-2 rounded-lg text-sm font-medium ${isDarkTheme ? "bg-gray-800 text-gray-100 border border-gray-700 hover:bg-gray-700" : "bg-white text-gray-700 border border-gray-300 hover:bg-gray-50"}`
        },
        /* @__PURE__ */ React.createElement("i", { className: "fas fa-rotate-left mr-2" }),
        "Use Values from Connections"
      )))), troubleshootResult && troubleshootResult.kind === kind && renderTroubleshootResult(troubleshootResult, panelClass2)));
    };
    const renderSecurityAccessSettings = () => {
      var _a2, _b2;
      if (!config) {
        return null;
      }
      if (activeSettingsTab !== "users" && activeSettingsTab !== "access") {
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
      return /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("div", { className: `rounded-lg p-6 border ${isDarkTheme ? "bg-gray-800 border-gray-700" : "bg-white border-gray-200"}` }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between mb-5" }, /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("h3", { className: "text-lg font-semibold text-gray-900 mb-2" }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-user-shield mr-2 text-indigo-600" }), activeSettingsTab === "users" ? "Users and Roles" : "Security"), /* @__PURE__ */ React.createElement("p", { className: "text-sm text-gray-600" }, activeSettingsTab === "users" ? "Create local users, set their roles, and choose their default MCP connection." : "Turn on sign-in and manage tokens for the external REST API and inbound MCP endpoint.")), /* @__PURE__ */ React.createElement("div", { className: `rounded-lg border px-4 py-3 text-xs ${isDarkTheme ? "bg-gray-900 border-gray-700 text-gray-300" : "bg-white border-gray-200 text-gray-600"}` }, /* @__PURE__ */ React.createElement("div", { className: "font-semibold text-gray-900" }, "Current state"), /* @__PURE__ */ React.createElement("div", { className: "mt-1" }, "Sign-in: ", securityConfig2.auth_enabled ? "required" : "off (anyone can use the app)"), /* @__PURE__ */ React.createElement("div", null, "External API: ", securityConfig2.external_api_enabled ? "on" : "off"), /* @__PURE__ */ React.createElement("div", null, "Inbound MCP: ", securityConfig2.external_mcp_enabled ? "on" : "off"))), activeSettingsTab === "access" && /* @__PURE__ */ React.createElement("div", { className: "grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-4 mb-6" }, /* @__PURE__ */ React.createElement("div", { className: `rounded-lg border p-4 ${isDarkTheme ? "bg-gray-900 border-gray-700" : "bg-white border-gray-200"}` }, /* @__PURE__ */ React.createElement("div", { className: "text-xs uppercase tracking-wider text-gray-500" }, "Mode"), /* @__PURE__ */ React.createElement("div", { className: "mt-2 text-xl font-bold text-gray-900" }, securityConfig2.auth_enabled ? "Secured" : "Open"), /* @__PURE__ */ React.createElement("div", { className: "mt-1 text-xs text-gray-500" }, securityConfig2.auth_enabled ? "Sign-in required" : "No sign-in required")), /* @__PURE__ */ React.createElement("div", { className: `rounded-lg border p-4 ${isDarkTheme ? "bg-gray-900 border-gray-700" : "bg-white border-gray-200"}` }, /* @__PURE__ */ React.createElement("div", { className: "text-xs uppercase tracking-wider text-gray-500" }, "Current Session"), /* @__PURE__ */ React.createElement("div", { className: "mt-2 text-xl font-bold text-gray-900" }, (authStatus == null ? void 0 : authStatus.authenticated) ? (currentUser == null ? void 0 : currentUser.username) || "Signed in" : "Not signed in"), /* @__PURE__ */ React.createElement("div", { className: "mt-1 text-xs text-gray-500" }, (authStatus == null ? void 0 : authStatus.authenticated) ? `${(currentUser == null ? void 0 : currentUser.role) || "unknown"} access` : "No one is signed in")), /* @__PURE__ */ React.createElement("div", { className: `rounded-lg border p-4 ${isDarkTheme ? "bg-gray-900 border-gray-700" : "bg-white border-gray-200"}` }, /* @__PURE__ */ React.createElement("div", { className: "text-xs uppercase tracking-wider text-gray-500" }, "Users"), /* @__PURE__ */ React.createElement("div", { className: "mt-2 text-xl font-bold text-gray-900" }, securityUsers.length), /* @__PURE__ */ React.createElement("div", { className: "mt-1 text-xs text-gray-500" }, "Local accounts")), /* @__PURE__ */ React.createElement("div", { className: `rounded-lg border p-4 ${isDarkTheme ? "bg-gray-900 border-gray-700" : "bg-white border-gray-200"}` }, /* @__PURE__ */ React.createElement("div", { className: "text-xs uppercase tracking-wider text-gray-500" }, "Tokens"), /* @__PURE__ */ React.createElement("div", { className: "mt-2 text-xl font-bold text-gray-900" }, securityTokens.length), /* @__PURE__ */ React.createElement("div", { className: "mt-1 text-xs text-gray-500" }, "For external API and MCP clients"))), activeSettingsTab === "access" && /* @__PURE__ */ React.createElement("div", { className: `rounded-xl border p-5 ${isDarkTheme ? "bg-gray-900 border-gray-700" : "bg-white border-gray-200"}` }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-col gap-2 md:flex-row md:items-start md:justify-between mb-4" }, /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("h4", { className: "text-base font-semibold text-gray-900" }, "Sign-in and API Settings"), /* @__PURE__ */ React.createElement("p", { className: "text-xs text-gray-500 mt-1" }, "Click Save Settings at the bottom to apply changes.")), /* @__PURE__ */ React.createElement("div", { className: `rounded-lg px-3 py-2 text-xs ${isDarkTheme ? "bg-gray-950 border border-gray-700 text-gray-300" : "bg-gray-50 border border-gray-200 text-gray-600"}` }, "Session timeout: ", securityConfig2.session_timeout_minutes || 480, " min")), /* @__PURE__ */ React.createElement("div", { className: "grid gap-4 xl:grid-cols-2" }, /* @__PURE__ */ React.createElement("div", { className: `flex items-start justify-between gap-4 rounded-lg border px-4 py-3 ${isDarkTheme ? "bg-gray-950 border-gray-700" : "bg-gray-50 border-gray-200"}` }, /* @__PURE__ */ React.createElement("div", { className: "min-w-0" }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-wrap items-center gap-2" }, /* @__PURE__ */ React.createElement("div", { className: "text-sm font-semibold text-gray-900" }, "Enable Authentication"), /* @__PURE__ */ React.createElement(
        "button",
        {
          type: "button",
          "data-testid": "settings-auth-enable-info-button",
          onClick: () => openAuthEnableInfoModal({ requestEnable: false }),
          className: `inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-xs font-medium ${isDarkTheme ? "bg-gray-900 border-gray-700 text-sky-100 hover:bg-gray-800" : "bg-white border-gray-300 text-sky-700 hover:bg-sky-50"}`
        },
        /* @__PURE__ */ React.createElement("i", { className: "fas fa-circle-info", "aria-hidden": "true" }),
        /* @__PURE__ */ React.createElement("span", null, "Info")
      )), /* @__PURE__ */ React.createElement("div", { className: "mt-1 text-xs text-gray-500" }, "Users must sign in before using the app."), authEnableGateActive && /* @__PURE__ */ React.createElement("div", { className: `mt-2 text-xs ${isDarkTheme ? "text-amber-200" : "text-amber-700"}` }, "Read the authentication guide before you turn this on.")), /* @__PURE__ */ React.createElement(
        "button",
        {
          type: "button",
          "data-testid": "settings-auth-enable-toggle",
          "aria-pressed": !!securityConfig2.auth_enabled,
          "aria-label": securityConfig2.auth_enabled ? "Disable authentication" : authEnableGateActive ? "Read the authentication guide before turning on authentication" : "Enable authentication",
          onClick: handleAuthEnableToggle,
          className: `mt-1 inline-flex h-6 w-6 flex-shrink-0 items-center justify-center rounded border transition ${securityConfig2.auth_enabled ? "bg-indigo-600 border-indigo-600 text-white hover:bg-indigo-700" : authEnableGateActive ? isDarkTheme ? "bg-gray-800 border-gray-600 text-gray-400 hover:bg-gray-700" : "bg-gray-200 border-gray-300 text-gray-400 hover:bg-gray-300" : isDarkTheme ? "bg-gray-950 border-gray-500 text-transparent hover:border-indigo-400" : "bg-white border-gray-300 text-transparent hover:border-indigo-400"}`
        },
        securityConfig2.auth_enabled ? /* @__PURE__ */ React.createElement("i", { className: "fas fa-check text-xs", "aria-hidden": "true" }) : authEnableGateActive ? /* @__PURE__ */ React.createElement("i", { className: "fas fa-lock text-xs", "aria-hidden": "true" }) : /* @__PURE__ */ React.createElement("span", { className: "h-2 w-2 rounded-sm bg-transparent", "aria-hidden": "true" })
      )), /* @__PURE__ */ React.createElement("label", { className: `flex items-start justify-between gap-4 rounded-lg border px-4 py-3 ${isDarkTheme ? "bg-gray-950 border-gray-700" : "bg-gray-50 border-gray-200"}` }, /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("div", { className: "text-sm font-semibold text-gray-900" }, "Require Password Change on First Sign-in"), /* @__PURE__ */ React.createElement("div", { className: "mt-1 text-xs text-gray-500" }, "New users must choose their own password the first time they sign in.")), /* @__PURE__ */ React.createElement(
        "input",
        {
          type: "checkbox",
          checked: !!securityConfig2.require_password_reset_on_first_login,
          onChange: (event) => {
            setConfig((current) => ({
              ...current,
              security: {
                ...(current == null ? void 0 : current.security) || {},
                require_password_reset_on_first_login: event.target.checked
              }
            }));
            handleSettingsChange();
          },
          className: "mt-1 h-4 w-4"
        }
      )), /* @__PURE__ */ React.createElement("label", { className: `flex items-start justify-between gap-4 rounded-lg border px-4 py-3 ${isDarkTheme ? "bg-gray-950 border-gray-700" : "bg-gray-50 border-gray-200"}` }, /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("div", { className: "text-sm font-semibold text-gray-900" }, "Enable External REST API"), /* @__PURE__ */ React.createElement("div", { className: "mt-1 text-xs text-gray-500" }, "Lets clients with a token use the read-only /api/external/rag/ endpoints.")), /* @__PURE__ */ React.createElement(
        "input",
        {
          type: "checkbox",
          checked: !!securityConfig2.external_api_enabled,
          onChange: (event) => {
            setConfig((current) => ({
              ...current,
              security: {
                ...(current == null ? void 0 : current.security) || {},
                external_api_enabled: event.target.checked
              }
            }));
            handleSettingsChange();
          },
          className: "mt-1 h-4 w-4"
        }
      )), /* @__PURE__ */ React.createElement("label", { className: `flex items-start justify-between gap-4 rounded-lg border px-4 py-3 ${isDarkTheme ? "bg-gray-950 border-gray-700" : "bg-gray-50 border-gray-200"}` }, /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("div", { className: "text-sm font-semibold text-gray-900" }, "Enable External MCP"), /* @__PURE__ */ React.createElement("div", { className: "mt-1 text-xs text-gray-500" }, "Lets clients with a token use the read-only inbound MCP endpoint.")), /* @__PURE__ */ React.createElement(
        "input",
        {
          type: "checkbox",
          checked: !!securityConfig2.external_mcp_enabled,
          onChange: (event) => {
            setConfig((current) => ({
              ...current,
              security: {
                ...(current == null ? void 0 : current.security) || {},
                external_mcp_enabled: event.target.checked
              }
            }));
            handleSettingsChange();
          },
          className: "mt-1 h-4 w-4"
        }
      ))), /* @__PURE__ */ React.createElement("div", { className: "grid gap-4 md:grid-cols-3 mt-4" }, /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("label", { className: "block text-sm font-medium text-gray-700 mb-1" }, "Sign-in Method"), /* @__PURE__ */ React.createElement(
        "select",
        {
          value: securityConfig2.auth_provider || "local_password",
          onChange: (event) => {
            const nextProvider = event.target.value;
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
        /* @__PURE__ */ React.createElement("option", { value: "local_password" }, "Local password"),
        /* @__PURE__ */ React.createElement("option", { value: "oidc" }, "OIDC (enterprise SSO)")
      ), /* @__PURE__ */ React.createElement("div", { className: "mt-1 text-xs text-gray-500" }, authProviderSelection === "oidc" ? oidcCanEnableAuth ? "OIDC is ready to turn on with these provider settings." : "Add the issuer URL, client ID, and client secret before you turn on OIDC sign-in." : "Users sign in with a local username and password. Switch to OIDC when your provider settings are ready.")), /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("label", { className: "block text-sm font-medium text-gray-700 mb-1" }, "Session Timeout (minutes)"), /* @__PURE__ */ React.createElement(
        "input",
        {
          type: "number",
          min: "15",
          value: (_a2 = securityConfig2.session_timeout_minutes) != null ? _a2 : 480,
          onChange: (event) => {
            const nextValue = Number.parseInt(event.target.value, 10);
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
          onChange: (event) => {
            const nextValue = Number.parseInt(event.target.value, 10);
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
      ))), showOidcPanel && /* @__PURE__ */ React.createElement("div", { className: `mt-4 rounded-xl border p-4 ${isDarkTheme ? "bg-gray-950 border-gray-700" : "bg-gray-50 border-gray-200"}` }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between mb-4" }, /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("h5", { className: "text-sm font-semibold text-gray-900" }, "OIDC Provider"), /* @__PURE__ */ React.createElement("p", { className: "mt-1 text-xs text-gray-500" }, "OIDC can be turned on once the issuer URL, client ID, and client secret are set.")), /* @__PURE__ */ React.createElement("div", { className: "flex flex-wrap gap-2 text-xs font-medium" }, /* @__PURE__ */ React.createElement("span", { className: `inline-flex items-center rounded-full px-2 py-1 ${(oidcStatus == null ? void 0 : oidcStatus.configured) ? "bg-blue-50 text-gray-900" : "bg-gray-100 text-gray-700"}` }, (oidcStatus == null ? void 0 : oidcStatus.configured) ? "Configured" : "Not configured"), /* @__PURE__ */ React.createElement("span", { className: `inline-flex items-center rounded-full px-2 py-1 ${oidcCanEnableAuth ? "bg-emerald-50 text-gray-900" : "bg-amber-50 text-gray-900"}` }, oidcCanEnableAuth ? "Ready to turn on" : "Setup needed"), /* @__PURE__ */ React.createElement("span", { className: `inline-flex items-center rounded-full px-2 py-1 ${oidcImplemented ? "bg-indigo-50 text-gray-900" : "bg-gray-100 text-gray-700"}` }, oidcImplemented ? "Provider reachable" : "Provider unavailable"))), /* @__PURE__ */ React.createElement("div", { className: "grid gap-3 md:grid-cols-2 xl:grid-cols-3" }, /* @__PURE__ */ React.createElement("div", { className: "xl:col-span-2" }, /* @__PURE__ */ React.createElement("label", { className: "block text-sm font-medium text-gray-700 mb-1" }, "Issuer URL"), /* @__PURE__ */ React.createElement(
        "input",
        {
          type: "text",
          value: oidcConfig.issuer_url || "",
          onChange: (event) => updateOidcConfig("issuer_url", event.target.value),
          className: "w-full px-3 py-2 border border-gray-300 rounded-md",
          placeholder: "https://idp.example.com/application/o/dt4sms/"
        }
      )), /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("label", { className: "block text-sm font-medium text-gray-700 mb-1" }, "Audience"), /* @__PURE__ */ React.createElement(
        "input",
        {
          type: "text",
          value: oidcConfig.audience || "",
          onChange: (event) => updateOidcConfig("audience", event.target.value),
          className: "w-full px-3 py-2 border border-gray-300 rounded-md",
          placeholder: "optional audience"
        }
      )), /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("label", { className: "block text-sm font-medium text-gray-700 mb-1" }, "Client ID"), /* @__PURE__ */ React.createElement(
        "input",
        {
          type: "text",
          value: oidcConfig.client_id || "",
          onChange: (event) => updateOidcConfig("client_id", event.target.value),
          className: "w-full px-3 py-2 border border-gray-300 rounded-md",
          placeholder: "dt4sms-client"
        }
      )), /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("label", { className: "block text-sm font-medium text-gray-700 mb-1" }, "Client Secret"), /* @__PURE__ */ React.createElement(
        "input",
        {
          type: "password",
          value: oidcConfig.client_secret || "",
          onChange: (event) => updateOidcConfig("client_secret", event.target.value),
          className: "w-full px-3 py-2 border border-gray-300 rounded-md",
          placeholder: (oidcStatus == null ? void 0 : oidcStatus.client_secret_configured) ? "*** keeps the current secret" : "OIDC client secret"
        }
      )), /* @__PURE__ */ React.createElement("div", { className: "md:col-span-2 xl:col-span-1" }, /* @__PURE__ */ React.createElement("label", { className: "block text-sm font-medium text-gray-700 mb-1" }, "Scopes"), /* @__PURE__ */ React.createElement(
        "input",
        {
          type: "text",
          value: oidcScopesValue,
          onChange: (event) => updateOidcConfig("scopes", event.target.value.split(",").map((value) => value.trim()).filter(Boolean)),
          className: "w-full px-3 py-2 border border-gray-300 rounded-md",
          placeholder: "openid, profile, email"
        }
      )), /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("label", { className: "block text-sm font-medium text-gray-700 mb-1" }, "Username Claim"), /* @__PURE__ */ React.createElement(
        "input",
        {
          type: "text",
          value: oidcConfig.username_claim || "preferred_username",
          onChange: (event) => updateOidcConfig("username_claim", event.target.value),
          className: "w-full px-3 py-2 border border-gray-300 rounded-md"
        }
      )), /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("label", { className: "block text-sm font-medium text-gray-700 mb-1" }, "Email Claim"), /* @__PURE__ */ React.createElement(
        "input",
        {
          type: "text",
          value: oidcConfig.email_claim || "email",
          onChange: (event) => updateOidcConfig("email_claim", event.target.value),
          className: "w-full px-3 py-2 border border-gray-300 rounded-md"
        }
      )), /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("label", { className: "block text-sm font-medium text-gray-700 mb-1" }, "Role Claim"), /* @__PURE__ */ React.createElement(
        "input",
        {
          type: "text",
          value: oidcConfig.role_claim || "roles",
          onChange: (event) => updateOidcConfig("role_claim", event.target.value),
          className: "w-full px-3 py-2 border border-gray-300 rounded-md"
        }
      )), /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("label", { className: "block text-sm font-medium text-gray-700 mb-1" }, "Default Role"), /* @__PURE__ */ React.createElement(
        "select",
        {
          value: oidcConfig.default_role || "viewer",
          onChange: (event) => updateOidcConfig("default_role", event.target.value),
          className: "w-full px-3 py-2 border border-gray-300 rounded-md"
        },
        SECURITY_ROLE_OPTIONS.map((role) => /* @__PURE__ */ React.createElement("option", { key: `oidc-default-role-${role}`, value: role }, role))
      )), /* @__PURE__ */ React.createElement("div", { className: "md:col-span-2 xl:col-span-2" }, /* @__PURE__ */ React.createElement("label", { className: "block text-sm font-medium text-gray-700 mb-1" }, "MCP Assignment Claim"), /* @__PURE__ */ React.createElement(
        "input",
        {
          type: "text",
          value: oidcConfig.mcp_assignment_claim || "",
          onChange: (event) => updateOidcConfig("mcp_assignment_claim", event.target.value),
          className: "w-full px-3 py-2 border border-gray-300 rounded-md",
          placeholder: "optional claim for default MCP assignment"
        }
      )))), /* @__PURE__ */ React.createElement("div", { className: `mt-4 rounded-lg px-4 py-3 text-xs ${isDarkTheme ? "bg-gray-950 border border-gray-700 text-gray-300" : "bg-gray-50 border border-gray-200 text-gray-600"}` }, authProviderSelection === "oidc" ? oidcCanEnableAuth ? "OIDC is ready. Save, turn on authentication, then sign in once to confirm roles and MCP assignments map correctly." : "Set the issuer URL, client ID, and client secret before you turn on authentication." : securityConfig2.auth_enabled ? "After you turn on authentication, sign in as the first admin and change its password before others use the app." : "Anyone can use the app until you turn on authentication and save. You can create users and tokens first.")), activeSettingsTab === "users" && /* @__PURE__ */ React.createElement("div", { className: `mt-6 rounded-xl border p-5 ${isDarkTheme ? "bg-gray-900 border-gray-700" : "bg-white border-gray-200"}` }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-col gap-3 md:flex-row md:items-start md:justify-between mb-4" }, /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("h4", { className: "text-base font-semibold text-gray-900" }, "Local Users"), /* @__PURE__ */ React.createElement("p", { className: "text-xs text-gray-500 mt-1" }, "Create and disable users, assign MCP connections, and require password changes.")), /* @__PURE__ */ React.createElement(
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
          onChange: (event) => setSecurityUserComposer((current) => ({ ...current, username: event.target.value })),
          className: "w-full px-3 py-2 border border-gray-300 rounded-md",
          placeholder: "analyst1"
        }
      )), /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("label", { className: "block text-sm font-medium text-gray-700 mb-1" }, "Initial Password"), /* @__PURE__ */ React.createElement(
        "input",
        {
          type: "password",
          value: securityUserComposer.password,
          onChange: (event) => setSecurityUserComposer((current) => ({ ...current, password: event.target.value })),
          className: "w-full px-3 py-2 border border-gray-300 rounded-md",
          placeholder: `At least ${securityConfig2.password_min_length || 12} characters`
        }
      )), /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("label", { className: "block text-sm font-medium text-gray-700 mb-1" }, "Role"), /* @__PURE__ */ React.createElement(
        "select",
        {
          value: securityUserComposer.role,
          onChange: (event) => setSecurityUserComposer((current) => ({ ...current, role: event.target.value })),
          className: "w-full px-3 py-2 border border-gray-300 rounded-md"
        },
        SECURITY_ROLE_OPTIONS.map((role) => /* @__PURE__ */ React.createElement("option", { key: `security-role-create-${role}`, value: role }, role))
      )), /* @__PURE__ */ React.createElement("div", { className: "md:col-span-2 xl:col-span-1" }, /* @__PURE__ */ React.createElement("label", { className: "block text-sm font-medium text-gray-700 mb-1" }, "Assigned MCP Connection"), /* @__PURE__ */ React.createElement(
        "select",
        {
          value: securityUserComposer.mcp_config_name,
          onChange: (event) => setSecurityUserComposer((current) => ({ ...current, mcp_config_name: event.target.value })),
          className: "w-full px-3 py-2 border border-gray-300 rounded-md"
        },
        /* @__PURE__ */ React.createElement("option", { value: "" }, "No default assignment"),
        availableMCPAssignments.map((name) => /* @__PURE__ */ React.createElement("option", { key: `security-user-create-mcp-${name}`, value: name }, name))
      )), /* @__PURE__ */ React.createElement("label", { className: `flex items-center gap-3 rounded-lg border px-3 py-2 ${isDarkTheme ? "bg-gray-900 border-gray-700" : "bg-white border-gray-200"}` }, /* @__PURE__ */ React.createElement(
        "input",
        {
          type: "checkbox",
          checked: !!securityUserComposer.is_enabled,
          onChange: (event) => setSecurityUserComposer((current) => ({ ...current, is_enabled: event.target.checked })),
          className: "h-4 w-4"
        }
      ), /* @__PURE__ */ React.createElement("span", { className: "text-sm text-gray-700" }, "User enabled")), /* @__PURE__ */ React.createElement("label", { className: `flex items-center gap-3 rounded-lg border px-3 py-2 ${isDarkTheme ? "bg-gray-900 border-gray-700" : "bg-white border-gray-200"}` }, /* @__PURE__ */ React.createElement(
        "input",
        {
          type: "checkbox",
          checked: !!securityUserComposer.require_password_reset,
          onChange: (event) => setSecurityUserComposer((current) => ({ ...current, require_password_reset: event.target.checked })),
          className: "h-4 w-4"
        }
      ), /* @__PURE__ */ React.createElement("span", { className: "text-sm text-gray-700" }, "Force reset on first login"))), /* @__PURE__ */ React.createElement("div", { className: "mt-4 flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between" }, /* @__PURE__ */ React.createElement("div", { className: "text-xs text-gray-500" }, "Create the user first. You can change assignments and password settings below."), /* @__PURE__ */ React.createElement("div", { className: "flex gap-2" }, /* @__PURE__ */ React.createElement(
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
      )))), securityUsersState.loading ? /* @__PURE__ */ React.createElement("div", { className: "flex items-center justify-center py-10 text-sm text-gray-500" }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-spinner fa-spin mr-2" }), "Loading local users...") : securityUsersState.error ? /* @__PURE__ */ React.createElement("div", { className: `rounded-lg border px-4 py-4 text-sm ${isDarkTheme ? "bg-gray-950 border-gray-700 text-red-300" : "bg-red-50 border-red-200 text-red-700"}` }, securityUsersState.error) : securityUsers.length === 0 ? /* @__PURE__ */ React.createElement("div", { className: `rounded-lg border px-4 py-8 text-center text-sm ${isDarkTheme ? "bg-gray-950 border-gray-700 text-gray-400" : "bg-gray-50 border-gray-200 text-gray-600"}` }, "No local users yet.") : /* @__PURE__ */ React.createElement("div", { className: "space-y-3 max-h-[30rem] overflow-y-auto pr-1" }, securityUsers.map((user) => {
        const draft = securityUserDrafts[user.id] || buildSecurityUserDraft(user);
        const isCurrentUser = currentUser && Number(currentUser.id) === Number(user.id);
        return /* @__PURE__ */ React.createElement("div", { key: `security-user-${user.id}`, className: `rounded-xl border p-4 ${isDarkTheme ? "bg-gray-950 border-gray-700" : "bg-gray-50 border-gray-200"}` }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between" }, /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("div", { className: "flex flex-wrap items-center gap-2" }, /* @__PURE__ */ React.createElement("h5", { className: "text-base font-semibold text-gray-900" }, user.username), /* @__PURE__ */ React.createElement("span", { className: `inline-flex items-center rounded-full px-2 py-0.5 text-xs font-semibold ${user.is_enabled ? "bg-emerald-50 text-gray-900" : "bg-amber-50 text-gray-900"}` }, user.is_enabled ? "enabled" : "disabled"), draft.require_password_reset && /* @__PURE__ */ React.createElement("span", { className: "inline-flex items-center rounded-full px-2 py-0.5 text-xs font-semibold bg-amber-50 text-gray-900" }, "reset required"), isCurrentUser && /* @__PURE__ */ React.createElement("span", { className: "inline-flex items-center rounded-full px-2 py-0.5 text-xs font-semibold bg-gray-100 text-gray-900" }, "current session")), /* @__PURE__ */ React.createElement("div", { className: "mt-2 text-xs text-gray-500" }, "Role: ", user.role || "unknown", " · ", "MCP assignment: ", user.mcp_config_name || "none", " · ", "Last login: ", user.last_login_at ? formatMissionDateTime(user.last_login_at) : "never")), /* @__PURE__ */ React.createElement(
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
            onChange: (event) => updateSecurityUserDraft(user.id, "role", event.target.value),
            className: "w-full px-3 py-2 border border-gray-300 rounded-md"
          },
          SECURITY_ROLE_OPTIONS.map((role) => /* @__PURE__ */ React.createElement("option", { key: `security-role-edit-${user.id}-${role}`, value: role }, role))
        )), /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("label", { className: "block text-sm font-medium text-gray-700 mb-1" }, "Assigned MCP Connection"), /* @__PURE__ */ React.createElement(
          "select",
          {
            value: draft.mcp_config_name,
            onChange: (event) => updateSecurityUserDraft(user.id, "mcp_config_name", event.target.value),
            className: "w-full px-3 py-2 border border-gray-300 rounded-md"
          },
          /* @__PURE__ */ React.createElement("option", { value: "" }, "No default assignment"),
          availableMCPAssignments.map((name) => /* @__PURE__ */ React.createElement("option", { key: `security-user-mcp-${user.id}-${name}`, value: name }, name))
        )), /* @__PURE__ */ React.createElement("label", { className: `flex items-center gap-3 rounded-lg border px-3 py-2 ${isDarkTheme ? "bg-gray-900 border-gray-700" : "bg-white border-gray-200"}` }, /* @__PURE__ */ React.createElement(
          "input",
          {
            type: "checkbox",
            checked: !!draft.is_enabled,
            onChange: (event) => updateSecurityUserDraft(user.id, "is_enabled", event.target.checked),
            className: "h-4 w-4"
          }
        ), /* @__PURE__ */ React.createElement("span", { className: "text-sm text-gray-700" }, "User enabled")), /* @__PURE__ */ React.createElement("label", { className: `flex items-center gap-3 rounded-lg border px-3 py-2 ${isDarkTheme ? "bg-gray-900 border-gray-700" : "bg-white border-gray-200"}` }, /* @__PURE__ */ React.createElement(
          "input",
          {
            type: "checkbox",
            checked: !!draft.require_password_reset,
            onChange: (event) => updateSecurityUserDraft(user.id, "require_password_reset", event.target.checked),
            className: "h-4 w-4"
          }
        ), /* @__PURE__ */ React.createElement("span", { className: "text-sm text-gray-700" }, "Force password reset on next login")), /* @__PURE__ */ React.createElement("div", { className: "md:col-span-2" }, /* @__PURE__ */ React.createElement("label", { className: "block text-sm font-medium text-gray-700 mb-1" }, "Set New Password (optional)"), /* @__PURE__ */ React.createElement(
          "input",
          {
            type: "password",
            value: draft.new_password,
            onChange: (event) => updateSecurityUserDraft(user.id, "new_password", event.target.value),
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
      }))), activeSettingsTab === "access" && /* @__PURE__ */ React.createElement("div", { className: `mt-6 rounded-xl border p-5 ${isDarkTheme ? "bg-gray-900 border-gray-700" : "bg-white border-gray-200"}` }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-col gap-3 md:flex-row md:items-start md:justify-between mb-4" }, /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("h4", { className: "text-base font-semibold text-gray-900" }, "Access Tokens"), /* @__PURE__ */ React.createElement("p", { className: "text-xs text-gray-500 mt-1" }, "Create, review, and revoke tokens for the external REST API and inbound MCP endpoint.")), /* @__PURE__ */ React.createElement(
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
      )), securityTokenReveal && /* @__PURE__ */ React.createElement("div", { className: `rounded-xl border p-4 mb-4 ${isDarkTheme ? "bg-gray-950 border-gray-700" : "bg-amber-50 border-gray-200"}` }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-col gap-3 md:flex-row md:items-start md:justify-between" }, /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("div", { className: "text-sm font-semibold text-gray-900" }, "One-time token reveal"), /* @__PURE__ */ React.createElement("div", { className: "mt-1 text-xs text-gray-500" }, "Copy this token now. You cannot see it again after you leave this panel.")), /* @__PURE__ */ React.createElement("div", { className: "flex gap-2" }, /* @__PURE__ */ React.createElement(
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
          onChange: (event) => setSecurityTokenComposer((current) => ({ ...current, name: event.target.value })),
          className: "w-full px-3 py-2 border border-gray-300 rounded-md",
          placeholder: "External RAG Reader"
        }
      )), /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("label", { className: "block text-sm font-medium text-gray-700 mb-1" }, "Token Type"), /* @__PURE__ */ React.createElement(
        "select",
        {
          value: securityTokenComposer.token_type,
          onChange: (event) => resetSecurityTokenComposer(event.target.value),
          className: "w-full px-3 py-2 border border-gray-300 rounded-md"
        },
        /* @__PURE__ */ React.createElement("option", { value: "external_api" }, "External REST API"),
        /* @__PURE__ */ React.createElement("option", { value: "inbound_mcp" }, "Inbound MCP")
      )), /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("label", { className: "block text-sm font-medium text-gray-700 mb-1" }, "Expires In (days)"), /* @__PURE__ */ React.createElement(
        "input",
        {
          type: "number",
          min: "1",
          value: securityTokenComposer.expires_in_days,
          onChange: (event) => setSecurityTokenComposer((current) => ({ ...current, expires_in_days: event.target.value })),
          className: "w-full px-3 py-2 border border-gray-300 rounded-md"
        }
      )), /* @__PURE__ */ React.createElement("div", { className: "md:col-span-2" }, /* @__PURE__ */ React.createElement("label", { className: "block text-sm font-medium text-gray-700 mb-1" }, "Owner (optional)"), /* @__PURE__ */ React.createElement(
        "select",
        {
          value: securityTokenComposer.owner_user_id,
          onChange: (event) => setSecurityTokenComposer((current) => ({ ...current, owner_user_id: event.target.value })),
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
      })))), /* @__PURE__ */ React.createElement("div", { className: "mt-4 flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between" }, /* @__PURE__ */ React.createElement("div", { className: "text-xs text-gray-500" }, "The token type and scopes decide what the token can access."), /* @__PURE__ */ React.createElement("div", { className: "flex gap-2" }, /* @__PURE__ */ React.createElement(
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
      )))), securityTokensState.loading ? /* @__PURE__ */ React.createElement("div", { className: "flex items-center justify-center py-10 text-sm text-gray-500" }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-spinner fa-spin mr-2" }), "Loading token inventory...") : securityTokensState.error ? /* @__PURE__ */ React.createElement("div", { className: `rounded-lg border px-4 py-4 text-sm ${isDarkTheme ? "bg-gray-950 border-gray-700 text-red-300" : "bg-red-50 border-red-200 text-red-700"}` }, securityTokensState.error) : securityTokens.length === 0 ? /* @__PURE__ */ React.createElement("div", { className: `rounded-lg border px-4 py-8 text-center text-sm ${isDarkTheme ? "bg-gray-950 border-gray-700 text-gray-400" : "bg-gray-50 border-gray-200 text-gray-600"}` }, "No tokens yet.") : /* @__PURE__ */ React.createElement("div", { className: "space-y-3 max-h-[30rem] overflow-y-auto pr-1" }, securityTokens.map((token) => {
        const isRevoked = !!token.revoked_at;
        return /* @__PURE__ */ React.createElement("div", { key: `security-token-${token.id}`, className: `rounded-xl border p-4 ${isDarkTheme ? "bg-gray-950 border-gray-700" : "bg-gray-50 border-gray-200"}` }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between" }, /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("div", { className: "flex flex-wrap items-center gap-2" }, /* @__PURE__ */ React.createElement("h5", { className: "text-base font-semibold text-gray-900" }, token.name), /* @__PURE__ */ React.createElement("span", { className: "inline-flex items-center rounded-full px-2 py-0.5 text-xs font-semibold bg-gray-100 text-gray-900" }, token.token_type), isRevoked && /* @__PURE__ */ React.createElement("span", { className: "inline-flex items-center rounded-full px-2 py-0.5 text-xs font-semibold bg-amber-50 text-gray-900" }, "revoked")), /* @__PURE__ */ React.createElement("div", { className: "mt-2 text-xs text-gray-500" }, "Prefix: ", token.token_prefix || "hidden", " · ", "Owner: ", token.owner_username || "service-managed", " · ", "Created by: ", token.created_by_username || "system")), /* @__PURE__ */ React.createElement("div", { className: "flex flex-wrap gap-2" }, !isRevoked && /* @__PURE__ */ React.createElement(
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
        ))), /* @__PURE__ */ React.createElement("div", { className: "mt-3 flex flex-wrap gap-2" }, (token.scopes || []).map((scope) => /* @__PURE__ */ React.createElement("span", { key: `token-scope-chip-${token.id}-${scope}`, className: `inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium ${isDarkTheme ? "bg-gray-900 border border-gray-700 text-gray-200" : "bg-white border border-gray-300 text-gray-700"}` }, scope))), /* @__PURE__ */ React.createElement("div", { className: "grid gap-2 mt-4 sm:grid-cols-2 xl:grid-cols-4 text-xs text-gray-500" }, /* @__PURE__ */ React.createElement("div", null, "Created: ", token.created_at ? formatMissionDateTime(token.created_at) : "Unknown"), /* @__PURE__ */ React.createElement("div", null, "Expires: ", token.expires_at ? formatMissionDateTime(token.expires_at) : "No expiry"), /* @__PURE__ */ React.createElement("div", null, "Last used: ", token.last_used_at ? formatMissionDateTime(token.last_used_at) : "Never"), /* @__PURE__ */ React.createElement("div", null, "Use count: ", token.use_count || 0)));
      })))));
    };
    const openConnectionModal = (event) => {
      const target = event == null ? void 0 : event.currentTarget;
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
    const REPORT_DISPLAY_NAMES = [
      ["v2_intelligence_blueprint_", "Full findings"],
      ["v2_insights_brief_", "Insights brief"],
      ["v2_operator_runbook_", "Operator runbook"],
      ["v2_developer_handoff_", "Developer handoff"],
      ["v2_ai_summary_", "AI summary"],
      ["ai_summary_", "AI summary"],
      ["summary_infographic_", "Summary infographic"],
      ["discovery_export_", "Discovery data export"],
      ["executive_summary_", "Executive summary"],
      ["detailed_discovery_", "Detailed discovery"],
      ["recommendations_", "Recommendations"],
      ["suggested_use_cases_", "Suggested use cases"],
      ["persona_playbooks_", "Role playbooks"],
      ["mcp_capabilities_", "MCP server tools"],
      ["implementation_guide_", "Implementation guide"],
      ["data_classification_", "Data classification"]
    ];
    const REPORT_NAME_ACRONYMS = /* @__PURE__ */ new Set(["ai", "api", "csv", "json", "kb", "mcp", "rag", "spl"]);
    const getReportDisplayName = (reportName) => {
      const name = String(reportName || "").trim();
      if (!name) return "Report";
      const known = REPORT_DISPLAY_NAMES.find(([prefix]) => name.startsWith(prefix));
      if (known) return known[1];
      const words = name.replace(/\.[a-z0-9]+$/i, "").replace(/_?[0-9]{8}_[0-9]{6}/g, "").replace(/^v2_/, "").replace(/[_-]+/g, " ").replace(/\s+/g, " ").trim().split(" ").map((word) => REPORT_NAME_ACRONYMS.has(word.toLowerCase()) ? word.toUpperCase() : word).join(" ");
      if (!words) return name;
      return words.charAt(0).toUpperCase() + words.slice(1);
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
    const newestReportGroupKeys = (() => {
      const newestTimestamp = (Array.isArray(reports) ? reports : []).map(getReportSessionTimestamp).filter(Boolean).sort().pop();
      if (!newestTimestamp) return {};
      const newestDate = parseTimestamp(newestTimestamp);
      const yearKey = `year_${newestDate.getFullYear()}`;
      const monthKey = `${yearKey}_month_${newestDate.getMonth()}`;
      return { year: yearKey, month: monthKey, day: `${monthKey}_day_${newestDate.getDate()}`, session: newestTimestamp };
    })();
    const isReportGroupExpanded = (expandedMap, key, level) => Object.prototype.hasOwnProperty.call(expandedMap, key) ? !!expandedMap[key] : key === newestReportGroupKeys[level];
    const toggleSession = (timestamp) => {
      setExpandedSessions((prev) => ({
        ...prev,
        [timestamp]: !isReportGroupExpanded(prev, timestamp, "session")
      }));
    };
    const toggleYear = (yearKey) => {
      setExpandedYears((prev) => ({
        ...prev,
        [yearKey]: !isReportGroupExpanded(prev, yearKey, "year")
      }));
    };
    const toggleMonth = (monthKey) => {
      setExpandedMonths((prev) => ({
        ...prev,
        [monthKey]: !isReportGroupExpanded(prev, monthKey, "month")
      }));
    };
    const toggleDay = (dayKey) => {
      setExpandedDays((prev) => ({
        ...prev,
        [dayKey]: !isReportGroupExpanded(prev, dayKey, "day")
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
            investigation_mode: investigationMode,
            mission: chatMission.trim()
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
          eyebrow: "Summary in progress",
          title: "Reconnect to the summary in progress?",
          summary: "A summary is already being created for this run. Reconnect to follow its progress, or come back later.",
          details: [
            `${(activeSummaryProgress == null ? void 0 : activeSummaryProgress.message) || "The summary is still being created."}`,
            `It keeps running in the background (process ${activeSummaryWorkerPid}) even if you close the summary.`,
            "To stop it, reconnect and select Stop Summary."
          ],
          confirmLabel: "Reconnect",
          cancelLabel: "Not Now"
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
          eyebrow: "Local AI model",
          title: "Create a summary with a local AI model?",
          summary: "This run has no saved summary yet. Creating one with a local model can take several minutes.",
          details: [
            "The AI model reads the reports, writes SPL queries, and builds the summary.",
            "Progress is shown step by step while it runs.",
            "Opening a summary that already exists skips this question, because no new AI work is needed."
          ],
          confirmLabel: "Create Summary",
          cancelLabel: "Cancel"
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
      if (typeof score !== "number") return "Not scored";
      if (score >= 85) return "Strong";
      if (score >= 70) return "Improving";
      if (score >= 50) return "At risk";
      return "Needs action now";
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
    const getQueryPriorityMeta = (priority) => {
      const level = String(priority || "").replace(/[^A-Za-z\s]/g, " ").trim().split(/\s+/)[0].toLowerCase();
      if (!level) return null;
      const label = `${level.charAt(0).toUpperCase()}${level.slice(1)} priority`;
      if (level === "critical" || level === "high") {
        return { label, className: isDarkTheme ? "bg-red-950 text-red-200 border-red-800" : "bg-red-50 text-red-800 border-red-200" };
      }
      if (level === "medium") {
        return { label, className: isDarkTheme ? "bg-amber-950 text-amber-200 border-amber-800" : "bg-amber-50 text-amber-800 border-amber-200" };
      }
      return { label, className: isDarkTheme ? "bg-gray-800 text-gray-200 border-gray-700" : "bg-gray-100 text-gray-700 border-gray-200" };
    };
    const getVerificationStatusLabel = (status) => {
      if (status === "success") return "Passed";
      if (status === "partial") return "Partly passed";
      if (status === "failed") return "Failed";
      return "Could not run";
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
        sourceLabel: "From Context Explorer",
        description: `Showing searches related to ${searchAnchor}.`,
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
        sourceLabel: "From Top Risks",
        description: `Showing searches that check this ${(risk == null ? void 0 : risk.domain) || "general"} risk.`,
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
        sourceLabel: "From Admin Tasks",
        description: `Showing searches for ${(task == null ? void 0 : task.category) || "General"} tasks.`,
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
        successMessage: (action == null ? void 0 : action.successMessage) || "Saved to the Knowledge Base.",
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
        sourceLabel: queryFocus2.sourceLabel || "From Context Explorer",
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
    const nextLoopSection = getSummarySection(summarySections, "Next Check") || getSummarySection(summarySections, "Recursive Next Loop");
    const readinessScore = typeof ((_O = summaryData == null ? void 0 : summaryData.readiness_score) != null ? _O : (_N = summaryData == null ? void 0 : summaryData.v2_context) == null ? void 0 : _N.readiness_score) === "number" ? (_Q = summaryData == null ? void 0 : summaryData.readiness_score) != null ? _Q : (_P = summaryData == null ? void 0 : summaryData.v2_context) == null ? void 0 : _P.readiness_score : null;
    const coverageGapItems = Array.isArray(summaryData == null ? void 0 : summaryData.coverage_gaps) ? summaryData.coverage_gaps.filter((gap) => gap && typeof gap === "object" && gap.gap).slice(0, 3) : [];
    const trendDomainEntries = ((_R = summaryData == null ? void 0 : summaryData.trend_signals) == null ? void 0 : _R.recommendation_by_domain) ? Object.entries(summaryData.trend_signals.recommendation_by_domain).filter(([, count]) => Number(count) > 0) : [];
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
      { key: "ai_finding", label: "AI-generated", count: querySourceCounts.ai_finding, activeClass: "bg-indigo-600 text-white" },
      { key: "context_engine", label: "Environment-based", count: querySourceCounts.context_engine, activeClass: "bg-indigo-600 text-white" },
      { key: "template", label: "Template-based", count: querySourceCounts.template, activeClass: "bg-indigo-600 text-white" }
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
      { key: "open", label: "Open", count: openTaskCount, activeClass: "bg-indigo-600 text-white" },
      { key: "in-progress", label: "In Progress", count: inProgressTaskCount, activeClass: "bg-indigo-600 text-white" },
      { key: "completed", label: "Completed", count: completedTaskCount, activeClass: "bg-indigo-600 text-white" },
      ...Object.entries(taskCategoryCounts).sort((left, right) => right[1] - left[1] || left[0].localeCompare(right[0])).map(([category, count]) => ({
        key: `category:${category}`,
        label: category,
        count,
        activeClass: "bg-indigo-600 text-white"
      }))
    ].filter((option) => option.key === "all" || option.count > 0);
    const activeTaskFilterKey = taskFilterOptions.some((option) => option.key === taskFilter) ? taskFilter : "all";
    const activeTaskFilterLabel = ((_S = taskFilterOptions.find((option) => option.key === activeTaskFilterKey)) == null ? void 0 : _S.label) || "All";
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
      var _a2;
      const { type, data } = message;
      switch (type) {
        case "banner":
          return /* @__PURE__ */ React.createElement("div", { className: "bg-indigo-700 text-white p-6 rounded-lg fade-in" }, /* @__PURE__ */ React.createElement("h1", { className: "text-2xl font-bold" }, data.title), /* @__PURE__ */ React.createElement("p", { className: "text-indigo-50" }, data.subtitle), /* @__PURE__ */ React.createElement("p", { className: "text-sm text-indigo-100 mt-2" }, "Started ", formatMissionDateTime(data.start_time_iso || data.start_time, data.start_time || "at an unknown time")));
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
          return /* @__PURE__ */ React.createElement("div", { className: `p-4 rounded-lg fade-in border ${isDarkTheme ? "bg-slate-800 border-slate-700" : "bg-blue-50 border-blue-200"}` }, /* @__PURE__ */ React.createElement("h3", { className: `font-semibold mb-2 ${isDarkTheme ? "text-blue-200" : "text-blue-900"}` }, "Environment overview"), /* @__PURE__ */ React.createElement("div", { className: `grid grid-cols-2 gap-2 text-sm ${isDarkTheme ? "text-slate-200" : "text-slate-800"}` }, /* @__PURE__ */ React.createElement("div", { className: isDarkTheme ? "bg-slate-700 rounded px-2 py-1" : "" }, "Indexes: ", data.total_indexes), /* @__PURE__ */ React.createElement("div", { className: isDarkTheme ? "bg-slate-700 rounded px-2 py-1" : "" }, "Sourcetypes: ", data.total_sourcetypes), /* @__PURE__ */ React.createElement("div", { className: isDarkTheme ? "bg-slate-700 rounded px-2 py-1" : "" }, "Data Volume: ", data.data_volume_24h), /* @__PURE__ */ React.createElement("div", { className: isDarkTheme ? "bg-slate-700 rounded px-2 py-1" : "" }, "Active Sources: ", data.active_sources)));
        case "rate_limit":
          if (data.event === "rate_limit_start") {
            return /* @__PURE__ */ React.createElement("div", { className: `border p-4 rounded-lg fade-in ${isDarkTheme ? "bg-amber-950 border-amber-700" : "bg-yellow-50 border-yellow-200"}` }, /* @__PURE__ */ React.createElement("div", { className: `flex items-center ${isDarkTheme ? "text-amber-200" : "text-yellow-700"}` }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-clock mr-2" }), /* @__PURE__ */ React.createElement("span", null, "The AI provider is limiting requests. Waiting ", data.details.delay, " seconds (try ", data.details.retry_count, " of ", data.details.max_retries, ").")));
          } else if (data.event === "rate_limit_countdown") {
            return /* @__PURE__ */ React.createElement("div", { className: `p-3 rounded border ${isDarkTheme ? "bg-amber-950 border-amber-700" : "bg-yellow-50 border-yellow-200"}` }, /* @__PURE__ */ React.createElement("div", { className: `flex items-center justify-between text-sm ${isDarkTheme ? "text-amber-200" : "text-yellow-700"}` }, /* @__PURE__ */ React.createElement("span", null, "Waiting"), /* @__PURE__ */ React.createElement("span", null, Math.ceil(data.details.remaining_seconds), " seconds left")), /* @__PURE__ */ React.createElement("div", { className: `w-full rounded-full h-2 mt-2 ${isDarkTheme ? "bg-amber-900" : "bg-yellow-200"}` }, /* @__PURE__ */ React.createElement(
              "div",
              {
                className: `h-2 rounded-full progress-bar ${isDarkTheme ? "bg-amber-400" : "bg-yellow-500"}`,
                style: { width: `${data.details.percentage}%` }
              }
            )));
          } else if (data.event === "rate_limit_complete") {
            return /* @__PURE__ */ React.createElement("div", { className: `flex items-center p-2 rounded fade-in ${isDarkTheme ? "text-emerald-300 bg-emerald-950" : "text-green-700 bg-green-50"}` }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-check-circle mr-2" }), /* @__PURE__ */ React.createElement("span", null, "Done waiting. Continuing."));
          }
          break;
        case "completion":
          return /* @__PURE__ */ React.createElement("div", { className: `border p-4 rounded-lg fade-in ${isDarkTheme ? "bg-emerald-950 border-emerald-700" : "bg-green-50 border-green-200"}` }, /* @__PURE__ */ React.createElement("div", { className: `flex items-center mb-2 ${isDarkTheme ? "text-emerald-200" : "text-green-700"}` }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-trophy mr-2" }), /* @__PURE__ */ React.createElement("span", { className: "font-semibold" }, "Discovery finished")), /* @__PURE__ */ React.createElement("p", { className: `text-sm ${isDarkTheme ? "text-emerald-300" : "text-green-600"}` }, "Took ", formatDurationWords((_a2 = data.duration_seconds) != null ? _a2 : data.duration) || "an unknown time"), /* @__PURE__ */ React.createElement("p", { className: `text-sm ${isDarkTheme ? "text-emerald-300" : "text-green-600"}` }, countLabel(Number.isFinite(Number(data.report_count)) ? Number(data.report_count) : Array.isArray(data.report_paths) ? data.report_paths.length : 0, "report"), " saved"));
        default:
          return /* @__PURE__ */ React.createElement("div", { className: `fade-in ${isDarkTheme ? "text-gray-300" : "text-gray-600"}` }, /* @__PURE__ */ React.createElement("pre", { className: `text-xs p-2 rounded ${isDarkTheme ? "bg-gray-800 border border-gray-700" : "bg-gray-50 border border-gray-200"}` }, JSON.stringify(data, null, 2)));
      }
    };
    const summaryCardClass = isDarkTheme ? "bg-gray-950 border-gray-800" : "bg-white border-gray-200";
    const summaryInsetClass = isDarkTheme ? "bg-slate-900 border-slate-800" : "bg-gray-50 border-gray-200";
    const summaryLabelClass = isDarkTheme ? "text-gray-400" : "text-gray-600";
    const summaryCodeClass = isDarkTheme ? "bg-gray-950 border-gray-700 text-gray-100" : "bg-gray-50 border-gray-200 text-gray-900";
    const summaryPillClass = `inline-flex items-center rounded-full border px-2 py-0.5 text-xs font-medium ${isDarkTheme ? "bg-gray-800 text-gray-200 border-gray-700" : "bg-gray-100 text-gray-700 border-gray-200"}`;
    const summaryButtonClass = `inline-flex items-center justify-center gap-1.5 rounded-md border px-3 py-1.5 text-sm font-medium transition-colors ${secondaryButtonClass}`;
    const formatSummaryLevel = (value, fallback = "") => {
      const text = String(value || fallback || "").trim();
      return text ? `${text.charAt(0).toUpperCase()}${text.slice(1).toLowerCase()}` : "";
    };
    const renderExecutiveControlSummary = () => {
      var _a2, _b2, _c2, _d2, _e2, _f2, _g2, _h2, _i2, _j2, _k2, _l2, _m2, _n2, _o2, _p2, _q2, _r2, _s2, _t2, _u2, _v2, _w2;
      const narrativeParagraphs = ((_a2 = executiveNarrativeSection == null ? void 0 : executiveNarrativeSection.paragraphs) == null ? void 0 : _a2.length) ? executiveNarrativeSection.paragraphs.slice(1, 4) : summaryData.ai_summary ? [summaryData.ai_summary] : [];
      const hasTrendStory = !!trendStorySection && (trendStorySection.paragraphs.length > 0 || trendStorySection.items.length > 0);
      const summaryIconClass = isDarkTheme ? "text-indigo-300" : "text-indigo-600";
      return /* @__PURE__ */ React.createElement(React.Fragment, null, /* @__PURE__ */ React.createElement("div", { className: `border rounded-xl overflow-hidden shadow-sm ${isDarkTheme ? "bg-gray-900 border-gray-700" : "bg-white border-gray-200"}` }, /* @__PURE__ */ React.createElement("div", { className: `p-6 md:p-7 border-b ${isDarkTheme ? "border-gray-700" : "border-gray-200"}` }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-col gap-6 xl:flex-row xl:items-start xl:justify-between" }, /* @__PURE__ */ React.createElement("div", { className: "xl:max-w-3xl" }, /* @__PURE__ */ React.createElement("div", { className: `text-xs font-semibold uppercase tracking-wider ${isDarkTheme ? "text-indigo-300" : "text-indigo-700"}` }, "Executive Summary"), /* @__PURE__ */ React.createElement("h3", { className: `mt-2 text-2xl font-semibold ${isDarkTheme ? "text-gray-100" : "text-gray-900"}` }, "What this run found"), /* @__PURE__ */ React.createElement("p", { className: `mt-3 max-w-3xl text-sm leading-6 ${isDarkTheme ? "text-gray-300" : "text-gray-700"}` }, ((_b2 = executiveNarrativeSection == null ? void 0 : executiveNarrativeSection.paragraphs) == null ? void 0 : _b2[0]) || "No executive summary was recorded for this run.")), /* @__PURE__ */ React.createElement("div", { className: "grid grid-cols-2 gap-3 xl:w-[440px]" }, /* @__PURE__ */ React.createElement("div", { className: `rounded-lg border p-4 ${summaryCardClass}` }, /* @__PURE__ */ React.createElement("div", { className: `text-xs uppercase tracking-wide ${summaryLabelClass}` }, "Readiness"), /* @__PURE__ */ React.createElement("div", { className: `mt-2 text-2xl font-semibold ${isDarkTheme ? "text-gray-100" : "text-gray-900"}` }, readinessScore != null ? readinessScore : "N/A"), /* @__PURE__ */ React.createElement("div", { className: `mt-1 text-xs ${isDarkTheme ? "text-gray-400" : "text-gray-600"}` }, getReadinessLabel(readinessScore))), /* @__PURE__ */ React.createElement("div", { className: `rounded-lg border p-4 ${summaryCardClass}` }, /* @__PURE__ */ React.createElement("div", { className: `text-xs uppercase tracking-wide ${summaryLabelClass}` }, "Open Risks"), /* @__PURE__ */ React.createElement("div", { className: `mt-2 text-2xl font-semibold ${isDarkTheme ? "text-gray-100" : "text-gray-900"}` }, (_f2 = (_e2 = (_c2 = summaryData.risk_register) == null ? void 0 : _c2.length) != null ? _e2 : (_d2 = summaryData.v2_context) == null ? void 0 : _d2.risk_register) != null ? _f2 : 0), /* @__PURE__ */ React.createElement("div", { className: `mt-1 text-xs ${isDarkTheme ? "text-gray-400" : "text-gray-600"}` }, "Risks to address")), /* @__PURE__ */ React.createElement("div", { className: `rounded-lg border p-4 ${summaryCardClass}` }, /* @__PURE__ */ React.createElement("div", { className: `text-xs uppercase tracking-wide ${summaryLabelClass}` }, "Coverage Gaps"), /* @__PURE__ */ React.createElement("div", { className: `mt-2 text-2xl font-semibold ${isDarkTheme ? "text-gray-100" : "text-gray-900"}` }, (_j2 = (_i2 = (_g2 = summaryData.coverage_gaps) == null ? void 0 : _g2.length) != null ? _i2 : (_h2 = summaryData.v2_context) == null ? void 0 : _h2.coverage_gaps) != null ? _j2 : 0), /* @__PURE__ */ React.createElement("div", { className: `mt-1 text-xs ${isDarkTheme ? "text-gray-400" : "text-gray-600"}` }, "Missing or incomplete coverage")), /* @__PURE__ */ React.createElement("div", { className: `rounded-lg border p-4 ${summaryCardClass}` }, /* @__PURE__ */ React.createElement("div", { className: `text-xs uppercase tracking-wide ${summaryLabelClass}` }, "Admin Tasks"), /* @__PURE__ */ React.createElement("div", { className: `mt-2 text-2xl font-semibold ${isDarkTheme ? "text-gray-100" : "text-gray-900"}` }, ((_k2 = summaryData.admin_tasks) == null ? void 0 : _k2.length) || 0), /* @__PURE__ */ React.createElement("div", { className: `mt-1 text-xs ${isDarkTheme ? "text-gray-400" : "text-gray-600"}` }, "Ready to start"))))), /* @__PURE__ */ React.createElement("div", { className: "grid gap-6 p-6 xl:grid-cols-[minmax(0,1.55fr),minmax(320px,0.95fr)]" }, /* @__PURE__ */ React.createElement("div", { className: "space-y-6" }, (narrativeParagraphs.length > 0 || hasTrendStory) && /* @__PURE__ */ React.createElement("div", { className: `rounded-lg border p-5 ${isDarkTheme ? "bg-gray-950 border-gray-800" : "bg-gray-50 border-gray-200"}` }, /* @__PURE__ */ React.createElement("div", { className: "flex items-center gap-2 mb-3" }, /* @__PURE__ */ React.createElement("i", { className: `fas fa-brain ${summaryIconClass}`, "aria-hidden": "true" }), /* @__PURE__ */ React.createElement("h4", { className: `text-lg font-semibold ${isDarkTheme ? "text-gray-100" : "text-gray-900"}` }, "Details")), narrativeParagraphs.length > 0 && /* @__PURE__ */ React.createElement("div", { className: "space-y-3" }, narrativeParagraphs.map((paragraph, idx) => /* @__PURE__ */ React.createElement("p", { key: idx, className: `text-sm leading-6 ${isDarkTheme ? "text-gray-300" : "text-gray-700"}` }, paragraph))), hasTrendStory && /* @__PURE__ */ React.createElement("div", { className: `${narrativeParagraphs.length > 0 ? "mt-4 " : ""}rounded-lg border px-4 py-3 ${summaryCardClass}` }, /* @__PURE__ */ React.createElement("div", { className: `text-xs font-semibold uppercase tracking-wide ${summaryLabelClass}` }, "Trend"), /* @__PURE__ */ React.createElement("div", { className: "mt-2 space-y-2" }, (trendStorySection.paragraphs.length > 0 ? trendStorySection.paragraphs : trendStorySection.items).slice(0, 2).map((paragraph, idx) => /* @__PURE__ */ React.createElement("p", { key: idx, className: `text-sm leading-6 ${isDarkTheme ? "text-gray-300" : "text-gray-700"}` }, paragraph))))), /* @__PURE__ */ React.createElement("div", { className: "grid gap-4 lg:grid-cols-2" }, /* @__PURE__ */ React.createElement("div", { className: `rounded-lg border p-5 ${isDarkTheme ? "bg-gray-950 border-gray-800" : "bg-white border-gray-200"}` }, /* @__PURE__ */ React.createElement("div", { className: "flex items-center gap-2 mb-3" }, /* @__PURE__ */ React.createElement("i", { className: `fas fa-bullseye ${summaryIconClass}`, "aria-hidden": "true" }), /* @__PURE__ */ React.createElement("h4", { className: `text-lg font-semibold ${isDarkTheme ? "text-gray-100" : "text-gray-900"}` }, "Priority Actions")), /* @__PURE__ */ React.createElement("ol", { className: "space-y-3" }, (((_l2 = priorityActionsSection == null ? void 0 : priorityActionsSection.items) == null ? void 0 : _l2.length) ? priorityActionsSection.items : ["This summary lists no priority actions."]).slice(0, 3).map((item, idx) => /* @__PURE__ */ React.createElement("li", { key: idx, className: `flex items-start gap-3 text-sm ${isDarkTheme ? "text-gray-300" : "text-gray-700"}` }, /* @__PURE__ */ React.createElement("span", { className: `mt-0.5 inline-flex h-6 w-6 flex-shrink-0 items-center justify-center rounded-full text-xs font-bold ${isDarkTheme ? "bg-indigo-950 text-indigo-200" : "bg-indigo-50 text-indigo-700"}` }, idx + 1), /* @__PURE__ */ React.createElement("span", { className: "leading-6" }, item))))), /* @__PURE__ */ React.createElement("div", { className: `rounded-lg border p-5 ${isDarkTheme ? "bg-gray-950 border-gray-800" : "bg-white border-gray-200"}` }, /* @__PURE__ */ React.createElement("div", { className: "flex items-center gap-2 mb-3" }, /* @__PURE__ */ React.createElement("i", { className: `fas fa-bolt ${summaryIconClass}`, "aria-hidden": "true" }), /* @__PURE__ */ React.createElement("h4", { className: `text-lg font-semibold ${isDarkTheme ? "text-gray-100" : "text-gray-900"}` }, "Quick Wins")), /* @__PURE__ */ React.createElement("ul", { className: "space-y-3" }, (((_m2 = quickWinsSection == null ? void 0 : quickWinsSection.items) == null ? void 0 : _m2.length) ? quickWinsSection.items : ["This summary lists no quick wins."]).slice(0, 3).map((item, idx) => /* @__PURE__ */ React.createElement("li", { key: idx, className: `flex items-start gap-3 text-sm ${isDarkTheme ? "text-gray-300" : "text-gray-700"}` }, /* @__PURE__ */ React.createElement("i", { className: `fas fa-check-circle mt-1 ${isDarkTheme ? "text-green-300" : "text-green-700"}`, "aria-hidden": "true" }), /* @__PURE__ */ React.createElement("span", { className: "leading-6" }, item))))))), /* @__PURE__ */ React.createElement("div", { className: "space-y-6" }, /* @__PURE__ */ React.createElement("div", { className: `rounded-lg border p-5 ${isDarkTheme ? "bg-gray-950 border-gray-800" : "bg-white border-gray-200"}` }, /* @__PURE__ */ React.createElement("div", { className: "flex items-center gap-2 mb-3" }, /* @__PURE__ */ React.createElement("i", { className: `fas fa-chart-bar ${summaryIconClass}`, "aria-hidden": "true" }), /* @__PURE__ */ React.createElement("h4", { className: `text-lg font-semibold ${isDarkTheme ? "text-gray-100" : "text-gray-900"}` }, "By the Numbers")), /* @__PURE__ */ React.createElement("dl", { className: `divide-y text-sm ${isDarkTheme ? "divide-gray-800" : "divide-gray-200"}` }, [
        ["Evidence steps", (_o2 = (_n2 = summaryData.trend_signals) == null ? void 0 : _n2.evidence_steps) != null ? _o2 : 0],
        ["High-priority recommendations", (_q2 = (_p2 = summaryData.trend_signals) == null ? void 0 : _p2.high_priority_recommendations) != null ? _q2 : 0],
        ["Use case categories", ((_s2 = (_r2 = summaryData.stats) == null ? void 0 : _r2.categories) == null ? void 0 : _s2.length) || 0],
        ["Data sources to classify", ((_t2 = summaryData.stats) == null ? void 0 : _t2.unknown_items) || 0]
      ].map(([label, value]) => /* @__PURE__ */ React.createElement("div", { key: label, className: "flex items-center justify-between gap-3 py-2" }, /* @__PURE__ */ React.createElement("dt", { className: summaryLabelClass }, label), /* @__PURE__ */ React.createElement("dd", { className: `font-semibold tabular-nums ${headingClass}` }, value)))), trendDomainEntries.length > 0 && /* @__PURE__ */ React.createElement("div", { className: "mt-4" }, /* @__PURE__ */ React.createElement("div", { className: `text-xs font-semibold uppercase tracking-wide ${summaryLabelClass}` }, "Recommendations by Area"), /* @__PURE__ */ React.createElement("div", { className: "mt-2 flex flex-wrap gap-2" }, trendDomainEntries.map(([domain, count]) => /* @__PURE__ */ React.createElement("span", { key: domain, className: `inline-flex items-center rounded-full border px-2.5 py-1 text-xs ${isDarkTheme ? "bg-gray-900 border-gray-700 text-gray-200" : "bg-gray-50 border-gray-200 text-gray-700"}` }, /* @__PURE__ */ React.createElement("span", { className: "font-semibold mr-2 capitalize" }, domain.replace(/_/g, " ")), /* @__PURE__ */ React.createElement("span", null, count))))), (((_u2 = riskAreasSection == null ? void 0 : riskAreasSection.items) == null ? void 0 : _u2.length) > 0 || coverageGapItems.length > 0) && /* @__PURE__ */ React.createElement("div", { className: `mt-4 rounded-lg border px-4 py-3 ${summaryInsetClass}` }, /* @__PURE__ */ React.createElement("div", { className: `text-xs font-semibold uppercase tracking-wide ${summaryLabelClass}` }, "Main Risks"), /* @__PURE__ */ React.createElement("ul", { className: "mt-2 space-y-2" }, (((_v2 = riskAreasSection == null ? void 0 : riskAreasSection.items) == null ? void 0 : _v2.length) ? riskAreasSection.items : coverageGapItems.map((gap) => gap.gap)).slice(0, 3).map((item, idx) => /* @__PURE__ */ React.createElement("li", { key: idx, className: `text-sm leading-6 ${isDarkTheme ? "text-gray-300" : "text-gray-700"}` }, item))))), /* @__PURE__ */ React.createElement("div", { className: `rounded-lg border p-5 ${isDarkTheme ? "bg-gray-950 border-gray-800" : "bg-white border-gray-200"}` }, /* @__PURE__ */ React.createElement("div", { className: "flex items-center gap-2 mb-3" }, /* @__PURE__ */ React.createElement("i", { className: `fas fa-sync-alt ${summaryIconClass}`, "aria-hidden": "true" }), /* @__PURE__ */ React.createElement("h4", { className: `text-lg font-semibold ${isDarkTheme ? "text-gray-100" : "text-gray-900"}` }, "Next Check")), /* @__PURE__ */ React.createElement("ul", { className: "space-y-3" }, (((_w2 = nextLoopSection == null ? void 0 : nextLoopSection.items) == null ? void 0 : _w2.length) ? nextLoopSection.items : ["This summary does not say when to check again."]).slice(0, 5).map((item, idx) => /* @__PURE__ */ React.createElement("li", { key: idx, className: `flex items-start gap-3 text-sm ${isDarkTheme ? "text-gray-300" : "text-gray-700"}` }, /* @__PURE__ */ React.createElement("i", { className: `fas fa-arrow-rotate-right mt-1 ${summaryLabelClass}`, "aria-hidden": "true" }), /* @__PURE__ */ React.createElement("span", { className: "leading-6" }, item)))), summaryData.recursive_investigations && summaryData.recursive_investigations.length > 0 && /* @__PURE__ */ React.createElement("div", { className: "mt-4 space-y-2" }, summaryData.recursive_investigations.slice(0, 2).map((loop, idx) => /* @__PURE__ */ React.createElement("div", { key: idx, className: `rounded-lg border px-3 py-3 ${summaryInsetClass}` }, /* @__PURE__ */ React.createElement("div", { className: `text-sm font-semibold ${isDarkTheme ? "text-gray-100" : "text-gray-900"}` }, loop.loop || `Check ${idx + 1}`), loop.next_iteration_trigger && /* @__PURE__ */ React.createElement("div", { className: `mt-1 text-xs ${summaryLabelClass}` }, /* @__PURE__ */ React.createElement("strong", null, "Trigger:"), " ", loop.next_iteration_trigger)))))))), summaryData.risk_register && summaryData.risk_register.length > 0 && /* @__PURE__ */ React.createElement("div", { className: `${summaryCardClass} border rounded-lg p-5` }, /* @__PURE__ */ React.createElement("div", { className: "mb-4" }, /* @__PURE__ */ React.createElement("h3", { className: `text-lg font-semibold flex items-center ${headingClass}` }, /* @__PURE__ */ React.createElement("i", { className: `fas fa-shield-alt mr-2 ${isDarkTheme ? "text-red-300" : "text-red-600"}`, "aria-hidden": "true" }), "Top Risks", /* @__PURE__ */ React.createElement("span", { className: `ml-2 text-sm font-normal ${summaryLabelClass}` }, "(", Math.min(summaryData.risk_register.length, 6), ")")), /* @__PURE__ */ React.createElement("p", { className: `mt-1 text-sm ${mutedTextClass}` }, "The gaps most likely to cause outages, blind spots, or lost confidence.")), /* @__PURE__ */ React.createElement("ul", { className: "space-y-3" }, summaryData.risk_register.slice(0, 6).map((risk, idx) => {
        const severityMeta = getQueryPriorityMeta(risk.severity || "medium");
        const riskDomain = String(risk.domain || "").replace(/_/g, " ").trim();
        return /* @__PURE__ */ React.createElement("li", { key: idx, className: `${summaryInsetClass} border rounded-lg p-4` }, /* @__PURE__ */ React.createElement("div", { className: "flex items-center gap-2 mb-1 flex-wrap" }, /* @__PURE__ */ React.createElement("span", { className: `inline-flex items-center rounded-full border px-2 py-0.5 text-xs font-semibold ${severityMeta.className}` }, formatSummaryLevel(risk.severity, "medium"), " risk"), riskDomain && /* @__PURE__ */ React.createElement("span", { className: `text-xs capitalize ${summaryLabelClass}` }, riskDomain)), /* @__PURE__ */ React.createElement("p", { className: `font-semibold ${headingClass}` }, risk.risk || "Unnamed risk"), risk.impact && /* @__PURE__ */ React.createElement("p", { className: `text-sm mt-1 leading-6 ${mutedTextClass}` }, risk.impact), /* @__PURE__ */ React.createElement("div", { className: "mt-3 flex flex-wrap gap-2" }, /* @__PURE__ */ React.createElement(
          "button",
          {
            type: "button",
            onClick: () => focusRiskControlPath(risk),
            className: summaryButtonClass
          },
          "Show Related Tasks"
        ), /* @__PURE__ */ React.createElement(
          "button",
          {
            type: "button",
            onClick: () => focusQueriesForRisk(risk),
            className: summaryButtonClass
          },
          "Show Related Searches"
        ), /* @__PURE__ */ React.createElement(
          "button",
          {
            type: "button",
            onClick: () => launchChatInvestigation(
              buildRiskInvestigationPrompt(risk),
              { freshContext: true }
            ),
            className: summaryButtonClass
          },
          "Investigate in Chat"
        )));
      }))), unknownDataItems.length > 0 && /* @__PURE__ */ React.createElement("div", { className: `${summaryCardClass} border rounded-lg p-5` }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-col gap-4 md:flex-row md:items-start md:justify-between" }, /* @__PURE__ */ React.createElement("div", { className: "max-w-3xl" }, /* @__PURE__ */ React.createElement("h3", { className: `text-lg font-semibold flex items-center ${headingClass}` }, /* @__PURE__ */ React.createElement("i", { className: `fas fa-layer-group mr-2 ${summaryIconClass}`, "aria-hidden": "true" }), "Classify Unclear Data Sources", /* @__PURE__ */ React.createElement("span", { className: `ml-2 text-sm font-normal ${summaryLabelClass}` }, "(", unknownDataItems.length, ")")), /* @__PURE__ */ React.createElement("p", { className: `text-sm mt-1 leading-6 ${mutedTextClass}` }, "Discovery could not tell what these data sources are for. Decide who owns each one, whether it matters, and whether it needs monitoring.")), unknownDataItems.length > 4 && /* @__PURE__ */ React.createElement(
        "button",
        {
          type: "button",
          onClick: () => setShowAllUnknownData((current) => !current),
          className: `${summaryButtonClass} flex-shrink-0`
        },
        showAllUnknownData ? "Show Fewer" : `Show All ${unknownDataItems.length}`
      )), /* @__PURE__ */ React.createElement("div", { className: "mt-5 grid gap-4 lg:grid-cols-2" }, visibleUnknownData.map((item, idx) => {
        var _a3, _b3;
        return /* @__PURE__ */ React.createElement("div", { key: `${item.name || "unknown"}-${idx}`, className: `${summaryInsetClass} border rounded-lg p-4` }, /* @__PURE__ */ React.createElement("div", { className: "flex items-start justify-between gap-3" }, /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("div", { className: "flex flex-wrap items-center gap-2 mb-2" }, /* @__PURE__ */ React.createElement("span", { className: summaryPillClass }, item.type === "index" ? "Index" : "Sourcetype"), ((_a3 = item.context) == null ? void 0 : _a3.volume_category) && /* @__PURE__ */ React.createElement("span", { className: summaryPillClass }, formatVolumeCategory(item.context.volume_category), " volume"), ((_b3 = item.context) == null ? void 0 : _b3.has_significant_data) && /* @__PURE__ */ React.createElement("span", { className: summaryPillClass }, "Has significant data")), /* @__PURE__ */ React.createElement("h4", { className: `text-base font-semibold ${isDarkTheme ? "text-gray-100" : "text-gray-900"}` }, /* @__PURE__ */ React.createElement("code", { className: `px-2 py-0.5 rounded border text-sm ${summaryCodeClass}` }, item.name || "unknown")))), /* @__PURE__ */ React.createElement("p", { className: `mt-3 text-sm leading-6 ${mutedTextClass}` }, item.question || `Find out what ${item.name || "this data source"} is used for and who owns it.`), Array.isArray(item.suggestions) && item.suggestions.length > 0 && /* @__PURE__ */ React.createElement("div", { className: "mt-4" }, /* @__PURE__ */ React.createElement("div", { className: `text-xs font-semibold uppercase tracking-wide ${isDarkTheme ? "text-gray-400" : "text-gray-500"}` }, "Likely Types"), /* @__PURE__ */ React.createElement("div", { className: "mt-2 grid gap-2 sm:grid-cols-2" }, item.suggestions.slice(0, 2).map((suggestion, suggestionIdx) => /* @__PURE__ */ React.createElement("div", { key: `${suggestion.value || suggestion.label || "suggestion"}-${suggestionIdx}`, className: `${summaryCardClass} border rounded-lg px-3 py-2` }, /* @__PURE__ */ React.createElement("div", { className: `text-sm font-medium ${isDarkTheme ? "text-gray-100" : "text-gray-900"}` }, suggestion.label), suggestion.description && /* @__PURE__ */ React.createElement("div", { className: `text-xs mt-1 leading-5 ${isDarkTheme ? "text-gray-400" : "text-gray-600"}` }, suggestion.description))))), /* @__PURE__ */ React.createElement("div", { className: "mt-4 flex flex-wrap gap-2" }, /* @__PURE__ */ React.createElement(
          "button",
          {
            type: "button",
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
            className: summaryButtonClass
          },
          "Investigate in Chat"
        ), /* @__PURE__ */ React.createElement(
          "button",
          {
            type: "button",
            onClick: () => launchChatInvestigation(
              buildUnknownEntityValidationChatPrompt(item),
              {
                freshContext: true,
                investigationMode: "unknown_entity_context_builder"
              }
            ),
            className: summaryButtonClass
          },
          "Build Validation Query"
        )));
      })), unknownHiddenCount > 0 && !showAllUnknownData && /* @__PURE__ */ React.createElement("p", { className: `mt-4 text-sm text-center ${isDarkTheme ? "text-gray-400" : "text-gray-500"}` }, countLabel(unknownHiddenCount, "more item"), " not shown.")));
    };
    const discoveryShowsSummaryAction = isDiscoverySummaryReady && !!discoverySummarySession;
    const discoverySummaryIsSaved = !!discoverySummarySession && (Boolean(discoverySummarySession.hasSummary) || (Array.isArray(reports) ? reports : []).some((report) => isSummaryArtifact(report == null ? void 0 : report.name) && getReportSessionTimestamp(report) === discoverySummarySession.timestamp));
    const discoveryStatusFacts = (() => {
      if (isMissionDiscoveryActive) {
        return [
          { label: "Progress", value: `${discoveryProgressPercent}%` },
          discoveryPhaseEntries.length > 0 ? { label: "Stages done", value: `${discoveryCompletedPhaseCount} of ${discoveryPhaseEntries.length}` } : null,
          { label: "Elapsed", value: formatElapsedTime(elapsedTime) },
          { label: discoveryEtaMethodLabel, value: discoveryEtaLabel }
        ].filter(Boolean);
      }
      if (discoveryStatusNormalized === "completed") {
        return [{ label: "Finished", value: discoveryCompletedLabel }];
      }
      if (discoveryStatusNormalized === "error" || discoveryStatusNormalized === "aborted") {
        return [
          { label: "Stopped during", value: discoveryPhaseLeadTitle },
          { label: "Progress", value: `${discoveryProgressPercent}%` },
          { label: "Updated", value: discoveryUpdatedLabel }
        ];
      }
      return [];
    })();
    const renderMarkdownInline = (text, keyPrefix) => {
      const source = String(text || "");
      const parts = [];
      const pattern = /(`[^`]+`|\*\*[^*]+\*\*|\[[^\]]+\]\([^)\s]+\)|\*[^*\s][^*]*\*)/g;
      let lastIndex = 0;
      let tokenIndex = 0;
      let match;
      while ((match = pattern.exec(source)) !== null) {
        if (match.index > lastIndex) parts.push(source.slice(lastIndex, match.index));
        const token = match[0];
        const key = `${keyPrefix}-${tokenIndex}`;
        tokenIndex += 1;
        if (token.startsWith("`")) {
          parts.push(/* @__PURE__ */ React.createElement("code", { key, className: `rounded px-1 py-0.5 font-mono text-xs ${isDarkTheme ? "bg-gray-900 text-gray-100" : "bg-gray-100 text-gray-900"}` }, token.slice(1, -1)));
        } else if (token.startsWith("**")) {
          parts.push(/* @__PURE__ */ React.createElement("strong", { key, className: "font-semibold" }, token.slice(2, -2)));
        } else if (token.startsWith("[")) {
          const linkMatch = token.match(/^\[([^\]]+)\]\(([^)\s]+)\)$/);
          if (linkMatch && /^https?:\/\//i.test(linkMatch[2])) {
            parts.push(/* @__PURE__ */ React.createElement("a", { key, href: linkMatch[2], target: "_blank", rel: "noopener noreferrer", className: "ui-link" }, linkMatch[1]));
          } else {
            parts.push(linkMatch ? linkMatch[1] : token);
          }
        } else {
          parts.push(/* @__PURE__ */ React.createElement("em", { key }, token.slice(1, -1)));
        }
        lastIndex = match.index + token.length;
      }
      if (lastIndex < source.length) parts.push(source.slice(lastIndex));
      return parts;
    };
    const renderMarkdownDocument = (source) => {
      const lines = String(source || "").replace(/\r\n?/g, "\n").split("\n");
      const fencePattern = /^\s*```/;
      const headingPattern = /^(#{1,6})\s+(.*?)\s*#*\s*$/;
      const rulePattern = /^\s*([-*_])(\s*\1){2,}\s*$/;
      const quotePattern = /^\s*>\s?/;
      const listPattern = /^(\s*)([-*+]|\d+[.)])\s+(.*)$/;
      const tableRowPattern = /^\s*\|.*\|\s*$/;
      const tableDividerPattern = /^\s*\|?\s*:?-{3,}:?\s*(\|\s*:?-{3,}:?\s*)*\|?\s*$/;
      const splitTableRow = (row) => row.trim().replace(/^\|/, "").replace(/\|$/, "").split("|").map((cell) => cell.trim());
      const startsBlock = (line, nextLine) => fencePattern.test(line) || headingPattern.test(line) || rulePattern.test(line) || quotePattern.test(line) || listPattern.test(line) || tableRowPattern.test(line) && tableDividerPattern.test(nextLine || "");
      const bodyClass = isDarkTheme ? "text-gray-200" : "text-gray-800";
      const ruleClass = isDarkTheme ? "border-gray-700" : "border-gray-200";
      const headingSizes = ["text-xl", "text-lg", "text-base"];
      const blocks = [];
      let index = 0;
      while (index < lines.length) {
        const line = lines[index];
        const key = `md-${index}`;
        if (!line.trim()) {
          index += 1;
          continue;
        }
        if (fencePattern.test(line)) {
          const body = [];
          index += 1;
          while (index < lines.length && !fencePattern.test(lines[index])) {
            body.push(lines[index]);
            index += 1;
          }
          index += 1;
          blocks.push(
            /* @__PURE__ */ React.createElement("pre", { key, className: `overflow-x-auto rounded-lg border px-3 py-3 font-mono text-xs whitespace-pre-wrap ${isDarkTheme ? "bg-gray-950 border-gray-700 text-gray-100" : "bg-gray-50 border-gray-200 text-gray-900"}` }, body.join("\n"))
          );
          continue;
        }
        const heading = line.match(headingPattern);
        if (heading) {
          const level = Math.min(heading[1].length, 3);
          const HeadingTag = `h${level + 2}`;
          blocks.push(
            /* @__PURE__ */ React.createElement(HeadingTag, { key, className: `${level === 1 ? "pt-2" : "pt-3"} font-semibold ${headingSizes[level - 1]} ${headingClass}` }, renderMarkdownInline(heading[2], key))
          );
          index += 1;
          continue;
        }
        if (rulePattern.test(line)) {
          blocks.push(/* @__PURE__ */ React.createElement("hr", { key, className: ruleClass }));
          index += 1;
          continue;
        }
        if (quotePattern.test(line)) {
          const quoted = [];
          while (index < lines.length && quotePattern.test(lines[index])) {
            quoted.push(lines[index].replace(quotePattern, ""));
            index += 1;
          }
          blocks.push(
            /* @__PURE__ */ React.createElement("blockquote", { key, className: `border-l-4 pl-4 ${isDarkTheme ? "border-gray-600 text-gray-300" : "border-gray-300 text-gray-700"}` }, quoted.map((quotedLine, quotedIndex) => /* @__PURE__ */ React.createElement("p", { key: `${key}-${quotedIndex}` }, renderMarkdownInline(quotedLine, `${key}-${quotedIndex}`))))
          );
          continue;
        }
        if (tableRowPattern.test(line) && tableDividerPattern.test(lines[index + 1] || "")) {
          const headerCells = splitTableRow(line);
          const rows = [];
          index += 2;
          while (index < lines.length && tableRowPattern.test(lines[index])) {
            rows.push(splitTableRow(lines[index]));
            index += 1;
          }
          blocks.push(
            /* @__PURE__ */ React.createElement("div", { key, className: `overflow-x-auto rounded-lg border ${ruleClass}` }, /* @__PURE__ */ React.createElement("table", { className: "min-w-full text-left text-sm" }, /* @__PURE__ */ React.createElement("thead", { className: isDarkTheme ? "bg-gray-900" : "bg-gray-50" }, /* @__PURE__ */ React.createElement("tr", null, headerCells.map((cell, cellIndex) => /* @__PURE__ */ React.createElement("th", { key: `${key}-h-${cellIndex}`, scope: "col", className: `px-3 py-2 font-semibold ${headingClass}` }, renderMarkdownInline(cell, `${key}-h-${cellIndex}`))))), /* @__PURE__ */ React.createElement("tbody", { className: `divide-y ${isDarkTheme ? "divide-gray-700" : "divide-gray-200"}` }, rows.map((row, rowIndex) => /* @__PURE__ */ React.createElement("tr", { key: `${key}-r-${rowIndex}` }, row.map((cell, cellIndex) => /* @__PURE__ */ React.createElement("td", { key: `${key}-r-${rowIndex}-${cellIndex}`, className: `px-3 py-2 align-top ${bodyClass}` }, renderMarkdownInline(cell, `${key}-r-${rowIndex}-${cellIndex}`))))))))
          );
          continue;
        }
        const listMatch = line.match(listPattern);
        if (listMatch) {
          const ordered = /\d/.test(listMatch[2]);
          const items = [];
          while (index < lines.length) {
            const itemMatch = lines[index].match(listPattern);
            if (!itemMatch) break;
            const isNested = itemMatch[1].length >= 2 && items.length > 0;
            if (!isNested && /\d/.test(itemMatch[2]) !== ordered) break;
            const item = { text: itemMatch[3], ordered: /\d/.test(itemMatch[2]), children: [] };
            if (isNested) {
              items[items.length - 1].children.push(item);
            } else {
              items.push(item);
            }
            index += 1;
          }
          const ListTag = ordered ? "ol" : "ul";
          blocks.push(
            /* @__PURE__ */ React.createElement(ListTag, { key, className: `space-y-1 pl-5 ${ordered ? "list-decimal" : "list-disc"} ${bodyClass}` }, items.map((item, itemIndex) => /* @__PURE__ */ React.createElement("li", { key: `${key}-${itemIndex}` }, renderMarkdownInline(item.text, `${key}-${itemIndex}`), item.children.length > 0 && /* @__PURE__ */ React.createElement("ul", { className: "mt-1 space-y-1 pl-5", style: { listStyleType: "circle" } }, item.children.map((child, childIndex) => /* @__PURE__ */ React.createElement("li", { key: `${key}-${itemIndex}-${childIndex}` }, renderMarkdownInline(child.text, `${key}-${itemIndex}-${childIndex}`)))))))
          );
          continue;
        }
        const paragraph = [];
        while (index < lines.length && lines[index].trim() && (paragraph.length === 0 || !startsBlock(lines[index], lines[index + 1]))) {
          paragraph.push(lines[index].trim());
          index += 1;
        }
        blocks.push(
          /* @__PURE__ */ React.createElement("p", { key, className: bodyClass }, paragraph.map((paragraphLine, lineIndex) => /* @__PURE__ */ React.createElement(React.Fragment, { key: `${key}-${lineIndex}` }, lineIndex > 0 && /* @__PURE__ */ React.createElement("br", null), renderMarkdownInline(paragraphLine, `${key}-${lineIndex}`))))
        );
      }
      return blocks;
    };
    const isMarkdownReportName = (reportName) => /\.(md|markdown)$/i.test(String(reportName || ""));
    const openDiscoveryLibraryReport = (reportName) => {
      discoveryViewerScrollPendingRef.current = true;
      loadReport(reportName);
    };
    const renderReportViewerPanel = () => {
      var _a2, _b2;
      if (!hasSelectedReport) {
        return null;
      }
      const selectedReportType = String((selectedWorkspaceReportRecord == null ? void 0 : selectedWorkspaceReportRecord.type) || (reportContent == null ? void 0 : reportContent.type) || "file").toUpperCase();
      const selectedReportSize = (_b2 = (_a2 = selectedWorkspaceReportRecord == null ? void 0 : selectedWorkspaceReportRecord.size_bytes) != null ? _a2 : selectedWorkspaceReportRecord == null ? void 0 : selectedWorkspaceReportRecord.size) != null ? _b2 : null;
      const selectedReportModifiedAt = (selectedWorkspaceReportRecord == null ? void 0 : selectedWorkspaceReportRecord.modified_at) || (selectedWorkspaceReportRecord == null ? void 0 : selectedWorkspaceReportRecord.modified) || null;
      const reportSplQueries = Array.isArray(reportContent == null ? void 0 : reportContent.spl_queries) ? reportContent.spl_queries : [];
      const reportContextExcerpt = (reportContent == null ? void 0 : reportContent.type) === "text" ? String((reportContent == null ? void 0 : reportContent.content) || "").slice(0, 900) : "";
      return /* @__PURE__ */ React.createElement("div", { className: `rounded-lg shadow-sm border ${panelClass}` }, /* @__PURE__ */ React.createElement("div", { className: `p-6 border-b ${isDarkTheme ? "border-gray-700" : "border-gray-200"}` }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-col gap-4 xl:flex-row xl:items-start xl:justify-between" }, /* @__PURE__ */ React.createElement("div", { className: "min-w-0" }, /* @__PURE__ */ React.createElement("h2", { "data-testid": "report-viewer-title", className: `text-lg font-semibold ${headingClass}` }, getReportDisplayName(selectedReport)), /* @__PURE__ */ React.createElement("div", { className: `mt-1 text-xs break-all ${mutedTextClass}` }, selectedReport), /* @__PURE__ */ React.createElement("div", { className: `mt-2 flex flex-wrap items-center gap-2 text-xs ${mutedTextClass}` }, /* @__PURE__ */ React.createElement("span", { className: `inline-flex items-center rounded-full px-2.5 py-1 border ${isDarkTheme ? "bg-gray-900 border-gray-700 text-gray-200" : "bg-gray-50 border-gray-200 text-gray-700"}` }, selectedReportType), selectedReportSize != null && /* @__PURE__ */ React.createElement("span", null, (selectedReportSize / 1024).toFixed(1), " KB"), selectedReportModifiedAt && /* @__PURE__ */ React.createElement("span", null, formatMissionDateTime(selectedReportModifiedAt)))), /* @__PURE__ */ React.createElement("div", { className: "flex items-center gap-3" }, reportContent.type === "image" && /* @__PURE__ */ React.createElement(
        "button",
        {
          type: "button",
          onClick: () => setIsReportFullViewOpen(true),
          className: "ui-link"
        },
        /* @__PURE__ */ React.createElement("i", { className: "fas fa-expand mr-1" }),
        "Full View"
      ), /* @__PURE__ */ React.createElement(
        "button",
        {
          type: "button",
          onClick: () => downloadReportArtifact(selectedReport, reportContent),
          className: "ui-link"
        },
        /* @__PURE__ */ React.createElement("i", { className: "fas fa-download mr-1" }),
        "Export"
      )))), /* @__PURE__ */ React.createElement(
        "div",
        {
          className: "p-6 overflow-y-auto scroll-container",
          style: { height: `${reportViewerHeight}px` }
        },
        reportSplQueries.length > 0 && /* @__PURE__ */ React.createElement("div", { className: "mb-6 space-y-3", "data-testid": "report-viewer-spl-blocks" }, /* @__PURE__ */ React.createElement("div", { className: `rounded-lg border px-4 py-3 ${panelMutedClass}` }, /* @__PURE__ */ React.createElement("div", { className: `text-sm font-medium ${headingClass}` }, "Detected SPL Blocks"), /* @__PURE__ */ React.createElement("div", { className: `mt-1 text-xs ${subtextClass}` }, "Save SPL from this report to the Knowledge Base, open it in Splunk Web, or bring it into Chat.")), reportSplQueries.map((splQuery, splIndex) => /* @__PURE__ */ React.createElement("div", { key: `${selectedReport || "report"}-spl-${splIndex}`, "data-testid": "report-viewer-spl-card", className: `rounded-lg border px-4 py-3 ${isDarkTheme ? "bg-gray-900 border-gray-700" : "bg-white border-gray-300"}` }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-col gap-2 sm:flex-row sm:items-start sm:justify-between" }, /* @__PURE__ */ React.createElement("div", { className: `text-xs font-semibold uppercase tracking-wide ${mutedTextClass}` }, "SPL Block ", splIndex + 1), renderSplQueryActionButtons2(splQuery, {
          originKind: "report_viewer",
          originLabel: selectedReport || "Report Viewer",
          sourceLabel: selectedReport || "Report Viewer",
          contextExcerpt: reportContextExcerpt,
          className: "sm:justify-end"
        })), /* @__PURE__ */ React.createElement("pre", { className: `mt-3 max-h-40 overflow-auto rounded-lg border px-3 py-3 text-xs whitespace-pre-wrap font-mono ${isDarkTheme ? "bg-gray-950 border-gray-700 text-gray-100" : "bg-gray-50 border-gray-200 text-gray-900"}` }, splQuery)))),
        reportContent.type === "image" ? /* @__PURE__ */ React.createElement("div", { className: "h-full flex flex-col gap-4" }, /* @__PURE__ */ React.createElement("div", { className: `text-xs uppercase tracking-wider ${mutedTextClass}` }, isInfographicArtifact(selectedReport) ? "Summary infographic preview" : "Image preview"), /* @__PURE__ */ React.createElement("div", { className: `flex-1 min-h-[320px] rounded-2xl border p-4 ${isDarkTheme ? "bg-gray-950 border-gray-700" : "bg-slate-50 border-gray-200"}` }, /* @__PURE__ */ React.createElement(
          "img",
          {
            src: buildReportImageSrc(reportContent),
            alt: selectedReport,
            className: "h-full w-full object-contain rounded-xl shadow-lg"
          }
        ))) : reportContent.type === "json" ? /* @__PURE__ */ React.createElement("pre", { className: `text-sm whitespace-pre-wrap font-mono ${isDarkTheme ? "text-gray-100" : "text-gray-800"}` }, JSON.stringify(reportContent.content, null, 2)) : isMarkdownReportName(selectedReport) ? /* @__PURE__ */ React.createElement("div", { "data-testid": "report-viewer-markdown", className: "max-w-4xl space-y-3 text-sm leading-6 break-words" }, renderMarkdownDocument(reportContent.content)) : /* @__PURE__ */ React.createElement("pre", { className: `text-sm whitespace-pre-wrap font-sans leading-relaxed break-words ${isDarkTheme ? "text-gray-100" : "text-gray-800"}` }, reportContent.content)
      ), /* @__PURE__ */ React.createElement(
        "div",
        {
          className: `h-2 border-t cursor-ns-resize flex items-center justify-center group ${isDarkTheme ? "bg-gray-700 border-gray-600 hover:bg-gray-600" : "bg-gray-100 border-gray-200 hover:bg-gray-200"}`,
          onMouseDown: handleReportMouseDown
        },
        /* @__PURE__ */ React.createElement("div", { className: "w-12 h-1 bg-gray-400 rounded group-hover:bg-gray-500" })
      ));
    };
    const renderArtifactEmptyState = () => /* @__PURE__ */ React.createElement("div", { "data-testid": "report-viewer-empty", className: `rounded-lg border border-dashed px-6 py-5 text-sm ${isDarkTheme ? "border-gray-600 text-gray-300" : "border-gray-300 text-gray-600"}` }, reports.length > 0 ? "Choose a report from the library to read it here." : "Reports from your discovery runs show up in the library.");
    const renderDiscoveryReportLibraryPanel = () => /* @__PURE__ */ React.createElement("div", { className: `rounded-lg shadow-sm border overflow-hidden min-w-0 lg:flex lg:max-h-[calc(100vh-8.5rem)] lg:flex-col ${panelClass}` }, /* @__PURE__ */ React.createElement("div", { className: `p-6 border-b ${isDarkTheme ? "border-gray-700" : "border-gray-200"}` }, /* @__PURE__ */ React.createElement("div", { className: "flex justify-between items-center gap-3" }, /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("h2", { className: `text-lg font-medium ${headingClass}` }, "Report library"), /* @__PURE__ */ React.createElement("p", { className: `text-xs mt-1 ${mutedTextClass}` }, countLabel(sessionCatalog.length, "discovery run"))), /* @__PURE__ */ React.createElement(
      "button",
      {
        type: "button",
        onClick: refreshArtifactsWorkspace,
        className: "ui-link",
        "aria-label": "Refresh generated reports"
      },
      /* @__PURE__ */ React.createElement("i", { className: "fas fa-refresh" })
    ))), /* @__PURE__ */ React.createElement("div", { className: `divide-y overflow-x-hidden min-w-0 lg:flex-1 lg:overflow-y-auto ${isDarkTheme ? "divide-gray-700" : "divide-gray-200"}` }, reports.length === 0 ? /* @__PURE__ */ React.createElement("p", { className: `p-6 text-sm ${mutedTextClass}` }, "No reports yet. Select Run Discovery to create them.") : (() => {
      const hierarchy = groupReportsByHierarchy(reports);
      return Object.entries(hierarchy).sort((a, b) => b[1].year - a[1].year).map(([yearKey, yearData]) => /* @__PURE__ */ React.createElement("div", { key: yearKey }, yearData.visible && /* @__PURE__ */ React.createElement(
        "button",
        {
          type: "button",
          "data-testid": "discovery-report-year-toggle",
          className: `w-full p-3 border-b text-left font-semibold ${isDarkTheme ? "bg-gray-900 border-gray-700 hover:bg-gray-700" : "bg-gray-100 border-gray-200 hover:bg-gray-200"}`,
          onClick: () => toggleYear(yearKey),
          "aria-expanded": isReportGroupExpanded(expandedYears, yearKey, "year")
        },
        /* @__PURE__ */ React.createElement("div", { className: "flex items-center" }, /* @__PURE__ */ React.createElement("i", { className: `fas ${isReportGroupExpanded(expandedYears, yearKey, "year") ? "fa-chevron-down" : "fa-chevron-right"} mr-2 text-xs ${mutedTextClass}` }), /* @__PURE__ */ React.createElement("span", { className: `text-sm ${headingClass}` }, yearData.display))
      ), (!yearData.visible || isReportGroupExpanded(expandedYears, yearKey, "year")) && Object.entries(yearData.months).sort((a, b) => b[1].month - a[1].month).map(([monthKey, monthData]) => /* @__PURE__ */ React.createElement("div", { key: monthKey }, monthData.visible && /* @__PURE__ */ React.createElement(
        "button",
        {
          type: "button",
          "data-testid": "discovery-report-month-toggle",
          className: `w-full p-3 border-b text-left ${isDarkTheme ? "bg-gray-800 border-gray-700 hover:bg-gray-700" : "bg-gray-50 border-gray-200 hover:bg-gray-100"}`,
          onClick: () => toggleMonth(monthKey),
          style: { paddingLeft: yearData.visible ? "1.5rem" : "0.75rem" },
          "aria-expanded": isReportGroupExpanded(expandedMonths, monthKey, "month")
        },
        /* @__PURE__ */ React.createElement("div", { className: "flex items-center" }, /* @__PURE__ */ React.createElement("i", { className: `fas ${isReportGroupExpanded(expandedMonths, monthKey, "month") ? "fa-chevron-down" : "fa-chevron-right"} mr-2 text-xs ${mutedTextClass}` }), /* @__PURE__ */ React.createElement("span", { className: `text-sm font-medium ${headingClass}` }, monthData.display))
      ), (!monthData.visible || isReportGroupExpanded(expandedMonths, monthKey, "month")) && Object.entries(monthData.days).sort((a, b) => b[1].day - a[1].day).map(([dayKey, dayData]) => /* @__PURE__ */ React.createElement("div", { key: dayKey }, /* @__PURE__ */ React.createElement(
        "button",
        {
          type: "button",
          "data-testid": "discovery-report-day-toggle",
          className: `w-full p-3 border-b text-left ${dayData.isToday ? isDarkTheme ? "bg-green-900" : "bg-green-50" : isDarkTheme ? "bg-gray-800" : "bg-gray-50"} ${isDarkTheme ? "hover:bg-gray-700 border-gray-700" : "hover:bg-gray-100 border-gray-200"}`,
          onClick: () => toggleDay(dayKey),
          style: { paddingLeft: monthData.visible ? yearData.visible ? "3rem" : "1.5rem" : yearData.visible ? "1.5rem" : "0.75rem" },
          "aria-expanded": isReportGroupExpanded(expandedDays, dayKey, "day")
        },
        /* @__PURE__ */ React.createElement("div", { className: "flex items-center" }, /* @__PURE__ */ React.createElement("i", { className: `fas ${isReportGroupExpanded(expandedDays, dayKey, "day") ? "fa-chevron-down" : "fa-chevron-right"} mr-2 text-xs ${dayData.isToday ? isDarkTheme ? "text-green-200" : "text-green-600" : mutedTextClass}` }), /* @__PURE__ */ React.createElement("span", { className: `text-sm ${dayData.isToday ? isDarkTheme ? "text-green-100 font-semibold" : "text-green-900 font-semibold" : isDarkTheme ? "text-gray-100 font-medium" : "text-gray-900 font-medium"}` }, dayData.display), /* @__PURE__ */ React.createElement("span", { className: `ml-2 text-xs ${mutedTextClass}` }, "(", dayData.sessions.length, ")"))
      ), isReportGroupExpanded(expandedDays, dayKey, "day") && dayData.sessions.map((session) => {
        return /* @__PURE__ */ React.createElement("div", { key: session.timestamp }, /* @__PURE__ */ React.createElement(
          "div",
          {
            "data-testid": "discovery-report-session-toggle",
            className: `p-4 border-b cursor-pointer transition-colors overflow-hidden ${isDarkTheme ? "bg-gray-800 hover:bg-gray-700 border-gray-700" : "bg-white hover:bg-gray-50 border-gray-200"}`,
            onClick: () => toggleSession(session.timestamp),
            onKeyDown: (event) => handleKeyActivate(event, () => toggleSession(session.timestamp)),
            style: { paddingLeft: monthData.visible ? yearData.visible ? "3rem" : "2rem" : yearData.visible ? "2rem" : "1.25rem" },
            role: "button",
            tabIndex: 0,
            "aria-expanded": isReportGroupExpanded(expandedSessions, session.timestamp, "session")
          },
          /* @__PURE__ */ React.createElement("div", { className: "flex flex-col gap-2" }, /* @__PURE__ */ React.createElement("div", { className: "flex items-start flex-1 min-w-0" }, /* @__PURE__ */ React.createElement("i", { className: `fas ${isReportGroupExpanded(expandedSessions, session.timestamp, "session") ? "fa-chevron-down" : "fa-chevron-right"} mr-3 text-xs mt-1 ${mutedTextClass}` }), /* @__PURE__ */ React.createElement("div", { className: "flex-1 min-w-0" }, /* @__PURE__ */ React.createElement("h3", { className: `text-sm font-semibold mb-1 tracking-wide ${headingClass}` }, formatSessionTime(session.timestamp)), /* @__PURE__ */ React.createElement("div", { className: `flex items-center gap-2 text-xs flex-wrap ${mutedTextClass}` }, /* @__PURE__ */ React.createElement("span", { className: `flex items-center px-2 py-0.5 rounded ${isDarkTheme ? "bg-gray-700 text-gray-300" : "bg-gray-100 text-gray-600"}` }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-file-alt mr-1" }), countLabel(session.reports.length, "report")), session.hasSummary && /* @__PURE__ */ React.createElement("span", { className: `flex items-center px-2 py-0.5 rounded-full font-medium ${isDarkTheme ? "bg-emerald-900 text-emerald-100 border border-emerald-700" : "bg-emerald-100 text-emerald-800 border border-emerald-200"}` }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-check-circle mr-1" }), "Summarized")))), /* @__PURE__ */ React.createElement("div", { className: "flex items-center pl-6" }, /* @__PURE__ */ React.createElement(
            "button",
            {
              type: "button",
              onClick: (e) => {
                e.stopPropagation();
                openSummaryModal(session.timestamp, { hasSummary: session.hasSummary });
              },
              onKeyDown: (e) => e.stopPropagation(),
              className: `inline-flex items-center gap-1.5 rounded-md border px-2.5 py-1 text-xs font-medium whitespace-nowrap transition-colors ${secondaryButtonClass}`,
              title: session.hasSummary ? "Open the saved summary for this run" : "Ask the AI model to summarize this run"
            },
            /* @__PURE__ */ React.createElement("i", { className: `fas ${session.hasSummary ? "fa-eye" : "fa-magic"}` }),
            /* @__PURE__ */ React.createElement("span", null, session.hasSummary ? "View Summary" : "Summarize")
          )))
        ), isReportGroupExpanded(expandedSessions, session.timestamp, "session") && /* @__PURE__ */ React.createElement("div", { className: `divide-y ${isDarkTheme ? "divide-gray-700" : "divide-gray-100"}` }, session.reports.map((report) => /* @__PURE__ */ React.createElement(
          "div",
          {
            key: report.name,
            "data-testid": "discovery-report-row",
            className: `p-4 cursor-pointer ${isDarkTheme ? "hover:bg-gray-700" : "hover:bg-gray-50"} ${selectedReport === report.name ? isDarkTheme ? "bg-indigo-900 border-r-4 border-indigo-400" : "bg-indigo-50 border-r-4 border-indigo-500" : ""}`,
            onClick: () => openDiscoveryLibraryReport(report.name),
            onKeyDown: (event) => handleKeyActivate(event, () => openDiscoveryLibraryReport(report.name)),
            style: { paddingLeft: monthData.visible ? yearData.visible ? "4rem" : "3rem" : yearData.visible ? "3rem" : "2rem" },
            role: "button",
            tabIndex: 0
          },
          /* @__PURE__ */ React.createElement("div", { className: "flex items-center justify-between gap-2 min-w-0" }, /* @__PURE__ */ React.createElement("div", { className: "flex-1 min-w-0" }, /* @__PURE__ */ React.createElement("p", { "data-testid": "discovery-report-row-title", className: `text-sm font-medium truncate ${headingClass}` }, getReportDisplayName(report.name)), /* @__PURE__ */ React.createElement("p", { className: `text-xs truncate ${mutedTextClass}`, title: report.name }, report.name, " · ", (report.size / 1024).toFixed(1), " KB")), /* @__PURE__ */ React.createElement("div", { className: "flex items-center space-x-2 flex-shrink-0" }, /* @__PURE__ */ React.createElement("span", { className: `px-2 py-1 text-xs rounded ${report.type === "json" ? isDarkTheme ? "bg-blue-900 text-blue-100" : "bg-blue-100 text-blue-800" : isDarkTheme ? "bg-green-900 text-green-100" : "bg-green-100 text-green-800"}` }, report.type.toUpperCase())))
        ))));
      })))))));
    })()));
    return /* @__PURE__ */ React.createElement("div", { className: `dt4sms-theme-scope min-h-screen ${isDarkTheme ? "bg-gray-900 text-gray-100" : "bg-gray-50 text-gray-900"}` }, /* @__PURE__ */ React.createElement("header", { ref: headerRef, className: `dt4sms-top-shell ${isDarkTheme ? "bg-gray-800 border-gray-700" : "bg-white border-gray-200"} sticky top-0 z-50 shadow-sm border-b` }, /* @__PURE__ */ React.createElement("div", { className: `${workspaceShellWidthClass} mx-auto px-4 sm:px-6 lg:px-8` }, /* @__PURE__ */ React.createElement("div", { className: "dt4sms-shell-topbar flex items-center justify-between gap-3 pt-3 pb-2" }, /* @__PURE__ */ React.createElement("div", { className: "dt4sms-shell-brand flex items-center min-w-0" }, /* @__PURE__ */ React.createElement("i", { className: "dt4sms-shell-brand-icon fas fa-search text-lg sm:text-xl text-indigo-600 mr-2 sm:mr-3", "aria-hidden": "true" }), /* @__PURE__ */ React.createElement("h1", { className: `dt4sms-shell-title truncate text-base sm:text-lg font-semibold ${isDarkTheme ? "text-gray-100" : "text-gray-900"}` }, "Splunk Discovery Tool")), /* @__PURE__ */ React.createElement("div", { className: "dt4sms-shell-status-actions flex flex-shrink-0 items-center justify-end gap-2" }, /* @__PURE__ */ React.createElement(
      "button",
      {
        type: "button",
        "data-testid": "header-connection-status",
        className: `dt4sms-shell-action inline-flex items-center gap-2 rounded-lg border px-2.5 py-1.5 text-sm transition-colors ${headerButtonClass}`,
        onClick: openConnectionModal,
        title: `${headerConnectionMeta.summary} AI model: ${headerLlmDisplayLabel}.`,
        "aria-label": `Connection details. ${headerConnectionMeta.label}. AI model: ${headerLlmDisplayLabel}.`,
        "aria-haspopup": "dialog",
        "aria-expanded": isConnectionModalOpen,
        "aria-controls": "connection-details-popover"
      },
      /* @__PURE__ */ React.createElement("span", { "aria-hidden": "true", className: `h-2.5 w-2.5 flex-shrink-0 rounded-full ${headerConnectionMeta.dotClass}` }),
      /* @__PURE__ */ React.createElement("span", { className: "hidden sm:inline font-medium" }, headerConnectionMeta.label),
      ((_T = connectionInfo == null ? void 0 : connectionInfo.llm) == null ? void 0 : _T.configured) && /* @__PURE__ */ React.createElement("span", { "aria-hidden": "true", className: `hidden xl:inline max-w-[16rem] truncate ${mutedTextClass}` }, headerLlmDisplayLabel)
    ), /* @__PURE__ */ React.createElement(
      "button",
      {
        type: "button",
        onClick: openChatSurface,
        className: "dt4sms-shell-primary-action inline-flex items-center gap-2 rounded-lg px-3 py-1.5 text-sm font-medium bg-indigo-600 hover:bg-indigo-700 text-white",
        title: isChatFullscreen ? "Go to the full-screen chat" : "Chat with your Splunk environment",
        "aria-label": "Open chat"
      },
      /* @__PURE__ */ React.createElement("i", { className: "fas fa-comments", "aria-hidden": "true" }),
      /* @__PURE__ */ React.createElement("span", { className: "hidden sm:inline" }, "Chat")
    ), headerAuthVisible && /* @__PURE__ */ React.createElement(
      "div",
      {
        "data-testid": "header-auth-indicator",
        className: `flex items-center gap-2 text-sm ${mutedTextClass}`,
        title: headerAuthSummary
      },
      /* @__PURE__ */ React.createElement("i", { className: `fas fa-user-circle ${isDarkTheme ? "text-emerald-300" : "text-indigo-600"}`, "aria-hidden": "true" }),
      /* @__PURE__ */ React.createElement("span", { className: "sr-only" }, "Signed in as ", currentAuthUser.username, ". ", headerAuthRoleLabel, ". ", headerAuthProviderLabel, ".", headerAuthAssignmentLabel ? ` ${headerAuthAssignmentLabel}.` : ""),
      /* @__PURE__ */ React.createElement("span", { "aria-hidden": "true", className: `hidden md:inline max-w-[10rem] truncate font-medium ${headingClass}` }, currentAuthUser.username),
      /* @__PURE__ */ React.createElement("span", { "aria-hidden": "true", className: "hidden 2xl:inline text-xs" }, headerAuthRoleLabel),
      /* @__PURE__ */ React.createElement(
        "button",
        {
          type: "button",
          "data-testid": "header-logout-button",
          onClick: handleAuthLogout,
          className: `dt4sms-shell-action inline-flex items-center gap-1.5 rounded-lg border px-2.5 py-1.5 text-sm font-medium transition-colors ${headerButtonClass}`,
          "aria-label": "Sign Out"
        },
        /* @__PURE__ */ React.createElement("i", { className: "fas fa-right-from-bracket md:hidden", "aria-hidden": "true" }),
        /* @__PURE__ */ React.createElement("span", { className: "hidden md:inline" }, "Sign Out")
      )
    ), /* @__PURE__ */ React.createElement(
      "button",
      {
        type: "button",
        onClick: openSettings,
        className: `dt4sms-shell-action inline-flex items-center rounded-lg border px-2.5 py-1.5 text-sm transition-colors ${headerButtonClass}`,
        title: "Open settings",
        "aria-label": "Open settings"
      },
      /* @__PURE__ */ React.createElement("i", { className: "fas fa-cog", "aria-hidden": "true" })
    ))), /* @__PURE__ */ React.createElement("nav", { className: "dt4sms-shell-nav -mb-px", "aria-label": "Workspace" }, /* @__PURE__ */ React.createElement("div", { className: "dt4sms-shell-tablist flex items-stretch gap-1 overflow-x-auto", role: "tablist", "aria-label": "Workspace views", onKeyDown: handleTablistKeyDown }, /* @__PURE__ */ React.createElement(
      "button",
      {
        type: "button",
        id: "workspace-tab-overview",
        "data-testid": "workspace-tab-overview",
        role: "tab",
        "aria-selected": isMissionTab,
        tabIndex: isMissionTab ? 0 : -1,
        onClick: () => setWorkspaceTab("mission"),
        className: getWorkspaceTabClass(isMissionTab),
        title: "The latest run at a glance, with the next steps"
      },
      "Overview"
    ), /* @__PURE__ */ React.createElement(
      "button",
      {
        type: "button",
        id: "workspace-tab-findings",
        "data-testid": "workspace-tab-findings",
        role: "tab",
        "aria-selected": isIntelligenceTab,
        tabIndex: isIntelligenceTab ? 0 : -1,
        onClick: openFindingsWorkspace,
        className: getWorkspaceTabClass(isIntelligenceTab),
        title: "Coverage gaps, investigations, and evidence from the latest run"
      },
      "Findings"
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
        className: getWorkspaceTabClass(isArtifactsTab),
        title: "Run discovery and open its reports"
      },
      "Discovery",
      discoveryTabIndicator && /* @__PURE__ */ React.createElement("span", { "data-testid": "header-discovery-status", className: `inline-flex items-center gap-1.5 text-xs font-semibold ${discoveryTabIndicator.textClass}` }, /* @__PURE__ */ React.createElement("span", { "aria-hidden": "true", className: `h-2 w-2 rounded-full ${discoveryStatusMeta.dotClass} ${isMissionDiscoveryActive ? "animate-pulse" : ""}` }), discoveryTabIndicator.text, /* @__PURE__ */ React.createElement("span", { className: "sr-only" }, "(", discoveryTabIndicator.srText, ")"))
    ), /* @__PURE__ */ React.createElement(
      "button",
      {
        type: "button",
        id: "workspace-tab-knowledge-base",
        "data-testid": "workspace-tab-knowledge-base",
        role: "tab",
        "aria-selected": isCapabilitiesRagView,
        tabIndex: isCapabilitiesRagView ? 0 : -1,
        onClick: () => openRagCapabilitiesWorkspace({ libraryFilter: "spl_library" }),
        className: getWorkspaceTabClass(isCapabilitiesRagView),
        title: "Documents and saved SPL that Chat can search"
      },
      "Knowledge Base"
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
        className: getWorkspaceTabClass(isCapabilitiesOverview),
        title: "Optional add-ons for search, export, charts, and Splunk links"
      },
      "Capabilities"
    ), isChatFullscreen && /* @__PURE__ */ React.createElement(
      "button",
      {
        type: "button",
        id: "workspace-tab-chat",
        "data-testid": "workspace-tab-chat",
        role: "tab",
        "aria-selected": isChatTab,
        tabIndex: isChatTab ? 0 : -1,
        onClick: () => {
          setIsChatOpen(false);
          setWorkspaceTab("chat");
        },
        className: getWorkspaceTabClass(isChatTab),
        title: "Chat in full screen"
      },
      "Chat"
    ), isSummaryFullscreen && /* @__PURE__ */ React.createElement(
      "button",
      {
        type: "button",
        id: "workspace-tab-summary",
        "data-testid": "workspace-tab-summary",
        role: "tab",
        "aria-selected": isSummaryTab,
        tabIndex: isSummaryTab ? 0 : -1,
        onClick: () => {
          setIsSummaryModalOpen(false);
          setWorkspaceTab("summary-workspace");
        },
        className: getWorkspaceTabClass(isSummaryTab),
        title: "Discovery summary in full screen"
      },
      "Summary"
    ), moduleWorkspaceTabs.map((moduleTab, index) => /* @__PURE__ */ React.createElement(
      "button",
      {
        key: moduleTab.id,
        type: "button",
        id: `workspace-tab-${moduleTab.id}`,
        "data-testid": `workspace-tab-${moduleTab.id}`,
        role: "tab",
        "aria-selected": moduleTab.isActive,
        tabIndex: moduleTab.isActive ? 0 : -1,
        onClick: moduleTab.open,
        className: `${getWorkspaceTabClass(moduleTab.isActive)}${index === 0 ? " dt4sms-shell-module-start" : ""}`,
        title: moduleTab.description || moduleTab.label
      },
      /* @__PURE__ */ React.createElement("i", { className: "fas fa-puzzle-piece text-xs", "aria-hidden": "true" }),
      moduleTab.label
    )))))), /* @__PURE__ */ React.createElement("div", { className: `${workspaceShellWidthClass} mx-auto px-4 sm:px-6 lg:px-8 py-6` }, /* @__PURE__ */ React.createElement("div", { className: workspaceShellClass }, /* @__PURE__ */ React.createElement("div", { className: workspaceMainClass }, isMissionTab && /* @__PURE__ */ React.createElement("div", { className: `dt4sms-neo-workspace rounded-lg shadow-sm p-6 mb-6 border ${panelClass}` }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-wrap items-start justify-between gap-3 mb-4" }, /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("h2", { className: `text-lg font-semibold ${headingClass}` }, "Overview"), /* @__PURE__ */ React.createElement("p", { className: `text-sm ${subtextClass}` }, "What the latest discovery run found and what to do next.")), /* @__PURE__ */ React.createElement("div", { className: "flex flex-wrap items-center gap-2" }, renderOperatorVoiceSelect(), renderWorkspaceRefreshButton(refreshIntelligenceWorkspace, "Refresh the overview"))), !discoveryDashboard || !discoveryDashboard.has_data ? /* @__PURE__ */ React.createElement("div", { className: `text-sm rounded p-4 border ${panelMutedClass} ${mutedTextClass}` }, "No results yet. Run discovery from the Discovery tab to see results here.") : /* @__PURE__ */ React.createElement(React.Fragment, null, /* @__PURE__ */ React.createElement("div", { className: `dt4sms-neo-hero rounded-xl border p-5 mb-4 ${isDarkTheme ? "bg-gray-950 border-gray-800" : "bg-slate-50 border-slate-200"}` }, /* @__PURE__ */ React.createElement("div", { className: "max-w-3xl" }, /* @__PURE__ */ React.createElement("div", { className: `text-xs uppercase tracking-wider ${mutedTextClass}` }, "Latest run"), /* @__PURE__ */ React.createElement("div", { className: "mt-2 flex flex-wrap items-center gap-2" }, /* @__PURE__ */ React.createElement("span", { className: `dt4sms-neo-chip inline-flex items-center rounded-full px-2.5 py-1 text-xs font-semibold ${missionFreshness.badgeClass}` }, missionFreshness.label), /* @__PURE__ */ React.createElement("span", { className: `text-xs ${mutedTextClass}` }, "Last run: ", formatMissionDateTime((latestMissionSession == null ? void 0 : latestMissionSession.created_at) || (latestMissionSession == null ? void 0 : latestMissionSession.timestamp), (latestMissionSession == null ? void 0 : latestMissionSession.timestamp) || "Unavailable"))), /* @__PURE__ */ React.createElement("h3", { className: `mt-3 text-xl font-semibold ${headingClass}` }, missionExecutiveHeadline), /* @__PURE__ */ React.createElement("p", { className: `mt-2 text-sm leading-6 ${subtextClass}` }, missionFreshness.summary)), /* @__PURE__ */ React.createElement("div", { "data-testid": "overview-stats", className: "mt-5 grid grid-cols-2 sm:grid-cols-3 xl:grid-cols-6 gap-3" }, missionStatCards.map(renderWorkspaceMetricCard))), /* @__PURE__ */ React.createElement("div", { className: `dt4sms-neo-status-band rounded-xl border p-5 mb-4 ${discoveryStatusMeta.tonePanelClass}` }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between" }, /* @__PURE__ */ React.createElement("div", { className: "max-w-3xl" }, /* @__PURE__ */ React.createElement("div", { className: `text-xs uppercase tracking-wider ${discoveryStatusMeta.toneTextClass}` }, "Discovery status"), /* @__PURE__ */ React.createElement("h3", { className: `mt-1 text-lg font-semibold ${discoveryStatusMeta.toneTextClass}` }, missionDiscoveryMonitorCard.title), /* @__PURE__ */ React.createElement("p", { className: `mt-2 text-sm leading-6 ${discoveryStatusMeta.toneTextClass}` }, missionDiscoveryMonitorCard.summary)), /* @__PURE__ */ React.createElement("div", { className: "flex flex-wrap items-center gap-2" }, /* @__PURE__ */ React.createElement("span", { className: `inline-flex items-center rounded-full px-3 py-1 text-xs font-semibold ${discoveryStatusMeta.statusBadgeClass}` }, /* @__PURE__ */ React.createElement("span", { "aria-hidden": "true", className: `mr-2 h-2 w-2 rounded-full ${discoveryStatusMeta.dotClass} ${isMissionDiscoveryActive ? "animate-pulse" : ""}` }), discoveryStatusMeta.label), /* @__PURE__ */ React.createElement(
      "button",
      {
        type: "button",
        onClick: openDiscoveryWorkspace,
        className: "inline-flex items-center rounded-lg bg-indigo-600 px-3 py-2 text-sm font-medium text-white transition-colors hover:bg-indigo-700"
      },
      /* @__PURE__ */ React.createElement("i", { className: "fas fa-satellite-dish mr-2" }),
      missionDiscoveryMonitorCard.ctaLabel
    ))), /* @__PURE__ */ React.createElement("div", { className: "mt-4 grid grid-cols-1 gap-3 md:grid-cols-3" }, /* @__PURE__ */ React.createElement("div", { className: `dt4sms-neo-item rounded-xl border px-4 py-3 ${isDarkTheme ? "bg-gray-950 border-gray-700" : "bg-white border-gray-200"}` }, /* @__PURE__ */ React.createElement("div", { className: `text-xs uppercase tracking-wide ${mutedTextClass}` }, "Stage"), /* @__PURE__ */ React.createElement("div", { className: `mt-1 text-sm font-semibold ${headingClass}` }, discoveryPhaseLeadTitle)), /* @__PURE__ */ React.createElement("div", { className: `dt4sms-neo-item rounded-xl border px-4 py-3 ${isDarkTheme ? "bg-gray-950 border-gray-700" : "bg-white border-gray-200"}` }, /* @__PURE__ */ React.createElement("div", { className: `text-xs uppercase tracking-wide ${mutedTextClass}` }, missionDiscoveryMonitorCard.detailLabel), /* @__PURE__ */ React.createElement("div", { className: `mt-1 text-sm font-semibold ${headingClass}` }, missionDiscoveryMonitorCard.detail)), /* @__PURE__ */ React.createElement("div", { className: `dt4sms-neo-item rounded-xl border px-4 py-3 ${isDarkTheme ? "bg-gray-950 border-gray-700" : "bg-white border-gray-200"}` }, /* @__PURE__ */ React.createElement("div", { className: `text-xs uppercase tracking-wide ${mutedTextClass}` }, "Reports"), /* @__PURE__ */ React.createElement("div", { className: `mt-1 text-sm font-semibold ${headingClass}` }, discoveryReportCount > 0 ? discoveryReportCount : "None yet")))), /* @__PURE__ */ React.createElement("div", { "data-testid": "overview-next-steps", className: `dt4sms-neo-section rounded-xl border p-4 mb-4 ${isDarkTheme ? "bg-gray-950 border-gray-800" : "bg-white border-gray-200"}` }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-wrap items-center justify-between gap-2 mb-3" }, /* @__PURE__ */ React.createElement("div", { className: "flex items-center gap-2" }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-list-check text-emerald-600", "aria-hidden": "true" }), /* @__PURE__ */ React.createElement("h3", { className: `text-sm font-semibold ${headingClass}` }, "Next steps")), /* @__PURE__ */ React.createElement(
      "button",
      {
        type: "button",
        "data-testid": "overview-see-all-findings",
        onClick: openFindingsWorkspace,
        className: "ui-link text-xs font-medium"
      },
      "See all findings"
    )), findingsNextSteps.length === 0 ? /* @__PURE__ */ React.createElement("div", { className: `text-xs ${mutedTextClass}` }, (v2Intelligence == null ? void 0 : v2Intelligence.has_data) ? "The latest run suggested no next steps." : "Next steps appear here after discovery finishes.") : /* @__PURE__ */ React.createElement("ol", { className: `grid grid-cols-1 gap-3 ${findingsNextSteps.length >= 3 ? "lg:grid-cols-3" : findingsNextSteps.length === 2 ? "md:grid-cols-2" : ""}` }, findingsNextSteps.map((item, idx) => /* @__PURE__ */ React.createElement("li", { key: `next-step-${idx}`, "data-testid": "overview-next-step", className: `dt4sms-neo-item rounded-lg border px-3 py-3 text-xs ${isDarkTheme ? "bg-gray-900 border-gray-800" : "bg-gray-50 border-gray-200"}` }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-wrap items-start justify-between gap-2" }, /* @__PURE__ */ React.createElement("span", { className: `uppercase tracking-wide ${mutedTextClass}` }, item.audience), item.badge && /* @__PURE__ */ React.createElement("span", { className: `rounded-full px-2 py-0.5 border ${item.badgeClass}` }, item.badge)), /* @__PURE__ */ React.createElement("div", { "data-testid": "overview-next-step-title", className: `mt-2 text-sm font-medium ${headingClass}` }, item.title), /* @__PURE__ */ React.createElement("div", { className: `mt-1 leading-5 ${subtextClass}` }, item.summary), item.meta && /* @__PURE__ */ React.createElement("div", { className: `mt-2 ${mutedTextClass}` }, item.meta))))), sessionCatalog.length >= 2 && /* @__PURE__ */ React.createElement("div", { className: `border rounded p-3 mb-4 ${isDarkTheme ? "border-gray-600" : "border-gray-200"}` }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-col md:flex-row md:items-end md:justify-between gap-3" }, /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("h3", { className: `text-sm font-semibold ${headingClass}` }, "Compare runs"), /* @__PURE__ */ React.createElement("p", { className: `text-xs ${mutedTextClass}` }, "See what changed between two discovery runs.")), /* @__PURE__ */ React.createElement("div", { className: "flex flex-wrap items-center gap-2 text-xs" }, /* @__PURE__ */ React.createElement(
      "select",
      {
        value: compareSelection.current,
        onChange: (e) => setCompareSelection((prev) => ({ ...prev, current: e.target.value })),
        className: `border rounded px-2 py-1 ${isDarkTheme ? "border-gray-600 bg-gray-700 text-gray-100" : "border-gray-300 bg-white text-gray-900"}`
      },
      /* @__PURE__ */ React.createElement("option", { value: "latest" }, "Latest run"),
      sessionCatalog.map((session) => /* @__PURE__ */ React.createElement("option", { key: `current-${session.timestamp}`, value: session.timestamp }, formatMissionSessionSelectionLabel(session.timestamp)))
    ), /* @__PURE__ */ React.createElement("span", { className: mutedTextClass }, "vs"), /* @__PURE__ */ React.createElement(
      "select",
      {
        value: compareSelection.baseline,
        onChange: (e) => setCompareSelection((prev) => ({ ...prev, baseline: e.target.value })),
        className: `border rounded px-2 py-1 ${isDarkTheme ? "border-gray-600 bg-gray-700 text-gray-100" : "border-gray-300 bg-white text-gray-900"}`
      },
      /* @__PURE__ */ React.createElement("option", { value: "previous" }, "Previous run"),
      sessionCatalog.map((session) => /* @__PURE__ */ React.createElement("option", { key: `baseline-${session.timestamp}`, value: session.timestamp }, formatMissionSessionSelectionLabel(session.timestamp)))
    ), /* @__PURE__ */ React.createElement(
      "button",
      {
        onClick: refreshCompareSelection,
        className: "px-3 py-1 bg-indigo-600 hover:bg-indigo-700 text-white rounded"
      },
      "Compare"
    ))), !discoveryCompare || !discoveryCompare.has_data ? /* @__PURE__ */ React.createElement("div", { className: `text-xs mt-3 ${mutedTextClass}` }, (discoveryCompare == null ? void 0 : discoveryCompare.message) || "Run discovery at least twice to compare runs.") : /* @__PURE__ */ React.createElement("div", { className: "grid grid-cols-2 md:grid-cols-5 gap-2 mt-3 text-xs" }, /* @__PURE__ */ React.createElement("div", { className: `${isDarkTheme ? "bg-gray-700" : "bg-gray-50"} rounded p-2` }, /* @__PURE__ */ React.createElement("div", { className: mutedTextClass }, "Readiness change"), /* @__PURE__ */ React.createElement("div", { className: `font-semibold ${headingClass}` }, (_W = (_V = (_U = discoveryCompare.metrics) == null ? void 0 : _U.readiness) == null ? void 0 : _V.delta) != null ? _W : 0)), /* @__PURE__ */ React.createElement("div", { className: `${isDarkTheme ? "bg-gray-700" : "bg-gray-50"} rounded p-2` }, /* @__PURE__ */ React.createElement("div", { className: mutedTextClass }, "Index change"), /* @__PURE__ */ React.createElement("div", { className: `font-semibold ${headingClass}` }, (_Z = (_Y = (_X = discoveryCompare.metrics) == null ? void 0 : _X.indexes) == null ? void 0 : _Y.delta) != null ? _Z : 0)), /* @__PURE__ */ React.createElement("div", { className: `${isDarkTheme ? "bg-gray-700" : "bg-gray-50"} rounded p-2` }, /* @__PURE__ */ React.createElement("div", { className: mutedTextClass }, "Sourcetype change"), /* @__PURE__ */ React.createElement("div", { className: `font-semibold ${headingClass}` }, (_aa = (_$ = (__ = discoveryCompare.metrics) == null ? void 0 : __.sourcetypes) == null ? void 0 : _$.delta) != null ? _aa : 0)), /* @__PURE__ */ React.createElement("div", { className: `${isDarkTheme ? "bg-gray-700" : "bg-gray-50"} rounded p-2` }, /* @__PURE__ */ React.createElement("div", { className: mutedTextClass }, "Recommendation change"), /* @__PURE__ */ React.createElement("div", { className: `font-semibold ${headingClass}` }, (_da = (_ca = (_ba = discoveryCompare.metrics) == null ? void 0 : _ba.recommendations) == null ? void 0 : _ca.delta) != null ? _da : 0)), /* @__PURE__ */ React.createElement("div", { className: `${isDarkTheme ? "bg-gray-700" : "bg-gray-50"} rounded p-2` }, /* @__PURE__ */ React.createElement("div", { className: mutedTextClass }, "MCP tool change"), /* @__PURE__ */ React.createElement("div", { className: `font-semibold ${headingClass}` }, (_ga = (_fa = (_ea = discoveryCompare.metrics) == null ? void 0 : _ea.tools) == null ? void 0 : _fa.delta) != null ? _ga : 0)))), /* @__PURE__ */ React.createElement("div", { className: "grid grid-cols-1 xl:grid-cols-5 gap-4" }, /* @__PURE__ */ React.createElement("div", { className: `dt4sms-neo-runbook xl:col-span-3 border rounded p-3 ${isDarkTheme ? "border-gray-600 bg-gray-800/40" : "border-gray-200 bg-white"}` }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-col gap-3 mb-3" }, /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("h3", { className: `text-sm font-semibold ${headingClass}` }, "Runbook"), /* @__PURE__ */ React.createElement("p", { className: `text-xs mt-1 ${mutedTextClass}` }, "A step-by-step plan for the selected audience, written in the ", operatorVoiceDefinition.label, " style. Download it as Markdown.")), /* @__PURE__ */ React.createElement("div", { className: "flex flex-wrap items-center gap-2 text-xs" }, /* @__PURE__ */ React.createElement(
      "button",
      {
        type: "button",
        onClick: refreshRunbook,
        className: `px-3 py-1 whitespace-nowrap rounded border ${secondaryButtonClass}`
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
        className: `px-3 py-1 whitespace-nowrap rounded ${(discoveryDashboard == null ? void 0 : discoveryDashboard.has_data) ? "bg-indigo-600 hover:bg-indigo-700 text-white" : isDarkTheme ? "bg-gray-700 text-gray-400 cursor-not-allowed" : "bg-gray-200 text-gray-500 cursor-not-allowed"}`
      },
      "Download Runbook"
    ))), /* @__PURE__ */ React.createElement("div", { className: `inline-flex rounded border overflow-hidden text-xs mb-3 ${isDarkTheme ? "border-gray-600" : "border-gray-300"}`, role: "tablist", "aria-label": "Runbook audience", onKeyDown: handleTablistKeyDown }, /* @__PURE__ */ React.createElement(
      "button",
      {
        type: "button",
        id: "workflow-tab-admin",
        role: "tab",
        "aria-selected": workflowTab === "admin",
        "aria-controls": "workflow-panel-admin",
        tabIndex: workflowTab === "admin" ? 0 : -1,
        onClick: () => setWorkflowTab("admin"),
        className: `px-3 py-1 ${workflowTab === "admin" ? "bg-indigo-600 text-white" : isDarkTheme ? "bg-gray-900 text-gray-200 hover:bg-gray-800" : "bg-white text-gray-700 hover:bg-gray-100"}`
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
        className: `px-3 py-1 border-l ${isDarkTheme ? "border-gray-600" : "border-gray-300"} ${workflowTab === "analyst" ? "bg-indigo-600 text-white" : isDarkTheme ? "bg-gray-900 text-gray-200 hover:bg-gray-800" : "bg-white text-gray-700 hover:bg-gray-100"}`
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
        className: `px-3 py-1 border-l ${isDarkTheme ? "border-gray-600" : "border-gray-300"} ${workflowTab === "executive" ? "bg-indigo-600 text-white" : isDarkTheme ? "bg-gray-900 text-gray-200 hover:bg-gray-800" : "bg-white text-gray-700 hover:bg-gray-100"}`
      },
      "Executive"
    )), /* @__PURE__ */ React.createElement("div", { id: `workflow-panel-${workflowTab}`, role: "tabpanel", "aria-labelledby": `workflow-tab-${workflowTab}`, className: `text-xs ${mutedTextClass}` }, runbookPayload && runbookPayload.has_data ? `Ready to download: ${runbookPayload.title || "Runbook"}.` : "Select Generate Runbook to build it.")), /* @__PURE__ */ React.createElement("div", { className: `dt4sms-neo-runbook xl:col-span-2 border rounded p-3 ${isDarkTheme ? "border-gray-600 bg-gray-800/40" : "border-gray-200 bg-white"}` }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-col gap-3" }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-col gap-3" }, /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("h3", { className: `text-sm font-semibold ${headingClass}` }, "Report Package"), /* @__PURE__ */ React.createElement("p", { className: `text-xs mt-1 ${mutedTextClass}` }, "A zip file with the run's reports and the selected runbook.")), /* @__PURE__ */ React.createElement("div", { className: "flex flex-wrap items-center gap-2 text-xs" }, /* @__PURE__ */ React.createElement(
      "button",
      {
        onClick: async () => {
          const currentRunbook = await ensureCurrentRunbookPayload();
          await buildCapabilityExport({
            timestamp: compareSelection.current || "latest",
            persona: workflowTab,
            voice: operatorVoice,
            runbook_markdown: (currentRunbook == null ? void 0 : currentRunbook.markdown) || void 0,
            runbook_filename: (currentRunbook == null ? void 0 : currentRunbook.filename) || void 0
          });
        },
        disabled: !canUseExportTools || exportBuildState.status === "loading",
        className: `px-3 py-1 whitespace-nowrap rounded ${canUseExportTools && exportBuildState.status !== "loading" ? "bg-cyan-700 hover:bg-cyan-800 text-white" : isDarkTheme ? "bg-gray-700 text-gray-400 cursor-not-allowed" : "bg-gray-200 text-gray-500 cursor-not-allowed"}`
      },
      exportBuildState.status === "loading" ? "Building Package..." : "Build Report Package"
    ), /* @__PURE__ */ React.createElement(
      "button",
      {
        onClick: () => {
          var _a2, _b2;
          return downloadCapabilityExport(((_a2 = exportBuildState.bundle) == null ? void 0 : _a2.download_name) || ((_b2 = exportCapability == null ? void 0 : exportCapability.latest_bundle) == null ? void 0 : _b2.name));
        },
        disabled: !(((_ha = exportBuildState.bundle) == null ? void 0 : _ha.download_name) || ((_ia = exportCapability == null ? void 0 : exportCapability.latest_bundle) == null ? void 0 : _ia.name)),
        className: `px-3 py-1 whitespace-nowrap rounded ${((_ja = exportBuildState.bundle) == null ? void 0 : _ja.download_name) || ((_ka = exportCapability == null ? void 0 : exportCapability.latest_bundle) == null ? void 0 : _ka.name) ? "bg-slate-700 hover:bg-slate-800 text-white" : isDarkTheme ? "bg-gray-700 text-gray-400 cursor-not-allowed" : "bg-gray-200 text-gray-500 cursor-not-allowed"}`
      },
      downloadPackageLabel
    ))), /* @__PURE__ */ React.createElement("div", { className: `text-xs ${mutedTextClass}` }, "Contents: ", packageTargetLabel, "."), !canUseExportTools && /* @__PURE__ */ React.createElement("div", { className: `text-xs ${mutedTextClass}` }, "To build a package, install Report Packages on the Capabilities tab and turn it on."), exportBuildState.status === "error" && /* @__PURE__ */ React.createElement("div", { className: `rounded-lg border px-3 py-2 text-xs ${isDarkTheme ? "border-red-800 bg-red-950 text-red-200" : "border-red-200 bg-red-50 text-red-700"}` }, exportBuildState.error), activePackageBundle ? /* @__PURE__ */ React.createElement("div", { className: `rounded-lg border px-3 py-2 text-xs ${panelMutedClass} ${subtextClass}` }, /* @__PURE__ */ React.createElement("div", { className: "font-medium mb-1" }, packageCardTitle), /* @__PURE__ */ React.createElement("div", null, "Contents: ", packageTargetLabel), /* @__PURE__ */ React.createElement("div", null, "Package: ", formatPackageFileLabel(((_la = exportBuildState.bundle) == null ? void 0 : _la.bundle_name) || ((_ma = exportCapability == null ? void 0 : exportCapability.latest_bundle) == null ? void 0 : _ma.name))), ((_na = exportBuildState.bundle) == null ? void 0 : _na.session_timestamp) && /* @__PURE__ */ React.createElement("div", null, "Run: ", formatMissionSessionSelectionLabel(exportBuildState.bundle.session_timestamp)), ((_oa = exportBuildState.bundle) == null ? void 0 : _oa.artifact_count) != null && /* @__PURE__ */ React.createElement("div", null, "Files included: ", exportBuildState.bundle.artifact_count), ((_pa = exportBuildState.bundle) == null ? void 0 : _pa.operator_voice_label) && /* @__PURE__ */ React.createElement("div", null, "Style: ", exportBuildState.bundle.operator_voice_label), (((_qa = exportBuildState.bundle) == null ? void 0 : _qa.bundle_size_bytes) || ((_ra = exportCapability == null ? void 0 : exportCapability.latest_bundle) == null ? void 0 : _ra.size_bytes)) && /* @__PURE__ */ React.createElement("div", null, "Size: ", formatByteSize(((_sa = exportBuildState.bundle) == null ? void 0 : _sa.bundle_size_bytes) || ((_ta = exportCapability == null ? void 0 : exportCapability.latest_bundle) == null ? void 0 : _ta.size_bytes))), !hasFreshPackageBuild && /* @__PURE__ */ React.createElement("div", { className: `mt-2 ${mutedTextClass}` }, "Built earlier. Select Build Report Package to make a new one.")) : /* @__PURE__ */ React.createElement("div", { className: `rounded-lg border px-3 py-2 text-xs ${panelMutedClass} ${mutedTextClass}` }, "No package built yet.")))))), isIntelligenceTab && /* @__PURE__ */ React.createElement("div", { className: `dt4sms-neo-workspace rounded-lg shadow-sm p-6 mb-6 border ${panelClass}` }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-wrap items-start justify-between gap-3 mb-4" }, /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("h2", { className: `text-lg font-semibold ${headingClass}` }, "Findings"), /* @__PURE__ */ React.createElement("p", { className: `text-sm ${subtextClass}` }, "Coverage gaps, investigations, and evidence from the latest discovery run.")), /* @__PURE__ */ React.createElement("div", { className: "flex flex-wrap items-center gap-2" }, renderOperatorVoiceSelect(), renderWorkspaceRefreshButton(refreshIntelligenceWorkspace, "Refresh findings"))), !v2Intelligence || !v2Intelligence.has_data ? /* @__PURE__ */ React.createElement("div", { className: `text-sm rounded p-4 border ${panelMutedClass} ${mutedTextClass}` }, "No findings yet. Run discovery from the Discovery tab to see findings here.") : /* @__PURE__ */ React.createElement(React.Fragment, null, /* @__PURE__ */ React.createElement("div", { className: `dt4sms-neo-hero rounded-xl border p-5 mb-4 ${isDarkTheme ? "bg-gray-950 border-gray-800" : "bg-slate-50 border-slate-200"}` }, /* @__PURE__ */ React.createElement("div", { className: "max-w-3xl" }, /* @__PURE__ */ React.createElement("div", { className: `text-xs uppercase tracking-wider ${mutedTextClass}` }, "Latest run"), /* @__PURE__ */ React.createElement("div", { className: "mt-2 flex flex-wrap items-center gap-2" }, /* @__PURE__ */ React.createElement("span", { className: `dt4sms-neo-chip inline-flex items-center rounded-full px-2.5 py-1 text-xs font-semibold ${missionFreshness.badgeClass}` }, missionFreshness.label), /* @__PURE__ */ React.createElement("span", { className: `text-xs ${mutedTextClass}` }, "Last run: ", formatMissionDateTime((latestMissionSession == null ? void 0 : latestMissionSession.created_at) || (latestMissionSession == null ? void 0 : latestMissionSession.timestamp), (latestMissionSession == null ? void 0 : latestMissionSession.timestamp) || "Unavailable"))), /* @__PURE__ */ React.createElement("h3", { className: `mt-3 text-xl font-semibold ${headingClass}` }, intelligenceHeadline), /* @__PURE__ */ React.createElement("p", { className: `mt-2 text-sm leading-6 ${subtextClass}` }, intelligenceWhyNow)), /* @__PURE__ */ React.createElement("div", { "data-testid": "findings-stats", className: "mt-5 grid grid-cols-2 lg:grid-cols-4 gap-3" }, intelligenceSummaryCards.map(renderWorkspaceMetricCard))), /* @__PURE__ */ React.createElement("div", { className: "grid grid-cols-1 xl:grid-cols-3 gap-4 mb-4" }, renderFindingsList({
      key: "admin",
      icon: "fa-shield-alt",
      iconClass: "text-rose-600",
      title: "Coverage gaps",
      audience: "For admins. Highest priority first.",
      items: findingsAdminItems,
      emptyText: "No coverage gaps found."
    }), renderFindingsList({
      key: "analyst",
      icon: "fa-search",
      iconClass: "text-indigo-600",
      title: "Investigations",
      audience: "For analysts.",
      items: findingsAnalystItems,
      emptyText: "No investigations suggested."
    }), renderFindingsList({
      key: "executive",
      icon: "fa-briefcase",
      iconClass: "text-purple-600",
      title: "Executive summary",
      audience: "For leadership.",
      items: findingsExecutiveItems,
      emptyText: "No executive summary was generated."
    })), /* @__PURE__ */ React.createElement("div", { className: "grid grid-cols-1 md:grid-cols-2 gap-4 mb-4" }, /* @__PURE__ */ React.createElement("div", { className: `border rounded p-4 ${isDarkTheme ? "border-gray-600 bg-gray-800" : "border-gray-200 bg-white"}` }, /* @__PURE__ */ React.createElement("div", { className: "flex items-center gap-2 mb-3" }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-project-diagram text-sky-600" }), /* @__PURE__ */ React.createElement("h3", { className: `text-sm font-semibold ${headingClass}` }, "Environment Profile")), /* @__PURE__ */ React.createElement("div", { className: "grid grid-cols-2 gap-2 text-xs mb-3" }, /* @__PURE__ */ React.createElement("div", { className: `${isDarkTheme ? "bg-gray-900 border-gray-700" : "bg-gray-50 border-gray-200"} border rounded-lg px-3 py-3` }, /* @__PURE__ */ React.createElement("div", { className: mutedTextClass }, "Splunk"), /* @__PURE__ */ React.createElement("div", { className: `mt-1 font-medium ${headingClass}` }, v2Overview.splunk_version || "Unknown"), /* @__PURE__ */ React.createElement("div", { className: `mt-1 ${subtextClass}` }, "License: ", v2Overview.license_state || "Unknown")), /* @__PURE__ */ React.createElement("div", { className: `${isDarkTheme ? "bg-gray-900 border-gray-700" : "bg-gray-50 border-gray-200"} border rounded-lg px-3 py-3` }, /* @__PURE__ */ React.createElement("div", { className: mutedTextClass }, "Data"), /* @__PURE__ */ React.createElement("div", { className: `mt-1 font-medium ${headingClass}` }, formatMissionMetricValue(((_ua = v2CapabilityGraph == null ? void 0 : v2CapabilityGraph.data_surface) == null ? void 0 : _ua.indexes) || v2Overview.total_indexes), " indexes"), /* @__PURE__ */ React.createElement("div", { className: `mt-1 ${subtextClass}` }, formatMissionMetricValue(((_va = v2CapabilityGraph == null ? void 0 : v2CapabilityGraph.data_surface) == null ? void 0 : _va.sourcetypes) || v2Overview.total_sourcetypes), " sourcetypes • ", formatMissionMetricValue(((_wa = v2CapabilityGraph == null ? void 0 : v2CapabilityGraph.data_surface) == null ? void 0 : _wa.sources) || v2Overview.total_sources), " sources")), /* @__PURE__ */ React.createElement("div", { className: `col-span-2 ${isDarkTheme ? "bg-gray-900 border-gray-700" : "bg-gray-50 border-gray-200"} border rounded-lg px-3 py-3` }, /* @__PURE__ */ React.createElement("div", { className: mutedTextClass }, "Users and objects"), /* @__PURE__ */ React.createElement("div", { className: `mt-1 font-medium ${headingClass}` }, formatMissionMetricValue(((_xa = v2CapabilityGraph == null ? void 0 : v2CapabilityGraph.operations_surface) == null ? void 0 : _xa.users) || v2Overview.total_users), " users"), /* @__PURE__ */ React.createElement("div", { className: `mt-1 ${subtextClass}` }, formatMissionMetricValue(((_ya = v2CapabilityGraph == null ? void 0 : v2CapabilityGraph.operations_surface) == null ? void 0 : _ya.knowledge_objects) || v2Overview.total_knowledge_objects), " knowledge objects • ", formatMissionMetricValue(((_za = v2CapabilityGraph == null ? void 0 : v2CapabilityGraph.operations_surface) == null ? void 0 : _za.kv_collections) || v2Overview.total_kv_collections), " KV collections")))), /* @__PURE__ */ React.createElement("div", { className: `border rounded p-4 ${isDarkTheme ? "border-gray-600 bg-gray-800" : "border-gray-200 bg-white"}` }, /* @__PURE__ */ React.createElement("div", { className: "flex items-center gap-2 mb-3" }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-stream text-emerald-600" }), /* @__PURE__ */ React.createElement("h3", { className: `text-sm font-semibold ${headingClass}` }, "Key evidence")), v2FindingLedger.length === 0 ? /* @__PURE__ */ React.createElement("div", { className: `text-xs ${mutedTextClass}` }, "No evidence recorded.") : /* @__PURE__ */ React.createElement("ul", { className: "space-y-2 text-xs" }, v2FindingLedger.slice(0, 6).map((entry, idx) => /* @__PURE__ */ React.createElement("li", { key: idx, className: `${isDarkTheme ? "bg-gray-900 border-gray-700" : "bg-gray-50 border-gray-200"} border rounded-lg p-3` }, /* @__PURE__ */ React.createElement("div", { className: "flex items-start justify-between gap-3" }, /* @__PURE__ */ React.createElement("div", { className: `font-medium ${headingClass}` }, "Step ", entry.step || 0, ": ", entry.title || "Discovery step"), /* @__PURE__ */ React.createElement("span", { className: `text-xs ${mutedTextClass}` }, formatMissionDateTime(entry.timestamp, "Time not recorded"))), /* @__PURE__ */ React.createElement("div", { className: `mt-1 ${subtextClass}` }, summarizeFindingEntry(entry))))))), /* @__PURE__ */ React.createElement("div", { className: `border rounded p-4 ${isDarkTheme ? "border-gray-600 bg-gray-800" : "border-gray-200 bg-white"}` }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between mb-3" }, /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("div", { className: "flex items-center gap-2" }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-fingerprint text-sky-600" }), /* @__PURE__ */ React.createElement("h3", { className: `text-sm font-semibold ${headingClass}` }, "Patterns")), /* @__PURE__ */ React.createElement("div", { className: `mt-2 text-xs ${subtextClass}` }, "Themes that came up repeatedly in the latest run.")), intelligenceNotablePatterns.length > 0 && /* @__PURE__ */ React.createElement("div", { className: "flex flex-wrap items-center justify-end gap-2" }, hasExpandableIntelligencePatterns && /* @__PURE__ */ React.createElement(
      "button",
      {
        type: "button",
        "data-testid": "intelligence-notable-patterns-toggle",
        "aria-expanded": showAllIntelligencePatterns,
        onClick: () => setShowAllIntelligencePatterns((current) => !current),
        className: `inline-flex items-center rounded-full px-3 py-1 text-xs font-medium border ${isDarkTheme ? "bg-gray-900 border-gray-700 text-sky-100 hover:bg-gray-950" : "bg-white border-gray-300 text-sky-700 hover:bg-sky-50"}`
      },
      showAllIntelligencePatterns ? "Show fewer" : `View all ${intelligenceNotablePatterns.length} patterns`
    ), /* @__PURE__ */ React.createElement("div", { className: `inline-flex items-center rounded-full px-2.5 py-1 text-xs border ${panelMutedClass} ${mutedTextClass}` }, "Showing ", visibleIntelligenceNotablePatterns.length, " of ", intelligenceNotablePatterns.length))), intelligenceNotablePatterns.length === 0 ? /* @__PURE__ */ React.createElement("div", { className: `text-xs ${mutedTextClass}` }, "No repeated patterns found.") : /* @__PURE__ */ React.createElement("div", { className: "grid grid-cols-1 xl:grid-cols-3 gap-3", "data-testid": "intelligence-notable-patterns" }, visibleIntelligenceNotablePatterns.map((pattern, idx) => {
      const distinctEvidenceItems = getDistinctIntelligencePatternEvidence(pattern);
      return /* @__PURE__ */ React.createElement(
        "div",
        {
          key: `notable-pattern-${idx}`,
          "data-testid": "intelligence-notable-pattern-card",
          className: `${isDarkTheme ? "bg-gray-900 border-gray-700" : "bg-gray-50 border-gray-200"} border rounded-xl px-4 py-4`
        },
        /* @__PURE__ */ React.createElement("div", { className: "flex items-start justify-between gap-3" }, /* @__PURE__ */ React.createElement("div", { className: `text-xs uppercase tracking-wider ${mutedTextClass}` }, getIntelligencePatternEyebrowLabel(pattern, idx)), pattern.signal && /* @__PURE__ */ React.createElement("span", { className: `rounded-full px-2 py-0.5 border text-xs ${panelMutedClass} ${mutedTextClass}` }, "Key signal")),
        /* @__PURE__ */ React.createElement("div", { className: `mt-2 text-sm font-semibold ${headingClass}` }, formatIntelligencePatternLabel(pattern.title || pattern.category || `Pattern ${idx + 1}`, `Pattern ${idx + 1}`)),
        /* @__PURE__ */ React.createElement("div", { className: `mt-2 text-xs leading-5 ${subtextClass}` }, pattern.description || "No description was recorded for this pattern."),
        pattern.signal && /* @__PURE__ */ React.createElement("div", { className: `mt-3 text-xs ${mutedTextClass}` }, "Key signal: ", pattern.signal),
        distinctEvidenceItems.length > 0 && /* @__PURE__ */ React.createElement("div", { className: "mt-3 flex flex-wrap gap-2" }, distinctEvidenceItems.slice(0, 2).map((item, evidenceIdx) => /* @__PURE__ */ React.createElement(
          "span",
          {
            key: `notable-pattern-${idx}-evidence-${evidenceIdx}`,
            className: `rounded-full px-2 py-0.5 border text-xs ${isDarkTheme ? "bg-gray-800 text-gray-200 border-gray-600" : "bg-white text-gray-700 border-gray-300"}`
          },
          item
        )))
      );
    }))))), isCapabilitiesTab && /* @__PURE__ */ React.createElement("div", { className: "space-y-6 mb-6" }, /* @__PURE__ */ React.createElement("div", { className: `rounded-lg shadow-sm p-6 border ${panelClass}` }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-col xl:flex-row xl:items-start xl:justify-between gap-4" }, /* @__PURE__ */ React.createElement("div", { className: "max-w-3xl" }, /* @__PURE__ */ React.createElement("h2", { className: `text-lg font-semibold ${headingClass}` }, isCapabilitiesRagView ? "Knowledge Base" : "Capabilities"), /* @__PURE__ */ React.createElement("p", { className: `text-sm mt-2 ${subtextClass}` }, isCapabilitiesRagView ? "Import documents and saved searches, index them, and preview what the AI assistant will see when it answers." : "Install, turn on, and test optional features. Each one stays off until you turn it on."), !isCapabilitiesRagView && capabilityList.length > 0 && /* @__PURE__ */ React.createElement("p", { "data-testid": "capabilities-count-summary", className: `mt-3 text-sm font-medium ${headingClass}` }, capabilityCountSummary)), /* @__PURE__ */ React.createElement("div", { className: "flex flex-wrap items-center gap-2" }, isCapabilitiesRagView ? renderWorkspaceRefreshButton(() => openRagCapabilitiesWorkspace({ libraryFilter: ragLibraryFilter }), "Refresh the Knowledge Base") : renderWorkspaceRefreshButton(refreshCapabilitiesWorkspace, "Refresh capabilities"))), renderCapabilityNotice()), capabilitiesData.status === "error" ? /* @__PURE__ */ React.createElement("div", { className: `rounded-lg shadow-sm p-4 border ${isDarkTheme ? "bg-red-950 border-red-800 text-red-100" : "bg-red-50 border-red-200 text-red-800"}` }, capabilitiesData.error || "Failed to load capabilities.") : isCapabilitiesOverview ? /* @__PURE__ */ React.createElement(React.Fragment, null, renderRagOverviewCard(), /* @__PURE__ */ React.createElement("section", { "aria-labelledby": "other-capabilities-title", className: `rounded-lg shadow-sm p-6 border ${panelClass}` }, /* @__PURE__ */ React.createElement("h3", { id: "other-capabilities-title", className: `text-base font-semibold ${headingClass}` }, "Other capabilities"), /* @__PURE__ */ React.createElement("p", { className: `text-sm mt-1 ${subtextClass}` }, "Optional tools for charts, Splunk search links, report packages, and more."), /* @__PURE__ */ React.createElement("div", { className: "mt-4 grid grid-cols-1 xl:grid-cols-2 gap-4" }, genericCapabilityList.map((capability) => {
      const actionInProgress = capabilityActionState[capability.name];
      const isBusy = !!actionInProgress;
      const statusLabel = capability.health_status || "unknown";
      const lifecycle = getCapabilityLifecycleState(capability);
      const canBuildDeeplink = capability.name === "splunk_deeplink_tools" && lifecycle === "on" && String(statusLabel).toLowerCase() === "ready";
      const deeplinkDraft = deeplinkDrafts[capability.name] || {};
      const deeplinkBuildResult = deeplinkBuildResults[capability.name] || null;
      const showHealthMessage = !!capability.health_message && !["not_installed", "disabled", "unavailable"].includes(String(statusLabel).toLowerCase());
      const capabilityFacts = capability.installed ? [
        capability.last_tested_at ? `Checked ${formatMissionDateTime(capability.last_tested_at)}` : null,
        capability.version && capability.version !== "bundled" ? `Version ${capability.version}` : null
      ].filter(Boolean) : [];
      return /* @__PURE__ */ React.createElement("div", { key: capability.name, "data-testid": "capability-card", "data-capability": capability.name, className: `flex flex-col rounded-lg border p-4 ${isDarkTheme ? "bg-gray-900 border-gray-700" : "bg-white border-gray-200"}` }, /* @__PURE__ */ React.createElement("div", { className: "flex items-start justify-between gap-3" }, /* @__PURE__ */ React.createElement("div", { className: "min-w-0" }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-wrap items-center gap-2" }, /* @__PURE__ */ React.createElement("h4", { className: `text-base font-semibold ${headingClass}` }, capability.title || formatTokenLabel(capability.name)), /* @__PURE__ */ React.createElement("span", { className: `inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium ${getCapabilityStatusClasses(statusLabel)}` }, formatCapabilityStatusLabel(statusLabel))), /* @__PURE__ */ React.createElement("p", { className: `mt-1 text-sm ${subtextClass}` }, capability.description || "Optional feature.")), /* @__PURE__ */ React.createElement(
        "button",
        {
          type: "button",
          onClick: () => openCapabilityDetail(capability.name),
          "aria-label": `View details for ${capability.title || capability.name}`,
          title: "View details",
          className: `inline-flex h-9 w-9 flex-shrink-0 items-center justify-center rounded-full border ${isDarkTheme ? "border-gray-600 bg-gray-800 text-sky-200 hover:bg-gray-700" : "border-gray-300 bg-white text-sky-700 hover:bg-sky-50"}`
        },
        /* @__PURE__ */ React.createElement("i", { className: "fa-solid fa-circle-info text-sm", "aria-hidden": "true" })
      )), (showHealthMessage || capabilityFacts.length > 0) && /* @__PURE__ */ React.createElement("p", { className: `mt-3 text-xs ${mutedTextClass}` }, showHealthMessage ? capability.health_message : "", showHealthMessage && capabilityFacts.length > 0 ? " " : "", capabilityFacts.join(" · ")), lifecycle === "not_installed" && capability.install_method === "pip" && /* @__PURE__ */ React.createElement("p", { className: `mt-3 text-xs ${mutedTextClass}` }, "Installing downloads extra Python packages, which can take a few minutes."), canBuildDeeplink && /* @__PURE__ */ React.createElement("div", { className: `mt-3 rounded-lg border px-3 py-3 ${isDarkTheme ? "border-gray-700 bg-gray-950" : "border-gray-200 bg-gray-50"}` }, /* @__PURE__ */ React.createElement("label", { htmlFor: `deeplink-query-${capability.name}`, className: `block text-sm font-medium mb-2 ${headingClass}` }, "Build a Splunk search link"), /* @__PURE__ */ React.createElement(
        "textarea",
        {
          id: `deeplink-query-${capability.name}`,
          value: deeplinkDraft.query || "",
          onChange: (event) => updateDeeplinkDraft(capability.name, "query", event.target.value),
          rows: 3,
          placeholder: "search index=_internal | head 20",
          className: `w-full rounded-lg border px-3 py-2 text-xs font-mono ${isDarkTheme ? "bg-gray-900 border-gray-700 text-gray-100" : "bg-white border-gray-300 text-gray-900"}`
        }
      ), /* @__PURE__ */ React.createElement("div", { className: "grid grid-cols-1 sm:grid-cols-3 gap-2 mt-2" }, /* @__PURE__ */ React.createElement(
        "input",
        {
          "aria-label": "Earliest time",
          value: deeplinkDraft.earliest || "",
          onChange: (event) => updateDeeplinkDraft(capability.name, "earliest", event.target.value),
          placeholder: "-24h",
          className: `rounded-lg border px-3 py-2 text-xs font-mono ${isDarkTheme ? "bg-gray-900 border-gray-700 text-gray-100" : "bg-white border-gray-300 text-gray-900"}`
        }
      ), /* @__PURE__ */ React.createElement(
        "input",
        {
          "aria-label": "Latest time",
          value: deeplinkDraft.latest || "",
          onChange: (event) => updateDeeplinkDraft(capability.name, "latest", event.target.value),
          placeholder: "now",
          className: `rounded-lg border px-3 py-2 text-xs font-mono ${isDarkTheme ? "bg-gray-900 border-gray-700 text-gray-100" : "bg-white border-gray-300 text-gray-900"}`
        }
      ), /* @__PURE__ */ React.createElement(
        "input",
        {
          "aria-label": "Splunk app",
          value: deeplinkDraft.app || "",
          onChange: (event) => updateDeeplinkDraft(capability.name, "app", event.target.value),
          placeholder: "search",
          className: `rounded-lg border px-3 py-2 text-xs font-mono ${isDarkTheme ? "bg-gray-900 border-gray-700 text-gray-100" : "bg-white border-gray-300 text-gray-900"}`
        }
      )), (deeplinkBuildResult == null ? void 0 : deeplinkBuildResult.url) && /* @__PURE__ */ React.createElement("div", { className: `mt-2 text-xs break-all ${subtextClass}` }, "Latest link:", " ", /* @__PURE__ */ React.createElement(
        "a",
        {
          href: deeplinkBuildResult.url,
          target: "_blank",
          rel: "noreferrer",
          className: "ui-link underline"
        },
        deeplinkBuildResult.url
      )), /* @__PURE__ */ React.createElement("div", { className: "flex flex-wrap gap-2 mt-3" }, /* @__PURE__ */ React.createElement(
        "button",
        {
          type: "button",
          onClick: () => buildCapabilityDeeplink({
            query: deeplinkDraft.query || "",
            earliest: deeplinkDraft.earliest || void 0,
            latest: deeplinkDraft.latest || void 0,
            app: deeplinkDraft.app || void 0
          }, { name: capability.name }),
          disabled: isBusy,
          className: getCapabilityActionButtonClass(false, isBusy)
        },
        actionInProgress === "build" ? "Building..." : "Build Link"
      ), /* @__PURE__ */ React.createElement(
        "button",
        {
          type: "button",
          onClick: () => buildCapabilityDeeplink({
            query: deeplinkDraft.query || "",
            earliest: deeplinkDraft.earliest || void 0,
            latest: deeplinkDraft.latest || void 0,
            app: deeplinkDraft.app || void 0
          }, { name: capability.name, openAfterBuild: true, suppressNotice: true }),
          disabled: isBusy,
          className: getCapabilityActionButtonClass(false, isBusy)
        },
        /* @__PURE__ */ React.createElement("i", { className: "fas fa-external-link-alt mr-1.5", "aria-hidden": "true" }),
        "Open in Splunk"
      ))), /* @__PURE__ */ React.createElement("div", { className: "mt-4" }, renderCapabilityLifecycleActions(capability)), capability.installed && /* @__PURE__ */ React.createElement("details", { className: `mt-3 rounded-lg border ${isDarkTheme ? "border-gray-700 bg-gray-900" : "border-gray-200 bg-gray-50"}` }, /* @__PURE__ */ React.createElement("summary", { className: `cursor-pointer px-3 py-2 text-sm font-medium ${headingClass}` }, "Advanced settings"), /* @__PURE__ */ React.createElement("div", { className: "px-3 pb-3" }, /* @__PURE__ */ React.createElement(
        "textarea",
        {
          "aria-label": `Settings for ${capability.title || capability.name} (JSON)`,
          value: capabilityDrafts[capability.name] || "{}",
          onChange: (event) => updateCapabilityDraft(capability.name, event.target.value),
          rows: 8,
          className: `w-full rounded-lg border px-3 py-2 text-xs font-mono ${isDarkTheme ? "bg-gray-900 border-gray-700 text-gray-100" : "bg-white border-gray-300 text-gray-900"}`
        }
      ), capability.name === "rag_local" && /* @__PURE__ */ React.createElement("div", { className: `mt-2 text-xs ${mutedTextClass}` }, "To use this in chat, turn it on here, then turn on Quick Report Search in Chat Settings."), capability.name === "splunk_deeplink_tools" && /* @__PURE__ */ React.createElement("div", { className: `mt-2 text-xs ${mutedTextClass}` }, "Set web_base_url to your Splunk Web address, including http:// or https://, if the guessed address is wrong. Select Test to confirm the address works."), capability.name === "visualization_tools" && /* @__PURE__ */ React.createElement("div", { className: `mt-2 text-xs ${mutedTextClass}` }, "Keep preview_enabled on to show charts for search results in chat."), capability.name === "export_tools" && /* @__PURE__ */ React.createElement("div", { className: `mt-2 text-xs ${mutedTextClass}` }, "Change source_dir and export_dir only if your reports are not in the default output folder. Once it is on, Build Report Package creates a zip with the reports, a summary note, and the runbook."), /* @__PURE__ */ React.createElement(
        "button",
        {
          type: "button",
          onClick: () => saveCapabilityConfig(capability.name),
          disabled: isBusy,
          className: `mt-3 ${getCapabilityActionButtonClass(true, isBusy)}`
        },
        actionInProgress === "config" ? "Saving..." : "Save Settings"
      ))));
    })))) : renderRagWorkspaceView()), isM2614Tab && /* @__PURE__ */ React.createElement("div", { className: "mb-6 space-y-6" }, renderM2614WorkspaceView()), isArtifactsTab && /* @__PURE__ */ React.createElement("div", { className: "mb-6 space-y-6" }, /* @__PURE__ */ React.createElement(
      "section",
      {
        "data-testid": "discovery-status-card",
        "aria-labelledby": "discovery-status-title",
        className: `rounded-lg shadow-sm p-6 border ${panelClass}`
      },
      /* @__PURE__ */ React.createElement("div", { className: "flex flex-col gap-5 lg:flex-row lg:items-start lg:justify-between" }, /* @__PURE__ */ React.createElement("div", { className: "min-w-0 max-w-3xl" }, /* @__PURE__ */ React.createElement("span", { className: `inline-flex items-center rounded-full px-3 py-1 text-xs font-semibold ${discoveryStatusMeta.statusBadgeClass}` }, /* @__PURE__ */ React.createElement("span", { "aria-hidden": "true", className: `w-2 h-2 rounded-full mr-2 ${discoveryStatusMeta.dotClass} ${isMissionDiscoveryActive ? "animate-pulse" : ""}` }), discoveryStatusMeta.shortValue), /* @__PURE__ */ React.createElement("h2", { id: "discovery-status-title", className: `mt-3 text-xl font-semibold ${headingClass}` }, discoveryStatusMeta.bannerTitle), /* @__PURE__ */ React.createElement("p", { className: `mt-2 text-sm leading-6 ${subtextClass}` }, discoveryNarrative), discoveryStatusFacts.length > 0 && /* @__PURE__ */ React.createElement("dl", { "data-testid": "discovery-status-facts", className: "mt-3 flex flex-wrap gap-x-6 gap-y-1 text-sm" }, discoveryStatusFacts.map((fact) => /* @__PURE__ */ React.createElement("div", { key: fact.label, className: "flex gap-1.5" }, /* @__PURE__ */ React.createElement("dt", { className: mutedTextClass }, fact.label), /* @__PURE__ */ React.createElement("dd", { className: `font-medium ${headingClass}` }, fact.value))))), /* @__PURE__ */ React.createElement("div", { className: "flex flex-wrap items-center gap-2 lg:flex-shrink-0 lg:justify-end" }, isMissionDiscoveryActive ? /* @__PURE__ */ React.createElement(
        "button",
        {
          type: "button",
          onClick: abortDiscovery,
          className: "inline-flex items-center rounded-lg px-4 py-2 text-sm font-medium text-white bg-red-600 hover:bg-red-700",
          title: "Stop the discovery run"
        },
        /* @__PURE__ */ React.createElement("i", { className: "fas fa-stop mr-2", "aria-hidden": "true" }),
        "Stop Discovery"
      ) : /* @__PURE__ */ React.createElement(React.Fragment, null, discoveryShowsSummaryAction && /* @__PURE__ */ React.createElement(
        "button",
        {
          type: "button",
          "data-testid": "discovery-ledger-summary-action",
          onClick: () => openSummaryModal(discoverySummarySession.timestamp, { hasSummary: discoverySummaryIsSaved }),
          className: "inline-flex items-center rounded-lg px-4 py-2 text-sm font-medium text-white bg-indigo-600 hover:bg-indigo-700",
          title: discoverySummaryIsSaved ? "View the saved summary for this run" : "Ask the AI model to summarize this run"
        },
        /* @__PURE__ */ React.createElement("i", { className: `fas ${discoverySummaryIsSaved ? "fa-eye" : "fa-magic"} mr-2`, "aria-hidden": "true" }),
        discoverySummaryIsSaved ? "View Summary" : "Summarize"
      ), /* @__PURE__ */ React.createElement(
        "button",
        {
          type: "button",
          onClick: startDiscovery,
          className: discoveryShowsSummaryAction ? `inline-flex items-center rounded-lg border px-4 py-2 text-sm font-medium transition-colors ${secondaryButtonClass}` : "inline-flex items-center rounded-lg px-4 py-2 text-sm font-medium text-white bg-indigo-600 hover:bg-indigo-700",
          title: "Start a full discovery run"
        },
        /* @__PURE__ */ React.createElement("i", { className: "fas fa-rocket mr-2", "aria-hidden": "true" }),
        "Run Discovery"
      )))),
      isMissionDiscoveryActive && /* @__PURE__ */ React.createElement(
        "div",
        {
          className: `mt-5 h-2 rounded-full ${isDarkTheme ? "bg-gray-700" : "bg-gray-200"}`,
          role: "progressbar",
          "aria-label": "Discovery progress",
          "aria-valuemin": 0,
          "aria-valuemax": 100,
          "aria-valuenow": discoveryProgressPercent
        },
        /* @__PURE__ */ React.createElement(
          "div",
          {
            className: `${discoveryStatusMeta.progressFillClass} h-2 rounded-full progress-bar`,
            style: { width: `${Math.max(discoveryProgressPercent, 4)}%` }
          }
        )
      )
    ), reports.length === 0 ? renderDiscoveryReportLibraryPanel() : /* @__PURE__ */ React.createElement("div", { className: discoveryWorkspaceSplitClass }, /* @__PURE__ */ React.createElement(
      "div",
      {
        ref: discoveryReportViewerRef,
        className: `order-2 min-w-0 lg:order-1 lg:col-span-2 ${discoveryHasFocusedReport ? "" : "hidden lg:block"}`,
        style: { scrollMarginTop: "7rem" }
      },
      discoveryHasFocusedReport ? renderReportViewerPanel() : renderArtifactEmptyState()
    ), /* @__PURE__ */ React.createElement("div", { className: "order-1 min-w-0 lg:order-2 lg:col-span-1" }, renderDiscoveryReportLibraryPanel())), /* @__PURE__ */ React.createElement(
      "details",
      {
        "data-testid": "discovery-run-details",
        open: isDiscoveryRunDetailsOpen,
        onToggle: handleDiscoveryRunDetailsToggle,
        className: `rounded-lg shadow-sm border ${panelClass}`
      },
      /* @__PURE__ */ React.createElement("summary", { className: "flex cursor-pointer list-none items-center justify-between gap-4 rounded-lg p-6" }, /* @__PURE__ */ React.createElement("div", { className: "min-w-0" }, /* @__PURE__ */ React.createElement("h2", { className: `text-lg font-medium ${headingClass}` }, "Run details"), /* @__PURE__ */ React.createElement("p", { className: `mt-1 text-sm ${subtextClass}` }, discoveryPhaseEntries.length > 0 ? `${discoveryCompletedPhaseCount} of ${discoveryPhaseEntries.length} stages done. Shows each stage and the discovery log.` : "Shows each stage and the discovery log once discovery runs.")), /* @__PURE__ */ React.createElement("i", { "aria-hidden": "true", className: `fas ${isDiscoveryRunDetailsOpen ? "fa-chevron-up" : "fa-chevron-down"} ${mutedTextClass}` })),
      /* @__PURE__ */ React.createElement("div", { className: `space-y-6 border-t px-6 pb-6 pt-5 ${isDarkTheme ? "border-gray-700" : "border-gray-200"}` }, /* @__PURE__ */ React.createElement("section", { "aria-labelledby": "discovery-stages-title" }, /* @__PURE__ */ React.createElement("h3", { id: "discovery-stages-title", className: `text-base font-semibold ${headingClass}` }, "Discovery stages"), discoveryPhaseEntries.length === 0 ? /* @__PURE__ */ React.createElement("p", { className: `mt-2 text-sm ${mutedTextClass}` }, "Stages appear here when discovery runs.") : /* @__PURE__ */ React.createElement("ol", { className: "mt-3 grid gap-3 xl:grid-cols-2" }, discoveryPhaseEntries.map((phase, index) => {
        const phaseStatus = String(phase.status || "pending").trim().toLowerCase();
        const phaseStatusLabel = phaseStatus === "active" ? "In progress" : phaseStatus === "completed" ? "Done" : phaseStatus === "error" ? "Issue" : phaseStatus === "aborted" ? "Stopped" : "Not started";
        const phaseShellClass = phaseStatus === "active" ? isDarkTheme ? "bg-indigo-950/40 border-indigo-700" : "bg-indigo-50 border-indigo-200" : phaseStatus === "error" ? isDarkTheme ? "bg-rose-950/35 border-rose-700" : "bg-rose-50 border-rose-200" : phaseStatus === "aborted" ? isDarkTheme ? "bg-orange-950/35 border-orange-700" : "bg-orange-50 border-orange-200" : isDarkTheme ? "bg-gray-900 border-gray-700" : "bg-white border-gray-200";
        const phaseIconClass = phaseStatus === "active" ? `fas fa-circle-notch fa-spin ${isDarkTheme ? "text-indigo-300" : "text-indigo-600"}` : phaseStatus === "completed" ? `fas fa-check-circle ${isDarkTheme ? "text-emerald-300" : "text-emerald-600"}` : phaseStatus === "error" ? `fas fa-exclamation-circle ${isDarkTheme ? "text-rose-300" : "text-rose-600"}` : phaseStatus === "aborted" ? `fas fa-stop-circle ${isDarkTheme ? "text-orange-300" : "text-orange-600"}` : `far fa-circle ${mutedTextClass}`;
        const phaseStatusTextClass = phaseStatus === "active" ? isDarkTheme ? "text-indigo-200" : "text-indigo-800" : phaseStatus === "completed" ? isDarkTheme ? "text-emerald-200" : "text-emerald-800" : phaseStatus === "error" ? isDarkTheme ? "text-rose-200" : "text-rose-800" : phaseStatus === "aborted" ? isDarkTheme ? "text-orange-200" : "text-orange-800" : mutedTextClass;
        const phaseNarrative = phaseStatus === "active" ? progress.description || phase.last_detail || phase.description : phase.last_detail || phase.description || "";
        return /* @__PURE__ */ React.createElement("li", { key: phase.key || index, "data-testid": "discovery-stage", className: `rounded-xl border px-4 py-3 ${phaseShellClass}` }, /* @__PURE__ */ React.createElement("div", { className: "flex items-start gap-3" }, /* @__PURE__ */ React.createElement("i", { "aria-hidden": "true", className: `${phaseIconClass} mt-0.5` }), /* @__PURE__ */ React.createElement("div", { className: "min-w-0 flex-1" }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-wrap items-baseline justify-between gap-x-3 gap-y-1" }, /* @__PURE__ */ React.createElement("span", { className: `text-sm font-semibold ${headingClass}` }, index + 1, ". ", phase.label), /* @__PURE__ */ React.createElement("span", { className: `text-xs font-semibold ${phaseStatusTextClass}` }, phaseStatusLabel)), phaseNarrative && /* @__PURE__ */ React.createElement("p", { className: `mt-1 text-xs leading-5 ${subtextClass}` }, phaseNarrative), phase.started_at && /* @__PURE__ */ React.createElement("p", { className: `mt-1 text-xs ${mutedTextClass}` }, "Started ", formatMissionDateTime(phase.started_at, "just now"), phase.completed_at ? `, finished ${formatMissionDateTime(phase.completed_at, "time not recorded")}` : ""))));
      }))), /* @__PURE__ */ React.createElement("section", { "aria-labelledby": "discovery-log-title" }, /* @__PURE__ */ React.createElement("h3", { id: "discovery-log-title", className: `text-base font-semibold ${headingClass}` }, "Discovery log"), messages.length === 0 ? /* @__PURE__ */ React.createElement("p", { className: `mt-2 text-sm ${mutedTextClass}` }, "The log fills in while discovery runs.") : /* @__PURE__ */ React.createElement("div", { className: `mt-3 overflow-hidden rounded-lg border ${isDarkTheme ? "border-gray-700" : "border-gray-200"}` }, /* @__PURE__ */ React.createElement(
        "div",
        {
          ref: discoveryLogContainerRef,
          className: "p-4 overflow-y-auto scroll-container",
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
      ))))
    ))))), discoveryActionDialog && /* @__PURE__ */ React.createElement(
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
          onClick: (event) => event.stopPropagation(),
          onKeyDown: (event) => handleDialogKeyDown(event, closeDiscoveryActionDialog),
          tabIndex: -1
        },
        /* @__PURE__ */ React.createElement("div", { className: `rounded-t-2xl border-b px-6 py-5 ${isDarkTheme ? "border-gray-700" : "border-gray-200"} ${discoveryActionDialog.tone === "rose" ? isDarkTheme ? "bg-rose-950/40" : "bg-rose-50" : isDarkTheme ? "bg-amber-950/40" : "bg-amber-50"}` }, /* @__PURE__ */ React.createElement("div", { className: "flex items-start justify-between gap-4" }, /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("div", { className: `text-xs uppercase tracking-wider ${mutedTextClass}` }, discoveryActionDialog.eyebrow), /* @__PURE__ */ React.createElement("h2", { id: "discovery-action-dialog-title", className: `mt-2 text-lg font-semibold ${headingClass}` }, /* @__PURE__ */ React.createElement("i", { className: `fas ${discoveryActionDialog.icon} mr-2 ${discoveryActionDialog.tone === "rose" ? "text-rose-600" : "text-amber-600"}` }), discoveryActionDialog.title)), /* @__PURE__ */ React.createElement(
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
          onClick: (event) => event.stopPropagation(),
          onKeyDown: (event) => handleDialogKeyDown(event, closeSummaryActionDialog),
          tabIndex: -1
        },
        /* @__PURE__ */ React.createElement("div", { className: `rounded-t-2xl border-b px-6 py-5 ${isDarkTheme ? "border-gray-700" : "border-gray-200"} ${summaryActionDialog.tone === "rose" ? isDarkTheme ? "bg-rose-950/40" : "bg-rose-50" : isDarkTheme ? "bg-amber-950/40" : "bg-amber-50"}` }, /* @__PURE__ */ React.createElement("div", { className: "flex items-start justify-between gap-4" }, /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("div", { className: `text-xs uppercase tracking-wider ${mutedTextClass}` }, summaryActionDialog.eyebrow), /* @__PURE__ */ React.createElement("h2", { id: "summary-action-dialog-title", className: `mt-2 text-lg font-semibold ${headingClass}` }, /* @__PURE__ */ React.createElement("i", { className: `fas ${summaryActionDialog.icon} mr-2 ${summaryActionDialog.tone === "rose" ? "text-rose-600" : "text-amber-600"}` }), summaryActionDialog.title)), /* @__PURE__ */ React.createElement(
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
    ), renderCapabilityDetailModal(), isConnectionModalOpen && (() => {
      var _a2, _b2, _c2, _d2, _e2, _f2, _g2;
      const info = connectionInfo;
      const hasError = !!info && (!!info.error || connectionInfoStatus === "error");
      const mcpConfigured = !!((_a2 = info == null ? void 0 : info.mcp) == null ? void 0 : _a2.configured);
      const llmConfigured = !!((_b2 = info == null ? void 0 : info.llm) == null ? void 0 : _b2.configured);
      const mcpEndpoint = String(((_c2 = info == null ? void 0 : info.mcp) == null ? void 0 : _c2.endpoint) || "").trim();
      const llmModel = String(((_d2 = info == null ? void 0 : info.llm) == null ? void 0 : _d2.model) || "").trim();
      const llmSavedAs = String(((_e2 = info == null ? void 0 : info.llm) == null ? void 0 : _e2.display_label) || "").trim();
      const llmEndpoint = String(((_f2 = info == null ? void 0 : info.llm) == null ? void 0 : _f2.endpoint) || "").trim();
      const headingClass2 = isDarkTheme ? "text-gray-100" : "text-gray-900";
      const labelClass = isDarkTheme ? "text-gray-400" : "text-gray-600";
      const valueClass = isDarkTheme ? "text-gray-100" : "text-gray-900";
      const dividerClass = isDarkTheme ? "border-gray-700" : "border-gray-200";
      const iconClass = isDarkTheme ? "text-indigo-300" : "text-indigo-600";
      const openSettingsFromPopover = () => {
        setIsConnectionModalOpen(false);
        openSettings();
      };
      const renderSetupPill = (configured) => /* @__PURE__ */ React.createElement("span", { className: `inline-flex flex-shrink-0 items-center gap-1.5 rounded-full border px-2 py-0.5 text-xs font-medium ${configured ? isDarkTheme ? "border-green-800 bg-green-950 text-green-200" : "border-green-200 bg-green-50 text-green-800" : isDarkTheme ? "border-gray-700 bg-gray-800 text-gray-300" : "border-gray-200 bg-gray-100 text-gray-700"}` }, /* @__PURE__ */ React.createElement("span", { "aria-hidden": "true", className: `h-1.5 w-1.5 rounded-full ${configured ? "bg-green-500" : "bg-gray-400"}` }), configured ? "Set up" : "Not set up");
      const renderDetailRow = (label, value, { mono = false } = {}) => /* @__PURE__ */ React.createElement("div", { className: "grid grid-cols-[5.5rem,1fr] gap-2" }, /* @__PURE__ */ React.createElement("dt", { className: `text-xs ${labelClass}` }, label), /* @__PURE__ */ React.createElement("dd", { className: `min-w-0 break-all text-xs ${valueClass} ${mono ? "font-mono" : "font-medium"}` }, value));
      const renderSection = (title, icon, configured, details, missingHint) => /* @__PURE__ */ React.createElement("section", { className: `py-3 first:pt-0 last:pb-0 border-b last:border-b-0 ${dividerClass}` }, /* @__PURE__ */ React.createElement("div", { className: "flex items-center justify-between gap-2" }, /* @__PURE__ */ React.createElement("h3", { className: `flex items-center gap-2 text-sm font-semibold ${headingClass2}` }, /* @__PURE__ */ React.createElement("i", { className: `fas ${icon} text-xs ${iconClass}`, "aria-hidden": "true" }), title), renderSetupPill(configured)), configured ? /* @__PURE__ */ React.createElement("dl", { className: "mt-2 space-y-1.5" }, details) : /* @__PURE__ */ React.createElement("p", { className: `mt-2 text-xs ${labelClass}` }, missingHint));
      return /* @__PURE__ */ React.createElement(
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
            onKeyDown: (event) => handleDialogKeyDown(event, () => setIsConnectionModalOpen(false)),
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
              "aria-hidden": "true",
              className: `absolute -top-2 w-4 h-4 rotate-45 border-l border-t ${isDarkTheme ? "bg-gray-800 border-gray-600" : "bg-white border-gray-200"}`,
              style: { left: `${connectionModalPosition.pointerLeft}px` }
            }
          ),
          /* @__PURE__ */ React.createElement("div", { className: `relative z-10 flex items-start justify-between gap-3 rounded-t-xl border-b px-4 py-3 ${isDarkTheme ? "border-gray-700 bg-gray-800" : "border-gray-200 bg-white"}` }, /* @__PURE__ */ React.createElement("div", { className: "min-w-0" }, /* @__PURE__ */ React.createElement("h2", { id: "connection-details-title", className: `text-base font-semibold ${headingClass2}` }, "Connection Details"), info && /* @__PURE__ */ React.createElement("p", { className: `mt-0.5 flex items-center gap-1.5 text-xs ${labelClass}` }, /* @__PURE__ */ React.createElement("span", { "aria-hidden": "true", className: `h-2 w-2 flex-shrink-0 rounded-full ${headerConnectionMeta.dotClass}` }), headerConnectionMeta.label)), /* @__PURE__ */ React.createElement(
            "button",
            {
              type: "button",
              autoFocus: true,
              onClick: () => setIsConnectionModalOpen(false),
              className: `-mr-1 rounded-md p-1.5 transition-colors ${isDarkTheme ? "text-gray-400 hover:bg-gray-700 hover:text-gray-100" : "text-gray-500 hover:bg-gray-100 hover:text-gray-900"}`,
              "aria-label": "Close connection details"
            },
            /* @__PURE__ */ React.createElement("i", { className: "fas fa-times", "aria-hidden": "true" })
          )),
          /* @__PURE__ */ React.createElement("div", { className: "px-4 py-3" }, !info ? /* @__PURE__ */ React.createElement("div", { role: "status", className: `flex items-center justify-center gap-2 py-6 text-xs ${labelClass}` }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-spinner fa-spin", "aria-hidden": "true" }), "Loading connection details...") : hasError ? /* @__PURE__ */ React.createElement("div", { role: "alert", className: `text-sm ${isDarkTheme ? "text-red-300" : "text-red-700"}` }, "The app could not read its connection settings. Check the server logs, then try again.") : /* @__PURE__ */ React.createElement(React.Fragment, null, renderSection(
            "Splunk MCP server",
            "fa-server",
            mcpConfigured,
            mcpEndpoint ? renderDetailRow("Address", mcpEndpoint, { mono: true }) : null,
            "Add the server address and token in Settings."
          ), renderSection(
            "AI model",
            "fa-brain",
            llmConfigured,
            /* @__PURE__ */ React.createElement(React.Fragment, null, llmSavedAs && llmSavedAs !== llmModel && renderDetailRow("Saved as", llmSavedAs), renderDetailRow("Provider", formatProviderName((_g2 = info == null ? void 0 : info.llm) == null ? void 0 : _g2.provider)), llmModel && renderDetailRow("Model", llmModel, { mono: true }), llmEndpoint && renderDetailRow("Endpoint", llmEndpoint)),
            "Choose a provider and model in Settings."
          ))),
          /* @__PURE__ */ React.createElement("div", { className: `flex justify-end gap-2 rounded-b-xl border-t px-4 py-3 ${dividerClass}` }, hasError && /* @__PURE__ */ React.createElement(
            "button",
            {
              type: "button",
              onClick: loadConnectionInfo,
              className: `inline-flex items-center justify-center rounded-md border px-3 py-1.5 text-sm font-medium transition-colors ${secondaryButtonClass}`
            },
            "Try Again"
          ), /* @__PURE__ */ React.createElement(
            "button",
            {
              type: "button",
              onClick: openSettingsFromPopover,
              className: connectionInfoStatus === "connected" ? `inline-flex items-center justify-center rounded-md border px-3 py-1.5 text-sm font-medium transition-colors ${secondaryButtonClass}` : "inline-flex items-center justify-center rounded-md bg-indigo-600 px-3 py-1.5 text-sm font-medium text-white transition-colors hover:bg-indigo-700"
            },
            "Open Settings"
          ))
        )
      );
    })(), (isChatOpen || isChatTab) && /* @__PURE__ */ React.createElement(
      "div",
      {
        className: isChatTab ? "fixed inset-x-0 bottom-0 z-40" : "fixed inset-0 bg-black bg-opacity-50 z-50 overflow-y-auto p-3 sm:p-6",
        style: isChatTab ? { top: `${headerHeight}px` } : void 0
      },
      /* @__PURE__ */ React.createElement("div", { className: isChatTab ? `${workspaceShellWidthClass} mx-auto h-full px-4 sm:px-6 lg:px-8 py-6` : "min-h-full w-full flex items-center justify-center" }, /* @__PURE__ */ React.createElement("div", { className: `${isChatTab ? `h-full min-h-0 rounded-2xl shadow-2xl flex flex-col overflow-hidden ${isDarkTheme ? "bg-gray-800 border border-gray-700" : "bg-white border border-gray-200"}` : `rounded-xl shadow-2xl w-full max-w-4xl min-h-0 flex flex-col overflow-hidden ${isDarkTheme ? "bg-gray-800 border border-gray-700" : "bg-white"}`}`, style: isChatTab ? void 0 : windowedChatDialogStyle, role: "dialog", "aria-modal": isChatTab ? "false" : "true", "aria-labelledby": "chat-modal-title", onKeyDown: (event) => handleDialogKeyDown(event, closeChatSurface) }, /* @__PURE__ */ React.createElement("div", { className: `px-6 py-4 border-b flex justify-between items-center gap-4 ${isDarkTheme ? "border-gray-700" : "border-gray-200"}` }, /* @__PURE__ */ React.createElement("div", { className: "flex items-center" }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-comments text-xl text-indigo-600 mr-3", "aria-hidden": "true" }), /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("h2", { id: "chat-modal-title", className: `text-xl font-semibold ${isDarkTheme ? "text-gray-100" : "text-gray-900"}` }, "Chat"))), /* @__PURE__ */ React.createElement("div", { className: "flex items-center gap-1" }, /* @__PURE__ */ React.createElement(
        "button",
        {
          type: "button",
          onClick: () => setIsChatSettingsOpen(true),
          className: `rounded-md p-1.5 ${isDarkTheme ? "text-gray-300 hover:text-gray-100 hover:bg-gray-700" : "text-gray-500 hover:text-gray-700 hover:bg-gray-100"}`,
          title: "Chat settings",
          "aria-label": "Open chat settings"
        },
        /* @__PURE__ */ React.createElement("i", { className: "fas fa-cog", "aria-hidden": "true" })
      ), isChatTab ? /* @__PURE__ */ React.createElement(
        "button",
        {
          type: "button",
          onClick: () => exitChatFullscreen({ reopenModal: true }),
          className: `rounded-md p-1.5 ${isDarkTheme ? "text-gray-300 hover:text-gray-100 hover:bg-gray-700" : "text-gray-500 hover:text-gray-700 hover:bg-gray-100"}`,
          title: "Show chat in a window",
          "aria-label": "Show chat in a window"
        },
        /* @__PURE__ */ React.createElement("i", { className: "fas fa-compress-arrows-alt", "aria-hidden": "true" })
      ) : /* @__PURE__ */ React.createElement(
        "button",
        {
          type: "button",
          onClick: enterChatFullscreen,
          className: `rounded-md p-1.5 ${isDarkTheme ? "text-gray-300 hover:text-gray-100 hover:bg-gray-700" : "text-gray-500 hover:text-gray-700 hover:bg-gray-100"}`,
          title: "Open chat full screen",
          "aria-label": "Open chat full screen"
        },
        /* @__PURE__ */ React.createElement("i", { className: "fas fa-expand-arrows-alt", "aria-hidden": "true" })
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
          className: `rounded-md p-1.5 ${isDarkTheme ? "text-gray-300 hover:text-gray-100 hover:bg-gray-700" : "text-gray-500 hover:text-gray-700 hover:bg-gray-100"}`,
          title: "Clear chat",
          "aria-label": "Clear chat history"
        },
        /* @__PURE__ */ React.createElement("i", { className: "fas fa-trash", "aria-hidden": "true" })
      ), /* @__PURE__ */ React.createElement(
        "button",
        {
          type: "button",
          onClick: closeChatSurface,
          className: `rounded-md p-1.5 ${isDarkTheme ? "text-gray-300 hover:text-gray-100 hover:bg-gray-700" : "text-gray-500 hover:text-gray-700 hover:bg-gray-100"}`,
          "aria-label": "Close chat"
        },
        /* @__PURE__ */ React.createElement("i", { className: "fas fa-times text-xl", "aria-hidden": "true" })
      ))), /* @__PURE__ */ React.createElement("div", { className: `px-6 py-3 border-b flex items-center gap-3 ${isDarkTheme ? "border-gray-700 bg-gray-800" : "border-gray-200 bg-gray-50"}` }, /* @__PURE__ */ React.createElement("label", { htmlFor: "chat-mission-input", className: `text-xs font-semibold uppercase tracking-wide whitespace-nowrap ${mutedTextClass}` }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-bullseye mr-1", "aria-hidden": "true" }), "Goal"), /* @__PURE__ */ React.createElement(
        "input",
        {
          id: "chat-mission-input",
          type: "text",
          value: chatMission,
          maxLength: CHAT_MISSION_MAX_CHARS,
          onChange: (event) => setChatMission(event.target.value),
          placeholder: "Optional. What do you want to find out? For example, why sensor data stopped arriving",
          title: "The assistant keeps its searches, answers, and next steps focused on this goal.",
          className: `flex-1 min-w-0 px-3 py-1.5 text-sm rounded border ${isDarkTheme ? "bg-gray-900 border-gray-600 text-gray-100" : "bg-white border-gray-300 text-gray-900"}`
        }
      ), chatMission && /* @__PURE__ */ React.createElement(
        "button",
        {
          type: "button",
          onClick: () => setChatMission(""),
          className: `px-2 py-1 text-xs ${isDarkTheme ? "text-gray-300 hover:text-gray-100" : "text-gray-600 hover:text-gray-800"}`,
          "aria-label": "Clear chat goal",
          title: "Clear goal"
        },
        /* @__PURE__ */ React.createElement("i", { className: "fas fa-times" })
      )), /* @__PURE__ */ React.createElement("div", { className: `flex-1 min-h-0 overflow-y-auto p-6 ${isDarkTheme ? "bg-gray-900" : "bg-white"}` }, /* @__PURE__ */ React.createElement("div", { className: "space-y-4", style: fullscreenChatConversationStyle }, chatMessages.length === 0 && /* @__PURE__ */ React.createElement("div", { className: `text-center mt-12 ${isDarkTheme ? "text-gray-400" : "text-gray-500"}` }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-robot text-3xl mb-3", "aria-hidden": "true" }), /* @__PURE__ */ React.createElement("p", { className: `text-base font-medium ${headingClass}` }, "Ask about your Splunk environment"), /* @__PURE__ */ React.createElement("p", { className: "text-sm mt-2" }, "For example: which indexes have the most data, what a search does, or how to write an SPL query.")), chatMessages.map((msg) => /* @__PURE__ */ React.createElement("div", { key: msg.id, className: `flex min-w-0 ${msg.type === "user" ? "justify-end" : "justify-start"}` }, /* @__PURE__ */ React.createElement("div", { className: `max-w-3xl min-w-0 p-4 rounded-lg ${msg.type === "user" ? "bg-indigo-600 text-white" : msg.type === "error" ? isDarkTheme ? "bg-red-900 text-red-100 border border-red-700" : "bg-red-50 text-red-800 border border-red-200" : msg.type === "warning" ? isDarkTheme ? "bg-amber-900 text-amber-100 border border-amber-700" : "bg-amber-50 text-amber-900 border border-amber-200" : isDarkTheme ? "bg-gray-700 text-gray-100 border border-gray-600" : "bg-gray-100 text-gray-800"}`, style: getChatBubbleStyle(msg.type) }, msg.type === "user" && /* @__PURE__ */ React.createElement("div", { className: "flex items-start min-w-0" }, /* @__PURE__ */ React.createElement("div", { className: "flex-1 min-w-0" }, /* @__PURE__ */ React.createElement("p", { className: "whitespace-pre-wrap break-words", style: { overflowWrap: "anywhere" } }, msg.content)), /* @__PURE__ */ React.createElement("i", { className: "fas fa-user ml-3 mt-1", "aria-hidden": "true" })), msg.type === "assistant" && /* @__PURE__ */ React.createElement("div", { className: "flex items-start min-w-0" }, /* @__PURE__ */ React.createElement("i", { className: `fas fa-robot mr-3 mt-1 ${isDarkTheme ? "text-indigo-300" : "text-indigo-600"}`, "aria-hidden": "true" }), /* @__PURE__ */ React.createElement("div", { className: "flex-1 min-w-0" }, /* @__PURE__ */ React.createElement("p", { className: "whitespace-pre-wrap break-words", style: { overflowWrap: "anywhere" } }, msg.content), msg.spl_query && /* @__PURE__ */ React.createElement("details", { className: "mt-3", open: true }, /* @__PURE__ */ React.createElement("summary", { className: "cursor-pointer text-sm font-medium ui-link flex items-center" }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-code mr-2", "aria-hidden": "true" }), "Search that ran"), /* @__PURE__ */ React.createElement("div", { className: `mt-2 p-3 rounded-md border font-mono text-sm ${summaryCodeClass}` }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-col gap-2 sm:flex-row sm:items-start sm:justify-between mb-2" }, /* @__PURE__ */ React.createElement("span", { className: `text-xs font-sans font-semibold uppercase tracking-wide ${summaryLabelClass}` }, "SPL"), renderSplQueryActionButtons2(msg.spl_query, {
        originKind: "chat_assistant",
        originLabel: "Chat assistant response",
        sourceLabel: "Chat assistant response",
        contextExcerpt: msg.content,
        className: "sm:justify-end"
      })), /* @__PURE__ */ React.createElement("pre", { className: "whitespace-pre-wrap break-all" }, msg.spl_query))), !msg.spl_query && msg.spl_in_text && /* @__PURE__ */ React.createElement("details", { className: "mt-3" }, /* @__PURE__ */ React.createElement("summary", { className: `cursor-pointer text-sm font-medium flex items-center ${isDarkTheme ? "text-gray-300 hover:text-gray-100" : "text-gray-600 hover:text-gray-800"}` }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-code mr-2", "aria-hidden": "true" }), "Suggested search (not run)"), /* @__PURE__ */ React.createElement("div", { className: `mt-2 p-3 rounded-md border font-mono text-sm ${summaryCodeClass}` }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-col gap-2 sm:flex-row sm:items-start sm:justify-between mb-2" }, /* @__PURE__ */ React.createElement("span", { className: `text-xs font-sans font-semibold uppercase tracking-wide ${summaryLabelClass}` }, "SPL"), renderSplQueryActionButtons2(msg.spl_in_text, {
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
        /* @__PURE__ */ React.createElement("summary", { className: "cursor-pointer text-sm font-medium ui-link flex items-center" }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-puzzle-piece mr-2", "aria-hidden": "true" }), "Capability Evidence (", msg.capability_usage.length, ")"),
        /* @__PURE__ */ React.createElement("div", { className: "mt-2 space-y-3" }, msg.capability_usage.map((usage, usageIdx) => /* @__PURE__ */ React.createElement("div", { key: usageIdx, className: `rounded-lg border p-3 ${isDarkTheme ? "bg-gray-800 border-gray-700" : "bg-white border-gray-200"}` }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-wrap items-center gap-2 mb-2" }, /* @__PURE__ */ React.createElement("span", { className: `text-sm font-semibold ${headingClass}` }, usage.title || usage.name || "Capability"), usage.category && /* @__PURE__ */ React.createElement("span", { className: `inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium ${isDarkTheme ? "bg-gray-900 text-gray-200 border border-gray-600" : "bg-white text-gray-700 border border-gray-300"}` }, formatCapabilityCategoryLabel(usage.category)), usage.used_in && /* @__PURE__ */ React.createElement("span", { className: `inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium ${isDarkTheme ? "bg-gray-900 text-gray-200 border border-gray-600" : "bg-gray-100 text-gray-700 border border-gray-200"}` }, formatCapabilityUsageContextLabel(usage.used_in))), usage.contribution && /* @__PURE__ */ React.createElement("div", { className: `text-sm mb-2 ${subtextClass}` }, usage.contribution), renderCapabilityReusableQueryCards(usage), Array.isArray(usage.chunks) && usage.chunks.length > 0 && /* @__PURE__ */ React.createElement("div", { className: "space-y-2" }, usage.chunks.map((chunk, chunkIdx) => /* @__PURE__ */ React.createElement("div", { key: chunkIdx, className: `rounded border p-2 ${isDarkTheme ? "bg-gray-900 border-gray-700" : "bg-gray-50 border-gray-200"}` }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-wrap items-center justify-between gap-2 mb-1" }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-wrap items-center gap-2" }, /* @__PURE__ */ React.createElement("span", { className: `text-xs font-medium ${headingClass}` }, chunk.source || `artifact_${chunkIdx + 1}`), chunk.source_type && /* @__PURE__ */ React.createElement("span", { className: `inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium ${isDarkTheme ? "bg-gray-800 text-gray-200 border border-gray-600" : "bg-white text-gray-700 border border-gray-200"}` }, formatCapabilitySourceTypeLabel(chunk.source_type))), typeof chunk.score === "number" && /* @__PURE__ */ React.createElement("span", { className: `text-xs ${mutedTextClass}` }, "Match score ", chunk.score)), /* @__PURE__ */ React.createElement("div", { className: `text-xs whitespace-pre-wrap break-words ${subtextClass}`, style: { overflowWrap: "anywhere" } }, chunk.snippet)))))))
      ), msg.status_timeline && msg.status_timeline.length > 0 && /* @__PURE__ */ React.createElement("details", { className: "mt-3" }, /* @__PURE__ */ React.createElement("summary", { className: "cursor-pointer text-sm font-medium ui-link flex items-center" }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-tasks mr-2", "aria-hidden": "true" }), "Steps taken (", [msg.iterations ? countLabel(msg.iterations, "round") : "", msg.execution_time].filter(Boolean).join(", "), ")"), /* @__PURE__ */ React.createElement("div", { className: "mt-2 space-y-2" }, msg.status_timeline.map((status, idx) => /* @__PURE__ */ React.createElement("div", { key: idx, className: `flex items-center justify-between gap-3 px-3 py-2 rounded border-l-4 ${isDarkTheme ? "bg-gray-800 border-indigo-400" : "bg-white border-indigo-500"}` }, /* @__PURE__ */ React.createElement("span", { className: `text-sm ${isDarkTheme ? "text-gray-200" : "text-gray-700"}` }, status.action), /* @__PURE__ */ React.createElement("span", { className: `text-xs tabular-nums ${isDarkTheme ? "text-gray-400" : "text-gray-600"}` }, Number(status.time || 0).toFixed(1), "s"))))), msg.mcp_data && /* @__PURE__ */ React.createElement("details", { className: "mt-3" }, /* @__PURE__ */ React.createElement("summary", { className: `cursor-pointer text-sm ${isDarkTheme ? "text-gray-300 hover:text-gray-100" : "text-gray-600 hover:text-gray-800"}` }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-database mr-1", "aria-hidden": "true" }), "Show raw data"), /* @__PURE__ */ React.createElement("pre", { className: `mt-2 p-3 rounded text-xs overflow-x-auto ${isDarkTheme ? "bg-gray-800 text-gray-200" : "bg-gray-200 text-gray-800"}` }, JSON.stringify(msg.mcp_data, null, 2))), msg.has_follow_on && /* @__PURE__ */ React.createElement("div", { className: `mt-3 p-3 border rounded ${isDarkTheme ? "bg-indigo-900 border-indigo-700" : "bg-indigo-50 border-indigo-200"}` }, /* @__PURE__ */ React.createElement("div", { className: `text-xs font-semibold flex items-center mb-2 ${isDarkTheme ? "text-indigo-200" : "text-indigo-700"}` }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-arrow-right mr-1" }), /* @__PURE__ */ React.createElement("span", null, "Suggested next actions")), Array.isArray(msg.follow_on_actions) && msg.follow_on_actions.length > 0 ? /* @__PURE__ */ React.createElement("div", { className: "space-y-2" }, msg.follow_on_actions.map((action, idx) => {
        const actionLabel = typeof action === "string" ? action : action.label || action.prompt || "Follow-up action";
        const actionPrompt = typeof action === "string" ? action : action.prompt || action.label || "";
        return /* @__PURE__ */ React.createElement(
          "button",
          {
            key: idx,
            type: "button",
            onClick: () => actionPrompt && sendSuggestedQuery(actionPrompt),
            className: `w-full text-left rounded border px-3 py-2 transition-colors ${isDarkTheme ? "bg-indigo-950 border-indigo-700 hover:bg-indigo-800 text-indigo-100" : "bg-white border-indigo-200 hover:bg-indigo-100 text-indigo-900"}`,
            title: "Run this follow-up in chat"
          },
          /* @__PURE__ */ React.createElement("div", { className: "text-xs font-semibold" }, actionLabel),
          typeof action !== "string" && action.prompt && action.prompt !== actionLabel && /* @__PURE__ */ React.createElement("div", { className: `text-xs mt-1 ${isDarkTheme ? "text-indigo-200" : "text-indigo-700"}` }, action.prompt)
        );
      })) : /* @__PURE__ */ React.createElement("div", { className: `text-xs ${isDarkTheme ? "text-indigo-200" : "text-indigo-800"}` }, "Follow-up action available.")))), msg.type === "error" && /* @__PURE__ */ React.createElement("div", { className: "flex items-start min-w-0" }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-exclamation-triangle mr-3 mt-1 text-red-600" }), /* @__PURE__ */ React.createElement("p", { className: "flex-1 whitespace-pre-wrap break-words", style: { overflowWrap: "anywhere" } }, msg.content)), msg.type === "warning" && /* @__PURE__ */ React.createElement("div", { className: `flex items-start min-w-0 border-l-4 border-amber-400 p-4 rounded ${isDarkTheme ? "bg-amber-900" : "bg-amber-50"}` }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-exclamation-circle mr-3 mt-1 text-amber-600" }), /* @__PURE__ */ React.createElement("p", { className: `flex-1 whitespace-pre-wrap break-words ${isDarkTheme ? "text-amber-100" : "text-amber-800"}`, style: { overflowWrap: "anywhere" } }, msg.content)), /* @__PURE__ */ React.createElement("div", { className: "text-xs opacity-70 mt-2" }, new Date(msg.timestamp).toLocaleTimeString(void 0, { timeStyle: "short" }))))), isTyping && /* @__PURE__ */ React.createElement("div", { className: "flex justify-start" }, /* @__PURE__ */ React.createElement("div", { className: `p-4 rounded-lg border ${isDarkTheme ? "bg-gray-800 text-gray-200 border-gray-700" : "bg-gray-100 text-gray-800 border-gray-200"}`, role: "status", "aria-live": "polite" }, /* @__PURE__ */ React.createElement("div", { className: "flex items-center space-x-3" }, /* @__PURE__ */ React.createElement("i", { className: `fas fa-robot ${isDarkTheme ? "text-indigo-300" : "text-indigo-600"}`, "aria-hidden": "true" }), /* @__PURE__ */ React.createElement("div", { className: "flex space-x-1", "aria-hidden": "true" }, /* @__PURE__ */ React.createElement("div", { className: "w-2 h-2 bg-indigo-500 rounded-full motion-safe:animate-bounce" }), /* @__PURE__ */ React.createElement("div", { className: "w-2 h-2 bg-indigo-500 rounded-full motion-safe:animate-bounce", style: { animationDelay: "0.1s" } }), /* @__PURE__ */ React.createElement("div", { className: "w-2 h-2 bg-indigo-500 rounded-full motion-safe:animate-bounce", style: { animationDelay: "0.2s" } })), /* @__PURE__ */ React.createElement("span", { className: "sr-only" }, "The assistant is working."), chatStatus && /* @__PURE__ */ React.createElement("span", { className: `text-sm ml-2 ${isDarkTheme ? "text-gray-300" : "text-gray-600"}` }, chatStatus)))), /* @__PURE__ */ React.createElement("div", { ref: chatEndRef }))), /* @__PURE__ */ React.createElement("div", { className: `px-6 py-4 border-t ${isDarkTheme ? "border-gray-700 bg-gray-800" : "border-gray-200 bg-white"}` }, /* @__PURE__ */ React.createElement("div", { className: "mb-3" }, /* @__PURE__ */ React.createElement("div", { className: "flex items-center justify-between mb-2" }, /* @__PURE__ */ React.createElement("p", { className: `text-xs font-semibold uppercase tracking-wide ${isDarkTheme ? "text-gray-300" : "text-gray-600"}` }, "Suggested Questions"), /* @__PURE__ */ React.createElement("div", { className: "flex items-center gap-3" }, /* @__PURE__ */ React.createElement(
        "button",
        {
          type: "button",
          onClick: () => setShowSuggestedQueries((prev) => !prev),
          className: "text-xs ui-link flex items-center",
          title: showSuggestedQueries ? "Hide suggested questions" : "Show suggested questions",
          "aria-label": showSuggestedQueries ? "Hide suggested questions" : "Show suggested questions",
          "aria-expanded": showSuggestedQueries,
          "aria-controls": "suggested-queries-panel"
        },
        /* @__PURE__ */ React.createElement("i", { className: `fas ${showSuggestedQueries ? "fa-chevron-up" : "fa-chevron-down"}`, "aria-hidden": "true" })
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
          title: "Ask this now",
          "aria-label": `Ask now: ${query}`
        },
        /* @__PURE__ */ React.createElement("i", { className: "fas fa-play", "aria-hidden": "true" })
      ))))), /* @__PURE__ */ React.createElement("div", { className: "flex gap-3" }, /* @__PURE__ */ React.createElement(
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
          className: `flex-1 p-3 border rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-transparent resize-none ${isDarkTheme ? "bg-gray-900 border-gray-600 text-gray-100" : "bg-white border-gray-300 text-gray-900"}`,
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
          className: `px-5 py-3 rounded-lg font-medium ${chatInput.trim() && !isTyping ? "bg-indigo-600 hover:bg-indigo-700 text-white" : isDarkTheme ? "bg-gray-700 text-gray-400 cursor-not-allowed" : "bg-gray-300 text-gray-500 cursor-not-allowed"}`
        },
        /* @__PURE__ */ React.createElement("i", { className: "fas fa-paper-plane", "aria-hidden": "true" })
      )), /* @__PURE__ */ React.createElement("p", { className: `text-xs mt-2 ${isDarkTheme ? "text-gray-400" : "text-gray-500"}` }, "Press Enter to send and Shift+Enter for a new line. The conversation is kept until you clear it."))))
    ), isChatSettingsOpen && (() => {
      const closeChatSettings = () => setIsChatSettingsOpen(false);
      const sectionClass = `rounded-lg border p-5 ${isDarkTheme ? "bg-gray-900 border-gray-700" : "bg-white border-gray-200"}`;
      const sectionTitleClass = `text-base font-semibold mb-4 flex items-center ${headingClass}`;
      const sectionIconClass = `mr-2 ${isDarkTheme ? "text-indigo-300" : "text-indigo-600"}`;
      const fieldLabelClass = `block text-sm font-medium mb-2 ${isDarkTheme ? "text-gray-200" : "text-gray-700"}`;
      const fieldHintClass = `text-xs mt-2 ${summaryLabelClass}`;
      const formatTokenCount = (value) => Number(value).toLocaleString("en-US");
      const chatMaxTokens = Number(chatSettings == null ? void 0 : chatSettings.max_tokens) || 0;
      const connectionMaxTokens = Number(activeLlmTuning == null ? void 0 : activeLlmTuning.max_tokens) || 0;
      const tokenLimitHint = connectionMaxTokens > 0 ? chatMaxTokens > connectionMaxTokens ? `The current AI connection allows up to ${formatTokenCount(connectionMaxTokens)} tokens, so answers stop at ${formatTokenCount(connectionMaxTokens)}.` : `Answers stop at ${formatTokenCount(chatMaxTokens)} tokens. The current AI connection allows up to ${formatTokenCount(connectionMaxTokens)}.` : "Answers stop at this length or at the AI connection limit, whichever is lower.";
      const hasConnectionTemperature = activeLlmTuning && activeLlmTuning.temperature !== null && activeLlmTuning.temperature !== void 0;
      const renderRange = ({ id, label, settingKey, min, max, step = 1, minLabel, maxLabel, parse = (value) => parseInt(value, 10), fallback, disabled = false, hint = null }) => {
        var _a2;
        return /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("label", { htmlFor: id, className: fieldLabelClass }, label), /* @__PURE__ */ React.createElement(
          "input",
          {
            id,
            type: "range",
            min,
            max,
            step,
            value: (_a2 = chatSettings[settingKey]) != null ? _a2 : fallback,
            onChange: (e) => updateSetting(settingKey, parse(e.target.value)),
            className: "w-full",
            disabled
          }
        ), /* @__PURE__ */ React.createElement("div", { className: `flex justify-between text-xs mt-1 ${summaryLabelClass}`, "aria-hidden": "true" }, /* @__PURE__ */ React.createElement("span", null, minLabel), /* @__PURE__ */ React.createElement("span", null, maxLabel)), hint && /* @__PURE__ */ React.createElement("p", { className: fieldHintClass }, hint));
      };
      const renderToggle = ({ id, label, description, settingKey }) => /* @__PURE__ */ React.createElement("label", { htmlFor: id, className: `flex items-center justify-between gap-4 rounded-md border p-3 cursor-pointer ${isDarkTheme ? "border-gray-700 bg-gray-800" : "border-gray-200 bg-gray-50"}` }, /* @__PURE__ */ React.createElement("span", null, /* @__PURE__ */ React.createElement("span", { className: `block text-sm font-medium ${headingClass}` }, label), /* @__PURE__ */ React.createElement("span", { className: `block text-xs mt-0.5 ${summaryLabelClass}` }, description)), /* @__PURE__ */ React.createElement(
        "input",
        {
          id,
          type: "checkbox",
          checked: !!chatSettings[settingKey],
          onChange: (e) => updateSetting(settingKey, e.target.checked),
          className: "h-4 w-4 flex-shrink-0"
        }
      ));
      return /* @__PURE__ */ React.createElement("div", { className: "fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4", onClick: closeChatSettings }, /* @__PURE__ */ React.createElement("div", { className: `chat-settings-modal-shell rounded-xl shadow-2xl w-full max-w-3xl h-5/6 flex flex-col ${isDarkTheme ? "bg-gray-800 border border-gray-700" : "bg-white"}`, role: "dialog", "aria-modal": "true", "aria-labelledby": "chat-settings-title", onClick: (event) => event.stopPropagation(), onKeyDown: (event) => handleDialogKeyDown(event, closeChatSettings) }, /* @__PURE__ */ React.createElement("div", { className: `px-6 py-4 border-b flex justify-between items-center gap-4 ${isDarkTheme ? "border-gray-700" : "border-gray-200"}` }, /* @__PURE__ */ React.createElement("div", { className: "flex items-center min-w-0" }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-cog text-xl text-indigo-600 mr-3", "aria-hidden": "true" }), /* @__PURE__ */ React.createElement("div", { className: "min-w-0" }, /* @__PURE__ */ React.createElement("h2", { id: "chat-settings-title", className: `text-xl font-semibold ${headingClass}` }, "Chat Settings"), /* @__PURE__ */ React.createElement("p", { className: `text-sm mt-0.5 ${mutedTextClass}` }, "How the assistant searches and answers."))), /* @__PURE__ */ React.createElement("div", { className: "flex items-center gap-2" }, /* @__PURE__ */ React.createElement(
        "button",
        {
          type: "button",
          onClick: resetChatSettings,
          className: `inline-flex items-center gap-1.5 rounded-md border px-3 py-1.5 text-sm font-medium transition-colors ${secondaryButtonClass}`,
          title: "Reset to defaults"
        },
        /* @__PURE__ */ React.createElement("i", { className: "fas fa-undo", "aria-hidden": "true" }),
        "Reset"
      ), /* @__PURE__ */ React.createElement(
        "button",
        {
          type: "button",
          onClick: closeChatSettings,
          autoFocus: true,
          className: `rounded-md p-1.5 ${isDarkTheme ? "text-gray-300 hover:text-gray-100 hover:bg-gray-700" : "text-gray-500 hover:text-gray-700 hover:bg-gray-100"}`,
          "aria-label": "Close chat settings"
        },
        /* @__PURE__ */ React.createElement("i", { className: "fas fa-times text-xl", "aria-hidden": "true" })
      ))), /* @__PURE__ */ React.createElement("div", { className: "flex-1 overflow-y-auto p-6 space-y-5" }, chatSettings && /* @__PURE__ */ React.createElement(React.Fragment, null, /* @__PURE__ */ React.createElement("section", { className: sectionClass, "aria-labelledby": "chat-settings-limits-title" }, /* @__PURE__ */ React.createElement("h3", { id: "chat-settings-limits-title", className: sectionTitleClass }, /* @__PURE__ */ React.createElement("i", { className: `fas fa-stopwatch ${sectionIconClass}`, "aria-hidden": "true" }), "Answer Limits"), /* @__PURE__ */ React.createElement("div", { className: "space-y-5" }, renderRange({ id: "chat-setting-max-execution-time", label: `Time limit per answer: ${chatSettings.max_execution_time} seconds`, settingKey: "max_execution_time", min: 30, max: 300, minLabel: "30 s", maxLabel: "300 s" }), renderRange({ id: "chat-setting-max-iterations", label: `Max search rounds per answer: ${chatSettings.max_iterations}`, settingKey: "max_iterations", min: 1, max: 10, minLabel: "1", maxLabel: "10" }), renderRange({ id: "chat-setting-discovery-freshness", label: `Use discovery results up to ${countLabel(chatSettings.discovery_freshness_days, "day")} old`, settingKey: "discovery_freshness_days", min: 1, max: 30, minLabel: "1 day", maxLabel: "30 days" }))), /* @__PURE__ */ React.createElement("section", { className: sectionClass, "aria-labelledby": "chat-settings-model-title" }, /* @__PURE__ */ React.createElement("h3", { id: "chat-settings-model-title", className: sectionTitleClass }, /* @__PURE__ */ React.createElement("i", { className: `fas fa-brain ${sectionIconClass}`, "aria-hidden": "true" }), "AI Model"), /* @__PURE__ */ React.createElement("div", { className: "space-y-5" }, /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("label", { htmlFor: "chat-setting-max-tokens", className: fieldLabelClass }, "Max response length (tokens)"), /* @__PURE__ */ React.createElement(
        "input",
        {
          id: "chat-setting-max-tokens",
          type: "number",
          min: "1000",
          max: "128000",
          value: chatSettings.max_tokens,
          onChange: (e) => updateSetting("max_tokens", parseInt(e.target.value, 10)),
          "aria-describedby": "chat-setting-max-tokens-hint",
          className: `w-full px-3 py-2 border rounded-md ${isDarkTheme ? "bg-gray-950 border-gray-600 text-gray-100" : "bg-white border-gray-300 text-gray-900"}`
        }
      ), /* @__PURE__ */ React.createElement("p", { id: "chat-setting-max-tokens-hint", "data-testid": "chat-settings-token-hint", className: fieldHintClass }, tokenLimitHint)), renderRange({
        id: "chat-setting-temperature",
        label: `Temperature: ${Number(chatSettings.temperature || 0).toFixed(1)}`,
        settingKey: "temperature",
        min: 0,
        max: 2,
        step: 0.1,
        parse: (value) => parseFloat(value),
        minLabel: "0.0 (focused)",
        maxLabel: "2.0 (creative)",
        hint: hasConnectionTemperature ? `The AI connection default is ${activeLlmTuning.temperature}. Moving the slider overrides it until the server restarts.` : null
      }), renderRange({ id: "chat-setting-context-history", label: `Messages remembered: ${chatSettings.context_history}`, settingKey: "context_history", min: 0, max: 20, minLabel: "0", maxLabel: "20" }))), /* @__PURE__ */ React.createElement("section", { className: sectionClass, "aria-labelledby": "chat-settings-retries-title" }, /* @__PURE__ */ React.createElement("h3", { id: "chat-settings-retries-title", className: sectionTitleClass }, /* @__PURE__ */ React.createElement("i", { className: `fas fa-redo ${sectionIconClass}`, "aria-hidden": "true" }), "Retries and Sampling"), /* @__PURE__ */ React.createElement("div", { className: "space-y-5" }, renderRange({ id: "chat-setting-max-retry-delay", label: `Max retry delay: ${chatSettings.max_retry_delay} seconds`, settingKey: "max_retry_delay", min: 10, max: 600, minLabel: "10 s", maxLabel: "600 s" }), renderRange({ id: "chat-setting-max-retries", label: `Max retries: ${chatSettings.max_retries}`, settingKey: "max_retries", min: 1, max: 10, minLabel: "1", maxLabel: "10" }), renderRange({ id: "chat-setting-query-sample-size", label: `Sample rows per search: ${chatSettings.query_sample_size}`, settingKey: "query_sample_size", min: 1, max: 10, minLabel: "1", maxLabel: "10" }))), /* @__PURE__ */ React.createElement("section", { className: sectionClass, "aria-labelledby": "chat-settings-quality-title" }, /* @__PURE__ */ React.createElement("h3", { id: "chat-settings-quality-title", className: sectionTitleClass }, /* @__PURE__ */ React.createElement("i", { className: `fas fa-check-circle ${sectionIconClass}`, "aria-hidden": "true" }), "Answer Quality"), /* @__PURE__ */ React.createElement("div", { className: "space-y-5" }, renderRange({ id: "chat-setting-quality-threshold", label: `Minimum quality score: ${chatSettings.quality_threshold}`, settingKey: "quality_threshold", min: 0, max: 100, minLabel: "0 (permissive)", maxLabel: "100 (strict)" }), renderRange({ id: "chat-setting-convergence", label: `Stop after ${chatSettings.convergence_detection} rounds without progress`, settingKey: "convergence_detection", min: 3, max: 10, minLabel: "3", maxLabel: "10" }))), /* @__PURE__ */ React.createElement("section", { className: sectionClass, "aria-labelledby": "chat-settings-extras-title" }, /* @__PURE__ */ React.createElement("h3", { id: "chat-settings-extras-title", className: sectionTitleClass }, /* @__PURE__ */ React.createElement("i", { className: `fas fa-puzzle-piece ${sectionIconClass}`, "aria-hidden": "true" }), "Extras"), /* @__PURE__ */ React.createElement("div", { className: "space-y-4" }, renderToggle({ id: "chat-setting-splunk-augmentation", label: "Built-in Splunk Answers", description: "Answer common Splunk questions with built-in routines instead of the AI model", settingKey: "enable_splunk_augmentation" }), renderToggle({ id: "chat-setting-rag-context", label: "Search the Knowledge Base", description: "Add matching passages from your reports and imported documents to chat answers", settingKey: "enable_rag_context" }), renderRange({
        id: "chat-setting-rag-max-chunks",
        label: `Passages per answer: ${chatSettings.rag_max_chunks || 3}`,
        settingKey: "rag_max_chunks",
        min: 1,
        max: 6,
        fallback: 3,
        minLabel: "1",
        maxLabel: "6",
        disabled: !chatSettings.enable_rag_context,
        hint: "Install the Knowledge Base on the Capabilities tab and turn it on first."
      }))))), /* @__PURE__ */ React.createElement("div", { className: `px-6 py-3 border-t rounded-b-xl ${isDarkTheme ? "border-gray-700 bg-gray-900" : "border-gray-200 bg-gray-50"}` }, /* @__PURE__ */ React.createElement("p", { className: `text-sm text-center ${mutedTextClass}` }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-info-circle mr-2", "aria-hidden": "true" }), "Changes apply right away and reset when the server restarts."))));
    })(), isReportFullViewOpen && (reportContent == null ? void 0 : reportContent.type) === "image" && /* @__PURE__ */ React.createElement(
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
          onClick: (event) => event.stopPropagation(),
          onKeyDown: (event) => handleDialogKeyDown(event, () => setIsReportFullViewOpen(false)),
          tabIndex: -1
        },
        /* @__PURE__ */ React.createElement("div", { className: `flex items-center justify-between gap-4 px-6 py-4 border-b ${isDarkTheme ? "border-gray-800" : "border-gray-200"}` }, /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("div", { className: `text-xs uppercase tracking-wider ${mutedTextClass}` }, "Full View"), /* @__PURE__ */ React.createElement("div", { className: `mt-1 text-lg font-semibold ${headingClass}` }, selectedReport)), /* @__PURE__ */ React.createElement("div", { className: "flex items-center gap-3" }, /* @__PURE__ */ React.createElement(
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
      /* @__PURE__ */ React.createElement("div", { className: isSummaryTab ? `${workspaceShellWidthClass} mx-auto h-full px-4 sm:px-6 lg:px-8 py-6` : "min-h-full w-full flex items-center justify-center" }, /* @__PURE__ */ React.createElement("div", { className: `${isSummaryTab ? `${isDarkTheme ? "bg-gray-900 text-gray-100 border border-gray-700" : "bg-white text-gray-900 border border-gray-200"} h-full rounded-2xl shadow-2xl flex flex-col overflow-hidden` : `${isDarkTheme ? "bg-gray-900 text-gray-100" : "bg-white text-gray-900"} rounded-xl shadow-2xl w-full max-w-7xl min-h-0 flex flex-col overflow-hidden`}`, style: isSummaryTab ? void 0 : windowedSummaryDialogStyle, role: "dialog", "aria-modal": isSummaryTab ? "false" : "true", "aria-labelledby": "summary-modal-title", onKeyDown: (event) => handleDialogKeyDown(event, closeSummaryModal) }, /* @__PURE__ */ React.createElement("div", { className: `px-6 py-4 border-b flex justify-between items-center gap-4 ${isDarkTheme ? "border-gray-700" : "border-gray-200"} ${isSummaryTab ? "rounded-t-2xl" : "rounded-t-xl"}` }, /* @__PURE__ */ React.createElement("div", { className: "flex items-center min-w-0" }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-file-alt text-xl text-indigo-600 mr-3", "aria-hidden": "true" }), /* @__PURE__ */ React.createElement("div", { className: "min-w-0" }, /* @__PURE__ */ React.createElement("h2", { id: "summary-modal-title", className: `text-xl font-semibold flex flex-wrap items-center gap-2 ${headingClass}` }, "Discovery Summary", (summaryData == null ? void 0 : summaryData.from_cache) && /* @__PURE__ */ React.createElement("span", { className: `inline-flex items-center rounded-full border px-2 py-0.5 text-xs font-medium ${isDarkTheme ? "bg-emerald-950 border-emerald-700 text-emerald-200" : "bg-emerald-50 border-emerald-200 text-emerald-800"}` }, "Saved")), /* @__PURE__ */ React.createElement("p", { className: `text-sm mt-0.5 ${mutedTextClass}` }, `Run of ${formatMissionDateTime(currentSessionId, "an unknown date")}`))), /* @__PURE__ */ React.createElement("div", { className: "flex items-center gap-3" }, isSummaryTab ? /* @__PURE__ */ React.createElement(
        "button",
        {
          type: "button",
          onClick: () => exitSummaryFullscreen({ reopenModal: true }),
          className: `rounded-md p-1.5 ${isDarkTheme ? "text-gray-300 hover:text-gray-100 hover:bg-gray-800" : "text-gray-500 hover:text-gray-700 hover:bg-gray-100"}`,
          "aria-label": "Show summary in a window",
          title: "Show summary in a window"
        },
        /* @__PURE__ */ React.createElement("i", { className: "fas fa-compress-arrows-alt text-lg", "aria-hidden": "true" })
      ) : /* @__PURE__ */ React.createElement(
        "button",
        {
          type: "button",
          onClick: enterSummaryFullscreen,
          className: `rounded-md p-1.5 ${isDarkTheme ? "text-gray-300 hover:text-gray-100 hover:bg-gray-800" : "text-gray-500 hover:text-gray-700 hover:bg-gray-100"}`,
          "aria-label": "Open summary full screen",
          title: "Open summary full screen"
        },
        /* @__PURE__ */ React.createElement("i", { className: "fas fa-expand-arrows-alt text-lg", "aria-hidden": "true" })
      ), /* @__PURE__ */ React.createElement(
        "button",
        {
          type: "button",
          onClick: closeSummaryModal,
          className: `rounded-md p-1.5 ${isDarkTheme ? "text-gray-300 hover:text-gray-100 hover:bg-gray-800" : "text-gray-500 hover:text-gray-700 hover:bg-gray-100"}`,
          "aria-label": "Close summary"
        },
        /* @__PURE__ */ React.createElement("i", { className: "fas fa-times text-xl", "aria-hidden": "true" })
      ))), !isLoadingSummary && summaryData && /* @__PURE__ */ React.createElement("div", { className: `border-b ${isDarkTheme ? "border-gray-700 bg-gray-800" : "border-gray-200 bg-gray-50"}` }, /* @__PURE__ */ React.createElement("div", { className: "flex gap-1 px-4 overflow-x-auto", role: "tablist", "aria-label": "Summary views", onKeyDown: handleTablistKeyDown }, /* @__PURE__ */ React.createElement(
        "button",
        {
          type: "button",
          id: "summary-tab-summary",
          role: "tab",
          "aria-selected": activeTab === "summary",
          "aria-controls": "summary-tabpanel-summary",
          tabIndex: activeTab === "summary" ? 0 : -1,
          onClick: () => setActiveTab("summary"),
          className: `px-4 py-3 font-medium text-sm whitespace-nowrap border-b-2 transition-colors ${activeTab === "summary" ? isDarkTheme ? "border-indigo-400 text-indigo-200 bg-gray-900" : "border-indigo-600 text-indigo-700 bg-white" : isDarkTheme ? "border-transparent text-gray-300 hover:text-white hover:bg-gray-700" : "border-transparent text-gray-600 hover:text-gray-900 hover:bg-gray-100"}`
        },
        /* @__PURE__ */ React.createElement("i", { className: "fas fa-brain mr-2", "aria-hidden": "true" }),
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
          className: `px-4 py-3 font-medium text-sm whitespace-nowrap border-b-2 transition-colors ${activeTab === "context" ? isDarkTheme ? "border-indigo-400 text-indigo-200 bg-gray-900" : "border-indigo-600 text-indigo-700 bg-white" : isDarkTheme ? "border-transparent text-gray-300 hover:text-white hover:bg-gray-700" : "border-transparent text-gray-600 hover:text-gray-900 hover:bg-gray-100"}`
        },
        /* @__PURE__ */ React.createElement("i", { className: "fas fa-compass mr-2", "aria-hidden": "true" }),
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
          className: `px-4 py-3 font-medium text-sm whitespace-nowrap border-b-2 transition-colors ${activeTab === "queries" ? isDarkTheme ? "border-indigo-400 text-indigo-200 bg-gray-900" : "border-indigo-600 text-indigo-700 bg-white" : isDarkTheme ? "border-transparent text-gray-300 hover:text-white hover:bg-gray-700" : "border-transparent text-gray-600 hover:text-gray-900 hover:bg-gray-100"}`
        },
        /* @__PURE__ */ React.createElement("i", { className: "fas fa-code mr-2", "aria-hidden": "true" }),
        "SPL Queries ",
        /* @__PURE__ */ React.createElement("span", { className: "ml-1" }, "(", ((_Aa = summaryData.spl_queries) == null ? void 0 : _Aa.length) || 0, ")")
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
          className: `px-4 py-3 font-medium text-sm whitespace-nowrap border-b-2 transition-colors ${activeTab === "tasks" ? isDarkTheme ? "border-indigo-400 text-indigo-200 bg-gray-900" : "border-indigo-600 text-indigo-700 bg-white" : isDarkTheme ? "border-transparent text-gray-300 hover:text-white hover:bg-gray-700" : "border-transparent text-gray-600 hover:text-gray-900 hover:bg-gray-100"}`
        },
        /* @__PURE__ */ React.createElement("i", { className: "fas fa-tasks mr-2", "aria-hidden": "true" }),
        "Admin Tasks ",
        /* @__PURE__ */ React.createElement("span", { className: "ml-1" }, "(", ((_Ba = summaryData.admin_tasks) == null ? void 0 : _Ba.length) || 0, ")")
      ))), /* @__PURE__ */ React.createElement("div", { className: "flex-1 min-h-0 overflow-y-auto p-6" }, isLoadingSummary ? /* @__PURE__ */ React.createElement("div", { className: "flex items-center justify-center h-full" }, /* @__PURE__ */ React.createElement("div", { className: "text-center max-w-md" }, /* @__PURE__ */ React.createElement("div", { className: "relative mb-8" }, /* @__PURE__ */ React.createElement("div", { className: `inline-block animate-spin rounded-full h-20 w-20 border-4 ${isDarkTheme ? "border-indigo-900 border-t-indigo-400" : "border-indigo-200 border-t-indigo-600"}` }), /* @__PURE__ */ React.createElement("i", { className: `fas fa-brain absolute top-1/2 left-1/2 transform -translate-x-1/2 -translate-y-1/2 text-3xl animate-pulse ${isDarkTheme ? "text-indigo-300" : "text-indigo-600"}` })), /* @__PURE__ */ React.createElement("h3", { className: `text-xl font-semibold mb-4 ${headingClass}` }, "Building Your Summary"), /* @__PURE__ */ React.createElement("div", { className: `space-y-3 text-left rounded-lg shadow-sm border p-4 mb-4 ${isDarkTheme ? "bg-gray-800 border-gray-700" : "bg-white border-gray-200"}` }, /* @__PURE__ */ React.createElement("div", { className: `flex items-center text-sm ${isSummaryStepActive(1) ? "animate-pulse" : ""}` }, /* @__PURE__ */ React.createElement("div", { className: `flex-shrink-0 w-6 h-6 rounded-full flex items-center justify-center mr-3 ${isSummaryStepDone(1) ? "bg-green-600" : isSummaryStepActive(1) ? "bg-indigo-500" : isDarkTheme ? "border-2 border-gray-600" : "border-2 border-gray-300"}` }, isSummaryStepDone(1) ? /* @__PURE__ */ React.createElement("i", { className: "fas fa-check text-white text-xs" }) : isSummaryStepActive(1) ? /* @__PURE__ */ React.createElement("div", { className: "w-2 h-2 bg-white rounded-full animate-ping" }) : null), /* @__PURE__ */ React.createElement("span", { className: isSummaryStepActive(1) ? isDarkTheme ? "text-gray-100 font-medium" : "text-gray-700 font-medium" : isDarkTheme ? "text-gray-300" : "text-gray-700" }, "Loading discovery reports...")), /* @__PURE__ */ React.createElement("div", { className: `flex items-center text-sm ${isSummaryStepActive(2) ? "animate-pulse" : ""}` }, /* @__PURE__ */ React.createElement("div", { className: `flex-shrink-0 w-6 h-6 rounded-full flex items-center justify-center mr-3 ${isSummaryStepDone(2) ? "bg-green-600" : isSummaryStepActive(2) ? "bg-indigo-500" : isDarkTheme ? "border-2 border-gray-600" : "border-2 border-gray-300"}` }, isSummaryStepDone(2) ? /* @__PURE__ */ React.createElement("i", { className: "fas fa-check text-white text-xs" }) : isSummaryStepActive(2) ? /* @__PURE__ */ React.createElement("div", { className: "w-2 h-2 bg-white rounded-full animate-ping" }) : null), /* @__PURE__ */ React.createElement("span", { className: isSummaryStepActive(2) ? isDarkTheme ? "text-gray-100 font-medium" : "text-gray-700 font-medium" : isDarkTheme ? "text-gray-400" : "text-gray-500" }, "Generating SPL queries...")), /* @__PURE__ */ React.createElement("div", { className: `flex items-center text-sm ${isSummaryStepActive(3) ? "animate-pulse" : ""}` }, /* @__PURE__ */ React.createElement("div", { className: `flex-shrink-0 w-6 h-6 rounded-full flex items-center justify-center mr-3 ${isSummaryStepDone(3) ? "bg-green-600" : isSummaryStepActive(3) ? "bg-indigo-500" : isDarkTheme ? "border-2 border-gray-600" : "border-2 border-gray-300"}` }, isSummaryStepDone(3) ? /* @__PURE__ */ React.createElement("i", { className: "fas fa-check text-white text-xs" }) : isSummaryStepActive(3) ? /* @__PURE__ */ React.createElement("div", { className: "w-2 h-2 bg-white rounded-full animate-ping" }) : null), /* @__PURE__ */ React.createElement("span", { className: isSummaryStepActive(3) ? isDarkTheme ? "text-gray-100 font-medium" : "text-gray-700 font-medium" : isDarkTheme ? "text-gray-400" : "text-gray-500" }, "Building executive summary...")), /* @__PURE__ */ React.createElement("div", { className: `flex items-center text-sm ${isSummaryStepActive(4) ? "animate-pulse" : ""}` }, /* @__PURE__ */ React.createElement("div", { className: `flex-shrink-0 w-6 h-6 rounded-full flex items-center justify-center mr-3 ${isSummaryStepDone(4) ? "bg-green-600" : isSummaryStepActive(4) ? "bg-indigo-500" : isDarkTheme ? "border-2 border-gray-600" : "border-2 border-gray-300"}` }, isSummaryStepDone(4) ? /* @__PURE__ */ React.createElement("i", { className: "fas fa-check text-white text-xs" }) : isSummaryStepActive(4) ? /* @__PURE__ */ React.createElement("div", { className: "w-2 h-2 bg-white rounded-full animate-ping" }) : null), /* @__PURE__ */ React.createElement("span", { className: isSummaryStepActive(4) ? isDarkTheme ? "text-gray-100 font-medium" : "text-gray-700 font-medium" : isDarkTheme ? "text-gray-400" : "text-gray-500" }, "Creating admin tasks..."))), /* @__PURE__ */ React.createElement("div", { className: "mb-4" }, /* @__PURE__ */ React.createElement("div", { className: "flex justify-between items-center mb-1" }, /* @__PURE__ */ React.createElement("span", { className: `text-xs font-medium ${isDarkTheme ? "text-gray-200" : "text-gray-700"}` }, summaryProgress.message), /* @__PURE__ */ React.createElement("span", { className: `text-xs font-semibold ${isDarkTheme ? "text-indigo-300" : "text-indigo-700"}` }, summaryProgress.progress, "%")), /* @__PURE__ */ React.createElement("div", { className: `w-full rounded-full h-2 ${isDarkTheme ? "bg-gray-700" : "bg-gray-200"}` }, /* @__PURE__ */ React.createElement(
        "div",
        {
          className: "bg-indigo-600 h-2 rounded-full transition-all duration-500 ease-out",
          style: { width: `${summaryProgress.progress}%` }
        }
      ))), isSummaryWorkerActive && /* @__PURE__ */ React.createElement("div", { className: `mb-4 rounded-lg border px-4 py-3 text-left ${isDarkTheme ? "border-amber-800 bg-amber-950/40" : "border-amber-200 bg-amber-50"}` }, /* @__PURE__ */ React.createElement("div", { className: "flex items-start justify-between gap-3" }, /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("div", { className: `text-sm font-semibold ${isDarkTheme ? "text-amber-200" : "text-amber-800"}` }, "Running in the background"), /* @__PURE__ */ React.createElement("div", { className: `mt-1 text-sm leading-6 ${isDarkTheme ? "text-amber-100" : "text-amber-900"}` }, "This summary keeps running if you close this window (process ", summaryWorkerPid, "). Come back later to see it, or stop it now.")), /* @__PURE__ */ React.createElement(
        "button",
        {
          type: "button",
          onClick: abortSummaryRun,
          disabled: isAbortingSummary,
          className: `flex-shrink-0 rounded-md px-3 py-1.5 text-sm font-medium bg-red-600 text-white hover:bg-red-700 ${isAbortingSummary ? "cursor-wait" : ""}`
        },
        isAbortingSummary ? "Stopping..." : "Stop Summary"
      ))))) : summaryData ? /* @__PURE__ */ React.createElement("div", null, activeTab === "summary" && /* @__PURE__ */ React.createElement("div", { id: "summary-tabpanel-summary", role: "tabpanel", "aria-labelledby": "summary-tab-summary", className: "space-y-6" }, renderExecutiveControlSummary(), summaryInfographicCapability.available && /* @__PURE__ */ React.createElement("div", { className: "flex justify-center pb-2" }, /* @__PURE__ */ React.createElement(
        "button",
        {
          type: "button",
          onClick: generateSummaryInfographic,
          disabled: isGeneratingSummaryInfographic,
          "aria-label": summaryInfographicCapability.hasExisting ? "Open the saved infographic for this summary" : "Generate an infographic from this summary using gpt-image-2",
          className: `text-xs tracking-[0.35em] lowercase focus:outline-none ${isDarkTheme ? "text-gray-900" : "text-white"} ${isGeneratingSummaryInfographic ? "cursor-wait" : "cursor-pointer"}`
        },
        "magic"
      ))), activeTab === "context" && /* @__PURE__ */ React.createElement("div", { id: "summary-tabpanel-context", role: "tabpanel", "aria-labelledby": "summary-tab-context", className: "space-y-6" }, !hasContextExplorer ? /* @__PURE__ */ React.createElement("div", { className: `rounded-xl border p-6 ${isDarkTheme ? "bg-gray-900 border-gray-700 text-gray-300" : "bg-white border-gray-200 text-gray-700"}` }, "This summary has no environment details for this run.") : /* @__PURE__ */ React.createElement(React.Fragment, null, /* @__PURE__ */ React.createElement("div", { className: `rounded-xl border overflow-hidden shadow-sm ${isDarkTheme ? "bg-gray-900 border-gray-700" : "bg-white border-gray-200"}` }, /* @__PURE__ */ React.createElement("div", { className: `p-6 md:p-7 border-b ${isDarkTheme ? "border-gray-700" : "border-gray-200"}` }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-col gap-6 xl:flex-row xl:items-start xl:justify-between" }, /* @__PURE__ */ React.createElement("div", { className: "xl:max-w-3xl" }, /* @__PURE__ */ React.createElement("h3", { className: `text-2xl font-semibold ${isDarkTheme ? "text-gray-100" : "text-gray-900"}` }, "Context Explorer"), /* @__PURE__ */ React.createElement("p", { className: `mt-3 max-w-3xl text-sm leading-6 ${isDarkTheme ? "text-gray-300" : "text-gray-700"}` }, "The indexes, sourcetypes, and hosts this run found. Use them to start a chat, find related searches, or follow up on risks.")), /* @__PURE__ */ React.createElement("div", { className: "grid grid-cols-2 gap-3 xl:w-[440px]" }, /* @__PURE__ */ React.createElement("div", { className: `rounded-lg border p-4 ${summaryCardClass}` }, /* @__PURE__ */ React.createElement("div", { className: `text-xs uppercase tracking-wide ${summaryLabelClass}` }, "Readiness"), /* @__PURE__ */ React.createElement("div", { className: `mt-2 text-3xl font-bold ${isDarkTheme ? "text-gray-100" : "text-gray-900"}` }, (_Da = (_Ca = contextOverview.readiness_score) != null ? _Ca : readinessScore) != null ? _Da : "N/A"), /* @__PURE__ */ React.createElement("div", { className: `mt-1 text-xs ${isDarkTheme ? "text-gray-400" : "text-gray-600"}` }, "Out of 100")), /* @__PURE__ */ React.createElement("div", { className: `rounded-lg border p-4 ${summaryCardClass}` }, /* @__PURE__ */ React.createElement("div", { className: `text-xs uppercase tracking-wide ${summaryLabelClass}` }, "Indexes"), /* @__PURE__ */ React.createElement("div", { className: `mt-2 text-3xl font-bold ${isDarkTheme ? "text-gray-100" : "text-gray-900"}` }, (_Ea = contextOverview.total_indexes) != null ? _Ea : contextIndexAnchors.length), /* @__PURE__ */ React.createElement("div", { className: `mt-1 text-xs ${isDarkTheme ? "text-gray-400" : "text-gray-600"}` }, "Found by discovery")), /* @__PURE__ */ React.createElement("div", { className: `rounded-lg border p-4 ${summaryCardClass}` }, /* @__PURE__ */ React.createElement("div", { className: `text-xs uppercase tracking-wide ${summaryLabelClass}` }, "Sourcetypes"), /* @__PURE__ */ React.createElement("div", { className: `mt-2 text-3xl font-bold ${isDarkTheme ? "text-gray-100" : "text-gray-900"}` }, (_Fa = contextOverview.total_sourcetypes) != null ? _Fa : contextSourcetypeAnchors.length), /* @__PURE__ */ React.createElement("div", { className: `mt-1 text-xs ${isDarkTheme ? "text-gray-400" : "text-gray-600"}` }, "Found by discovery")), /* @__PURE__ */ React.createElement("div", { className: `rounded-lg border p-4 ${summaryCardClass}` }, /* @__PURE__ */ React.createElement("div", { className: `text-xs uppercase tracking-wide ${summaryLabelClass}` }, "Hosts"), /* @__PURE__ */ React.createElement("div", { className: `mt-2 text-3xl font-bold ${isDarkTheme ? "text-gray-100" : "text-gray-900"}` }, (_Ga = contextOverview.total_hosts) != null ? _Ga : contextHostAnchors.length), /* @__PURE__ */ React.createElement("div", { className: `mt-1 text-xs ${isDarkTheme ? "text-gray-400" : "text-gray-600"}` }, contextOverview.data_volume_24h ? `${contextOverview.data_volume_24h} in 24 hours` : "Found by discovery"))))), /* @__PURE__ */ React.createElement("div", { className: "p-6 space-y-6" }, contextPatterns.length > 0 && /* @__PURE__ */ React.createElement("div", { className: `rounded-lg border p-5 ${summaryCardClass}` }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-col gap-3 md:flex-row md:items-start md:justify-between" }, /* @__PURE__ */ React.createElement("div", { className: "max-w-3xl" }, /* @__PURE__ */ React.createElement("div", { className: "flex items-center gap-2" }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-project-diagram text-indigo-600", "aria-hidden": "true" }), /* @__PURE__ */ React.createElement("h4", { className: `text-lg font-semibold ${isDarkTheme ? "text-gray-100" : "text-gray-900"}` }, "Patterns"))), /* @__PURE__ */ React.createElement("div", { className: `inline-flex items-center rounded-full border px-3 py-1 text-xs font-semibold ${summaryInsetClass} ${headingClass}` }, countLabel(contextPatterns.length, "pattern"))), leadContextPattern && /* @__PURE__ */ React.createElement("div", { className: `mt-4 grid gap-4 ${supportingContextPatterns.length > 0 ? "xl:grid-cols-[minmax(0,1.15fr),minmax(0,0.85fr)]" : ""}` }, /* @__PURE__ */ React.createElement("div", { className: `rounded-xl border p-5 ${summaryInsetClass}` }, /* @__PURE__ */ React.createElement("div", { className: `text-xs font-semibold uppercase tracking-wider ${summaryLabelClass}` }, "Lead pattern"), /* @__PURE__ */ React.createElement("div", { className: `mt-3 text-lg font-semibold ${isDarkTheme ? "text-gray-100" : "text-gray-900"}` }, leadContextPattern.title || "Pattern 1"), leadContextPattern.description && /* @__PURE__ */ React.createElement("p", { className: `mt-3 text-sm leading-6 ${isDarkTheme ? "text-gray-300" : "text-gray-700"}` }, leadContextPattern.description), leadContextPattern.signal && /* @__PURE__ */ React.createElement("div", { className: `mt-4 rounded-lg border px-4 py-3 ${summaryCardClass} ${isDarkTheme ? "text-gray-100" : "text-gray-900"}` }, /* @__PURE__ */ React.createElement("div", { className: `text-xs font-semibold uppercase tracking-wider ${summaryLabelClass}` }, "Signal"), /* @__PURE__ */ React.createElement("div", { className: "mt-1 text-sm leading-6 break-words" }, leadContextPattern.signal))), supportingContextPatterns.length > 0 && /* @__PURE__ */ React.createElement("div", { className: "space-y-3" }, supportingContextPatterns.map((pattern, idx) => /* @__PURE__ */ React.createElement("div", { key: `context-pattern-${idx + 1}`, className: `rounded-lg border px-4 py-4 ${summaryInsetClass}` }, /* @__PURE__ */ React.createElement("div", { className: "flex items-start gap-3" }, /* @__PURE__ */ React.createElement("span", { className: `mt-0.5 inline-flex h-7 w-7 flex-shrink-0 items-center justify-center rounded-full text-xs font-bold ${isDarkTheme ? "bg-indigo-900 text-indigo-100" : "bg-indigo-100 text-indigo-700"}` }, idx + 2), /* @__PURE__ */ React.createElement("div", { className: "min-w-0" }, /* @__PURE__ */ React.createElement("div", { className: `text-sm font-semibold ${isDarkTheme ? "text-gray-100" : "text-gray-900"}` }, pattern.title || `Pattern ${idx + 2}`), pattern.description && /* @__PURE__ */ React.createElement("p", { className: `mt-1 text-xs leading-5 ${isDarkTheme ? "text-gray-300" : "text-gray-700"}` }, pattern.description), pattern.signal && /* @__PURE__ */ React.createElement("div", { className: `mt-2 text-xs leading-5 ${summaryLabelClass}` }, /* @__PURE__ */ React.createElement("span", { className: "font-semibold" }, "Signal:"), " ", pattern.signal))))))), hiddenContextPatternCount > 0 && /* @__PURE__ */ React.createElement("div", { className: `mt-4 text-xs ${isDarkTheme ? "text-gray-400" : "text-gray-600"}` }, "Showing the top ", visibleContextPatterns.length, " of ", contextPatterns.length, " patterns.")), /* @__PURE__ */ React.createElement("div", { className: "grid gap-6 xl:grid-cols-3" }, [
        {
          key: "index",
          title: "Indexes",
          icon: "fa-database",
          accent: isDarkTheme ? "text-blue-300" : "text-blue-700",
          panel: summaryCardClass,
          items: contextIndexAnchors
        },
        {
          key: "sourcetype",
          title: "Sourcetypes",
          icon: "fa-stream",
          accent: isDarkTheme ? "text-emerald-300" : "text-emerald-700",
          panel: summaryCardClass,
          items: contextSourcetypeAnchors
        },
        {
          key: "host",
          title: "Hosts",
          icon: "fa-server",
          accent: isDarkTheme ? "text-amber-300" : "text-amber-700",
          panel: summaryCardClass,
          items: contextHostAnchors
        }
      ].map((section) => /* @__PURE__ */ React.createElement("div", { key: section.key, className: `rounded-lg border p-5 ${section.panel}` }, /* @__PURE__ */ React.createElement("div", { className: "flex items-center gap-2 mb-4" }, /* @__PURE__ */ React.createElement("i", { className: `fas ${section.icon} ${section.accent}` }), /* @__PURE__ */ React.createElement("h4", { className: `text-lg font-semibold ${isDarkTheme ? "text-gray-100" : "text-gray-900"}` }, section.title)), /* @__PURE__ */ React.createElement("div", { className: "space-y-3" }, section.items.length === 0 ? /* @__PURE__ */ React.createElement("div", { className: `text-sm ${isDarkTheme ? "text-gray-400" : "text-gray-600"}` }, "None found.") : section.items.slice(0, 4).map((item, idx) => /* @__PURE__ */ React.createElement("div", { key: `${section.key}-${item.name || idx}`, className: `rounded-lg border px-4 py-3 ${summaryInsetClass}` }, /* @__PURE__ */ React.createElement("div", { className: "flex items-start justify-between gap-3" }, /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("div", { className: `text-base font-semibold break-all ${isDarkTheme ? "text-gray-100" : "text-gray-900"}` }, item.name || "Unnamed"), (item.events != null || item.size_mb != null) && /* @__PURE__ */ React.createElement("div", { className: `mt-1 text-xs ${summaryLabelClass}` }, [
        item.events != null ? `${Number(item.events).toLocaleString()} events` : "",
        item.size_mb != null ? `${Number(item.size_mb).toFixed(1)} MB` : ""
      ].filter(Boolean).join(" · ")))), renderSummaryContextActionButtons(item.actions))))))), /* @__PURE__ */ React.createElement("div", { className: "grid gap-6 xl:grid-cols-[minmax(0,1.1fr),minmax(0,0.9fr),minmax(0,0.9fr)]" }, /* @__PURE__ */ React.createElement("div", { className: `rounded-lg border p-5 ${isDarkTheme ? "bg-gray-950 border-gray-800" : "bg-white border-gray-200"}` }, /* @__PURE__ */ React.createElement("div", { className: "flex items-center gap-2 mb-4" }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-puzzle-piece text-indigo-600", "aria-hidden": "true" }), /* @__PURE__ */ React.createElement("h4", { className: `text-lg font-semibold ${isDarkTheme ? "text-gray-100" : "text-gray-900"}` }, "Needs Classification")), /* @__PURE__ */ React.createElement("div", { className: "space-y-3" }, contextUnknownEntities.length === 0 ? /* @__PURE__ */ React.createElement("div", { className: `text-sm ${isDarkTheme ? "text-gray-400" : "text-gray-600"}` }, "Nothing needs classification.") : contextUnknownEntities.slice(0, 3).map((item, idx) => /* @__PURE__ */ React.createElement("div", { key: `context-unknown-${item.name || idx}`, className: `rounded-lg border px-4 py-3 ${summaryInsetClass}` }, /* @__PURE__ */ React.createElement("div", { className: "flex items-start justify-between gap-3" }, /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("div", { className: `text-base font-semibold ${isDarkTheme ? "text-gray-100" : "text-gray-900"}` }, item.name || "Unnamed item"), /* @__PURE__ */ React.createElement("div", { className: `mt-1 text-xs ${isDarkTheme ? "text-gray-400" : "text-gray-600"}` }, item.question || item.reason || "Needs a description and an owner.")), /* @__PURE__ */ React.createElement("div", { className: `text-xs uppercase tracking-wide ${isDarkTheme ? "text-indigo-300" : "text-indigo-700"}` }, item.type || "item")), renderSummaryContextActionButtons(item.actions))))), /* @__PURE__ */ React.createElement("div", { className: `rounded-lg border p-5 ${isDarkTheme ? "bg-gray-950 border-gray-800" : "bg-white border-gray-200"}` }, /* @__PURE__ */ React.createElement("div", { className: "flex items-center gap-2 mb-4" }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-shield-alt text-red-600", "aria-hidden": "true" }), /* @__PURE__ */ React.createElement("h4", { className: `text-lg font-semibold ${isDarkTheme ? "text-gray-100" : "text-gray-900"}` }, "Risks and Coverage Gaps")), /* @__PURE__ */ React.createElement("div", { className: "space-y-3" }, contextRiskItems.length === 0 && contextCoverageGapItems.length === 0 && /* @__PURE__ */ React.createElement("div", { className: `text-sm ${summaryLabelClass}` }, "No risks or coverage gaps recorded."), contextRiskItems.slice(0, 2).map((risk, idx) => /* @__PURE__ */ React.createElement("div", { key: `context-risk-${idx}`, className: `rounded-lg border px-4 py-3 ${summaryInsetClass}` }, /* @__PURE__ */ React.createElement("div", { className: `text-xs uppercase tracking-wide ${isDarkTheme ? "text-red-300" : "text-red-700"}` }, [risk.severity ? `${String(risk.severity).charAt(0).toUpperCase()}${String(risk.severity).slice(1).toLowerCase()} risk` : "Risk", risk.domain].filter(Boolean).join(" · ")), /* @__PURE__ */ React.createElement("div", { className: `mt-1 text-sm font-semibold ${isDarkTheme ? "text-gray-100" : "text-gray-900"}` }, risk.risk || "Unnamed risk"), renderSummaryContextActionButtons(risk.actions))), contextCoverageGapItems.slice(0, 2).map((gap, idx) => /* @__PURE__ */ React.createElement("div", { key: `context-gap-${idx}`, className: `rounded-lg border px-4 py-3 ${summaryInsetClass}` }, /* @__PURE__ */ React.createElement("div", { className: `text-xs uppercase tracking-wide ${isDarkTheme ? "text-amber-300" : "text-amber-700"}` }, gap.priority ? `Coverage gap · ${gap.priority}` : "Coverage gap"), /* @__PURE__ */ React.createElement("div", { className: `mt-1 text-sm font-semibold ${isDarkTheme ? "text-gray-100" : "text-gray-900"}` }, gap.gap || "Coverage gap"), gap.why_it_matters && /* @__PURE__ */ React.createElement("div", { className: `mt-1 text-xs ${isDarkTheme ? "text-gray-400" : "text-gray-600"}` }, gap.why_it_matters), renderSummaryContextActionButtons(gap.actions))))), /* @__PURE__ */ React.createElement("div", { className: `rounded-lg border p-5 ${isDarkTheme ? "bg-gray-950 border-gray-800" : "bg-white border-gray-200"}` }, /* @__PURE__ */ React.createElement("div", { className: "flex items-center gap-2 mb-4" }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-tasks text-indigo-600", "aria-hidden": "true" }), /* @__PURE__ */ React.createElement("h4", { className: `text-lg font-semibold ${isDarkTheme ? "text-gray-100" : "text-gray-900"}` }, "Priority Tasks")), /* @__PURE__ */ React.createElement("div", { className: "space-y-3" }, contextPriorityTasks.length === 0 ? /* @__PURE__ */ React.createElement("div", { className: `text-sm ${isDarkTheme ? "text-gray-400" : "text-gray-600"}` }, "No tasks yet.") : contextPriorityTasks.slice(0, 4).map((task, idx) => /* @__PURE__ */ React.createElement("div", { key: `context-task-${idx}`, className: `rounded-lg border px-4 py-3 ${summaryInsetClass}` }, /* @__PURE__ */ React.createElement("div", { className: "flex items-start justify-between gap-3" }, /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("div", { className: `text-sm font-semibold ${isDarkTheme ? "text-gray-100" : "text-gray-900"}` }, task.title || `Task ${idx + 1}`), task.category && /* @__PURE__ */ React.createElement("div", { className: `mt-1 text-xs ${summaryLabelClass}` }, task.category)), task.priority && /* @__PURE__ */ React.createElement("div", { className: `text-xs uppercase tracking-wide whitespace-nowrap ${summaryLabelClass}` }, task.priority)), renderSummaryContextActionButtons(task.actions)))))))))), activeTab === "queries" && /* @__PURE__ */ React.createElement("div", { id: "summary-tabpanel-queries", role: "tabpanel", "aria-labelledby": "summary-tab-queries", className: isDarkTheme ? "text-gray-100" : "text-gray-900" }, queryFocus && /* @__PURE__ */ React.createElement("div", { className: `mb-4 rounded-lg p-4 border ${summaryInsetClass}` }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between" }, /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("div", { className: `text-xs font-semibold uppercase tracking-wider ${summaryLabelClass}` }, queryFocus.sourceLabel || "Filtered Searches"), /* @__PURE__ */ React.createElement("h4", { className: `mt-1 text-base font-semibold ${headingClass}` }, queryFocus.title), /* @__PURE__ */ React.createElement("p", { className: `mt-1 text-sm ${mutedTextClass}` }, queryFocus.description || `Showing searches for ${queryFocus.category}.`)), /* @__PURE__ */ React.createElement(
        "button",
        {
          type: "button",
          onClick: clearQueryFocus,
          className: `${summaryButtonClass} flex-shrink-0`
        },
        "Show All Searches"
      ))), summaryData.risk_register && summaryData.risk_register.length > 0 && /* @__PURE__ */ React.createElement("div", { className: `mb-4 rounded-lg p-4 border ${summaryCardClass}` }, /* @__PURE__ */ React.createElement("h4", { className: `text-sm font-semibold flex items-center ${headingClass}` }, /* @__PURE__ */ React.createElement("i", { className: `fas fa-shield-alt mr-2 ${isDarkTheme ? "text-red-300" : "text-red-600"}`, "aria-hidden": "true" }), "Searches for Top Risks"), /* @__PURE__ */ React.createElement("p", { className: `mt-1 mb-3 text-sm ${mutedTextClass}` }, "Start with searches that check the most severe risks from this run."), /* @__PURE__ */ React.createElement("ul", { className: "space-y-2" }, summaryData.risk_register.slice(0, 3).map((risk, idx) => /* @__PURE__ */ React.createElement("li", { key: idx, className: `text-sm rounded-md px-3 py-2 border ${summaryInsetClass}` }, /* @__PURE__ */ React.createElement("span", { className: "font-semibold" }, formatSummaryLevel(risk.severity, "medium"), " risk:"), " ", risk.risk || "Unnamed risk")))), /* @__PURE__ */ React.createElement("div", { className: "flex flex-col gap-3 mb-4 lg:flex-row lg:items-center lg:justify-between" }, /* @__PURE__ */ React.createElement("h3", { className: `text-lg font-semibold flex items-center ${headingClass}` }, /* @__PURE__ */ React.createElement("i", { className: `fas fa-code mr-2 ${isDarkTheme ? "text-indigo-300" : "text-indigo-600"}`, "aria-hidden": "true" }), "SPL Queries", /* @__PURE__ */ React.createElement("span", { className: `ml-2 text-sm font-normal ${summaryLabelClass}` }, "(", filteredSummaryQueries.length, ")")), /* @__PURE__ */ React.createElement("div", { className: "flex flex-wrap items-center gap-2", role: "group", "aria-label": "Filter searches by source" }, queryFilterOptions.map((option) => /* @__PURE__ */ React.createElement(
        "button",
        {
          key: option.key,
          type: "button",
          "aria-pressed": activeQueryFilterKey === option.key,
          onClick: () => setQueryFilter(option.key),
          className: `px-3 py-1 text-sm font-medium rounded-md transition-colors ${activeQueryFilterKey === option.key ? option.activeClass : isDarkTheme ? "bg-gray-800 text-gray-200 hover:bg-gray-700" : "bg-gray-100 text-gray-700 hover:bg-gray-200"}`
        },
        option.label,
        " (",
        option.count,
        ")"
      )))), /* @__PURE__ */ React.createElement("div", { className: "space-y-4" }, filteredSummaryQueries.length > 0 ? filteredSummaryQueries.map((query, idx) => {
        const priorityMeta = getQueryPriorityMeta(query.priority);
        const querySpl = String(query.spl || "").trim();
        const hasKnownSource = ["ai_finding", "context_engine", "template"].includes(query.query_source);
        const queryMetaItems = [
          query.category && { key: "category", icon: "fa-folder", label: "Category", text: query.category },
          query.use_case && query.use_case !== query.category && { key: "use-case", icon: "fa-chart-line", label: "Use case", text: query.use_case },
          query.difficulty && { key: "difficulty", icon: "fa-signal", label: "Difficulty", text: query.difficulty },
          query.execution_time && { key: "run-time", icon: "fa-clock", label: "Estimated run time", text: query.execution_time }
        ].filter(Boolean);
        return /* @__PURE__ */ React.createElement("div", { key: idx, className: `border rounded-lg p-5 ${summaryCardClass}` }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-col gap-3 md:flex-row md:items-start md:justify-between" }, /* @__PURE__ */ React.createElement("div", { className: "min-w-0 flex-1" }, (priorityMeta || hasKnownSource) && /* @__PURE__ */ React.createElement("div", { className: "mb-2 flex flex-wrap items-center gap-2" }, priorityMeta && /* @__PURE__ */ React.createElement("span", { className: `inline-flex items-center rounded-full border px-2 py-0.5 text-xs font-semibold ${priorityMeta.className}` }, priorityMeta.label), hasKnownSource && /* @__PURE__ */ React.createElement("span", { className: summaryPillClass }, getQuerySourceLabel(query.query_source))), /* @__PURE__ */ React.createElement("h4", { className: `text-base font-semibold ${headingClass}` }, query.title || "Untitled search"), query.description && /* @__PURE__ */ React.createElement("p", { className: `mt-1 text-sm ${mutedTextClass}` }, query.description), queryMetaItems.length > 0 && /* @__PURE__ */ React.createElement("ul", { className: `mt-2 flex flex-wrap gap-x-4 gap-y-1 text-xs ${summaryLabelClass}` }, queryMetaItems.map((item) => /* @__PURE__ */ React.createElement("li", { key: item.key, title: item.label, className: "flex items-center" }, /* @__PURE__ */ React.createElement("i", { className: `fas ${item.icon} mr-1`, "aria-hidden": "true" }), /* @__PURE__ */ React.createElement("span", { className: "sr-only" }, item.label, ": "), item.text)))), querySpl && /* @__PURE__ */ React.createElement("div", { className: "flex flex-wrap gap-2 md:ml-4 md:flex-shrink-0" }, canUseSplunkDeeplinks && /* @__PURE__ */ React.createElement(
          "button",
          {
            type: "button",
            onClick: () => openSplunkSearchFromChat(querySpl),
            className: summaryButtonClass,
            title: "Open this search in Splunk Web"
          },
          /* @__PURE__ */ React.createElement("i", { className: "fas fa-external-link-alt", "aria-hidden": "true" }),
          /* @__PURE__ */ React.createElement("span", null, "Open in Splunk")
        ), /* @__PURE__ */ React.createElement(
          "button",
          {
            type: "button",
            onClick: () => launchChatInvestigation(
              `Can you help me understand this query and run it?

${querySpl}`,
              { freshContext: true }
            ),
            className: summaryButtonClass,
            title: "Ask about this search in Chat"
          },
          /* @__PURE__ */ React.createElement("i", { className: "fas fa-comments", "aria-hidden": "true" }),
          /* @__PURE__ */ React.createElement("span", null, "Ask in Chat")
        ), /* @__PURE__ */ React.createElement(
          "button",
          {
            type: "button",
            onClick: () => copyToClipboard(querySpl),
            className: summaryButtonClass,
            title: "Copy the SPL to the clipboard"
          },
          /* @__PURE__ */ React.createElement("i", { className: "fas fa-copy", "aria-hidden": "true" }),
          /* @__PURE__ */ React.createElement("span", null, "Copy")
        ))), query.finding_reference && /* @__PURE__ */ React.createElement("div", { className: `mt-3 rounded-md border px-3 py-2 text-sm ${summaryInsetClass}` }, /* @__PURE__ */ React.createElement("span", { className: "font-semibold" }, "From discovery:"), " ", query.finding_reference), query.environment_evidence && query.environment_evidence.length > 0 && /* @__PURE__ */ React.createElement("div", { className: "mt-2 flex flex-wrap gap-2" }, query.environment_evidence.map((evidence, evidenceIdx) => /* @__PURE__ */ React.createElement("span", { key: evidenceIdx, className: summaryPillClass }, evidence))), querySpl && /* @__PURE__ */ React.createElement("details", { className: "mt-3" }, /* @__PURE__ */ React.createElement("summary", { className: `cursor-pointer text-sm font-medium ${isDarkTheme ? "text-indigo-300 hover:text-indigo-200" : "text-indigo-700 hover:text-indigo-800"}` }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-code mr-1", "aria-hidden": "true" }), "Show SPL"), /* @__PURE__ */ React.createElement("pre", { className: `mt-2 p-4 rounded-md border text-sm font-mono whitespace-pre-wrap break-words overflow-x-auto ${summaryCodeClass}` }, querySpl)), query.business_value && /* @__PURE__ */ React.createElement("p", { className: `mt-3 text-sm ${mutedTextClass}` }, /* @__PURE__ */ React.createElement("span", { className: `font-semibold ${headingClass}` }, "Why it matters:"), " ", query.business_value));
      }) : /* @__PURE__ */ React.createElement("div", { className: `rounded-lg border border-dashed p-6 text-center ${isDarkTheme ? "border-gray-700 bg-gray-900 text-gray-300" : "border-gray-300 bg-gray-50 text-gray-600"}` }, /* @__PURE__ */ React.createElement("div", { className: `text-sm font-semibold ${headingClass}` }, "No searches match this filter."), /* @__PURE__ */ React.createElement("p", { className: "mt-2 text-sm" }, queryFocus ? "Show all searches or choose another source to see more." : "Choose another source to see more searches.")))), activeTab === "tasks" && /* @__PURE__ */ React.createElement("div", { id: "summary-tabpanel-tasks", role: "tabpanel", "aria-labelledby": "summary-tab-tasks", className: isDarkTheme ? "text-gray-100" : "text-gray-900" }, riskFocus && /* @__PURE__ */ React.createElement("div", { className: `mb-5 rounded-lg p-4 border ${summaryInsetClass}` }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between" }, /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("div", { className: `text-xs font-semibold uppercase tracking-wider ${summaryLabelClass}` }, "From Top Risks"), /* @__PURE__ */ React.createElement("h4", { className: `mt-1 text-base font-semibold ${headingClass}` }, riskFocus.title), /* @__PURE__ */ React.createElement("p", { className: `mt-1 text-sm ${mutedTextClass}` }, "Showing ", activeTaskFilterLabel === "All" ? "all tasks" : `${activeTaskFilterLabel} tasks`, " for ", riskFocus.domain || "this risk", ". Run the related searches to confirm the gap before and after you make changes.")), /* @__PURE__ */ React.createElement("div", { className: "flex flex-wrap items-center gap-2" }, /* @__PURE__ */ React.createElement(
        "button",
        {
          type: "button",
          onClick: () => focusQueriesForRisk(riskFocus.riskData || { risk: riskFocus.title, domain: riskFocus.domain }),
          className: "inline-flex items-center justify-center rounded-md px-3 py-1.5 text-sm font-medium bg-indigo-600 text-white transition-colors hover:bg-indigo-700"
        },
        "Show Related Searches"
      ), /* @__PURE__ */ React.createElement(
        "button",
        {
          type: "button",
          onClick: () => launchChatInvestigation(
            buildRiskInvestigationPrompt(riskFocus.riskData || { risk: riskFocus.title }),
            { freshContext: true }
          ),
          className: summaryButtonClass
        },
        "Investigate in Chat"
      ), /* @__PURE__ */ React.createElement(
        "button",
        {
          type: "button",
          onClick: clearRiskFocus,
          className: summaryButtonClass
        },
        "Show All Tasks"
      )))), summaryData.recursive_investigations && summaryData.recursive_investigations.length > 0 && /* @__PURE__ */ React.createElement("div", { className: `mb-5 rounded-lg p-4 border ${summaryCardClass}` }, /* @__PURE__ */ React.createElement("h4", { className: `text-sm font-semibold mb-3 flex items-center ${headingClass}` }, /* @__PURE__ */ React.createElement("i", { className: `fas fa-sync-alt mr-2 ${isDarkTheme ? "text-indigo-300" : "text-indigo-600"}`, "aria-hidden": "true" }), "When to Check Again"), /* @__PURE__ */ React.createElement("ul", { className: "space-y-2" }, summaryData.recursive_investigations.slice(0, 2).map((loop, idx) => /* @__PURE__ */ React.createElement("li", { key: idx, className: `rounded-md px-3 py-2 text-sm border ${summaryInsetClass}` }, /* @__PURE__ */ React.createElement("div", { className: "font-semibold" }, loop.loop || `Check ${idx + 1}`), loop.next_iteration_trigger && /* @__PURE__ */ React.createElement("div", { className: `mt-1 ${mutedTextClass}` }, "Trigger: ", loop.next_iteration_trigger))))), summaryData.admin_tasks && summaryData.admin_tasks.length > 0 ? /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("div", { className: "mb-4" }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between" }, /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("h3", { className: `text-lg font-semibold flex items-center ${headingClass}` }, /* @__PURE__ */ React.createElement("i", { className: `fas fa-tasks mr-2 ${isDarkTheme ? "text-indigo-300" : "text-indigo-600"}`, "aria-hidden": "true" }), "Recommended Tasks", /* @__PURE__ */ React.createElement("span", { className: `ml-2 text-sm font-normal ${summaryLabelClass}` }, "(", filteredTaskSnapshots.length, ")")), /* @__PURE__ */ React.createElement("p", { className: `mt-1 text-sm ${mutedTextClass}` }, "Ranked for your environment. Filter by status or area.")), /* @__PURE__ */ React.createElement("div", { className: "flex flex-wrap items-center gap-2", role: "group", "aria-label": "Filter tasks" }, taskFilterOptions.map((option) => /* @__PURE__ */ React.createElement(
        "button",
        {
          key: option.key,
          type: "button",
          "aria-pressed": activeTaskFilterKey === option.key,
          onClick: () => setTaskFilter(option.key),
          className: `px-3 py-1 text-sm font-medium rounded-md transition-colors ${activeTaskFilterKey === option.key ? option.activeClass : isDarkTheme ? "bg-gray-800 text-gray-200 hover:bg-gray-700" : "bg-gray-100 text-gray-700 hover:bg-gray-200"}`
        },
        option.label,
        " (",
        option.count,
        ")"
      ))))), /* @__PURE__ */ React.createElement("dl", { className: "grid gap-3 mb-6 grid-cols-2 xl:grid-cols-4" }, [
        { key: "total", label: "Total Tasks", value: taskProgressSnapshots.length },
        { key: "high", label: "High Priority", value: highPriorityTaskCount },
        { key: "in-progress", label: "In Progress", value: inProgressTaskCount },
        { key: "completed", label: "Completed", value: completedTaskCount }
      ].map((tile) => /* @__PURE__ */ React.createElement("div", { key: tile.key, className: `rounded-lg border px-4 py-3 ${summaryCardClass}` }, /* @__PURE__ */ React.createElement("dt", { className: `text-xs font-medium uppercase tracking-wide ${summaryLabelClass}` }, tile.label), /* @__PURE__ */ React.createElement("dd", { className: `mt-1 text-2xl font-semibold ${headingClass}` }, tile.value)))), /* @__PURE__ */ React.createElement("div", { className: "space-y-4" }, filteredTaskSnapshots.length > 0 ? filteredTaskSnapshots.map(({ task, progress: progress2, completionPct, taskIndex }) => {
        const taskSurfaceClass = `rounded-lg border p-4 ${summaryInsetClass}`;
        const taskNestedSurfaceClass = `rounded-lg border ${summaryCardClass}`;
        const taskStepCount = Array.isArray(task.steps) ? task.steps.length : 0;
        const taskPriorityMeta = getQueryPriorityMeta(task.priority);
        const hasTaskChecklist = taskStepCount > 0 || Array.isArray(task.prerequisites) && task.prerequisites.length > 0;
        const hasTaskFollowUp = Boolean(task.verification_spl || task.rollback);
        const taskStatusPillClass = "inline-flex items-center rounded-full border px-2 py-0.5 text-xs font-semibold";
        return /* @__PURE__ */ React.createElement("div", { key: taskIndex, className: `border rounded-lg overflow-hidden ${summaryCardClass}` }, /* @__PURE__ */ React.createElement("div", { className: `p-5 ${hasTaskChecklist || hasTaskFollowUp ? `border-b ${isDarkTheme ? "border-gray-800" : "border-gray-200"}` : ""}` }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-wrap items-center gap-2 mb-2" }, progress2.status === "completed" && /* @__PURE__ */ React.createElement("span", { className: `${taskStatusPillClass} ${isDarkTheme ? "bg-green-950 text-green-200 border-green-800" : "bg-green-50 text-green-800 border-green-200"}` }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-check mr-1", "aria-hidden": "true" }), "Completed"), progress2.status === "in-progress" && /* @__PURE__ */ React.createElement("span", { className: `${taskStatusPillClass} ${isDarkTheme ? "bg-indigo-950 text-indigo-200 border-indigo-800" : "bg-indigo-50 text-indigo-800 border-indigo-200"}` }, "In Progress"), taskPriorityMeta && /* @__PURE__ */ React.createElement("span", { className: `${taskStatusPillClass} ${taskPriorityMeta.className}` }, taskPriorityMeta.label), task.category && /* @__PURE__ */ React.createElement("span", { className: summaryPillClass }, task.category), task.estimated_time && /* @__PURE__ */ React.createElement("span", { className: summaryPillClass }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-clock mr-1", "aria-hidden": "true" }), /* @__PURE__ */ React.createElement("span", { className: "sr-only" }, "Estimated time: "), task.estimated_time)), /* @__PURE__ */ React.createElement("h4", { className: `text-base font-semibold ${headingClass}` }, task.title || `Task ${taskIndex + 1}`), task.description && /* @__PURE__ */ React.createElement("p", { className: `mt-1 text-sm ${mutedTextClass}` }, task.description), taskStepCount > 0 && /* @__PURE__ */ React.createElement("div", { className: "mt-3" }, /* @__PURE__ */ React.createElement("div", { className: `flex items-center justify-between text-xs mb-1 ${summaryLabelClass}` }, /* @__PURE__ */ React.createElement("span", { className: "font-medium" }, completionPct, "% done"), /* @__PURE__ */ React.createElement("span", null, progress2.completedSteps.length, " of ", taskStepCount, " step", taskStepCount === 1 ? "" : "s")), /* @__PURE__ */ React.createElement(
          "div",
          {
            className: `w-full rounded-full h-1.5 overflow-hidden ${isDarkTheme ? "bg-gray-800" : "bg-gray-200"}`,
            role: "progressbar",
            "aria-label": `${task.title || `Task ${taskIndex + 1}`} progress`,
            "aria-valuemin": 0,
            "aria-valuemax": 100,
            "aria-valuenow": completionPct
          },
          /* @__PURE__ */ React.createElement(
            "div",
            {
              className: `h-full rounded-full transition-all duration-500 ${completionPct === 100 ? "bg-green-600" : "bg-indigo-600"}`,
              style: { width: `${completionPct}%` }
            }
          )
        )), task.impact && /* @__PURE__ */ React.createElement("p", { className: `mt-3 text-sm ${mutedTextClass}` }, /* @__PURE__ */ React.createElement("span", { className: `font-semibold ${headingClass}` }, "Impact:"), " ", task.impact), /* @__PURE__ */ React.createElement("div", { className: "mt-4 flex flex-wrap gap-2" }, /* @__PURE__ */ React.createElement(
          "button",
          {
            type: "button",
            onClick: () => focusQueriesForTask(task),
            className: summaryButtonClass
          },
          /* @__PURE__ */ React.createElement("i", { className: "fas fa-code", "aria-hidden": "true" }),
          "Show Related Searches"
        ))), (hasTaskChecklist || hasTaskFollowUp) && /* @__PURE__ */ React.createElement("details", { className: "group", open: progress2.status === "in-progress" }, /* @__PURE__ */ React.createElement("summary", { className: `cursor-pointer px-5 py-3 transition-colors list-none flex items-center justify-between ${isDarkTheme ? "bg-gray-900 hover:bg-gray-800" : "bg-gray-50 hover:bg-gray-100"}` }, /* @__PURE__ */ React.createElement("span", { className: `text-sm font-semibold flex items-center ${headingClass}` }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-chevron-right mr-2 group-open:rotate-90 transition-transform", "aria-hidden": "true" }), taskStepCount > 0 ? "Steps and Verification" : "Task Details"), taskStepCount > 0 && /* @__PURE__ */ React.createElement("span", { className: `text-sm ${summaryLabelClass}` }, taskStepCount, " step", taskStepCount === 1 ? "" : "s")), /* @__PURE__ */ React.createElement("div", { className: "p-5" }, /* @__PURE__ */ React.createElement("div", { className: `grid gap-5 ${hasTaskChecklist && hasTaskFollowUp ? "lg:grid-cols-2" : ""}` }, /* @__PURE__ */ React.createElement("div", { className: `space-y-4 min-w-0 ${hasTaskChecklist ? "" : "hidden"}` }, task.prerequisites && task.prerequisites.length > 0 && /* @__PURE__ */ React.createElement("div", { className: taskSurfaceClass }, /* @__PURE__ */ React.createElement("div", { className: "flex items-center justify-between gap-3" }, /* @__PURE__ */ React.createElement("h5", { className: `text-sm font-semibold flex items-center ${headingClass}` }, /* @__PURE__ */ React.createElement("i", { className: `fas fa-list-check mr-2 ${isDarkTheme ? "text-indigo-300" : "text-indigo-600"}`, "aria-hidden": "true" }), "Prerequisites"), /* @__PURE__ */ React.createElement("span", { className: `text-xs ${summaryLabelClass}` }, task.prerequisites.length, " item", task.prerequisites.length === 1 ? "" : "s")), /* @__PURE__ */ React.createElement("ul", { className: "mt-3 space-y-2" }, task.prerequisites.map((prereq, pIdx) => /* @__PURE__ */ React.createElement("li", { key: pIdx, className: `text-sm flex items-start ${mutedTextClass}` }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-angle-right mr-2 mt-1", "aria-hidden": "true" }), /* @__PURE__ */ React.createElement("span", null, prereq))))), taskStepCount > 0 && /* @__PURE__ */ React.createElement("div", { className: taskSurfaceClass }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between" }, /* @__PURE__ */ React.createElement("h5", { className: `text-sm font-semibold flex items-center ${headingClass}` }, /* @__PURE__ */ React.createElement("i", { className: `fas fa-list-ol mr-2 ${isDarkTheme ? "text-indigo-300" : "text-indigo-600"}`, "aria-hidden": "true" }), "Checklist"), /* @__PURE__ */ React.createElement("span", { className: `text-xs ${summaryLabelClass}` }, progress2.completedSteps.length, " of ", taskStepCount, " done")), /* @__PURE__ */ React.createElement("div", { className: "mt-4 space-y-3" }, task.steps && task.steps.length > 0 && task.steps.map((step, sIdx) => {
          const isCompleted = progress2.completedSteps.includes(step.number);
          return /* @__PURE__ */ React.createElement("div", { key: sIdx, className: `border rounded-lg p-4 transition-colors ${summaryCardClass}` }, /* @__PURE__ */ React.createElement("div", { className: "flex items-start gap-3 min-w-0" }, /* @__PURE__ */ React.createElement(
            "input",
            {
              type: "checkbox",
              id: `summary-task-${taskIndex}-step-${sIdx}`,
              checked: isCompleted,
              onChange: () => toggleStepCompletion(currentSessionId, taskIndex, step.number),
              className: "mt-1 w-4 h-4 text-indigo-600 border-gray-300 rounded focus:ring-indigo-500 cursor-pointer flex-shrink-0"
            }
          ), /* @__PURE__ */ React.createElement("label", { htmlFor: `summary-task-${taskIndex}-step-${sIdx}`, className: `flex-1 min-w-0 cursor-pointer text-sm leading-6 ${isCompleted ? `${summaryLabelClass} line-through` : headingClass}` }, /* @__PURE__ */ React.createElement("span", { className: "font-semibold" }, "Step ", step.number || sIdx + 1, "."), " ", step.action)), step.spl && /* @__PURE__ */ React.createElement("div", { className: "mt-3 sm:ml-7" }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between mb-2" }, /* @__PURE__ */ React.createElement("span", { className: `text-xs font-semibold uppercase tracking-wide ${summaryLabelClass}` }, "Step SPL"), renderSplQueryActionButtons2(step.spl, {
            originKind: "summary_task_step",
            originLabel: task.title || `Task ${taskIndex + 1}`,
            sourceLabel: task.title || "Summary task",
            contextExcerpt: step.action,
            className: "sm:justify-end"
          })), /* @__PURE__ */ React.createElement("pre", { className: `max-h-48 overflow-auto rounded-md border p-3 text-xs font-mono ${summaryCodeClass}` }, step.spl)));
        })))), /* @__PURE__ */ React.createElement("div", { className: `space-y-4 min-w-0 ${hasTaskFollowUp ? "" : "hidden"}` }, task.verification_spl && /* @__PURE__ */ React.createElement("div", { className: taskSurfaceClass }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between" }, /* @__PURE__ */ React.createElement("div", { className: "min-w-0" }, /* @__PURE__ */ React.createElement("h5", { className: `text-sm font-semibold flex items-center ${headingClass}` }, /* @__PURE__ */ React.createElement("i", { className: `fas fa-check-circle mr-2 ${isDarkTheme ? "text-indigo-300" : "text-indigo-600"}`, "aria-hidden": "true" }), "Verification"), task.expected_outcome && /* @__PURE__ */ React.createElement("p", { className: `mt-1 text-sm ${mutedTextClass}` }, /* @__PURE__ */ React.createElement("span", { className: `font-semibold ${headingClass}` }, "Expected result:"), " ", task.expected_outcome)), /* @__PURE__ */ React.createElement(
          "button",
          {
            type: "button",
            onClick: () => runVerification(currentSessionId, taskIndex, task),
            disabled: verifyingTask === taskIndex,
            "aria-busy": verifyingTask === taskIndex,
            className: `inline-flex flex-shrink-0 items-center justify-center rounded-md px-3 py-1.5 text-sm font-medium transition-colors ${verifyingTask === taskIndex ? `border cursor-wait ${isDarkTheme ? "border-gray-700 bg-gray-800 text-gray-200" : "border-gray-300 bg-gray-100 text-gray-800"}` : "bg-indigo-600 hover:bg-indigo-700 text-white"}`
          },
          verifyingTask === taskIndex ? /* @__PURE__ */ React.createElement(React.Fragment, null, /* @__PURE__ */ React.createElement("i", { className: "fas fa-spinner fa-spin mr-2", "aria-hidden": "true" }), "Verifying...") : /* @__PURE__ */ React.createElement(React.Fragment, null, /* @__PURE__ */ React.createElement("i", { className: "fas fa-play-circle mr-2", "aria-hidden": "true" }), "Run Verification")
        )), /* @__PURE__ */ React.createElement("details", { className: "mt-3" }, /* @__PURE__ */ React.createElement("summary", { className: `cursor-pointer text-sm font-medium ${isDarkTheme ? "text-indigo-300 hover:text-indigo-200" : "text-indigo-700 hover:text-indigo-800"}` }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-code mr-1", "aria-hidden": "true" }), "Show verification SPL"), /* @__PURE__ */ React.createElement("div", { className: "mt-2 flex flex-wrap items-center justify-end gap-2 mb-2" }, renderSplQueryActionButtons2(task.verification_spl, {
          originKind: "summary_verification",
          originLabel: task.title || `Task ${taskIndex + 1}`,
          sourceLabel: task.title || "Verification task",
          contextExcerpt: task.expected_outcome,
          className: "justify-end"
        })), /* @__PURE__ */ React.createElement("pre", { className: `max-h-48 overflow-auto rounded-md border p-3 text-xs font-mono ${summaryCodeClass}` }, task.verification_spl)), (() => {
          const verResult = getVerificationResult(currentSessionId, taskIndex);
          if (!verResult) return null;
          const verificationResultSurfaceClass = verResult.status === "success" ? isDarkTheme ? "bg-green-950/40 border-green-700" : "bg-green-50 border-green-200" : verResult.status === "partial" ? isDarkTheme ? "bg-amber-950/40 border-amber-700" : "bg-amber-50 border-amber-200" : verResult.status === "failed" ? isDarkTheme ? "bg-red-950/40 border-red-700" : "bg-red-50 border-red-200" : isDarkTheme ? "bg-gray-900 border-gray-700" : "bg-gray-50 border-gray-200";
          const verificationResultTextClass = verResult.status === "success" ? isDarkTheme ? "text-green-100" : "text-green-900" : verResult.status === "partial" ? isDarkTheme ? "text-amber-100" : "text-amber-900" : verResult.status === "failed" ? isDarkTheme ? "text-red-100" : "text-red-900" : isDarkTheme ? "text-gray-100" : "text-gray-900";
          const verificationResultPillClass = verResult.status === "success" ? isDarkTheme ? "bg-green-950 text-green-200 border-green-800" : "bg-white text-green-800 border-green-300" : verResult.status === "partial" ? isDarkTheme ? "bg-amber-950 text-amber-200 border-amber-800" : "bg-white text-amber-800 border-amber-300" : verResult.status === "failed" ? isDarkTheme ? "bg-red-950 text-red-200 border-red-800" : "bg-white text-red-800 border-red-300" : isDarkTheme ? "bg-gray-800 text-gray-200 border-gray-700" : "bg-white text-gray-700 border-gray-300";
          return /* @__PURE__ */ React.createElement("div", { className: `mt-4 rounded-lg border p-4 fade-in ${verificationResultSurfaceClass}` }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between" }, /* @__PURE__ */ React.createElement("div", { className: "flex items-center gap-2 flex-wrap" }, /* @__PURE__ */ React.createElement("span", { className: `${taskStatusPillClass} ${verificationResultPillClass}` }, getVerificationStatusLabel(verResult.status))), /* @__PURE__ */ React.createElement("span", { className: `text-xs ${summaryLabelClass}` }, formatMissionDateTime(verResult.timestamp))), /* @__PURE__ */ React.createElement("p", { className: `mt-3 text-sm leading-6 ${verificationResultTextClass}` }, verResult.message), verResult.metrics && /* @__PURE__ */ React.createElement("div", { className: `${taskNestedSurfaceClass} mt-4 p-3` }, /* @__PURE__ */ React.createElement("h6", { className: `text-xs font-semibold uppercase tracking-wide ${isDarkTheme ? "text-gray-300" : "text-gray-600"}` }, "Metrics"), /* @__PURE__ */ React.createElement("div", { className: "mt-3 grid gap-3 text-xs md:grid-cols-2" }, verResult.metrics.current_value && /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("span", { className: `${isDarkTheme ? "text-gray-400" : "text-gray-500"}` }, "Current:"), /* @__PURE__ */ React.createElement("div", { className: `mt-1 font-medium leading-5 ${isDarkTheme ? "text-gray-100" : "text-gray-900"}` }, verResult.metrics.current_value)), verResult.metrics.expected_value && /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("span", { className: `${isDarkTheme ? "text-gray-400" : "text-gray-500"}` }, "Expected:"), /* @__PURE__ */ React.createElement("div", { className: `mt-1 font-medium leading-5 ${isDarkTheme ? "text-gray-100" : "text-gray-900"}` }, verResult.metrics.expected_value)), verResult.metrics.gap && /* @__PURE__ */ React.createElement("div", { className: "md:col-span-2" }, /* @__PURE__ */ React.createElement("span", { className: `${isDarkTheme ? "text-gray-400" : "text-gray-500"}` }, "Gap:"), /* @__PURE__ */ React.createElement("div", { className: `mt-1 font-medium leading-5 ${isDarkTheme ? "text-amber-200" : "text-amber-800"}` }, verResult.metrics.gap)))), verResult.recommendations && verResult.recommendations.length > 0 && /* @__PURE__ */ React.createElement("div", { className: `${taskNestedSurfaceClass} mt-4 p-3` }, /* @__PURE__ */ React.createElement("h6", { className: `text-xs font-semibold uppercase tracking-wide flex items-center ${isDarkTheme ? "text-gray-300" : "text-gray-600"}` }, "Recommendations"), /* @__PURE__ */ React.createElement("ul", { className: "mt-3 space-y-2" }, verResult.recommendations.map((rec, rIdx) => /* @__PURE__ */ React.createElement("li", { key: rIdx, className: `text-xs flex items-start leading-5 ${isDarkTheme ? "text-gray-200" : "text-gray-700"}` }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-arrow-right mr-2 mt-1", "aria-hidden": "true" }), /* @__PURE__ */ React.createElement("span", null, rec))))), (verResult.status === "failed" || verResult.status === "partial") && /* @__PURE__ */ React.createElement("div", { className: "mt-4 flex flex-wrap gap-2" }, /* @__PURE__ */ React.createElement(
            "button",
            {
              type: "button",
              onClick: () => getRemediation(currentSessionId, taskIndex, task, verResult),
              disabled: loadingRemediation === taskIndex,
              "aria-busy": loadingRemediation === taskIndex,
              className: "inline-flex items-center justify-center rounded-md px-3 py-1.5 bg-indigo-600 hover:bg-indigo-700 text-white text-sm font-medium disabled:cursor-wait"
            },
            loadingRemediation === taskIndex ? /* @__PURE__ */ React.createElement(React.Fragment, null, /* @__PURE__ */ React.createElement("i", { className: "fas fa-spinner fa-spin mr-1", "aria-hidden": "true" }), "Analyzing...") : /* @__PURE__ */ React.createElement(React.Fragment, null, /* @__PURE__ */ React.createElement("i", { className: "fas fa-wrench mr-1", "aria-hidden": "true" }), "Suggest a Fix")
          ), /* @__PURE__ */ React.createElement(
            "button",
            {
              type: "button",
              onClick: () => runVerification(currentSessionId, taskIndex, task),
              disabled: verifyingTask === taskIndex,
              className: `${summaryButtonClass} disabled:cursor-wait`
            },
            /* @__PURE__ */ React.createElement("i", { className: "fas fa-redo", "aria-hidden": "true" }),
            "Run Again"
          ), /* @__PURE__ */ React.createElement(
            "button",
            {
              onClick: () => {
                loadVerificationHistory(currentSessionId, taskIndex);
                setShowHistory(showHistory === taskIndex ? null : taskIndex);
              },
              type: "button",
              "aria-expanded": showHistory === taskIndex,
              className: summaryButtonClass
            },
            /* @__PURE__ */ React.createElement("i", { className: "fas fa-history", "aria-hidden": "true" }),
            "History"
          )), verResult.status === "success" && /* @__PURE__ */ React.createElement("div", { className: "mt-4 flex flex-wrap gap-2" }, /* @__PURE__ */ React.createElement(
            "button",
            {
              onClick: () => {
                loadVerificationHistory(currentSessionId, taskIndex);
                setShowHistory(showHistory === taskIndex ? null : taskIndex);
              },
              type: "button",
              "aria-expanded": showHistory === taskIndex,
              className: summaryButtonClass
            },
            /* @__PURE__ */ React.createElement("i", { className: "fas fa-history", "aria-hidden": "true" }),
            "View History"
          )), (() => {
            var _a2;
            const remediation = remediationData[`${currentSessionId}_task${taskIndex}`];
            if (!remediation) return null;
            return /* @__PURE__ */ React.createElement("div", { className: `mt-4 rounded-lg border p-4 fade-in ${summaryCardClass}` }, /* @__PURE__ */ React.createElement("h6", { className: `text-sm font-semibold mb-3 flex items-center ${headingClass}` }, /* @__PURE__ */ React.createElement("i", { className: `fas fa-wrench mr-2 ${isDarkTheme ? "text-indigo-300" : "text-indigo-600"}`, "aria-hidden": "true" }), "Suggested Fix"), /* @__PURE__ */ React.createElement("div", { className: `rounded-lg border p-3 mb-3 ${summaryInsetClass}` }, /* @__PURE__ */ React.createElement("div", { className: `text-xs font-semibold mb-1 flex items-center ${isDarkTheme ? "text-gray-300" : "text-gray-700"}` }, "Likely Cause"), /* @__PURE__ */ React.createElement("p", { className: `text-xs leading-5 ${isDarkTheme ? "text-gray-200" : "text-gray-800"}` }, remediation.root_cause)), /* @__PURE__ */ React.createElement("div", { className: `rounded-lg border p-3 mb-3 ${summaryInsetClass}` }, /* @__PURE__ */ React.createElement("div", { className: `text-xs font-semibold mb-2 flex items-center ${isDarkTheme ? "text-gray-300" : "text-gray-700"}` }, "Steps"), /* @__PURE__ */ React.createElement("div", { className: "space-y-3" }, (_a2 = remediation.remediation_steps) == null ? void 0 : _a2.map((step, sIdx) => /* @__PURE__ */ React.createElement("div", { key: sIdx, className: `border-l-2 pl-3 ${isDarkTheme ? "border-indigo-500" : "border-indigo-300"}` }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-col gap-2 sm:flex-row sm:items-start sm:justify-between" }, /* @__PURE__ */ React.createElement("span", { className: `text-xs font-medium leading-5 ${isDarkTheme ? "text-gray-100" : "text-gray-900"}` }, step.number, ". ", step.action), step.risk && /* @__PURE__ */ React.createElement("span", { className: `${taskStatusPillClass} self-start ${step.risk === "low" ? isDarkTheme ? "bg-green-950 text-green-200 border-green-800" : "bg-green-50 text-green-800 border-green-200" : step.risk === "medium" ? isDarkTheme ? "bg-amber-950 text-amber-200 border-amber-800" : "bg-amber-50 text-amber-800 border-amber-200" : isDarkTheme ? "bg-red-950 text-red-200 border-red-800" : "bg-red-50 text-red-800 border-red-200"}` }, formatSummaryLevel(step.risk), " risk")), step.explanation && /* @__PURE__ */ React.createElement("p", { className: `mt-2 text-xs leading-5 ${isDarkTheme ? "text-gray-300" : "text-gray-600"}` }, step.explanation), step.spl && /* @__PURE__ */ React.createElement("pre", { className: `mt-2 max-h-40 overflow-auto rounded-md border p-2 text-xs font-mono ${summaryCodeClass}` }, step.spl))))), (remediation.estimated_time || remediation.success_probability) && /* @__PURE__ */ React.createElement("dl", { className: "grid gap-2 text-xs sm:grid-cols-2" }, remediation.estimated_time && /* @__PURE__ */ React.createElement("div", { className: `rounded-lg border p-3 ${summaryInsetClass}` }, /* @__PURE__ */ React.createElement("dt", { className: summaryLabelClass }, "Estimated time"), /* @__PURE__ */ React.createElement("dd", { className: `mt-1 font-medium ${headingClass}` }, remediation.estimated_time)), remediation.success_probability && /* @__PURE__ */ React.createElement("div", { className: `rounded-lg border p-3 ${summaryInsetClass}` }, /* @__PURE__ */ React.createElement("dt", { className: summaryLabelClass }, "Chance of success"), /* @__PURE__ */ React.createElement("dd", { className: `mt-1 font-medium ${remediation.success_probability === "high" ? isDarkTheme ? "text-green-300" : "text-green-700" : remediation.success_probability === "medium" ? isDarkTheme ? "text-amber-300" : "text-amber-800" : isDarkTheme ? "text-red-300" : "text-red-700"}` }, formatSummaryLevel(remediation.success_probability)))), remediation.preventive_measures && remediation.preventive_measures.length > 0 && /* @__PURE__ */ React.createElement("details", { className: `mt-3 rounded-lg border p-3 ${summaryInsetClass}` }, /* @__PURE__ */ React.createElement("summary", { className: `text-xs font-semibold cursor-pointer ${isDarkTheme ? "text-gray-300" : "text-gray-700"}` }, "How to Prevent It"), /* @__PURE__ */ React.createElement("ul", { className: "mt-2 space-y-1" }, remediation.preventive_measures.map((measure, mIdx) => /* @__PURE__ */ React.createElement("li", { key: mIdx, className: `text-xs flex items-start leading-5 ${isDarkTheme ? "text-gray-200" : "text-gray-700"}` }, /* @__PURE__ */ React.createElement("i", { className: `fas fa-check-circle mr-2 mt-1 ${isDarkTheme ? "text-green-300" : "text-green-700"}`, "aria-hidden": "true" }), /* @__PURE__ */ React.createElement("span", null, measure))))));
          })(), showHistory === taskIndex && (() => {
            var _a2, _b2, _c2;
            const history = verificationHistory[`${currentSessionId}_task${taskIndex}`];
            if (!history) {
              return /* @__PURE__ */ React.createElement("div", { className: `mt-4 text-xs ${summaryLabelClass}` }, "Loading history...");
            }
            return /* @__PURE__ */ React.createElement("div", { className: `${taskNestedSurfaceClass} mt-4 p-4 fade-in` }, /* @__PURE__ */ React.createElement("div", { className: "mb-3 flex items-center justify-between" }, /* @__PURE__ */ React.createElement("h6", { className: `text-sm font-semibold flex items-center ${headingClass}` }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-history mr-2", "aria-hidden": "true" }), "Verification History"), /* @__PURE__ */ React.createElement(
              "button",
              {
                type: "button",
                onClick: () => setShowHistory(null),
                "aria-label": "Close verification history",
                className: `rounded-md p-1.5 ${isDarkTheme ? "text-gray-400 hover:text-gray-200 hover:bg-gray-800" : "text-gray-500 hover:text-gray-700 hover:bg-gray-100"}`
              },
              /* @__PURE__ */ React.createElement("i", { className: "fas fa-times", "aria-hidden": "true" })
            )), /* @__PURE__ */ React.createElement("dl", { className: "grid gap-2 mb-3 grid-cols-2 lg:grid-cols-4" }, [
              { key: "attempts", label: "Attempts", value: (_a2 = history.total_attempts) != null ? _a2 : 0 },
              { key: "passed", label: "Passed", value: (_b2 = history.successful_attempts) != null ? _b2 : 0 },
              { key: "rate", label: "Pass rate", value: `${Math.round((history.success_rate || 0) * 100)}%` },
              {
                key: "trend",
                label: "Trend",
                value: history.improvement_trend === "improving" ? "Improving" : history.improvement_trend === "stable" ? "Stable" : history.improvement_trend ? "Declining" : "Not enough data"
              }
            ].map((stat) => /* @__PURE__ */ React.createElement("div", { key: stat.key, className: `flex flex-col-reverse rounded-lg border p-3 text-center ${summaryInsetClass}` }, /* @__PURE__ */ React.createElement("dt", { className: `text-xs ${summaryLabelClass}` }, stat.label), /* @__PURE__ */ React.createElement("dd", { className: `text-base font-semibold ${headingClass}` }, stat.value)))), history.time_to_success && /* @__PURE__ */ React.createElement("div", { className: `rounded-lg border p-2 mb-3 text-xs ${summaryInsetClass}` }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-clock mr-1", "aria-hidden": "true" }), "Time to success: ", /* @__PURE__ */ React.createElement("span", { className: "font-semibold" }, history.time_to_success)), /* @__PURE__ */ React.createElement("div", { className: "space-y-2 max-h-64 overflow-y-auto pr-1" }, (_c2 = history.verifications) == null ? void 0 : _c2.map((ver, vIdx) => /* @__PURE__ */ React.createElement("div", { key: vIdx, className: `rounded-lg p-3 border-l-4 ${ver.status === "success" ? isDarkTheme ? "bg-green-950/30 border-green-500" : "bg-green-50 border-green-500" : ver.status === "partial" ? isDarkTheme ? "bg-amber-950/30 border-amber-500" : "bg-amber-50 border-amber-500" : isDarkTheme ? "bg-red-950/30 border-red-500" : "bg-red-50 border-red-500"}` }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-col gap-1 sm:flex-row sm:items-center sm:justify-between mb-1" }, /* @__PURE__ */ React.createElement("span", { className: `text-xs font-semibold ${ver.status === "success" ? isDarkTheme ? "text-green-300" : "text-green-800" : ver.status === "partial" ? isDarkTheme ? "text-amber-300" : "text-amber-800" : isDarkTheme ? "text-red-300" : "text-red-800"}` }, "Attempt ", vIdx + 1, ": ", getVerificationStatusLabel(ver.status)), /* @__PURE__ */ React.createElement("span", { className: `text-xs ${summaryLabelClass}` }, formatMissionDateTime(ver.timestamp))), /* @__PURE__ */ React.createElement("p", { className: `text-xs leading-5 ${isDarkTheme ? "text-gray-200" : "text-gray-700"}` }, ver.message)))));
          })());
        })()), task.rollback && /* @__PURE__ */ React.createElement("div", { className: taskSurfaceClass }, /* @__PURE__ */ React.createElement("h5", { className: `font-semibold mb-1 flex items-center text-sm ${headingClass}` }, /* @__PURE__ */ React.createElement("i", { className: `fas fa-undo mr-2 ${isDarkTheme ? "text-indigo-300" : "text-indigo-600"}`, "aria-hidden": "true" }), "How to Undo"), /* @__PURE__ */ React.createElement("p", { className: `text-sm leading-6 ${mutedTextClass}` }, task.rollback)))))));
      }) : /* @__PURE__ */ React.createElement("div", { className: `rounded-lg border border-dashed p-6 text-center ${isDarkTheme ? "border-gray-700 bg-gray-900 text-gray-300" : "border-gray-300 bg-gray-50 text-gray-600"}` }, /* @__PURE__ */ React.createElement("p", { className: `text-sm font-semibold ${headingClass}` }, "No tasks match this filter."), /* @__PURE__ */ React.createElement("p", { className: "text-sm mt-2" }, "Choose another filter to see more tasks.")))) : /* @__PURE__ */ React.createElement("div", { className: `rounded-lg border border-dashed p-8 text-center ${isDarkTheme ? "border-gray-700 bg-gray-900 text-gray-300" : "border-gray-300 bg-gray-50 text-gray-600"}` }, /* @__PURE__ */ React.createElement("i", { className: `fas fa-tasks text-2xl mb-3 ${summaryLabelClass}`, "aria-hidden": "true" }), /* @__PURE__ */ React.createElement("p", { className: `text-sm font-semibold ${headingClass}` }, "No admin tasks for this run."), /* @__PURE__ */ React.createElement("p", { className: "mt-2 text-sm" }, "This summary did not include recommended tasks. Ask in Chat for next steps.")))) : /* @__PURE__ */ React.createElement("div", { className: `text-center py-12 ${mutedTextClass}` }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-exclamation-circle text-3xl mb-3", "aria-hidden": "true" }), /* @__PURE__ */ React.createElement("p", null, "No summary is available for this run.")))))
    ), isSettingsOpen && config && /* @__PURE__ */ React.createElement("div", { className: "fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50", onClick: closeSettings }, /* @__PURE__ */ React.createElement("div", { className: `settings-modal-shell rounded-xl shadow-2xl w-full max-w-5xl h-5/6 flex flex-col ${isDarkTheme ? "bg-gray-800" : "bg-white"}`, onClick: (e) => e.stopPropagation(), role: "dialog", "aria-modal": "true", "aria-labelledby": "settings-modal-title", onKeyDown: (event) => handleDialogKeyDown(event, closeSettings) }, /* @__PURE__ */ React.createElement("div", { className: `p-6 border-b flex justify-between items-center ${isDarkTheme ? "border-gray-700" : "border-gray-200"}` }, /* @__PURE__ */ React.createElement("div", { className: "flex items-center" }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-cog text-2xl text-indigo-600 mr-3" }), /* @__PURE__ */ React.createElement("h2", { id: "settings-modal-title", className: `text-xl font-semibold ${isDarkTheme ? "text-gray-100" : "text-gray-900"}` }, "Settings")), /* @__PURE__ */ React.createElement("button", { type: "button", onClick: closeSettings, className: `${isDarkTheme ? "text-gray-400 hover:text-gray-200" : "text-gray-500 hover:text-gray-700"}`, "aria-label": "Close settings" }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-times text-xl" }))), /* @__PURE__ */ React.createElement("div", { className: "flex-1 overflow-y-auto p-6 space-y-6" }, /* @__PURE__ */ React.createElement("div", { className: `rounded-xl border p-2 ${isDarkTheme ? "bg-gray-900 border-gray-700" : "bg-gray-50 border-gray-200"}` }, /* @__PURE__ */ React.createElement("div", { className: "grid gap-2 grid-cols-2 sm:grid-cols-3 md:grid-cols-5" }, SETTINGS_MODAL_TABS.map((tab) => {
      const isActive = activeSettingsTab === tab.id;
      return /* @__PURE__ */ React.createElement(
        "button",
        {
          key: `settings-tab-${tab.id}`,
          type: "button",
          "data-testid": `settings-tab-${tab.id}`,
          onClick: () => setActiveSettingsTab(tab.id),
          className: `flex items-center justify-center gap-2 rounded-lg px-4 py-3 text-sm font-medium transition-colors ${isActive ? "bg-indigo-600 text-white shadow-sm" : isDarkTheme ? "bg-gray-800 text-gray-200 hover:bg-gray-700" : "bg-white text-gray-700 hover:bg-gray-100"}`,
          "aria-pressed": isActive
        },
        /* @__PURE__ */ React.createElement("i", { className: `fas ${tab.icon}`, "aria-hidden": "true" }),
        /* @__PURE__ */ React.createElement("span", null, tab.label)
      );
    }))), renderServerCodeBanner(), renderSecurityAccessSettings(), renderSettingsTroubleshooter(), activeSettingsTab === "appearance" && /* @__PURE__ */ React.createElement("div", { "data-testid": "settings-appearance-panel", className: "space-y-6" }, /* @__PURE__ */ React.createElement("section", { className: `rounded-lg border p-6 ${isDarkTheme ? "bg-gray-800 border-gray-700" : "bg-white border-gray-200"}`, "aria-labelledby": "settings-appearance-heading" }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-wrap items-center justify-between gap-2 mb-2" }, /* @__PURE__ */ React.createElement("h3", { id: "settings-appearance-heading", className: `text-lg font-semibold ${isDarkTheme ? "text-gray-100" : "text-gray-900"}` }, /* @__PURE__ */ React.createElement("i", { className: `fas fa-adjust mr-2 ${isDarkTheme ? "text-indigo-300" : "text-indigo-600"}`, "aria-hidden": "true" }), "Theme"), themePreference === "system" && /* @__PURE__ */ React.createElement("span", { "data-testid": "settings-theme-resolved", className: `text-xs ${isDarkTheme ? "text-gray-300" : "text-gray-600"}` }, "Showing ", resolvedTheme === "dark" ? "Dark" : "Light", " to match your computer")), /* @__PURE__ */ React.createElement("p", { className: `text-sm ${isDarkTheme ? "text-gray-300" : "text-gray-600"}` }, "Changes apply right away and are saved for this browser. System follows your computer's light or dark setting. Neo is a dark green-on-black theme."), /* @__PURE__ */ React.createElement("div", { className: `dt4sms-appearance-theme-group mt-4 inline-flex rounded-lg border overflow-hidden ${isDarkTheme ? "border-gray-600" : "border-gray-300"}`, role: "group", "aria-labelledby": "settings-appearance-heading" }, THEME_PREFERENCE_OPTIONS.map((option, index) => {
      const isSelected = themePreference === option.value;
      return /* @__PURE__ */ React.createElement(
        "button",
        {
          key: option.value,
          type: "button",
          "data-testid": `settings-theme-option-${option.value}`,
          onClick: () => applyThemePreference(option.value),
          className: `px-4 py-2 text-sm font-medium ${index > 0 ? "border-l" : ""} ${isSelected ? "bg-indigo-600 text-white border-indigo-500" : isDarkTheme ? "bg-gray-800 text-gray-200 hover:bg-gray-700 border-gray-600" : "bg-white text-gray-700 hover:bg-gray-100 border-gray-300"}`,
          "aria-pressed": isSelected
        },
        option.label
      );
    }))), /* @__PURE__ */ React.createElement("section", { className: `rounded-lg border p-6 ${isDarkTheme ? "bg-gray-800 border-gray-700" : "bg-white border-gray-200"}`, "aria-labelledby": "settings-welcome-heading" }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-col gap-3 md:flex-row md:items-start md:justify-between" }, /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("h3", { id: "settings-welcome-heading", className: `text-lg font-semibold ${isDarkTheme ? "text-gray-100" : "text-gray-900"}` }, /* @__PURE__ */ React.createElement("i", { className: `fas fa-door-open mr-2 ${isDarkTheme ? "text-indigo-300" : "text-indigo-600"}`, "aria-hidden": "true" }), "Welcome Screen"), /* @__PURE__ */ React.createElement("p", { className: `mt-1 text-sm ${isDarkTheme ? "text-gray-300" : "text-gray-600"}` }, "The introduction shown the first time this browser opens the app.")), /* @__PURE__ */ React.createElement("span", { className: `inline-flex items-center rounded-full px-2.5 py-1 text-xs font-medium border ${hasDismissedWelcomeSplash ? isDarkTheme ? "bg-gray-950 border-emerald-800 text-emerald-200" : "bg-emerald-50 border-emerald-200 text-emerald-800" : isDarkTheme ? "bg-gray-900 border-amber-800 text-amber-200" : "bg-amber-50 border-amber-200 text-amber-800"}` }, hasDismissedWelcomeSplash ? "Hidden in this browser" : "Shows next time")), /* @__PURE__ */ React.createElement("div", { className: "mt-4 flex flex-wrap gap-2" }, /* @__PURE__ */ React.createElement(
      "button",
      {
        type: "button",
        "data-testid": "settings-preview-welcome-splash",
        onClick: previewWelcomeSplash,
        className: `rounded-lg px-3 py-2 text-sm font-medium ${isDarkTheme ? "bg-gray-900 text-gray-100 border border-gray-600 hover:bg-gray-700" : "bg-white text-gray-700 border border-gray-300 hover:bg-gray-50"}`
      },
      /* @__PURE__ */ React.createElement("i", { className: "fas fa-eye mr-2", "aria-hidden": "true" }),
      "Show Welcome Screen"
    ), /* @__PURE__ */ React.createElement(
      "button",
      {
        type: "button",
        "data-testid": "settings-reset-welcome-splash",
        onClick: resetWelcomeSplashPreference,
        className: `rounded-lg px-3 py-2 text-sm font-medium ${isDarkTheme ? "bg-indigo-950 text-indigo-100 border border-indigo-800 hover:bg-indigo-900" : "bg-indigo-50 text-indigo-800 border border-indigo-200 hover:bg-indigo-100"}`
      },
      /* @__PURE__ */ React.createElement("i", { className: "fas fa-rotate-left mr-2", "aria-hidden": "true" }),
      "Show Again Next Time"
    )))), /* @__PURE__ */ React.createElement("div", { "data-testid": "settings-connections-panel", className: "space-y-6", hidden: activeSettingsTab !== "connections" }, /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("div", { className: `rounded-lg p-6 border ${isDarkTheme ? "bg-gray-800 border-gray-700" : "bg-white border-gray-200"}` }, /* @__PURE__ */ React.createElement("div", { className: "mb-4" }, /* @__PURE__ */ React.createElement("h3", { className: "text-lg font-semibold text-gray-900 mb-2" }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-server mr-2 text-indigo-600", "aria-hidden": "true" }), "MCP Servers"), /* @__PURE__ */ React.createElement("p", { className: "text-sm text-gray-600" }, "Saved connections to your Splunk MCP servers.")), (loadedMCPConfigName || (config == null ? void 0 : config.active_mcp_config_name)) && /* @__PURE__ */ React.createElement("div", { className: "mb-4 bg-emerald-50 border-l-4 border-emerald-500 rounded-r-lg p-3" }, /* @__PURE__ */ React.createElement("div", { className: "flex items-center justify-between" }, /* @__PURE__ */ React.createElement("div", { className: "flex items-center gap-2" }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-check-circle text-emerald-600", "aria-hidden": "true" }), /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("p", { className: "text-sm font-semibold text-gray-900" }, "Active Configuration:"), /* @__PURE__ */ React.createElement("p", { className: "text-base font-bold text-gray-800" }, loadedMCPConfigName || (config == null ? void 0 : config.active_mcp_config_name)))), /* @__PURE__ */ React.createElement(
      "button",
      {
        onClick: () => {
          setLoadedMCPConfigName(null);
          setShowMCPConfigForm(false);
        },
        className: "text-emerald-700 hover:text-emerald-900 text-sm font-medium",
        title: "Clear and close editor"
      },
      /* @__PURE__ */ React.createElement("i", { className: "fas fa-times-circle mr-1", "aria-hidden": "true" }),
      "Close"
    ))), !showMCPConfigForm && /* @__PURE__ */ React.createElement("div", { className: "mb-4" }, /* @__PURE__ */ React.createElement(
      "button",
      {
        onClick: () => {
          setShowMCPConfigForm(true);
          setLoadedMCPConfigName(null);
          setMCPTokenPlaceholder("Enter token");
        },
        className: "w-full px-4 py-2 bg-indigo-600 hover:bg-indigo-700 text-white rounded-lg font-medium transition-colors"
      },
      /* @__PURE__ */ React.createElement("i", { className: "fas fa-plus-circle mr-2", "aria-hidden": "true" }),
      "Add MCP Server"
    )), /* @__PURE__ */ React.createElement("div", { id: "mcp-configs-list", className: "space-y-2 max-h-96 overflow-y-auto" }, /* @__PURE__ */ React.createElement("div", { className: "text-sm text-gray-500 text-center py-4 italic" }, "Loading configurations...")))), showMCPConfigForm && /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("div", { className: "flex items-center justify-between mb-3" }, /* @__PURE__ */ React.createElement("h3", { className: "text-lg font-semibold text-gray-900" }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-server mr-2 text-indigo-600", "aria-hidden": "true" }), loadedMCPConfigName ? "Edit Configuration" : "New Configuration"), /* @__PURE__ */ React.createElement(
      "button",
      {
        onClick: () => {
          setShowMCPConfigForm(false);
          setLoadedMCPConfigName(null);
        },
        className: "px-3 py-1 text-sm text-gray-600 hover:text-gray-900 hover:bg-gray-100 rounded transition-colors"
      },
      /* @__PURE__ */ React.createElement("i", { className: "fas fa-times mr-1", "aria-hidden": "true" }),
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
    ), /* @__PURE__ */ React.createElement("label", { htmlFor: "mcp-verify-ssl", className: "text-sm text-gray-700" }, "Verify SSL Certificate")), /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("label", { htmlFor: "mcp-ca-bundle", className: "block text-sm font-medium text-gray-700 mb-1" }, "CA Bundle File", /* @__PURE__ */ React.createElement("span", { className: "ml-2 text-xs text-gray-500" }, "(optional; a .pem file on the app server, used when Verify SSL is on)")), /* @__PURE__ */ React.createElement(
      "input",
      {
        type: "text",
        defaultValue: config.mcp.ca_bundle_path || "",
        placeholder: "/path/to/splunk-ca.pem",
        className: "w-full px-3 py-2 border border-gray-300 rounded-md",
        id: "mcp-ca-bundle"
      }
    )), /* @__PURE__ */ React.createElement("div", { className: "pt-3 border-t border-gray-200 space-y-2" }, /* @__PURE__ */ React.createElement(
      "button",
      {
        type: "button",
        onClick: async (event) => {
          var _a2, _b2;
          const urlEl = document.getElementById("mcp-url");
          const tokenEl = document.getElementById("mcp-token");
          const verifySslEl = document.getElementById("mcp-verify-ssl");
          const testUrl = (urlEl == null ? void 0 : urlEl.value) || config.mcp.url;
          const testToken = (tokenEl == null ? void 0 : tokenEl.value) || "";
          const testVerifySsl = (_a2 = verifySslEl == null ? void 0 : verifySslEl.checked) != null ? _a2 : config.mcp.verify_ssl;
          if (!testUrl) {
            alert("Please enter an MCP URL");
            return;
          }
          const button = event.currentTarget;
          const originalHTML2 = button.innerHTML;
          button.disabled = true;
          button.innerHTML = '<i class="fas fa-spinner fa-spin mr-2" aria-hidden="true"></i>Testing...';
          try {
            const response = await fetch("/api/mcp-configs/test", {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({
                url: testUrl,
                token: testToken,
                verify_ssl: testVerifySsl,
                ca_bundle_path: String(((_b2 = document.getElementById("mcp-ca-bundle")) == null ? void 0 : _b2.value) || "").trim() || void 0,
                name: loadedMCPConfigName || void 0
              })
            });
            const { data, text } = await readApiResponse(response);
            const result = data || {};
            if (response.ok && result.status === "success") {
              alert("✅ " + result.message);
            } else {
              const message = response.ok && result.message ? result.message : describeApiFailure(response, data, text);
              if (confirm("⚠️ " + message + "\n\nRun Troubleshoot to find out why?")) {
                openSettingsTroubleshooter("mcp", readTroubleshootDraftFromForm("mcp"), { autoRun: true });
              }
            }
          } catch (error) {
            alert("❌ Test failed: " + error.message);
          } finally {
            button.disabled = false;
            button.innerHTML = originalHTML2;
          }
        },
        className: `w-full px-4 py-2 rounded-lg border font-medium transition-colors ${secondaryButtonClass}`
      },
      /* @__PURE__ */ React.createElement("i", { className: "fas fa-network-wired mr-2", "aria-hidden": "true" }),
      "Test Connection"
    ), /* @__PURE__ */ React.createElement(
      "button",
      {
        type: "button",
        "data-testid": "mcp-troubleshoot",
        onClick: () => openSettingsTroubleshooter("mcp", readTroubleshootDraftFromForm("mcp"), { autoRun: true }),
        className: `w-full px-4 py-2 rounded-lg border font-medium transition-colors ${secondaryButtonClass}`
      },
      /* @__PURE__ */ React.createElement("i", { className: "fas fa-stethoscope mr-2", "aria-hidden": "true" }),
      "Troubleshoot"
    ), loadedMCPConfigName ? /* @__PURE__ */ React.createElement(React.Fragment, null, /* @__PURE__ */ React.createElement(
      "button",
      {
        onClick: () => openMCPSaveModal(""),
        className: `w-full px-4 py-2 rounded-lg border font-medium transition-colors ${secondaryButtonClass}`
      },
      /* @__PURE__ */ React.createElement("i", { className: "fas fa-plus-circle mr-2", "aria-hidden": "true" }),
      "Save as New"
    ), /* @__PURE__ */ React.createElement(
      "button",
      {
        onClick: () => openMCPSaveModal(loadedMCPConfigName),
        className: "w-full px-4 py-2 bg-indigo-600 hover:bg-indigo-700 text-white rounded-lg font-medium transition-colors"
      },
      /* @__PURE__ */ React.createElement("i", { className: "fas fa-sync-alt mr-2", "aria-hidden": "true" }),
      "Update Active Configuration"
    )) : /* @__PURE__ */ React.createElement(
      "button",
      {
        onClick: () => openMCPSaveModal(""),
        className: "w-full px-4 py-2 bg-indigo-600 hover:bg-indigo-700 text-white rounded-lg font-medium transition-colors"
      },
      /* @__PURE__ */ React.createElement("i", { className: "fas fa-save mr-2", "aria-hidden": "true" }),
      "Save as New Configuration"
    )))), /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("div", { className: `rounded-lg p-6 border ${isDarkTheme ? "bg-gray-800 border-gray-700" : "bg-white border-gray-200"}` }, /* @__PURE__ */ React.createElement("div", { className: "mb-4" }, /* @__PURE__ */ React.createElement("h3", { className: "text-lg font-semibold text-gray-900 mb-2" }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-key mr-2 text-indigo-600", "aria-hidden": "true" }), "AI Models"), /* @__PURE__ */ React.createElement("p", { className: "text-sm text-gray-600" }, "Saved connections to AI model providers.")), (loadedCredentialName || (config == null ? void 0 : config.active_credential_name)) && /* @__PURE__ */ React.createElement("div", { className: "mb-4 bg-amber-50 border-l-4 border-amber-500 rounded-r-lg p-3" }, /* @__PURE__ */ React.createElement("div", { className: "flex items-center justify-between" }, /* @__PURE__ */ React.createElement("div", { className: "flex items-center gap-2" }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-check-circle text-amber-600", "aria-hidden": "true" }), /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("p", { className: "text-sm font-semibold text-gray-900" }, "Active Connection:"), /* @__PURE__ */ React.createElement("p", { className: "text-base font-bold text-gray-800" }, loadedCredentialName || (config == null ? void 0 : config.active_credential_name)))), /* @__PURE__ */ React.createElement(
      "button",
      {
        onClick: () => {
          setLoadedCredentialName(null);
          setShowConfigForm(false);
        },
        className: "text-amber-600 hover:text-amber-800 text-sm font-medium",
        title: "Clear and close editor"
      },
      /* @__PURE__ */ React.createElement("i", { className: "fas fa-times-circle mr-1", "aria-hidden": "true" }),
      "Close"
    ))), !showConfigForm && /* @__PURE__ */ React.createElement("div", { className: "mb-4" }, /* @__PURE__ */ React.createElement(
      "button",
      {
        onClick: () => {
          setShowConfigForm(true);
          setLoadedCredentialName(null);
          setApiKeyPlaceholder(getApiKeyPlaceholderForProvider(selectedProvider));
        },
        className: "w-full px-4 py-2 bg-indigo-600 hover:bg-indigo-700 text-white rounded-lg font-medium transition-colors"
      },
      /* @__PURE__ */ React.createElement("i", { className: "fas fa-plus-circle mr-2", "aria-hidden": "true" }),
      "Add AI Model"
    )), /* @__PURE__ */ React.createElement("div", { id: "credentials-list", className: "space-y-2 max-h-96 overflow-y-auto" }, /* @__PURE__ */ React.createElement("div", { className: "text-sm text-gray-500 text-center py-4 italic" }, "Loading credentials...")))), showConfigForm && /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("div", { className: "flex items-center justify-between mb-3" }, /* @__PURE__ */ React.createElement("h3", { className: "text-lg font-semibold text-gray-900" }, /* @__PURE__ */ React.createElement("i", { className: "fas fa-brain mr-2 text-indigo-600", "aria-hidden": "true" }), loadedCredentialName ? "Edit Connection" : "New Connection"), /* @__PURE__ */ React.createElement(
      "button",
      {
        onClick: () => {
          setShowConfigForm(false);
          setLoadedCredentialName(null);
        },
        className: "px-3 py-1 text-sm text-gray-600 hover:text-gray-900 hover:bg-gray-100 rounded transition-colors"
      },
      /* @__PURE__ */ React.createElement("i", { className: "fas fa-times mr-1", "aria-hidden": "true" }),
      "Cancel"
    )), /* @__PURE__ */ React.createElement("div", { className: "space-y-3" }, /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("label", { className: "block text-sm font-medium text-gray-700 mb-1" }, "Provider"), /* @__PURE__ */ React.createElement(
      "select",
      {
        value: selectedProvider,
        className: "w-full px-3 py-2 border border-gray-300 rounded-md",
        id: "llm-provider",
        onChange: (e) => {
          setSelectedProvider(e.target.value);
          setAvailableModels([]);
          setModelRanking([]);
          setLlmTuningSummary(null);
          setApiKeyPlaceholder(getApiKeyPlaceholderForProvider(e.target.value));
          handleSettingsChange();
        }
      },
      /* @__PURE__ */ React.createElement("option", { value: "openai" }, "OpenAI"),
      /* @__PURE__ */ React.createElement("option", { value: "azure" }, "Azure OpenAI"),
      /* @__PURE__ */ React.createElement("option", { value: "anthropic" }, "Anthropic (Claude)"),
      /* @__PURE__ */ React.createElement("option", { value: "gemini" }, "Google Gemini"),
      /* @__PURE__ */ React.createElement("option", { value: "ollama" }, "Ollama"),
      /* @__PURE__ */ React.createElement("option", { value: "custom" }, "Custom Endpoint")
    )), selectedProvider !== "openai" && /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("label", { className: "block text-sm font-medium text-gray-700 mb-1" }, "Endpoint URL", /* @__PURE__ */ React.createElement("span", { className: "ml-2 text-xs text-gray-500" }, "(", selectedProvider === "custom" ? "used exactly as configured" : selectedProvider === "ollama" ? "base URL for local or remote Ollama" : "base URL or full API path", ")")), /* @__PURE__ */ React.createElement(
      "input",
      {
        type: "text",
        defaultValue: config.llm.endpoint_url || "",
        placeholder: selectedProvider === "azure" ? "https://YOUR-RESOURCE.openai.azure.com" : selectedProvider === "anthropic" ? "https://api.anthropic.com (optional)" : selectedProvider === "gemini" ? "https://generativelanguage.googleapis.com (optional)" : selectedProvider === "ollama" ? "http://localhost:11434" : "http://localhost:8000/v1/chat/completions",
        className: "w-full px-3 py-2 border border-gray-300 rounded-md",
        id: "llm-endpoint-url",
        onChange: handleSettingsChange
      }
    ), selectedProvider === "ollama" && /* @__PURE__ */ React.createElement("p", { className: "mt-1 text-xs text-gray-500" }, "Ollama uses the native ", /* @__PURE__ */ React.createElement("span", { className: "font-mono" }, "/api/tags"), " model inventory and will default to ", /* @__PURE__ */ React.createElement("span", { className: "font-mono" }, "http://localhost:11434"), " if you leave this blank."), selectedProvider === "custom" && /* @__PURE__ */ React.createElement("p", { className: "mt-1 text-xs text-gray-500" }, "✅ ", /* @__PURE__ */ React.createElement("strong", null, "Full API Path (Recommended):"), " ", /* @__PURE__ */ React.createElement("span", { className: "font-mono" }, "http://localhost:8000/v1/chat/completions"), /* @__PURE__ */ React.createElement("br", null), "⚠️ ", /* @__PURE__ */ React.createElement("strong", null, "Base URL (Slower):"), " ", /* @__PURE__ */ React.createElement("span", { className: "font-mono" }, "http://localhost:8000"), " - requires auto-detection", /* @__PURE__ */ React.createElement("br", null), /* @__PURE__ */ React.createElement("span", { className: "italic" }, "URL is used exactly as entered. No automatic path manipulation."))), /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("label", { className: "block text-sm font-medium text-gray-700 mb-1" }, "API Key", (selectedProvider === "custom" || selectedProvider === "ollama") && /* @__PURE__ */ React.createElement("span", { className: "ml-2 text-xs text-gray-500" }, "(", selectedProvider === "ollama" ? "Optional for local Ollama" : "Optional for local LLMs", ")")), /* @__PURE__ */ React.createElement(
      "input",
      {
        type: "password",
        placeholder: apiKeyPlaceholder,
        className: "w-full px-3 py-2 border border-gray-300 rounded-md",
        id: "llm-api-key",
        onChange: handleApiKeyChange
      }
    )), /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("div", { className: "mb-1 flex flex-wrap items-center gap-y-1" }, /* @__PURE__ */ React.createElement("label", { htmlFor: "llm-model", className: "text-sm font-medium text-gray-700" }, "Model"), /* @__PURE__ */ React.createElement(
      "button",
      {
        onClick: async () => {
          var _a2, _b2;
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
              const ranked = Array.isArray(data.ranked) ? data.ranked : [];
              const orderedModels = ranked.length > 0 ? ranked.map((item) => item.model) : data.models || [];
              const currentModel = (((_b2 = document.getElementById("llm-model")) == null ? void 0 : _b2.value) || selectedModel || "").trim();
              setModelRanking(ranked);
              setAvailableModels(orderedModels);
              if (orderedModels.length > 0) {
                setSelectedModel(
                  currentModel && orderedModels.includes(currentModel) ? currentModel : data.recommended_model || orderedModels[0]
                );
              }
            } else {
              const error = await response.json().catch(() => ({}));
              alert("Failed to fetch models: " + (error.detail || response.statusText));
            }
          } catch (error) {
            alert("Error fetching models: " + error.message);
          } finally {
            setIsLoadingModels(false);
          }
        },
        className: "ml-2 px-2 py-1 text-xs font-medium rounded border border-gray-300 bg-white text-gray-700 hover:bg-gray-100 disabled:opacity-50",
        disabled: isLoadingModels,
        type: "button"
      },
      /* @__PURE__ */ React.createElement("i", { className: `fas ${isLoadingModels ? "fa-spinner fa-spin" : "fa-download"}`, "aria-hidden": "true" }),
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
      availableModels.map((model) => {
        const ranking = modelRanking.find((item) => item.model === model);
        const suffix = (ranking == null ? void 0 : ranking.recommended) ? " ★ recommended" : ranking && ranking.eligible === false ? " (not a chat model)" : "";
        return /* @__PURE__ */ React.createElement("option", { key: model, value: model }, model, suffix);
      })
    ) : /* @__PURE__ */ React.createElement(
      "input",
      {
        type: "text",
        defaultValue: config.llm.model,
        placeholder: selectedProvider === "openai" ? "gpt-4o" : selectedProvider === "azure" ? "your-azure-deployment-name" : selectedProvider === "anthropic" ? "claude-3-5-sonnet-latest" : selectedProvider === "gemini" ? "gemini-1.5-pro" : selectedProvider === "ollama" ? "gpt-oss:20b or llama3.2:1b" : "e.g., llama3.2:3b",
        className: "w-full px-3 py-2 border border-gray-300 rounded-md",
        id: "llm-model",
        onChange: (e) => {
          setSelectedModel(e.target.value);
          handleSettingsChange();
        }
      }
    ), recommendedModelEntry && /* @__PURE__ */ React.createElement("div", { "data-testid": "llm-model-recommendation", className: "mt-2 rounded-md border border-emerald-200 bg-emerald-50 px-3 py-2 text-xs text-emerald-900" }, /* @__PURE__ */ React.createElement("div", { className: "flex flex-wrap items-center justify-between gap-2" }, /* @__PURE__ */ React.createElement("span", null, /* @__PURE__ */ React.createElement("i", { className: "fas fa-star mr-1", "aria-hidden": "true" }), /* @__PURE__ */ React.createElement("span", { className: "font-semibold" }, "Recommended:"), " ", /* @__PURE__ */ React.createElement("span", { className: "font-mono" }, recommendedModelEntry.model), /* @__PURE__ */ React.createElement("span", { className: "ml-1 text-emerald-700" }, "(best balance of quality, speed, and cost)")), recommendedModelEntry.model !== selectedModel && /* @__PURE__ */ React.createElement(
      "button",
      {
        type: "button",
        "data-testid": "llm-use-recommended-model",
        onClick: () => {
          setSelectedModel(recommendedModelEntry.model);
          handleSettingsChange();
        },
        className: "px-2 py-0.5 rounded bg-emerald-600 text-white hover:bg-emerald-700"
      },
      "Use recommended"
    )), Array.isArray(recommendedModelEntry.reasons) && recommendedModelEntry.reasons.length > 0 && /* @__PURE__ */ React.createElement("ul", { className: "mt-1 list-disc pl-4 space-y-0.5" }, recommendedModelEntry.reasons.slice(0, 4).map((reason, reasonIdx) => /* @__PURE__ */ React.createElement("li", { key: `recommended-reason-${reasonIdx}` }, reason)))), selectedModelRanking && !selectedModelRanking.recommended && Array.isArray(selectedModelRanking.notes) && selectedModelRanking.notes.length > 0 && /* @__PURE__ */ React.createElement("p", { className: "mt-1 text-xs text-amber-700" }, selectedModelRanking.notes.join(" ")), selectedProvider !== "openai" && !recommendedModelEntry && /* @__PURE__ */ React.createElement("p", { className: "mt-1 text-xs text-gray-500 italic" }, 'Tip: Click "Fetch Models" to list available models and get a recommendation')), /* @__PURE__ */ React.createElement("div", { "data-testid": "llm-auto-tune-panel", className: "rounded-md border border-indigo-200 bg-indigo-50 px-3 py-2" }, /* @__PURE__ */ React.createElement("label", { className: "flex items-start gap-2 text-sm text-indigo-900" }, /* @__PURE__ */ React.createElement(
      "input",
      {
        type: "checkbox",
        id: "llm-auto-tune",
        className: "mt-1",
        checked: llmAutoTune,
        onChange: (e) => {
          setLlmAutoTune(e.target.checked);
          handleSettingsChange();
        }
      }
    ), /* @__PURE__ */ React.createElement("span", null, /* @__PURE__ */ React.createElement("span", { className: "font-medium" }, "Auto-tune for this model"), " (recommended)", /* @__PURE__ */ React.createElement("span", { className: "block text-xs text-indigo-700" }, "Sets output budget, temperature, context window, timeout, and reasoning effort from the model profile. Turn off to use the Max Tokens and Temperature values below exactly."))), activeLlmTuning && /* @__PURE__ */ React.createElement("div", { "data-testid": "llm-tuning-summary", className: "mt-2 text-xs text-indigo-800" }, /* @__PURE__ */ React.createElement("div", { className: "font-medium" }, describeLlmTuning(activeLlmTuning)), activeLlmTuning.source && /* @__PURE__ */ React.createElement("div", { className: "text-indigo-700" }, "Based on ", activeLlmTuning.source, "."), Array.isArray(activeLlmTuning.notes) && activeLlmTuning.notes.length > 0 && /* @__PURE__ */ React.createElement("div", { className: "text-amber-700" }, activeLlmTuning.notes.join(" ")))), /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("div", { className: "mb-1 flex flex-wrap items-center gap-y-1" }, /* @__PURE__ */ React.createElement("label", { htmlFor: "llm-max-tokens", className: "text-sm font-medium text-gray-700" }, "Max Tokens", llmAutoTune && /* @__PURE__ */ React.createElement("span", { className: "ml-2 text-xs text-gray-500" }, "(used when auto-tune is off)")), /* @__PURE__ */ React.createElement(
      "button",
      {
        type: "button",
        onClick: async (event) => {
          var _a2, _b2, _c2, _d2, _e2;
          const btn = event.currentTarget;
          btn.disabled = true;
          btn.innerHTML = '<i class="fas fa-spinner fa-spin" aria-hidden="true"></i> Checking...';
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
            if (!response.ok) {
              throw new Error(result.detail || "Assessment failed");
            }
            if (Number.isFinite(result.recommended_max_tokens)) {
              document.getElementById("llm-max-tokens").value = result.recommended_max_tokens;
            }
            const recommendedTemperature = (_e2 = result.recommended_config) == null ? void 0 : _e2.temperature;
            const temperatureInput = document.getElementById("llm-temperature");
            if (temperatureInput && Number.isFinite(recommendedTemperature)) {
              temperatureInput.value = recommendedTemperature;
            }
            if (result.tuning) {
              setLlmTuningSummary(result.tuning);
            }
            btn.innerHTML = result.applicable === false ? '<i class="fas fa-image" aria-hidden="true"></i> Not Required' : '<i class="fas fa-check" aria-hidden="true"></i> Done';
            setTimeout(() => {
              btn.disabled = isOpenAIImageModelSelected;
              btn.innerHTML = isOpenAIImageModelSelected ? '<i class="fas fa-image" aria-hidden="true"></i> Not Used' : '<i class="fas fa-magic" aria-hidden="true"></i> Auto-Assess';
            }, 2e3);
          } catch (error) {
            btn.innerHTML = '<i class="fas fa-times" aria-hidden="true"></i> Failed';
            setTimeout(() => {
              btn.disabled = isOpenAIImageModelSelected;
              btn.innerHTML = isOpenAIImageModelSelected ? '<i class="fas fa-image" aria-hidden="true"></i> Not Used' : '<i class="fas fa-magic" aria-hidden="true"></i> Auto-Assess';
            }, 2e3);
          }
        },
        className: "ml-2 px-2 py-1 text-xs font-medium rounded border border-gray-300 bg-white text-gray-700 hover:bg-gray-100 disabled:opacity-50 disabled:cursor-not-allowed",
        disabled: isOpenAIImageModelSelected
      },
      /* @__PURE__ */ React.createElement("i", { className: `fas ${isOpenAIImageModelSelected ? "fa-image" : "fa-magic"}`, "aria-hidden": "true" }),
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
        disabled: isOpenAIImageModelSelected || llmAutoTune
      }
    ), isOpenAIImageModelSelected && /* @__PURE__ */ React.createElement("p", { className: "mt-1 text-xs text-amber-700" }, "gpt-image-2 uses the OpenAI images API. max_tokens is ignored for summary infographic generation, and text-generation features still require a text-capable model.")), /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("label", { className: "block text-sm font-medium text-gray-700 mb-1" }, "Temperature"), /* @__PURE__ */ React.createElement(
      "input",
      {
        type: "number",
        step: "0.1",
        defaultValue: config.llm.temperature,
        className: "w-full px-3 py-2 border border-gray-300 rounded-md",
        id: "llm-temperature",
        onChange: handleSettingsChange,
        disabled: llmAutoTune
      }
    )), /* @__PURE__ */ React.createElement("details", { "data-testid": "llm-advanced-tuning", className: "rounded-md border border-gray-200 px-3 py-2" }, /* @__PURE__ */ React.createElement("summary", { className: "cursor-pointer text-sm font-medium text-gray-700" }, "Advanced tuning overrides"), /* @__PURE__ */ React.createElement("p", { className: "mt-1 text-xs text-gray-500" }, "Leave at 0 or Automatic to use the model profile. These apply with or without auto-tune."), /* @__PURE__ */ React.createElement("div", { className: "mt-2 grid grid-cols-1 gap-2 sm:grid-cols-3" }, /* @__PURE__ */ React.createElement("label", { className: "text-xs text-gray-700" }, "Context window (tokens)", /* @__PURE__ */ React.createElement(
      "input",
      {
        type: "number",
        min: "0",
        step: "1024",
        id: "llm-context-window",
        defaultValue: config.llm.context_window || 0,
        className: "mt-1 w-full px-2 py-1 border border-gray-300 rounded-md",
        onChange: handleSettingsChange
      }
    )), /* @__PURE__ */ React.createElement("label", { className: "text-xs text-gray-700" }, "Request timeout (seconds)", /* @__PURE__ */ React.createElement(
      "input",
      {
        type: "number",
        min: "0",
        max: "3600",
        id: "llm-request-timeout",
        defaultValue: config.llm.request_timeout || 0,
        className: "mt-1 w-full px-2 py-1 border border-gray-300 rounded-md",
        onChange: handleSettingsChange
      }
    )), /* @__PURE__ */ React.createElement("label", { className: "text-xs text-gray-700" }, "Reasoning effort", /* @__PURE__ */ React.createElement(
      "select",
      {
        id: "llm-reasoning-effort",
        defaultValue: config.llm.reasoning_effort || "",
        className: "mt-1 w-full px-2 py-1 border border-gray-300 rounded-md",
        onChange: handleSettingsChange
      },
      /* @__PURE__ */ React.createElement("option", { value: "" }, "Automatic"),
      /* @__PURE__ */ React.createElement("option", { value: "minimal" }, "Minimal"),
      /* @__PURE__ */ React.createElement("option", { value: "low" }, "Low"),
      /* @__PURE__ */ React.createElement("option", { value: "medium" }, "Medium"),
      /* @__PURE__ */ React.createElement("option", { value: "high" }, "High")
    )))), /* @__PURE__ */ React.createElement("div", { className: "pt-3 border-t border-gray-200" }, /* @__PURE__ */ React.createElement(
      "button",
      {
        type: "button",
        "data-testid": "llm-test-connection",
        onClick: async (event) => {
          const btn = event.currentTarget;
          const resultsDiv = document.getElementById("llm-test-results");
          const idleLabel = '<i class="fas fa-plug mr-2" aria-hidden="true"></i> Test Connection & Auto-Configure';
          const resetButton = () => setTimeout(() => {
            btn.disabled = false;
            btn.innerHTML = idleLabel;
          }, 3e3);
          btn.disabled = true;
          btn.innerHTML = '<i class="fas fa-spinner fa-spin mr-2" aria-hidden="true"></i> Testing Connection...';
          resultsDiv.innerHTML = '<div class="text-blue-600"><i class="fas fa-spinner fa-spin mr-2" aria-hidden="true"></i> Running tests...</div>';
          resultsDiv.style.display = "block";
          try {
            const provider = document.getElementById("llm-provider").value;
            const endpointUrlInput = document.getElementById("llm-endpoint-url");
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
                  temperature: parseFloat(document.getElementById("llm-temperature").value),
                  ...readLlmTuningFormValues(config.llm)
                }
              })
            });
            const { data, text } = await readApiResponse(response);
            const result = response.ok && data ? data : { status: "error", message: describeApiFailure(response, data, text) };
            const esc = escapeSettingsHtml;
            let html = '<div class="space-y-2">';
            if (result.status === "success") {
              html += '<div class="bg-green-100 border border-green-300 rounded-lg p-3 mb-2">';
              html += '<div class="font-semibold text-green-800"><i class="fas fa-check-circle mr-2" aria-hidden="true"></i>All Tests Passed</div>';
              html += '<div class="text-sm text-green-700 mt-1">' + esc(result.message) + "</div>";
              html += "</div>";
              const recommended = result.recommended_config || {};
              if (Number.isFinite(recommended.max_tokens)) {
                document.getElementById("llm-max-tokens").value = recommended.max_tokens;
              }
              const temperatureInput = document.getElementById("llm-temperature");
              if (temperatureInput && Number.isFinite(recommended.temperature)) {
                temperatureInput.value = recommended.temperature;
              }
              if (result.tuning) {
                setLlmTuningSummary(result.tuning);
                html += '<div class="bg-indigo-50 border border-indigo-200 rounded-lg p-3 mb-2 text-xs text-indigo-900">';
                html += '<div class="font-semibold"><i class="fas fa-sliders-h mr-1" aria-hidden="true"></i>Recommended runtime settings</div>';
                html += '<div class="mt-1">' + esc(describeLlmTuning(result.tuning)) + "</div>";
                const rationale = Array.isArray(result.tuning.rationale) ? result.tuning.rationale : [];
                if (rationale.length > 0) {
                  html += '<ul class="mt-1 list-disc pl-4">' + rationale.map((line) => "<li>" + esc(line) + "</li>").join("") + "</ul>";
                }
                html += '<div class="mt-1 text-indigo-700">Click Save Settings to keep these values.</div>';
                html += "</div>";
              }
            } else {
              html += '<div class="bg-red-100 border border-red-300 rounded-lg p-3 mb-2">';
              html += '<div class="font-semibold text-red-800"><i class="fas fa-times-circle mr-2" aria-hidden="true"></i>Test Failed</div>';
              html += '<div class="text-sm text-red-700 mt-1">' + esc(result.message || result.error || "Unknown error") + "</div>";
              html += '<div class="text-xs text-red-700 mt-1">Click Troubleshoot below to find out why.</div>';
              html += "</div>";
            }
            html += '<div class="text-xs font-semibold text-gray-700 mb-1">Test Details:</div>';
            const tones = { success: ["green", "check"], error: ["red", "times"], warning: ["yellow", "exclamation-triangle"] };
            for (const [testName, testResult] of Object.entries(result.tests || {})) {
              const [statusColor, statusIcon] = tones[testResult.status] || ["blue", "info-circle"];
              const label = testName.replace(/_/g, " ");
              html += `<div class="bg-${statusColor}-50 border border-${statusColor}-200 rounded p-2 mb-1">`;
              html += `<div class="text-xs font-medium text-${statusColor}-800">`;
              html += `<i class="fas fa-${statusIcon} mr-1" aria-hidden="true"></i>${esc(label.charAt(0).toUpperCase() + label.slice(1))}: ${esc(testResult.message)}`;
              html += "</div>";
              if (testResult.response_preview) {
                html += `<div class="text-xs text-gray-600 mt-1 italic">"${esc(testResult.response_preview)}"</div>`;
              }
              html += "</div>";
            }
            html += "</div>";
            resultsDiv.innerHTML = html;
            btn.innerHTML = result.status === "success" ? '<i class="fas fa-check mr-2" aria-hidden="true"></i> Test Complete' : '<i class="fas fa-times mr-2" aria-hidden="true"></i> Test Failed';
            resetButton();
          } catch (error) {
            resultsDiv.innerHTML = `<div class="bg-red-100 border border-red-300 rounded-lg p-3">
                                                                <div class="font-semibold text-red-800"><i class="fas fa-times-circle mr-2" aria-hidden="true"></i>Error</div>
                                                                <div class="text-sm text-red-700 mt-1">${escapeSettingsHtml(error.message)}</div>
                                                            </div>`;
            btn.innerHTML = '<i class="fas fa-times mr-2" aria-hidden="true"></i> Test Failed';
            resetButton();
          }
        },
        className: `w-full px-4 py-2 rounded-lg border font-medium transition-colors ${secondaryButtonClass}`
      },
      /* @__PURE__ */ React.createElement("i", { className: "fas fa-plug mr-2", "aria-hidden": "true" }),
      " Test Connection & Auto-Configure"
    ), /* @__PURE__ */ React.createElement(
      "button",
      {
        type: "button",
        "data-testid": "llm-troubleshoot",
        onClick: () => openSettingsTroubleshooter("llm", readTroubleshootDraftFromForm("llm"), { autoRun: true }),
        className: `mt-2 w-full px-4 py-2 rounded-lg border font-medium transition-colors ${secondaryButtonClass}`
      },
      /* @__PURE__ */ React.createElement("i", { className: "fas fa-stethoscope mr-2", "aria-hidden": "true" }),
      "Troubleshoot"
    ), /* @__PURE__ */ React.createElement("div", { id: "llm-test-results", className: "mt-3", style: { display: "none" } }), /* @__PURE__ */ React.createElement("div", { className: "mt-3 pt-3 border-t border-gray-200 space-y-2" }, loadedCredentialName ? /* @__PURE__ */ React.createElement(React.Fragment, null, /* @__PURE__ */ React.createElement(
      "button",
      {
        onClick: () => {
          setIsUpdateMode(false);
          setCredentialName("");
          setIsCredentialModalOpen(true);
        },
        className: `w-full px-4 py-2 rounded-lg border font-medium transition-colors ${secondaryButtonClass}`
      },
      /* @__PURE__ */ React.createElement("i", { className: "fas fa-plus-circle mr-2", "aria-hidden": "true" }),
      "Save as New"
    ), /* @__PURE__ */ React.createElement(
      "button",
      {
        onClick: () => {
          setIsUpdateMode(true);
          setCredentialName(loadedCredentialName);
          setIsCredentialModalOpen(true);
        },
        className: "w-full px-4 py-2 bg-indigo-600 hover:bg-indigo-700 text-white rounded-lg font-medium transition-colors"
      },
      /* @__PURE__ */ React.createElement("i", { className: "fas fa-sync-alt mr-2", "aria-hidden": "true" }),
      "Update Active Connection"
    )) : /* @__PURE__ */ React.createElement(
      "button",
      {
        onClick: () => {
          setIsUpdateMode(false);
          setCredentialName("");
          setIsCredentialModalOpen(true);
        },
        className: "w-full px-4 py-2 bg-indigo-600 hover:bg-indigo-700 text-white rounded-lg font-medium transition-colors"
      },
      /* @__PURE__ */ React.createElement("i", { className: "fas fa-save mr-2", "aria-hidden": "true" }),
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
      /* @__PURE__ */ React.createElement("i", { className: "fas fa-list mr-2", "aria-hidden": "true" }),
      "View Dependencies"
    ), activeSettingsTab !== "appearance" && activeSettingsTab !== "troubleshoot" && /* @__PURE__ */ React.createElement(
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
          const mcpCaBundleEl = document.getElementById("mcp-ca-bundle");
          const provider = providerEl ? providerEl.value : selectedProvider;
          const mcpToken = mcpTokenEl ? mcpTokenEl.value : "";
          const mcpSettings = {
            url: mcpUrlEl ? mcpUrlEl.value : config.mcp.url,
            verify_ssl: mcpVerifyEl ? mcpVerifyEl.checked : config.mcp.verify_ssl
          };
          if (mcpCaBundleEl) {
            mcpSettings.ca_bundle_path = mcpCaBundleEl.value.trim() || null;
          }
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
              temperature: tempEl ? parseFloat(tempEl.value) : config.llm.temperature,
              ...readLlmTuningFormValues(config.llm)
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
      /* @__PURE__ */ React.createElement("i", { className: "fas fa-save mr-2", "aria-hidden": "true" }),
      "Save Settings"
    ))))), renderAuthEnableInfoModal(), renderWelcomeSplashModal(), isCredentialModalOpen && /* @__PURE__ */ React.createElement("div", { className: "fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4" }, /* @__PURE__ */ React.createElement(
      "div",
      {
        role: "dialog",
        "aria-modal": "true",
        "aria-labelledby": "credential-save-title",
        onKeyDown: (event) => handleDialogKeyDown(event, () => {
          setIsCredentialModalOpen(false);
          setCredentialName("");
          setIsUpdateMode(false);
        }),
        className: `rounded-xl shadow-2xl w-full max-w-md ${isDarkTheme ? "bg-gray-800 border border-gray-700" : "bg-white border border-gray-200"}`
      },
      /* @__PURE__ */ React.createElement("div", { className: `flex items-center justify-between gap-3 border-b px-6 py-4 ${isDarkTheme ? "border-gray-700" : "border-gray-200"}` }, /* @__PURE__ */ React.createElement("h2", { id: "credential-save-title", className: `text-lg font-semibold ${isDarkTheme ? "text-gray-100" : "text-gray-900"}` }, isUpdateMode ? "Update" : "Save", " AI Model Connection"), /* @__PURE__ */ React.createElement(
        "button",
        {
          type: "button",
          onClick: () => {
            setIsCredentialModalOpen(false);
            setCredentialName("");
            setIsUpdateMode(false);
          },
          "aria-label": "Close",
          className: `rounded-md p-1.5 transition-colors ${isDarkTheme ? "text-gray-400 hover:bg-gray-700 hover:text-gray-100" : "text-gray-500 hover:bg-gray-100 hover:text-gray-900"}`
        },
        /* @__PURE__ */ React.createElement("i", { className: "fas fa-times", "aria-hidden": "true" })
      )),
      /* @__PURE__ */ React.createElement("div", { className: "p-6" }, isUpdateMode ? /* @__PURE__ */ React.createElement("div", { role: "note", className: `mb-4 rounded-md border px-4 py-3 text-sm ${isDarkTheme ? "border-amber-700 bg-amber-950 text-amber-100" : "border-amber-200 bg-amber-50 text-amber-900"}` }, /* @__PURE__ */ React.createElement("p", { className: "font-semibold" }, "This replaces a saved connection"), /* @__PURE__ */ React.createElement("p", { className: "mt-1" }, 'Saving overwrites every setting in "', /* @__PURE__ */ React.createElement("strong", null, credentialName), '" with the values in the form. You cannot undo this.')) : /* @__PURE__ */ React.createElement("p", { className: `text-sm mb-4 ${isDarkTheme ? "text-gray-300" : "text-gray-600"}` }, "Save the current AI model settings with a name so you can load them again later."), /* @__PURE__ */ React.createElement("div", { className: "mb-6" }, /* @__PURE__ */ React.createElement("label", { htmlFor: "credential-save-name", className: `block text-sm font-medium mb-2 ${isDarkTheme ? "text-gray-200" : "text-gray-700"}` }, "Name ", /* @__PURE__ */ React.createElement("span", { "aria-hidden": "true", className: isDarkTheme ? "text-red-300" : "text-red-600" }, "*")), /* @__PURE__ */ React.createElement(
        "input",
        {
          id: "credential-save-name",
          type: "text",
          required: true,
          value: credentialName,
          onChange: (e) => setCredentialName(e.target.value),
          placeholder: "e.g., My OpenAI GPT-4, Local Llama Server",
          "aria-describedby": isUpdateMode ? "credential-save-name-hint" : void 0,
          className: `w-full px-4 py-2 border rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-transparent ${isDarkTheme ? "bg-gray-900 border-gray-600 text-gray-100 disabled:bg-gray-800" : "bg-white border-gray-300 text-gray-900 disabled:bg-gray-100"}`,
          disabled: isUpdateMode,
          autoFocus: !isUpdateMode
        }
      ), isUpdateMode && /* @__PURE__ */ React.createElement("p", { id: "credential-save-name-hint", className: `text-xs mt-1 ${isDarkTheme ? "text-gray-400" : "text-gray-600"}` }, "You cannot rename a connection while you update it.")), /* @__PURE__ */ React.createElement("div", { className: `rounded-lg p-4 mb-6 border ${isDarkTheme ? "bg-gray-900 border-gray-700" : "bg-gray-50 border-gray-200"}` }, /* @__PURE__ */ React.createElement("h3", { className: `text-xs font-semibold mb-2 uppercase tracking-wide ${isDarkTheme ? "text-gray-300" : "text-gray-700"}` }, "Settings to Save"), /* @__PURE__ */ React.createElement("dl", { className: `space-y-1 text-sm ${isDarkTheme ? "text-gray-300" : "text-gray-600"}` }, /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("dt", { className: "inline font-medium" }, "Provider:"), " ", /* @__PURE__ */ React.createElement("dd", { className: "inline" }, formatProviderName(selectedProvider))), /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("dt", { className: "inline font-medium" }, "Model:"), " ", /* @__PURE__ */ React.createElement("dd", { className: "inline" }, ((_Ha = document.getElementById("llm-model")) == null ? void 0 : _Ha.value) || "Not set")), /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("dt", { className: "inline font-medium" }, "Max response length:"), " ", /* @__PURE__ */ React.createElement("dd", { className: "inline" }, ((_Ia = document.getElementById("llm-max-tokens")) == null ? void 0 : _Ia.value) ? `${document.getElementById("llm-max-tokens").value} tokens` : "Not set")), /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("dt", { className: "inline font-medium" }, "Temperature:"), " ", /* @__PURE__ */ React.createElement("dd", { className: "inline" }, ((_Ja = document.getElementById("llm-temperature")) == null ? void 0 : _Ja.value) || "Not set")))), /* @__PURE__ */ React.createElement("div", { className: "flex gap-3" }, /* @__PURE__ */ React.createElement(
        "button",
        {
          onClick: () => {
            setIsCredentialModalOpen(false);
            setCredentialName("");
            setIsUpdateMode(false);
          },
          type: "button",
          className: `flex-1 px-4 py-2 rounded-lg border font-medium transition-colors ${secondaryButtonClass}`
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
              const confirmed = confirm(`Overwrite "${credentialName}"?

This replaces its provider, model, API key, endpoint URL, max response length, and temperature. You cannot undo this.`);
              if (!confirmed) return;
            } else if (savedCredentials == null ? void 0 : savedCredentials[credentialName.trim()]) {
              const confirmed = confirm(`A credential named "${credentialName.trim()}" already exists.

Overwrite it?`);
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
                  endpoint_url: provider !== "openai" && endpointUrlInput ? endpointUrlInput.value : null,
                  max_tokens: parseInt(document.getElementById("llm-max-tokens").value),
                  temperature: parseFloat(document.getElementById("llm-temperature").value),
                  ...readLlmTuningFormValues(config.llm)
                })
              });
              const { data: savedData, text: savedText } = await readApiResponse(response);
              const result = savedData || {};
              if (response.ok) {
                setIsCredentialModalOpen(false);
                setCredentialName("");
                const wasUpdate = isUpdateMode;
                setIsUpdateMode(false);
                await loadCredentials();
                if (result.activated) {
                  await loadConfig();
                }
                const successDiv = document.createElement("div");
                successDiv.className = "fixed top-6 right-6 bg-green-600 text-white px-6 py-4 rounded-xl shadow-2xl z-50";
                successDiv.setAttribute("role", "status");
                successDiv.innerHTML = `
                                                            <div class="flex items-center gap-3">
                                                                <i class="fas fa-check-circle text-2xl" aria-hidden="true"></i>
                                                                <div>
                                                                    <p class="font-bold text-base">AI model connection ${wasUpdate ? "updated" : "saved"}</p>
                                                                    <p class="text-sm opacity-90">${escapeSettingsHtml(credentialName)}</p>
                                                                    ${result.warning ? `<p class="text-xs opacity-80">${escapeSettingsHtml(result.warning)}</p>` : ""}
                                                                </div>
                                                            </div>
                                                        `;
                document.body.appendChild(successDiv);
                setTimeout(() => {
                  successDiv.style.animation = "none";
                  successDiv.style.opacity = "0";
                  successDiv.style.transition = "opacity 0.3s";
                  setTimeout(() => successDiv.remove(), 300);
                }, result.warning ? 8e3 : 2500);
              } else {
                offerTroubleshootAfterSaveFailure(
                  "llm",
                  "Failed to save credential: " + describeApiFailure(response, savedData, savedText),
                  { ...readTroubleshootDraftFromForm("llm"), name: credentialName.trim() },
                  () => setIsCredentialModalOpen(false)
                );
              }
            } catch (error) {
              offerTroubleshootAfterSaveFailure(
                "llm",
                "Error saving credential: " + error.message,
                { ...readTroubleshootDraftFromForm("llm"), name: credentialName.trim() },
                () => setIsCredentialModalOpen(false)
              );
            }
          },
          type: "button",
          disabled: !credentialName.trim(),
          className: "flex-1 px-4 py-2 rounded-lg font-medium transition-colors bg-indigo-600 hover:bg-indigo-700 text-white disabled:opacity-50 disabled:cursor-not-allowed"
        },
        isUpdateMode ? "Update Connection" : "Save Connection"
      )))
    )), isMCPSaveModalOpen && /* @__PURE__ */ React.createElement("div", { className: "fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4" }, /* @__PURE__ */ React.createElement(
      "div",
      {
        role: "dialog",
        "aria-modal": "true",
        "aria-labelledby": "mcp-save-title",
        onKeyDown: (event) => handleDialogKeyDown(event, () => {
          setIsMCPSaveModalOpen(false);
          setMCPConfigName("");
          setMCPConfigDescription("");
          setMCPSaveDraft(null);
        }),
        className: `rounded-xl shadow-2xl w-full max-w-md ${isDarkTheme ? "bg-gray-800 border border-gray-700" : "bg-white border border-gray-200"}`
      },
      /* @__PURE__ */ React.createElement("div", { className: `flex items-center justify-between gap-3 border-b px-6 py-4 ${isDarkTheme ? "border-gray-700" : "border-gray-200"}` }, /* @__PURE__ */ React.createElement("h2", { id: "mcp-save-title", className: `text-lg font-semibold ${isDarkTheme ? "text-gray-100" : "text-gray-900"}` }, (mcpSaveDraft == null ? void 0 : mcpSaveDraft.mode) === "update" ? "Update" : "Save", " MCP Configuration"), /* @__PURE__ */ React.createElement(
        "button",
        {
          type: "button",
          onClick: () => {
            setIsMCPSaveModalOpen(false);
            setMCPConfigName("");
            setMCPConfigDescription("");
            setMCPSaveDraft(null);
          },
          "aria-label": "Close",
          className: `rounded-md p-1.5 transition-colors ${isDarkTheme ? "text-gray-400 hover:bg-gray-700 hover:text-gray-100" : "text-gray-500 hover:bg-gray-100 hover:text-gray-900"}`
        },
        /* @__PURE__ */ React.createElement("i", { className: "fas fa-times", "aria-hidden": "true" })
      )),
      /* @__PURE__ */ React.createElement("div", { className: "p-6" }, (mcpSaveDraft == null ? void 0 : mcpSaveDraft.mode) === "update" ? /* @__PURE__ */ React.createElement("div", { role: "note", className: `mb-4 rounded-md border px-4 py-3 text-sm ${isDarkTheme ? "border-amber-700 bg-amber-950 text-amber-100" : "border-amber-200 bg-amber-50 text-amber-900"}` }, /* @__PURE__ */ React.createElement("p", { className: "font-semibold" }, "This replaces a saved configuration"), /* @__PURE__ */ React.createElement("p", { className: "mt-1" }, 'Saving overwrites every setting in "', /* @__PURE__ */ React.createElement("strong", null, mcpConfigName), '" with the values in the form. You cannot undo this.')) : /* @__PURE__ */ React.createElement("p", { className: `text-sm mb-4 ${isDarkTheme ? "text-gray-300" : "text-gray-600"}` }, "Save the current Splunk MCP server settings with a name so you can load them again later."), /* @__PURE__ */ React.createElement("div", { className: "mb-4" }, /* @__PURE__ */ React.createElement("label", { htmlFor: "mcp-save-name", className: `block text-sm font-medium mb-2 ${isDarkTheme ? "text-gray-200" : "text-gray-700"}` }, "Name ", /* @__PURE__ */ React.createElement("span", { "aria-hidden": "true", className: isDarkTheme ? "text-red-300" : "text-red-600" }, "*")), /* @__PURE__ */ React.createElement(
        "input",
        {
          id: "mcp-save-name",
          type: "text",
          required: true,
          value: mcpConfigName,
          onChange: (e) => setMCPConfigName(e.target.value),
          placeholder: "e.g., Production Splunk, Dev Environment",
          "aria-describedby": (mcpSaveDraft == null ? void 0 : mcpSaveDraft.mode) === "update" ? "mcp-save-name-hint" : void 0,
          className: `w-full px-4 py-2 border rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-transparent ${isDarkTheme ? "bg-gray-900 border-gray-600 text-gray-100 disabled:bg-gray-800" : "bg-white border-gray-300 text-gray-900 disabled:bg-gray-100"}`,
          disabled: (mcpSaveDraft == null ? void 0 : mcpSaveDraft.mode) === "update",
          autoFocus: !((mcpSaveDraft == null ? void 0 : mcpSaveDraft.mode) === "update")
        }
      ), (mcpSaveDraft == null ? void 0 : mcpSaveDraft.mode) === "update" && /* @__PURE__ */ React.createElement("p", { id: "mcp-save-name-hint", className: `text-xs mt-1 ${isDarkTheme ? "text-gray-400" : "text-gray-600"}` }, "You cannot rename a configuration while you update it.")), /* @__PURE__ */ React.createElement("div", { className: "mb-6" }, /* @__PURE__ */ React.createElement("label", { htmlFor: "mcp-save-description", className: `block text-sm font-medium mb-2 ${isDarkTheme ? "text-gray-200" : "text-gray-700"}` }, "Description (optional)"), /* @__PURE__ */ React.createElement(
        "input",
        {
          id: "mcp-save-description",
          type: "text",
          value: mcpConfigDescription,
          onChange: (e) => setMCPConfigDescription(e.target.value),
          placeholder: "e.g., Main production Splunk server",
          className: `w-full px-4 py-2 border rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-transparent ${isDarkTheme ? "bg-gray-900 border-gray-600 text-gray-100 disabled:bg-gray-800" : "bg-white border-gray-300 text-gray-900 disabled:bg-gray-100"}`
        }
      )), /* @__PURE__ */ React.createElement("div", { className: `rounded-lg p-4 mb-6 border ${isDarkTheme ? "bg-gray-900 border-gray-700" : "bg-gray-50 border-gray-200"}` }, /* @__PURE__ */ React.createElement("h3", { className: `text-xs font-semibold mb-2 uppercase tracking-wide ${isDarkTheme ? "text-gray-300" : "text-gray-700"}` }, "Settings to Save"), /* @__PURE__ */ React.createElement("dl", { className: `space-y-1 text-sm ${isDarkTheme ? "text-gray-300" : "text-gray-600"}` }, /* @__PURE__ */ React.createElement("div", { className: "break-all" }, /* @__PURE__ */ React.createElement("dt", { className: "inline font-medium" }, "URL:"), " ", /* @__PURE__ */ React.createElement("dd", { className: "inline" }, (mcpSaveDraft == null ? void 0 : mcpSaveDraft.url) || "Not set")), /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("dt", { className: "inline font-medium" }, "Token:"), " ", /* @__PURE__ */ React.createElement("dd", { className: "inline" }, describeMCPDraftToken(mcpSaveDraft, mcpConfigName))), /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("dt", { className: "inline font-medium" }, "Verify SSL:"), " ", /* @__PURE__ */ React.createElement("dd", { className: "inline" }, (mcpSaveDraft == null ? void 0 : mcpSaveDraft.verify_ssl) ? "Yes" : "No")), (mcpSaveDraft == null ? void 0 : mcpSaveDraft.ca_bundle_path) && /* @__PURE__ */ React.createElement("div", { className: "break-all" }, /* @__PURE__ */ React.createElement("dt", { className: "inline font-medium" }, "CA bundle:"), " ", /* @__PURE__ */ React.createElement("dd", { className: "inline" }, mcpSaveDraft.ca_bundle_path)))), /* @__PURE__ */ React.createElement("div", { className: "flex gap-3" }, /* @__PURE__ */ React.createElement(
        "button",
        {
          onClick: () => {
            setIsMCPSaveModalOpen(false);
            setMCPConfigName("");
            setMCPConfigDescription("");
            setMCPSaveDraft(null);
          },
          type: "button",
          className: `flex-1 px-4 py-2 rounded-lg border font-medium transition-colors ${secondaryButtonClass}`
        },
        "Cancel"
      ), /* @__PURE__ */ React.createElement(
        "button",
        {
          onClick: async () => {
            const savedName = mcpConfigName.trim();
            const isUpdate = (mcpSaveDraft == null ? void 0 : mcpSaveDraft.mode) === "update";
            const draft = mcpSaveDraft || {};
            if (!savedName) {
              alert("Please enter a configuration name");
              return;
            }
            if (!draft.url) {
              alert("Please enter an MCP URL");
              return;
            }
            if (isUpdate) {
              const confirmed = confirm(`Overwrite "${savedName}"?

This replaces its MCP URL, token (a blank token keeps the saved one), SSL settings, and description. You cannot undo this.`);
              if (!confirmed) return;
            } else if (savedMCPConfigs == null ? void 0 : savedMCPConfigs[savedName]) {
              const confirmed = confirm(`A configuration named "${savedName}" already exists.

Overwrite it?`);
              if (!confirmed) return;
            }
            try {
              const response = await fetch("/api/mcp-configs", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                  name: savedName,
                  url: draft.url,
                  token: draft.token || "",
                  verify_ssl: Boolean(draft.verify_ssl),
                  ca_bundle_path: draft.ca_bundle_path || null,
                  description: mcpConfigDescription.trim() || null
                })
              });
              const { data: savedData, text: savedText } = await readApiResponse(response);
              const result = savedData || {};
              if (response.ok) {
                setIsMCPSaveModalOpen(false);
                setMCPSaveDraft(null);
                setMCPConfigName("");
                setMCPConfigDescription("");
                if (result.activated) {
                  if (result.config) {
                    setConfig(result.config);
                  }
                  setLoadedMCPConfigName(savedName);
                  const tokenInput = document.getElementById("mcp-token");
                  if (tokenInput) {
                    tokenInput.value = "";
                  }
                  await loadConfig();
                }
                await loadMCPConfigs();
                const detailLine = [
                  result.activated ? "Active MCP connection updated" : result.token_configured === false ? "Saved without a token" : "",
                  result.warning || ""
                ].filter(Boolean).join(". ");
                const successDiv = document.createElement("div");
                successDiv.className = "fixed top-6 right-6 bg-green-600 text-white px-6 py-4 rounded-xl shadow-2xl z-50";
                successDiv.setAttribute("role", "status");
                successDiv.innerHTML = `
                                                            <div class="flex items-center gap-3">
                                                                <i class="fas fa-check-circle text-2xl" aria-hidden="true"></i>
                                                                <div>
                                                                    <p class="font-bold text-base">MCP configuration ${isUpdate ? "updated" : "saved"}</p>
                                                                    <p class="text-sm opacity-90">${escapeSettingsHtml(savedName)}</p>
                                                                    ${detailLine ? `<p class="text-xs opacity-80">${escapeSettingsHtml(detailLine)}</p>` : ""}
                                                                </div>
                                                            </div>
                                                        `;
                document.body.appendChild(successDiv);
                setTimeout(() => {
                  successDiv.style.animation = "none";
                  successDiv.style.opacity = "0";
                  successDiv.style.transition = "opacity 0.3s";
                  setTimeout(() => successDiv.remove(), 300);
                }, result.warning ? 8e3 : 2500);
              } else {
                offerTroubleshootAfterSaveFailure(
                  "mcp",
                  "Failed to save configuration: " + describeApiFailure(response, savedData, savedText),
                  { name: savedName, url: draft.url, token: draft.token || "", verify_ssl: Boolean(draft.verify_ssl), ca_bundle_path: draft.ca_bundle_path || "" },
                  () => setIsMCPSaveModalOpen(false)
                );
              }
            } catch (error) {
              offerTroubleshootAfterSaveFailure(
                "mcp",
                "Error saving configuration: " + error.message,
                { name: savedName, url: draft.url, token: draft.token || "", verify_ssl: Boolean(draft.verify_ssl), ca_bundle_path: draft.ca_bundle_path || "" },
                () => setIsMCPSaveModalOpen(false)
              );
            }
          },
          type: "button",
          disabled: !mcpConfigName.trim(),
          className: "flex-1 px-4 py-2 rounded-lg font-medium transition-colors bg-indigo-600 hover:bg-indigo-700 text-white disabled:opacity-50 disabled:cursor-not-allowed"
        },
        (mcpSaveDraft == null ? void 0 : mcpSaveDraft.mode) === "update" ? "Update Configuration" : "Save Configuration"
      )))
    )));
  }
  window.addEventListener("error", (event) => {
    console.error("Global error caught:", event.error);
    event.preventDefault();
  });
  window.addEventListener("unhandledrejection", (event) => {
    console.error("Unhandled promise rejection:", event.reason);
    event.preventDefault();
  });
  ReactDOM.render(
    /* @__PURE__ */ React.createElement(ErrorBoundary, null, isVisualizationRegressionView ? /* @__PURE__ */ React.createElement(VisualizationRegressionHarness, null) : /* @__PURE__ */ React.createElement(App, null)),
    document.getElementById("root")
  );
})();
