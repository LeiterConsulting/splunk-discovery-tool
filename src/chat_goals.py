"""Chat goals: what the user wants to find out, what is still open, and the chats spent on it.

A goal keeps a short list of progress items (questions that must be answered to reach it),
suggested next questions, the recent question-and-answer turns used to judge progress, and the
chats saved under it. Goals are kept per user when sign-in is on and in one shared library when
it is off.
"""

from __future__ import annotations

import json
import os
import re
import secrets
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence

GOALS_DIR_NAME = "goals"

MAX_GOAL_CHARS = 600
MAX_TITLE_CHARS = 80
MAX_ITEM_CHARS = 200
MAX_NOTE_CHARS = 240
MAX_SUMMARY_CHARS = 300
MAX_QUESTION_CHARS = 200
MAX_GOALS = 100
MAX_ITEMS = 10
MAX_QUESTIONS = 3
MAX_NEW_ITEMS_PER_ANSWER = 2
MAX_TURNS = 30
MAX_TURN_QUESTION_CHARS = 1000
MAX_TURN_ANSWER_CHARS = 2500
MAX_CHATS = 50
MAX_CHAT_MESSAGES = 200
MAX_CHAT_BYTES = 1_000_000

ITEM_STATUSES = ("open", "answered")
GOAL_STATUSES = ("active", "done")

FALLBACK_QUESTIONS = (
    "Which indexes, sourcetypes, and hosts relate to my goal?",
    "What is the first search I should run for my goal?",
    "What would show that my goal is reached?",
)


class GoalNotFoundError(LookupError):
    """The goal, progress item, or saved chat does not exist for this user."""


class GoalLimitError(ValueError):
    """A request would go past a library limit or is missing required text."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _new_id(prefix: str) -> str:
    return f"{prefix}_{secrets.token_hex(6)}"


def clean_text(value: Any, limit: int) -> str:
    """Single-line printable text, cut to ``limit`` characters."""
    if not isinstance(value, str):
        return ""
    cleaned = "".join(char if char.isprintable() else " " for char in value)
    cleaned = re.sub(r"\s+", " ", cleaned).strip()
    if len(cleaned) > limit:
        cleaned = cleaned[: max(1, limit - 3)].rstrip() + "..."
    return cleaned


def clean_block(value: Any, limit: int) -> str:
    """Multi-line text (answers keep their line breaks), cut to ``limit`` characters."""
    if not isinstance(value, str):
        return ""
    cleaned = "".join(char if (char.isprintable() or char in "\n\t") else " " for char in value)
    cleaned = re.sub(r"[ \t]+", " ", cleaned)
    cleaned = re.sub(r"\n{3,}", "\n\n", cleaned).strip()
    if len(cleaned) > limit:
        cleaned = cleaned[: max(1, limit - 3)].rstrip() + "..."
    return cleaned


def clean_id(value: Any) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_\-]", "_", str(value or "").strip())
    return cleaned[:64]


def owner_key(user: Optional[Mapping[str, Any]]) -> str:
    """Whose library to use: the signed-in user, or the shared library when sign-in is off."""
    if not isinstance(user, Mapping):
        return "local"
    cleaned = clean_id(user.get("id") or user.get("username"))
    return f"user_{cleaned}" if cleaned else "local"


def default_title(goal_text: str) -> str:
    text = clean_text(goal_text, MAX_GOAL_CHARS)
    first = re.split(r"(?<=[.!?])\s", text, maxsplit=1)[0]
    return clean_text(first, MAX_TITLE_CHARS) or "Untitled goal"


def _clean_list(values: Any, limit_items: int, limit_chars: int) -> List[str]:
    if not isinstance(values, (list, tuple)):
        return []
    seen = set()
    cleaned: List[str] = []
    for value in values:
        text = clean_text(value, limit_chars)
        key = text.lower()
        if text and key not in seen:
            seen.add(key)
            cleaned.append(text)
        if len(cleaned) >= limit_items:
            break
    return cleaned


def _new_item(text: str, source: str, status: str = "open", note: str = "") -> Dict[str, Any]:
    return {
        "id": _new_id("item"),
        "text": clean_text(text, MAX_ITEM_CHARS),
        "status": status if status in ITEM_STATUSES else "open",
        "note": clean_text(note, MAX_NOTE_CHARS),
        "source": source,
        "updated_at": _now(),
    }


def progress_counts(goal: Mapping[str, Any]) -> Dict[str, int]:
    items = [item for item in goal.get("items") or [] if isinstance(item, Mapping)]
    answered = sum(1 for item in items if item.get("status") == "answered")
    return {"answered": answered, "open": len(items) - answered, "total": len(items)}


def progress_brief(goal: Optional[Mapping[str, Any]], limit: int = 5) -> Dict[str, List[str]]:
    """Open and answered items for the chat prompt, newest answers first."""
    if not isinstance(goal, Mapping):
        return {"open": [], "answered": []}
    items = [item for item in goal.get("items") or [] if isinstance(item, Mapping)]
    open_items = [str(item.get("text") or "") for item in items if item.get("status") != "answered"]
    answered = []
    for item in reversed(items):
        if item.get("status") == "answered":
            note = str(item.get("note") or "").strip()
            answered.append(f"{item.get('text')} ({note})" if note else str(item.get("text") or ""))
    return {"open": [text for text in open_items if text][:limit], "answered": [text for text in answered if text][:limit]}


def _chat_meta(chat: Mapping[str, Any]) -> Dict[str, Any]:
    messages = chat.get("messages") if isinstance(chat.get("messages"), list) else []
    return {
        "id": chat.get("id"),
        "title": chat.get("title") or "Untitled chat",
        "created_at": chat.get("created_at"),
        "updated_at": chat.get("updated_at"),
        "message_count": len(messages),
    }


def goal_summary(goal: Mapping[str, Any]) -> Dict[str, Any]:
    chats = [chat for chat in goal.get("chats") or [] if isinstance(chat, Mapping)]
    return {
        "id": goal.get("id"),
        "title": goal.get("title") or default_title(str(goal.get("goal") or "")),
        "goal": goal.get("goal") or "",
        "status": goal.get("status") if goal.get("status") in GOAL_STATUSES else "active",
        "summary": goal.get("summary") or "",
        "progress": progress_counts(goal),
        "chat_count": len(chats),
        "created_at": goal.get("created_at"),
        "updated_at": goal.get("updated_at"),
    }


def goal_detail(goal: Mapping[str, Any]) -> Dict[str, Any]:
    detail = goal_summary(goal)
    turns = [turn for turn in goal.get("turns") or [] if isinstance(turn, Mapping)]
    chats = sorted(
        (_chat_meta(chat) for chat in goal.get("chats") or [] if isinstance(chat, Mapping)),
        key=lambda chat: str(chat.get("updated_at") or ""),
        reverse=True,
    )
    detail.update({
        "items": [dict(item) for item in goal.get("items") or [] if isinstance(item, Mapping)],
        "suggested_questions": list(goal.get("suggested_questions") or []),
        "planned_by": goal.get("planned_by") or "",
        "progress_checked_at": goal.get("progress_checked_at"),
        "pending_turns": sum(1 for turn in turns if not turn.get("evaluated")),
        "turn_count": len(turns),
        "chats": chats,
    })
    return detail


def _sanitize_messages(messages: Any) -> List[Dict[str, Any]]:
    if not isinstance(messages, list):
        raise GoalLimitError("Messages must be a list.")
    kept = [message for message in messages if isinstance(message, dict)][-MAX_CHAT_MESSAGES:]
    while kept and len(json.dumps(kept, default=str)) > MAX_CHAT_BYTES:
        kept = kept[1:]
    if messages and not kept:
        raise GoalLimitError("This chat is too large to save.")
    return json.loads(json.dumps(kept, default=str))


def _first_user_text(messages: Sequence[Mapping[str, Any]]) -> str:
    for message in messages:
        if message.get("type") == "user" or message.get("role") == "user":
            text = clean_text(message.get("content"), MAX_TITLE_CHARS)
            if text:
                return text
    return ""


class ChatGoalStore:
    """One JSON file per library owner under ``<root>/goals``; every change is a locked read-modify-write."""

    def __init__(self, root: Path):
        self._root = Path(root)
        self._lock = threading.RLock()

    def _path(self, owner: str) -> Path:
        return self._root / GOALS_DIR_NAME / f"{clean_id(owner) or 'local'}.json"

    def _load(self, owner: str) -> List[Dict[str, Any]]:
        try:
            with open(self._path(owner), "r", encoding="utf-8") as handle:
                data = json.load(handle)
        except (OSError, ValueError):
            return []
        goals = data.get("goals") if isinstance(data, dict) else None
        if not isinstance(goals, list):
            return []
        return [goal for goal in goals if isinstance(goal, dict) and goal.get("id")]

    def _save(self, owner: str, goals: List[Dict[str, Any]]) -> None:
        path = self._path(owner)
        path.parent.mkdir(parents=True, exist_ok=True)
        temp_path = path.with_name(f"{path.name}.{os.getpid()}.{threading.get_ident()}.tmp")
        try:
            with open(temp_path, "w", encoding="utf-8") as handle:
                json.dump({"goals": goals, "saved_at": _now()}, handle, indent=2, default=str)
            os.replace(temp_path, path)
        finally:
            if temp_path.exists():
                try:
                    temp_path.unlink()
                except OSError:
                    pass

    @staticmethod
    def _find(goals: Iterable[Dict[str, Any]], goal_id: str) -> Dict[str, Any]:
        for goal in goals:
            if goal.get("id") == goal_id:
                return goal
        raise GoalNotFoundError("Goal not found.")

    def _mutate(self, owner: str, goal_id: str, change: Callable[[Dict[str, Any]], Any]) -> Any:
        with self._lock:
            goals = self._load(owner)
            goal = self._find(goals, goal_id)
            result = change(goal)
            goal["updated_at"] = _now()
            self._save(owner, goals)
            return result

    # Goals

    def list_goals(self, owner: str) -> List[Dict[str, Any]]:
        with self._lock:
            goals = self._load(owner)
        summaries = [goal_summary(goal) for goal in goals]
        return sorted(summaries, key=lambda goal: str(goal.get("updated_at") or ""), reverse=True)

    def get_goal(self, owner: str, goal_id: str) -> Dict[str, Any]:
        with self._lock:
            return goal_detail(self._find(self._load(owner), goal_id))

    def get_raw_goal(self, owner: str, goal_id: str) -> Dict[str, Any]:
        with self._lock:
            return json.loads(json.dumps(self._find(self._load(owner), goal_id), default=str))

    def create_goal(
        self,
        owner: str,
        goal_text: Any,
        title: Any = "",
        items: Sequence[str] = (),
        questions: Sequence[str] = (),
        planned_by: str = "",
    ) -> Dict[str, Any]:
        text = clean_text(goal_text, MAX_GOAL_CHARS)
        if not text:
            raise GoalLimitError("Describe the goal first.")
        now = _now()
        goal = {
            "id": _new_id("goal"),
            "title": clean_text(title, MAX_TITLE_CHARS) or default_title(text),
            "goal": text,
            "status": "active",
            "summary": "",
            "items": [_new_item(item, "plan") for item in _clean_list(list(items), MAX_ITEMS, MAX_ITEM_CHARS)],
            "suggested_questions": _clean_list(list(questions), MAX_QUESTIONS, MAX_QUESTION_CHARS),
            "planned_by": planned_by,
            "turns": [],
            "chats": [],
            "created_at": now,
            "updated_at": now,
            "progress_checked_at": None,
        }
        with self._lock:
            goals = self._load(owner)
            if len(goals) >= MAX_GOALS:
                raise GoalLimitError(f"The goal library holds up to {MAX_GOALS} goals. Delete one to add another.")
            goals.append(goal)
            self._save(owner, goals)
        return goal_detail(goal)

    def update_goal(self, owner: str, goal_id: str, *, title: Any = None, goal: Any = None, status: Any = None) -> Dict[str, Any]:
        def change(record: Dict[str, Any]) -> Dict[str, Any]:
            if goal is not None:
                text = clean_text(goal, MAX_GOAL_CHARS)
                if not text:
                    raise GoalLimitError("Describe the goal first.")
                record["goal"] = text
            if title is not None:
                record["title"] = clean_text(title, MAX_TITLE_CHARS) or default_title(record.get("goal") or "")
            if status is not None:
                if status not in GOAL_STATUSES:
                    raise GoalLimitError("Status must be active or done.")
                record["status"] = status
            return record

        return goal_detail(self._mutate(owner, goal_id, change))

    def delete_goal(self, owner: str, goal_id: str) -> None:
        with self._lock:
            goals = self._load(owner)
            self._find(goals, goal_id)
            self._save(owner, [goal for goal in goals if goal.get("id") != goal_id])

    def replace_plan(self, owner: str, goal_id: str, items: Sequence[str], questions: Sequence[str], planned_by: str) -> Dict[str, Any]:
        """New open items and questions from a fresh plan; answered items stay."""
        def change(record: Dict[str, Any]) -> Dict[str, Any]:
            answered = [item for item in record.get("items") or [] if isinstance(item, dict) and item.get("status") == "answered"]
            known = {str(item.get("text") or "").lower() for item in answered}
            room = max(0, MAX_ITEMS - len(answered))
            fresh = [text for text in _clean_list(list(items), MAX_ITEMS, MAX_ITEM_CHARS) if text.lower() not in known][:room]
            record["items"] = answered + [_new_item(text, "plan") for text in fresh]
            record["suggested_questions"] = _clean_list(list(questions), MAX_QUESTIONS, MAX_QUESTION_CHARS)
            record["planned_by"] = planned_by
            return record

        return goal_detail(self._mutate(owner, goal_id, change))

    # Progress items

    def add_item(self, owner: str, goal_id: str, text: Any) -> Dict[str, Any]:
        item_text = clean_text(text, MAX_ITEM_CHARS)
        if not item_text:
            raise GoalLimitError("Write the question to track first.")

        def change(record: Dict[str, Any]) -> Dict[str, Any]:
            items = record.setdefault("items", [])
            if len(items) >= MAX_ITEMS:
                raise GoalLimitError(f"A goal tracks up to {MAX_ITEMS} questions. Delete one to add another.")
            items.append(_new_item(item_text, "user"))
            return record

        return goal_detail(self._mutate(owner, goal_id, change))

    def update_item(self, owner: str, goal_id: str, item_id: str, *, text: Any = None, status: Any = None, note: Any = None) -> Dict[str, Any]:
        def change(record: Dict[str, Any]) -> Dict[str, Any]:
            item = next((entry for entry in record.get("items") or [] if entry.get("id") == item_id), None)
            if item is None:
                raise GoalNotFoundError("Progress item not found.")
            if text is not None:
                item_text = clean_text(text, MAX_ITEM_CHARS)
                if not item_text:
                    raise GoalLimitError("Write the question to track first.")
                item["text"] = item_text
            if status is not None:
                if status not in ITEM_STATUSES:
                    raise GoalLimitError("Status must be open or answered.")
                item["status"] = status
                if status == "open":
                    item["note"] = ""
            if note is not None:
                item["note"] = clean_text(note, MAX_NOTE_CHARS)
            item["updated_at"] = _now()
            return record

        return goal_detail(self._mutate(owner, goal_id, change))

    def delete_item(self, owner: str, goal_id: str, item_id: str) -> Dict[str, Any]:
        def change(record: Dict[str, Any]) -> Dict[str, Any]:
            items = record.get("items") or []
            if not any(entry.get("id") == item_id for entry in items):
                raise GoalNotFoundError("Progress item not found.")
            record["items"] = [entry for entry in items if entry.get("id") != item_id]
            return record

        return goal_detail(self._mutate(owner, goal_id, change))

    # Turns and progress

    def record_turn(self, owner: str, goal_id: str, question: Any, answer: Any, chat_id: Any = "") -> bool:
        question_text = clean_block(question, MAX_TURN_QUESTION_CHARS)
        answer_text = clean_block(answer, MAX_TURN_ANSWER_CHARS)
        if not question_text or not answer_text:
            return False

        def change(record: Dict[str, Any]) -> bool:
            turns = record.setdefault("turns", [])
            turns.append({
                "id": _new_id("turn"),
                "question": question_text,
                "answer": answer_text,
                "chat_id": clean_id(chat_id),
                "at": _now(),
                "evaluated": False,
            })
            del turns[:-MAX_TURNS]
            return True

        try:
            return self._mutate(owner, goal_id, change)
        except GoalNotFoundError:
            return False

    def apply_progress(self, owner: str, goal_id: str, evaluation: Mapping[str, Any], turn_ids: Sequence[str]) -> Dict[str, Any]:
        evaluated = set(turn_ids)

        def change(record: Dict[str, Any]) -> Dict[str, Any]:
            items = record.setdefault("items", [])
            by_id = {item.get("id"): item for item in items if isinstance(item, dict)}
            for item_id, update in (evaluation.get("updates") or {}).items():
                item = by_id.get(item_id)
                if item is None or not isinstance(update, Mapping):
                    continue
                if update.get("status") in ITEM_STATUSES:
                    item["status"] = update["status"]
                note = clean_text(update.get("note"), MAX_NOTE_CHARS)
                if note:
                    item["note"] = note
                item["updated_at"] = _now()
            known = {str(item.get("text") or "").lower() for item in items}
            for text in evaluation.get("new_items") or []:
                if len(items) >= MAX_ITEMS:
                    break
                cleaned = clean_text(text, MAX_ITEM_CHARS)
                if cleaned and cleaned.lower() not in known:
                    items.append(_new_item(cleaned, "answer"))
                    known.add(cleaned.lower())
            summary = clean_text(evaluation.get("summary"), MAX_SUMMARY_CHARS)
            if summary:
                record["summary"] = summary
            questions = _clean_list(evaluation.get("questions"), MAX_QUESTIONS, MAX_QUESTION_CHARS)
            if questions:
                record["suggested_questions"] = questions
            for turn in record.get("turns") or []:
                if turn.get("id") in evaluated:
                    turn["evaluated"] = True
            record["progress_checked_at"] = _now()
            return record

        return goal_detail(self._mutate(owner, goal_id, change))

    # Saved chats

    def save_chat(self, owner: str, goal_id: str, chat_id: Any, messages: Any, title: Any = None) -> Dict[str, Any]:
        """Create or replace the saved copy of one conversation under a goal."""
        key = clean_id(chat_id)
        if not key:
            raise GoalLimitError("A chat id is required.")
        kept = _sanitize_messages(messages)

        def change(record: Dict[str, Any]) -> Dict[str, Any]:
            chats = record.setdefault("chats", [])
            chat = next((entry for entry in chats if entry.get("id") == key), None)
            now = _now()
            if chat is None:
                if len(chats) >= MAX_CHATS:
                    raise GoalLimitError(f"A goal keeps up to {MAX_CHATS} chats. Delete one to save another.")
                chat = {"id": key, "title": "", "created_at": now}
                chats.append(chat)
            if title is not None:
                chat["title"] = clean_text(title, MAX_TITLE_CHARS)
            if not chat.get("title"):
                chat["title"] = _first_user_text(kept) or "Untitled chat"
            chat["messages"] = kept
            chat["updated_at"] = now
            return _chat_meta(chat)

        return self._mutate(owner, goal_id, change)

    def get_chat(self, owner: str, goal_id: str, chat_id: str) -> Dict[str, Any]:
        with self._lock:
            goal = self._find(self._load(owner), goal_id)
        chat = next((entry for entry in goal.get("chats") or [] if entry.get("id") == chat_id), None)
        if chat is None:
            raise GoalNotFoundError("Saved chat not found.")
        return {**_chat_meta(chat), "messages": list(chat.get("messages") or [])}

    def rename_chat(self, owner: str, goal_id: str, chat_id: str, title: Any) -> Dict[str, Any]:
        new_title = clean_text(title, MAX_TITLE_CHARS)
        if not new_title:
            raise GoalLimitError("Give the chat a name first.")

        def change(record: Dict[str, Any]) -> Dict[str, Any]:
            chat = next((entry for entry in record.get("chats") or [] if entry.get("id") == chat_id), None)
            if chat is None:
                raise GoalNotFoundError("Saved chat not found.")
            chat["title"] = new_title
            chat["updated_at"] = _now()
            return _chat_meta(chat)

        return self._mutate(owner, goal_id, change)

    def delete_chat(self, owner: str, goal_id: str, chat_id: str) -> None:
        def change(record: Dict[str, Any]) -> None:
            chats = record.get("chats") or []
            if not any(entry.get("id") == chat_id for entry in chats):
                raise GoalNotFoundError("Saved chat not found.")
            record["chats"] = [entry for entry in chats if entry.get("id") != chat_id]

        self._mutate(owner, goal_id, change)


# Prompts for planning a goal and judging progress after an answer.

def build_plan_messages(goal_text: str, environment_brief: str = "") -> List[Dict[str, str]]:
    brief = clean_block(environment_brief, 1500)
    environment = f"\n\nWhat discovery found in this Splunk environment:\n{brief}" if brief else ""
    return [
        {
            "role": "system",
            "content": (
                "You help a Splunk user plan an investigation. Break their goal into the questions that must be "
                "answered to reach it, and suggest the first questions to ask a Splunk chat assistant that can run "
                "read-only searches. Use only index, sourcetype, and host names that appear in the environment notes. "
                "Return strict JSON only: "
                '{"title": "short name for the goal, at most 8 words", '
                '"items": ["3 to 6 questions that together settle the goal"], '
                '"questions": ["3 questions to ask first, written the way the user would type them"]}'
            ),
        },
        {"role": "user", "content": f"Goal: {clean_text(goal_text, MAX_GOAL_CHARS)}{environment}"},
    ]


def parse_plan(data: Any, goal_text: str) -> Optional[Dict[str, Any]]:
    if not isinstance(data, Mapping):
        return None
    items = _clean_list(data.get("items"), MAX_ITEMS, MAX_ITEM_CHARS)
    if not items:
        return None
    questions = _clean_list(data.get("questions"), MAX_QUESTIONS, MAX_QUESTION_CHARS) or items[:MAX_QUESTIONS]
    return {
        "title": clean_text(data.get("title"), MAX_TITLE_CHARS) or default_title(goal_text),
        "items": items,
        "questions": questions,
    }


def fallback_plan(goal_text: str) -> Dict[str, Any]:
    """Used when the AI model is unavailable: track the goal itself and offer starter questions."""
    return {
        "title": default_title(goal_text),
        "items": [clean_text(goal_text, MAX_ITEM_CHARS)],
        "questions": list(FALLBACK_QUESTIONS),
    }


def pending_turns(goal: Mapping[str, Any], limit: int = 2) -> List[Dict[str, Any]]:
    turns = [turn for turn in goal.get("turns") or [] if isinstance(turn, Mapping) and not turn.get("evaluated")]
    return [dict(turn) for turn in turns[-limit:]]


def build_progress_messages(goal: Mapping[str, Any], turns: Sequence[Mapping[str, Any]]) -> List[Dict[str, str]]:
    items = [item for item in goal.get("items") or [] if isinstance(item, Mapping)]
    item_lines = "\n".join(
        f'- id={item.get("id")} status={item.get("status")}: {item.get("text")}'
        + (f' (note: {item.get("note")})' if item.get("note") else "")
        for item in items
    ) or "- none yet"
    turn_text = "\n\n".join(
        f"Question: {turn.get('question')}\nAnswer: {turn.get('answer')}" for turn in turns
    )
    return [
        {
            "role": "system",
            "content": (
                "You track a Splunk user's progress toward a goal. Read the latest answers from the Splunk chat "
                "assistant and update the tracked questions. Mark a question answered only when the answers give "
                "evidence that settles it; an answer that could not find data or only suggests a search does not "
                "settle it. Return strict JSON only: "
                '{"updates": [{"id": "tracked question id", "status": "answered or open", '
                '"note": "one short sentence with what the evidence showed"}], '
                '"new_items": ["at most 2 new questions the answers showed must still be answered"], '
                '"summary": "one sentence on overall progress toward the goal", '
                '"questions": ["3 next questions to ask, written the way the user would type them, aimed at open items"]}'
            ),
        },
        {
            "role": "user",
            "content": f"Goal: {goal.get('goal')}\n\nTracked questions:\n{item_lines}\n\nLatest answers:\n{turn_text}",
        },
    ]


def parse_progress(data: Any, goal: Mapping[str, Any]) -> Optional[Dict[str, Any]]:
    if not isinstance(data, Mapping):
        return None
    known_ids = {item.get("id") for item in goal.get("items") or [] if isinstance(item, Mapping)}
    updates: Dict[str, Dict[str, Any]] = {}
    for update in data.get("updates") or []:
        if not isinstance(update, Mapping) or update.get("id") not in known_ids:
            continue
        status = str(update.get("status") or "").strip().lower()
        updates[str(update["id"])] = {
            "status": status if status in ITEM_STATUSES else None,
            "note": clean_text(update.get("note"), MAX_NOTE_CHARS),
        }
    return {
        "updates": updates,
        "new_items": _clean_list(data.get("new_items"), MAX_NEW_ITEMS_PER_ANSWER, MAX_ITEM_CHARS),
        "summary": clean_text(data.get("summary"), MAX_SUMMARY_CHARS),
        "questions": _clean_list(data.get("questions"), MAX_QUESTIONS, MAX_QUESTION_CHARS),
    }
