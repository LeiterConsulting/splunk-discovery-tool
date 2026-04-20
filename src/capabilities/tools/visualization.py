"""Deterministic visualization preview generation for Splunk result sets."""

import re
from typing import Any, Dict, List, Optional

from capabilities.models import CapabilityConfig, CapabilityDefinition


def _safe_float(value: Any) -> Optional[float]:
    try:
        if value in (None, ""):
            return None
        if isinstance(value, bool):
            return None
        cleaned = str(value).strip().replace(",", "")
        if not cleaned:
            return None
        return float(cleaned)
    except (TypeError, ValueError):
        return None


def _short_label(value: Any, limit: int = 22) -> str:
    text = str(value or "").strip()
    if len(text) <= limit:
        return text
    return f"{text[: max(3, limit - 3)]}..."


class VisualizationPreviewProvider:
    """Build lightweight chart previews without external visualization dependencies."""

    def __init__(self, config: CapabilityConfig, definition: CapabilityDefinition):
        self.config = config
        self.definition = definition

    def get_runtime_summary(self) -> Dict[str, Any]:
        return {
            "preview_enabled": self.preview_enabled(),
            "supported_chart_types": ["line", "bar"],
            "supported_query_shapes": ["time_series", "aggregation"],
            "max_preview_points": self.max_preview_points(),
        }

    def preview_enabled(self) -> bool:
        configured = self.config.config.get("preview_enabled", self.definition.default_config.get("preview_enabled", True))
        return bool(configured)

    def max_preview_points(self) -> int:
        configured = self.config.config.get("max_preview_points", self.definition.default_config.get("max_preview_points", 8))
        try:
            parsed = int(configured)
            return max(3, min(parsed, 24))
        except (TypeError, ValueError):
            return 8

    def build_preview(self, rows: Any, payload: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        if not self.preview_enabled():
            raise ValueError("Visualization previews are disabled in capability config.")

        dict_rows = [row for row in rows if isinstance(row, dict)] if isinstance(rows, list) else []
        if not dict_rows:
            raise ValueError("Query results are required to build a visualization preview.")

        metadata = payload if isinstance(payload, dict) else {}

        time_series_preview = self._build_time_series_preview(dict_rows, metadata)
        if time_series_preview:
            return time_series_preview

        aggregation_preview = self._build_bar_preview(dict_rows, metadata)
        if aggregation_preview:
            return aggregation_preview

        raise ValueError("Query results are not chartable with the staged visualization runtime.")

    def _build_time_series_preview(self, rows: List[Dict[str, Any]], metadata: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        sample_fields = self._sample_fields(rows)
        time_field = self._preferred_time_field(sample_fields)
        if not time_field:
            return None

        numeric_fields = self._numeric_fields(rows, sample_fields)
        value_field = self._preferred_numeric_field(numeric_fields)
        if not value_field:
            return None

        preview_rows = self._downsample_rows(rows, self.max_preview_points())
        points = []
        for row in preview_rows:
            raw_label = row.get(time_field)
            numeric_value = _safe_float(row.get(value_field))
            if raw_label in (None, "") or numeric_value is None:
                continue
            points.append(
                {
                    "label": self._normalize_time_label(raw_label),
                    "full_label": str(raw_label).strip(),
                    "value": numeric_value,
                }
            )

        if len(points) < 2:
            return None

        point_count = len(points)
        return {
            "title": str(metadata.get("title") or "Trend Preview"),
            "summary_text": f"Generated a line preview from {point_count} points using {time_field} and {value_field}.",
            "chart_type": "line",
            "query_shape": str(metadata.get("query_shape") or "time_series"),
            "x_field": time_field,
            "y_field": value_field,
            "point_count": point_count,
            "source_row_count": len(rows),
            "points": points,
        }

    def _build_bar_preview(self, rows: List[Dict[str, Any]], metadata: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        sample_fields = self._sample_fields(rows)
        numeric_fields = self._numeric_fields(rows, sample_fields)
        value_field = self._preferred_numeric_field(numeric_fields)
        if not value_field:
            return None

        label_fields = self._preferred_dimension_fields(sample_fields, numeric_fields, metadata)
        if not label_fields:
            return None

        aggregates: Dict[str, float] = {}
        for row in rows:
            label_parts = []
            for field in label_fields[:2]:
                value = row.get(field)
                if value not in (None, ""):
                    label_parts.append(str(value).strip())
            numeric_value = _safe_float(row.get(value_field))
            if not label_parts or numeric_value is None:
                continue
            label = " / ".join(label_parts)
            aggregates[label] = aggregates.get(label, 0.0) + numeric_value

        if len(aggregates) < 2:
            return None

        max_points = self.max_preview_points()
        ranked_points = sorted(aggregates.items(), key=lambda item: item[1], reverse=True)[:max_points]
        points = [
            {
                "label": _short_label(label),
                "full_label": label,
                "value": value,
            }
            for label, value in ranked_points
        ]

        return {
            "title": str(metadata.get("title") or "Breakdown Preview"),
            "summary_text": f"Generated a bar preview from {len(points)} ranked categories using {value_field}.",
            "chart_type": "bar",
            "query_shape": str(metadata.get("query_shape") or "aggregation"),
            "x_field": ", ".join(label_fields[:2]),
            "y_field": value_field,
            "point_count": len(points),
            "source_row_count": len(rows),
            "points": points,
        }

    def _sample_fields(self, rows: List[Dict[str, Any]]) -> List[str]:
        if not rows:
            return []
        first_row = rows[0] if isinstance(rows[0], dict) else {}
        return [str(field) for field in list(first_row.keys())[:12]]

    def _preferred_time_field(self, fields: List[str]) -> Optional[str]:
        preferred = ["_time", "time", "TIME"]
        for candidate in preferred:
            if candidate in fields:
                return candidate
        for field in fields:
            lowered = field.lower()
            if lowered.endswith("time") or lowered.endswith("timeiso"):
                return field
        return None

    def _numeric_fields(self, rows: List[Dict[str, Any]], fields: List[str]) -> List[str]:
        numeric_fields = []
        for field in fields:
            samples = [row.get(field) for row in rows[:8] if row.get(field) not in (None, "")]
            if samples and all(_safe_float(sample) is not None for sample in samples):
                numeric_fields.append(field)
        return numeric_fields

    def _preferred_numeric_field(self, numeric_fields: List[str]) -> Optional[str]:
        preferred = ["count", "COUNT", "event_count", "value", "avg", "sum", "total", "max", "min"]
        lowered_map = {field.lower(): field for field in numeric_fields}
        for candidate in preferred:
            matched = lowered_map.get(candidate.lower())
            if matched:
                return matched
        return numeric_fields[0] if numeric_fields else None

    def _preferred_dimension_fields(self, fields: List[str], numeric_fields: List[str], metadata: Dict[str, Any]) -> List[str]:
        top_dimensions = metadata.get("top_dimensions", []) if isinstance(metadata.get("top_dimensions", []), list) else []
        chosen = []
        for dimension in top_dimensions:
            if not isinstance(dimension, dict):
                continue
            field_name = str(dimension.get("field") or "").strip()
            if field_name and field_name in fields and field_name not in numeric_fields and field_name not in chosen:
                chosen.append(field_name)

        if chosen:
            return chosen[:2]

        preferred = ["sourcetype", "host", "index", "source", "user", "action", "status"]
        lowered_map = {field.lower(): field for field in fields}
        for candidate in preferred:
            matched = lowered_map.get(candidate)
            if matched and matched not in numeric_fields and matched not in chosen:
                chosen.append(matched)

        if chosen:
            return chosen[:2]

        for field in fields:
            lowered = field.lower()
            if field in numeric_fields or lowered.endswith("time") or lowered.endswith("timeiso"):
                continue
            chosen.append(field)

        return chosen[:2]

    def _downsample_rows(self, rows: List[Dict[str, Any]], max_points: int) -> List[Dict[str, Any]]:
        if len(rows) <= max_points:
            return rows

        sampled = []
        used_indexes = set()
        step = (len(rows) - 1) / float(max_points - 1)
        for offset in range(max_points):
            index = int(round(offset * step))
            if index in used_indexes:
                continue
            used_indexes.add(index)
            sampled.append(rows[index])
        return sampled

    def _normalize_time_label(self, value: Any) -> str:
        text = str(value or "").strip().replace("T", " ")
        text = re.sub(r"\.\d+", "", text)
        text = re.sub(r"\s+[A-Z]{2,5}$", "", text)
        if re.match(r"^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}", text):
            return text[:16]
        return _short_label(text, limit=18)