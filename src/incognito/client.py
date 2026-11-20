"""Model client wrapper that masks requests and restores replies for incognito sessions."""

from __future__ import annotations

from typing import Any, Callable, Optional

from .seeding import inventory_from_blueprint
from .session import IncognitoSession


def _same_kind(original: Any, restored: Any) -> Any:
    """Keep a str subclass reply (and its flags, such as ``ends_on_preamble``) after restoring names."""
    if type(original) is str or not isinstance(original, str) or not isinstance(restored, str):
        return restored
    try:
        copy = type(original)(restored)
        copy.__dict__.update(getattr(original, "__dict__", {}))
        return copy
    except Exception:  # noqa: BLE001 - fall back to plain text when the subclass cannot be rebuilt
        return restored


class IncognitoLLMClient:
    """Wraps any model client with ``generate_response`` and ``analyze_data``.

    The session comes from ``resolve_session`` on every call, so one cached client serves both
    incognito and normal requests.
    """

    def __init__(self, inner: Any, resolve_session: Callable[[], Optional[IncognitoSession]]) -> None:
        object.__setattr__(self, "_inner", inner)
        object.__setattr__(self, "_resolve_session", resolve_session)

    @property
    def inner(self) -> Any:
        return self._inner

    def __getattr__(self, name: str) -> Any:
        return getattr(object.__getattribute__(self, "_inner"), name)

    def _session(self) -> Optional[IncognitoSession]:
        session = self._resolve_session()
        return session if session is not None and session.active else None

    async def _forward(self, prompt: Optional[str], messages: Optional[list], args: tuple, kwargs: dict) -> Any:
        if args:
            return await self._inner.generate_response(prompt, messages, *args, **kwargs)
        # Keywords only, so clients whose parameters are in a different order still get the right values.
        call = dict(kwargs)
        if prompt is not None:
            call["prompt"] = prompt
        if messages is not None:
            call["messages"] = messages
        return await self._inner.generate_response(**call)

    async def generate_response(self, prompt: Optional[str] = None, messages: Optional[list] = None, *args: Any,
                                **kwargs: Any) -> str:
        session = self._session()
        if session is None:
            return await self._forward(prompt, messages, args, kwargs)
        masked_prompt, masked_messages = session.mask_request(prompt=prompt, messages=messages)
        recorded_prompt = masked_prompt if masked_messages is None else None
        try:
            reply = await self._forward(masked_prompt, masked_messages, args, kwargs)
        except Exception as error:
            # The masked text was sent even though no reply came back, so it belongs in the record.
            session.record(prompt=recorded_prompt, messages=masked_messages, error=error)
            raise
        session.record(prompt=recorded_prompt, messages=masked_messages, reply=reply)
        return _same_kind(reply, session.restore_text(reply))

    def learn_names(self, blueprint: Any) -> int:
        """Register names from discovery data shaped like a blueprint, for the current incognito session."""
        session = self._session()
        if session is None:
            return 0
        return session.learn_names(inventory_from_blueprint(blueprint))

    async def analyze_data(self, data: dict, analysis_type: str) -> dict:
        session = self._session()
        if session is None:
            return await self._inner.analyze_data(data, analysis_type)
        masked = session.mask_data(data)
        feature = f"discovery analysis: {analysis_type}"
        try:
            result = await self._inner.analyze_data(masked, analysis_type)
        except Exception as error:
            session.record(feature=feature, data=masked, error=error)
            raise
        session.record(feature=feature, data=masked, reply=result)
        return session.restore_data(result)
