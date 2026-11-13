"""Staff membership for the cross-user exception shared by the MCP servers.

A user is staff (allowed to query records other than their own) when either

* their group memberships (from the OIDC token/UserInfo or the fmcpv1
  ``groups`` claim) intersect ``STAFF_GROUPS`` (default ``cc-staff``,
  ``scinet``), or
* their username appears on the ops-maintained staff list on the shared
  token-issuer volume (``STAFF_LIST_PATH``), which mirrors the revocation
  store's mtime-based reload.

The two signals compose; the list is the admin override when the IdP does
not release the expected group values.
"""

from __future__ import annotations

import json
import logging
import os
import time
from pathlib import Path
from typing import Iterable

log = logging.getLogger(__name__)


class StaffList:
    """Staff usernames, mirrored from the token-issuer's shared volume.

    The file lives next to ``token-store.json`` on the shared token volume
    (mounted read-only here) and re-reads on the same mtime timer as the
    revocation list, so roster changes take effect within ``reload_seconds``.
    """

    def __init__(self, path: str | os.PathLike[str], *, reload_seconds: float = 15.0):
        self._path = Path(path)
        self._reload_seconds = reload_seconds
        self._mtime_ns: int | None = None
        self._last_check = 0.0
        self._loaded_once = False
        self._usernames: set[str] = set()

    def usernames(self) -> frozenset[str]:
        self._maybe_reload()
        return frozenset(self._usernames)

    def _maybe_reload(self) -> None:
        now = time.monotonic()
        if self._loaded_once and now - self._last_check < self._reload_seconds:
            return
        self._loaded_once = True
        self._last_check = now
        try:
            stat = self._path.stat()
        except OSError:
            self._usernames = set()
            return
        if stat.st_mtime_ns == self._mtime_ns:
            return
        self._mtime_ns = stat.st_mtime_ns
        try:
            data = json.loads(self._path.read_text("utf-8"))
        except (OSError, ValueError):
            return
        candidates: object = None
        if isinstance(data, dict):
            candidates = data.get("staffUsernames")
            if not isinstance(candidates, list):
                candidates = data.get("staff")
        elif isinstance(data, list):
            candidates = data
        if isinstance(candidates, list):
            self._usernames = {str(u) for u in candidates if isinstance(u, str) and u}

    def close(self) -> None:
        self._usernames = set()


class StaffEvaluator:
    """Decides whether a (username, groups) pair is staff for this server."""

    def __init__(
        self,
        *,
        staff_groups: Iterable[str] = (),
        staff_list_path: str | None = None,
    ) -> None:
        self._groups = frozenset(g for g in staff_groups if g)
        self._list = (
            StaffList(staff_list_path) if staff_list_path else None
        )

    @property
    def enabled(self) -> bool:
        return bool(self._groups) or self._list is not None

    def is_staff(self, username: str, groups: Iterable[str] = ()) -> bool:
        if self._list is not None and username in self._list.usernames():
            return True
        if self._groups:
            known = {g for g in groups if g}
            if known & self._groups:
                return True
        return False

    def close(self) -> None:
        if self._list is not None:
            self._list.close()
