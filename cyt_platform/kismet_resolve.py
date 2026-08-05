"""Resolve newest Kismet DB path with one-cycle rollover flag."""

from __future__ import annotations

import glob
import os
from typing import Optional


class KismetDbResolver:
    """Resolve newest Kismet DB path; expose one-cycle rollover flag."""

    def __init__(self, glob_pattern: str):
        self.pattern = glob_pattern
        self.current: Optional[str] = None
        self.just_rolled: bool = False

    def resolve(self) -> str:
        """
        Returns absolute path of newest matching file by mtime.

        Sets self.just_rolled:
          - True  iff the chosen path != self.current (including first resolve)
          - False iff path unchanged

        Raises FileNotFoundError if glob matches zero files.
        """
        files = glob.glob(self.pattern)
        if not files:
            self.just_rolled = False
            raise FileNotFoundError(self.pattern)
        newest = max(files, key=os.path.getmtime)
        newest = os.path.abspath(newest)
        self.just_rolled = newest != self.current
        self.current = newest
        return self.current
