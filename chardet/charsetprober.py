"""
`CharSetProber`
"""

from .charsetgroupprober import CharSetGroupProber
from .enums import ProbingState


class CharSetProber:
    """
    This is a state machine that walks through a sequence of probers to
    determine a character set.
    """

    def __init__(self, lang_filter=None, should_rename_legacy=False):
        self._m_prober = None
        self.should_rename_legacy = should_rename_legacy
        self.reset()

    def reset(self):
        self._m_state = ProbingState.DETECTING
        if self._m_prober:
            self._m_prober.reset()

    @property
    def charset_name(self):
        if not self._m_prober:
            return None
        return self._m_prober.charset_name

    @property
    def language(self):
        if not self._m_prober:
            return None
        return self._m_prober.language

    def feed(self, byte_str):
        if not self._m_prober:
            # TODO: create this in __init__
            self._m_prober = CharSetGroupProber(
                should_rename_legacy=self.should_rename_legacy
            )

        if self._m_state == ProbingState.DETECTING:
            self._m_state = self._m_prober.feed(byte_str)
            if self._m_state == ProbingState.FOUND_IT:
                return self.state

        return self.state

    @property
    def state(self):
        return self._m_state

    def get_confidence(self):
        if self._m_state == ProbingState.FOUND_IT:
            return self._m_prober.get_confidence()
        return 0.0

    def close(self):
        if self.state == ProbingState.DETECTING:
            self._m_state = ProbingState.NOT_ME
        return self.state
