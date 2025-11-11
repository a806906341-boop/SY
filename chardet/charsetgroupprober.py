"""
`CharSetGroupProber`
"""

from .big5prober import Big5Prober
from .cp949prober import CP949Prober
from .eucjpprober import EUCJPProber
from .euckrprober import EUCKRProber
from .euctwprober import EUCTWProber
from .gb2312prober import GB2312Prober
from .hebrewprober import HebrewProber
from .johabprober import JohabProber
from .langbulgarianmodel import (BULGARIAN_CHAR_TO_ORDER_MAP, BULGARIAN_LANG_MODEL)
from .langcyrillicmodel import (CYRILLIC_CHAR_TO_ORDER_MAP, CYRILLIC_LANG_MODEL)
from .langgreekmodel import (GREEK_CHAR_TO_ORDER_MAP, GREEK_LANG_MODEL)
from .langhebrewmodel import (HEBREW_CHAR_TO_ORDER_MAP, HEBREW_LANG_MODEL)
from .langhungarianmodel import (HUNGARIAN_CHAR_TO_ORDER_MAP, HUNGARIAN_LANG_MODEL)
from .langrussianmodel import (RUSSIAN_CHAR_TO_ORDER_MAP, RUSSIAN_LANG_MODEL)
from .langthaimodel import (THAI_CHAR_TO_ORDER_MAP, THAI_LANG_MODEL)
from .langturkishmodel import (TURKISH_CHAR_TO_ORDER_MAP, TURKISH_LANG_MODEL)
from .latin1prober import Latin1Prober
from .mbcsgroupprober import MBCSGroupProber
from .sbcsgroupprober import SBCSGroupProber
from .sjisprober import SJISProber
from .utf8prober import UTF8Prober


class CharSetGroupProber:
    """
    `CharSetGroupProber` uses a list of probers to find the character set.
    """

    def __init__(self, lang_filter=None, should_rename_legacy=False):
        self._m_probers = []
        self.should_rename_legacy = should_rename_legacy
        self._m_is_active = True
        self._m_best_prober = None
        self.reset()

    def reset(self):
        self._m_is_active = True
        self._m_best_prober = None
        for prober in self._m_probers:
            prober.reset()

    @property
    def charset_name(self):
        if not self._m_best_prober:
            self.get_confidence()
            if not self._m_best_prober:
                return None
        return self._m_best_prober.charset_name

    @property
    def language(self):
        if not self._m_best_prober:
            self.get_confidence()
            if not self._m_best_prober:
                return None
        return self._m_best_prober.language

    def feed(self, byte_str):
        if not self.is_active:
            return self.state

        for prober in self._m_probers:
            if not prober.is_active:
                continue
            state = prober.feed(byte_str)
            if state:
                # TODO: Should this be returning state?
                return

    def get_confidence(self):
        if not self.is_active:
            return 0.0

        best_conf = 0.0
        self._m_best_prober = None
        for prober in self._m_probers:
            if not prober.is_active:
                continue
            conf = prober.get_confidence()
            if conf > best_conf:
                best_conf = conf
                self._m_best_prober = prober

        if not self._m_best_prober:
            return 0.0

        return best_conf

    @property
    def state(self):
        if not self.is_active:
            # We have already found a match, so don't do anything more
            return None

        # No probers were found, so we can't say anything about the text.
        if not self._m_probers:
            return None

        # If any prober has found a match, we are done
        if self.get_confidence() > 0:
            return self.state

        # No character set could be found
        return None

    @property
    def is_active(self):
        return self._m_is_active

    def close(self):
        pass
