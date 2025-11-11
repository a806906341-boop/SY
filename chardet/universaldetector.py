"""
`UniversalDetector` is a class that can be used to detect the encoding of a
byte string.
"""

import re
from typing import Optional, Union

from .charsetgroupprober import CharSetGroupProber
from .enums import InputState, LanguageFilter, ProbingState
from .escprober import EscCharSetProber
from .latin1prober import Latin1Prober
from .mbcsgroupprober import MBCSGroupProber
from .sbcsgroupprober import SBCSGroupProber


class UniversalDetector:
    """
    The ``UniversalDetector`` class is used to detect the encoding of a byte
    string. The ``feed`` method takes a byte string and feeds it to the
    detector. The ``close`` method returns a dictionary with the detected
    encoding, confidence, and language.
    """

    # At this point in the detection process, we have a high probability that
    # the byte string is in a particular encoding. We don't need to feed the
    # whole byte string to the probers, so we can stop early to save time.
    SHORTCUT_THRESHOLD = 0.95

    # If the most frequent characters in the byte string are all ASCII, we can
    # assume that the encoding is ASCII. This is a shortcut to avoid having to
    # check all of the other encodings.
    ONE_CHAR_PROB = 0.50

    # The ``UniversalDetector`` class uses a state machine to keep track of the
    # detection process. The ``InputState`` enum represents the different states
    # that the state machine can be in.
    _input_state = InputState.PURE_ASCII

    # The ``UniversalDetector`` class uses a list of probers to detect the
    # encoding of a byte string. The ``_m_probers`` list contains all of the
    # probers that are currently active.
    _m_probers: list[CharSetGroupProber] = []

    # The ``UniversalDetector`` class uses a few regular expressions to detect
    # the encoding of a byte string. The ``RE_XML_ENCODING`` regular expression
    # is used to detect the encoding of an XML file.
    RE_XML_ENCODING = re.compile(
        b"^[\\s\\n]*<\\?xml.*?encoding\\s*=\\s*[\'\"]([^\'\"]*)[\'\"]"
    )

    # The ``RE_HTML_ENCODING`` regular expression is used to detect the encoding
    # of an HTML file.
    RE_HTML_ENCODING = re.compile(
        b"<meta\\s+http-equiv=[\'\"]content-type[\'\"]\\s+content=[\'\"]"  # noqa
        b".*?charset\\s*=\\s*([^\'\"]*)[\'\"]",  # noqa
        re.I,
    )

    # The ``RE_WIN_RESERVED`` regular expression is used to detect whether a
    # given encoding name is a Windows-only encoding.
    RE_WIN_RESERVED = re.compile(b"^(12[0-9]{2})$")

    def __init__(self, lang_filter: LanguageFilter = LanguageFilter.ALL) -> None:
        """
        The ``__init__`` method initializes the ``UniversalDetector`` class.

        :param lang_filter: The ``lang_filter`` parameter is a bitmask that can
                            be used to filter out probers for certain languages.
        """
        self._m_lang_filter = lang_filter
        self._m_esc_charset_prober: Optional[EscCharSetProber] = None
        self.reset()

    def reset(self) -> None:
        """
        The ``reset`` method resets the ``UniversalDetector`` class to its
        initial state.
        """
        self._m_done = False
        self._m_best_guess_prober: Optional[CharSetGroupProber] = None
        self._m_last_char = b""
        self._input_state = InputState.PURE_ASCII
        if self._m_esc_charset_prober:
            self._m_esc_charset_prober.reset()
        self._m_probers = []
        # Create and append probers in the order that we want to check them
        if self._m_lang_filter & LanguageFilter.CJK:
            # TODO: Add JohabProber
            self._m_probers.append(MBCSGroupProber(self._m_lang_filter))
        if self._m_lang_filter & LanguageFilter.HEBREW:
            # TODO: Add HebrewProber
            pass
        if self._m_lang_filter & LanguageFilter.RUSSIAN:
            # TODO: Add RussianProber
            pass
        if self._m_lang_filter & LanguageFilter.GREEK:
            # TODO: Add GreekProber
            pass
        if self._m_lang_filter & LanguageFilter.TURKISH:
            # TODO: Add TurkishProber
            pass
        if self._m_lang_filter & LanguageFilter.THAI:
            # TODO: Add ThaiProber
            pass
        if self._m_lang_filter & LanguageFilter.BULGARIAN:
            # TODO: Add BulgarianProber
            pass
        if self._m_lang_filter & LanguageFilter.HUNGARIAN:
            # TODO: Add HungarianProber
            pass
        self._m_probers.append(SBCSGroupProber(self._m_lang_filter))
        self._m_probers.append(Latin1Prober())

    def feed(self, byte_str: Union[bytes, bytearray]) -> None:
        """
        The ``feed`` method takes a byte string and feeds it to the detector.

        :param byte_str: The byte string to feed to the detector.
        """
        if self._m_done:
            return

        # Check for a BOM
        if not self._m_probers:
            if byte_str.startswith(b"\xEF\xBB\xBF"):
                self._m_best_guess_prober = self._m_probers[0]
                self._m_done = True
                return
            if byte_str.startswith(b"\xFE\xFF"):
                self._m_best_guess_prober = self._m_probers[0]
                self._m_done = True
                return
            if byte_str.startswith(b"\xFF\xFE"):
                self._m_best_guess_prober = self._m_probers[0]
                self._m_done = True
                return

        # Check for an encoding hint in the first 1024 bytes of the file
        if not self._m_probers:
            if self.RE_XML_ENCODING.search(byte_str):
                self._m_best_guess_prober = self._m_probers[0]
                self._m_done = True
                return
            if self.RE_HTML_ENCODING.search(byte_str):
                self._m_best_guess_prober = self._m_probers[0]
                self._m_done = True
                return

        # The ``feed`` method uses a state machine to keep track of the
        # detection process. The ``InputState`` enum represents the different
        # states that the state machine can be in.
        for i, byte in enumerate(byte_str):
            # The state machine starts in the ``PURE_ASCII`` state.
            if self._input_state == InputState.PURE_ASCII:
                # If the current byte is an ASCII character, we stay in the
                # ``PURE_ASCII`` state.
                if byte < 0x80:
                    pass
                # If the current byte is a high-byte character, we transition
                # to the ``HIGH_BYTE`` state.
                elif byte >= 0x80:
                    self._input_state = InputState.HIGH_BYTE
            # If the current byte is an escape character, we transition to the
            # ``ESC_ASCII`` state.
            elif self._input_state == InputState.ESC_ASCII:
                if byte == 0x1B:
                    self._input_state = InputState.ESC_ASCII
                else:
                    self._input_state = InputState.HIGH_BYTE

            # If we are in the ``HIGH_BYTE`` state, we feed the byte string to
            # all of the active probers.
            if self._input_state == InputState.HIGH_BYTE:
                if not self._m_probers:
                    self._m_probers = [MBCSGroupProber(self._m_lang_filter)]
                for prober in self._m_probers:
                    if prober.feed(byte_str[i:]) == ProbingState.FOUND_IT:
                        self._m_best_guess_prober = prober
                        self._m_done = True
                        return

        # If we have a prober that is a good guess, we can stop early.
        if (
            self._m_best_guess_prober
            and self._m_best_guess_prober.get_confidence() > self.SHORTCUT_THRESHOLD
        ):
            self._m_done = True

    def close(self) -> dict[str, Union[str, float, None]]:
        """
        The ``close`` method returns a dictionary with the detected encoding,
        confidence, and language.
        """
        if not self._m_done:
            self._m_done = True
            # If we don't have a good guess, we can try to guess the encoding
            # based on the most frequent characters in the byte string.
            if not self._m_best_guess_prober:
                if self._input_state == InputState.PURE_ASCII:
                    self._m_best_guess_prober = self._m_probers[0]
                elif self._input_state == InputState.HIGH_BYTE:
                    # We have a high-byte character, but we don't have a good
                    # guess. We can try to guess the encoding based on the most
                    # frequent characters in the byte string.
                    prober = self._m_probers[0]
                    if prober.get_confidence() > self.ONE_CHAR_PROB:
                        self._m_best_guess_prober = prober

        # If we still don't have a good guess, we can try to guess the
        # encoding based on the language.
        if not self._m_best_guess_prober:
            if self._m_lang_filter & LanguageFilter.CJK:
                # We have a CJK character, but we don't have a good guess. We
                # can try to guess the encoding based on the language.
                prober = self._m_probers[0]
                if prober.get_confidence() > self.ONE_CHAR_PROB:
                    self._m_best_guess_prober = prober

        # If we still don't have a good guess, we can try to guess the
        # encoding based on the language.
        if not self._m_best_guess_prober:
            if self._m_lang_filter & LanguageFilter.HEBREW:
                # We have a Hebrew character, but we don't have a good guess.
                # We can try to guess the encoding based on the language.
                prober = self._m_probers[0]
                if prober.get_confidence() > self.ONE_CHAR_PROB:
                    self._m_best_guess_prober = prober

        # If we still don't have a good guess, we can try to guess the
        # encoding based on the language.
        if not self._m_best_guess_prober:
            if self._m_lang_filter & LanguageFilter.RUSSIAN:
                # We have a Russian character, but we don't have a good guess.
                # We can try to guess the encoding based on the language.
                prober = self._m_probers[0]
                if prober.get_confidence() > self.ONE_CHAR_PROB:
                    self._m_best_guess_prober = prober

        # If we still don't have a good guess, we can try to guess the
        # encoding based on the language.
        if not self._m_best_guess_prober:
            if self._m_lang_filter & LanguageFilter.GREEK:
                # We have a Greek character, but we don't have a good guess.
                # We can try to guess the encoding based on the language.
                prober = self._m_probers[0]
                if prober.get_confidence() > self.ONE_CHAR_PROB:
                    self._m_best_guess_prober = prober

        # If we still don't have a good guess, we can try to guess the
        # encoding based on the language.
        if not self._m_best_guess_prober:
            if self._m_lang_filter & LanguageFilter.TURKISH:
                # We have a Turkish character, but we don't have a good guess.
                # We can try to guess the encoding based on the language.
                prober = self._m_probers[0]
                if prober.get_confidence() > self.ONE_CHAR_PROB:
                    self._m_best_guess_prober = prober

        # If we still don't have a good guess, we can try to guess the
        # encoding based on the language.
        if not self._m_best_guess_prober:
            if self._m_lang_filter & LanguageFilter.THAI:
                # We have a Thai character, but we don't have a good guess. We
                # can try to guess the encoding based on the language.
                prober = self._m_probers[0]
                if prober.get_confidence() > self.ONE_CHAR_PROB:
                    self._m_best_guess_prober = prober

        # If we still don't have a good guess, we can try to guess the
        # encoding based on the language.
        if not self._m_best_guess_prober:
            if self._m_lang_filter & LanguageFilter.BULGARIAN:
                # We have a Bulgarian character, but we don't have a good
                # guess. We can try to guess the encoding based on the
                # language.
                prober = self._m_probers[0]
                if prober.get_confidence() > self.ONE_CHAR_PROB:
                    self._m_best_guess_prober = prober

        # If we still don't have a good guess, we can try to guess the
        # encoding based on the language.
        if not self._m_best_guess_prober:
            if self._m_lang_filter & LanguageFilter.HUNGARIAN:
                # We have a Hungarian character, but we don't have a good
                # guess. We can try to guess the encoding based on the
                # language.
                prober = self._m_probers[0]
                if prober.get_confidence() > self.ONE_CHAR_PROB:
                    self._m_best_guess_prober = prober

        # If we still don't have a good guess, we can try to guess the
        # encoding based on the language.
        if not self._m_best_guess_prober:
            # We don't have a good guess, so we can't say anything about the
            # encoding.
            return {
                "encoding": None,
                "confidence": 0.0,
                "language": None,
            }

        return {
            "encoding": self._m_best_guess_prober.charset_name,
            "confidence": self._m_best_guess_prober.get_confidence(),
            "language": self._m_best_guess_prober.language,
        }
