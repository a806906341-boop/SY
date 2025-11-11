"""
All of the Enums that are used throughout the chardet package.
"""

from enum import Enum, Flag, auto


class InputState:
    """
    This enum represents the different states a state machine can be in.
    """

    PURE_ASCII = 0
    ESC_ASCII = 1
    HIGH_BYTE = 2


class LanguageFilter(Flag):
    """
    This enum represents the different language filters that can be applied to
    the universal character set detector.
    """

    NONE = auto()
    CHINESE_SIMPLIFIED = auto()
    CHINESE_TRADITIONAL = auto()
    JAPANESE = auto()
    KOREAN = auto()
    BULGARIAN = auto()
    RUSSIAN = auto()
    GREEK = auto()
    HEBREW = auto()
    TURKISH = auto()
    THAI = auto()
    HUNGARIAN = auto()
    ALL = (
        CHINESE_SIMPLIFIED
        | CHINESE_TRADITIONAL
        | JAPANESE
        | KOREAN
        | BULGARIAN
        | RUSSIAN
        | GREEK
        | HEBREW
        | TURKISH
        | THAI
        | HUNGARIAN
    )
    CHINESE = CHINESE_SIMPLIFIED | CHINESE_TRADITIONAL
    CJK = CHINESE | JAPANESE | KOREAN


class ProbingState(Enum):
    """
    This enum represents the different states a prober can be in.
    """

    DETECTING = auto()  # No sure answer yet, but still detecting.
    FOUND_IT = auto()  # That prober has found a result that it is sure of.
    NOT_ME = auto()  # That prober is sure that the text is not in its charset.


class MachineState:
    """
    This enum represents the different states a state machine can be in.
    """

    START = 0
    ME = 1
    ERROR = 2


class SequenceLikelihood:
    """
    This enum represents the likelihood of a character following the previous one.
    """

    NEGATIVE = 0
    UNLIKELY = 1
    LIKELY = 2
    POSITIVE = 3

    @classmethod
    def get_num_categories(cls) -> int:
        """
        The number of likelihood categories we have.
        """
        return 4


class CharacterCategory:
    """
    This enum represents the different categories a character can be in.
    """

    UNDEFINED = 255
    LINE_BREAK = 254
    SYMBOL = 253
    DIGIT = 252
    CONTROL = 251
