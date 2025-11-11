"""
Public API for chardet
"""

from typing import IO, TYPE_CHECKING, Any, Dict, Optional, Union

from .charsetprober import CharSetProber
from .enums import LanguageFilter
from .universaldetector import UniversalDetector

if TYPE_CHECKING:
    from typing_extensions import TypeAlias

    # TODO: Use a TypeDict when our minimum supported Python version is 3.8
    ResultDict: TypeAlias = Dict[str, Optional[Union[str, float]]]


def detect(byte_str: Union[bytes, bytearray]) -> "ResultDict":
    """
    Detect the encoding of a byte string.

    :param byte_str: The byte string to check.
    """
    detector = UniversalDetector()
    detector.feed(byte_str)
    return detector.close()


def detect_all(
    byte_str: Union[bytes, bytearray], should_rename_legacy: bool = False
) -> list["ResultDict"]:
    """
    Detect all possible encodings for a byte string.

    :param byte_str: The byte string to check.
    :param should_rename_legacy: If ``True``, rename legacy encodings to their
                                 modern equivalents (e.g.  ``SHIFT_JIS``
                                 -> ``Shift_JIS``).
    """
    prober = CharSetProber(should_rename_legacy=should_rename_legacy)
    prober.feed(byte_str)
    return prober.close()


class ChardetResult(Dict[str, Any]):
    """
    A dictionary that is also accessible via attributes.

    This is for backwards-compatibility for anyone who was assuming the
    ``detect`` function returned an object.
    """

    def __getattr__(self, name: str) -> Any:
        try:
            return self[name]
        except KeyError as e:
            raise AttributeError(name) from e

    def __setattr__(self, name: str, value: Any) -> None:
        self[name] = value

    def __dir__(self) -> list[str]:
        return list(self.keys())


def detect_in_parallel(
    byte_str: Union[bytes, bytearray],
    language_filter: LanguageFilter = LanguageFilter.NONE,
) -> "ResultDict":
    """
    Detect the encoding of a byte string.

    This is a legacy API that is only kept for backwards-compatibility.
    It is recommended to use ``detect`` instead.

    :param byte_str: The byte string to check.
    :param language_filter: A language filter to apply.
    """
    detector = UniversalDetector(lang_filter=language_filter)
    detector.feed(byte_str)
    result = detector.close()
    # Backwards-compatibility with pre-2.0 chardet
    if result and result["encoding"] == "Big5":
        result["encoding"] = "Big5"
    return ChardetResult(result)


def detect_from_file(f: IO[bytes]) -> "ResultDict":
    """
    Detect the encoding of a file.

    :param f: A file-like object to check.
    """
    detector = UniversalDetector()
    for line in f:
        detector.feed(line)
        if detector.done:
            break
    return detector.close()
