"""Case-sensitive phrase matching over headline tokens.

A headline and every alias are split into the same word tokens (runs of letters
and digits; punctuation separates). An alias matches only where its exact token
sequence appears, with the same capitalisation, so "Carbon" never matches
"carbon" and "Edge" never matches "edge". Where two aliases overlap at one
position, the longer one wins, so "Palo Alto Networks" is read once.
"""
import re

TOKEN = re.compile(r"[0-9A-Za-z\u00c0-\u024f]+")


def tokens(value):
    return tuple(TOKEN.findall(value or ""))


def words(value):
    """The casefolded word set of a text, for context-word and term checks."""
    return {token.casefold() for token in tokens(value)}


class PhraseIndex:
    """Maps token sequences to the ids that carry them."""

    def __init__(self):
        self._by_first = {}
        self._ids = {}

    def add(self, phrase, ident):
        key = tokens(phrase)
        if not key:
            return False
        self._ids.setdefault(key, set()).add(ident)
        bucket = self._by_first.setdefault(key[0], set())
        bucket.add(key)
        return True

    def __len__(self):
        return len(self._ids)

    def find(self, text):
        """[(start, phrase tokens, sorted ids)] for every longest, non-overlapping match, left to right."""
        found, sequence, position = [], tokens(text), 0
        while position < len(sequence):
            best = None
            for key in self._by_first.get(sequence[position], ()):
                if sequence[position:position + len(key)] == key and (best is None or len(key) > len(best)
                                                                       or len(key) == len(best) and key < best):
                    best = key
            if best is None:
                position += 1
                continue
            found.append((position, best, sorted(self._ids[best])))
            position += len(best)
        return found


def term_pattern(terms):
    """A case-insensitive whole-word pattern for a list of plain terms (event, sector and region terms)."""
    ordered = sorted({term for term in terms if term}, key=lambda term: (-len(term), term))
    if not ordered:
        return None
    body = "|".join(re.escape(term).replace(r"\ ", r"[\s-]+") for term in ordered)
    return re.compile(r"(?<![0-9A-Za-z])(?:" + body + r")(?![0-9A-Za-z])", re.I)
