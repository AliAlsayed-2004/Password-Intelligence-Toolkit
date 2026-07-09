import itertools


LEET_MAP = {
    "a": ["a", "@", "4"],
    "i": ["i", "1", "!"],
    "e": ["e", "3"],
    "o": ["o", "0"],
    "s": ["s", "$", "5"],
}

# Common numeric suffixes people actually append to passwords, on top of
# plain years. Based on well-documented patterns from breach analyses
# (sequential digits, repeated digits, "leet" numbers, short PINs).
COMMON_NUMERIC_SUFFIXES = [
    "1", "12", "123", "1234", "12345",
    "01", "007", "69", "99", "00",
]

COMMON_SYMBOLS = ["!", "@", "#", "$", "*"]


def leet_transform(word: str):
    results = [""]

    for char in word:
        if char.lower() in LEET_MAP:
            replacements = LEET_MAP[char.lower()]
        else:
            replacements = [char]

        results = [prefix + r for prefix in results for r in replacements]

    return results


def case_variations(word: str):
    """Common capitalization patterns people use: all lower, all upper,
    Capitalized, and toggle-case (aLTERNATING is rare enough to skip)."""
    if not word:
        return [word]
    variants = {word.lower(), word.upper(), word.capitalize()}
    return list(variants)


def mutate_with_years(word: str, years=None):
    if years is None:
        years = ["2024", "2025", "2026"]

    results = []

    for year in years:
        results.append(word + year)
        results.append(year + word)
        results.append(word + "_" + year)

    return results


def mutate_with_numeric_suffixes(word: str, suffixes=None):
    """Append/prepend common numeric patterns (birth-year-independent),
    e.g. word+123, word+007, 99+word."""
    if suffixes is None:
        suffixes = COMMON_NUMERIC_SUFFIXES

    results = []
    for suf in suffixes:
        results.append(word + suf)
        results.append(suf + word)
    return results


def add_symbols(words, symbols=None):
    if symbols is None:
        symbols = COMMON_SYMBOLS

    results = []

    for w in words:
        results.append(w)
        for s in symbols:
            results.append(w + s)
            results.append(s + w)

    return results


def combine_seeds(seeds: list[str]):
    """Combine pairs of seed words the way people actually build passwords
    from OSINT-gathered info, e.g. first name + last name, name + initial.
    Given ["john", "doe"] this produces things like "johndoe", "doejohn",
    "john.doe", "johnd", "jdoe".
    """
    cleaned = [s.strip().lower() for s in seeds if s.strip()]
    if len(cleaned) < 2:
        return []

    results = set()
    for a, b in itertools.permutations(cleaned, 2):
        results.add(a + b)
        results.add(a + "." + b)
        results.add(a + "_" + b)
        results.add(a + "-" + b)
        if b:
            results.add(a + b[0])   # john + d
        if a:
            results.add(a[0] + b)   # j + doe
    return list(results)


def generate_wordlist(
    seeds: list[str],
    combine: bool = True,
    case_variants: bool = True,
    min_length: int = None,
    max_length: int = None,
):
    """Generate a mutated wordlist from one or more seed words.

    Args:
        seeds: seed words (names, pet names, dates-as-strings, etc.)
        combine: when 2+ seeds are given, also generate pairwise
            combinations (firstname+lastname style) -- this is the biggest
            lever for realistic OSINT-driven wordlists.
        case_variants: also generate common capitalization patterns.
        min_length / max_length: filter final results by length (useful
            when the target has a known minimum/maximum password policy).
    """
    wordlist = set()
    base_words = [s.strip().lower() for s in seeds if s.strip()]

    for seed in base_words:
        wordlist.add(seed)
        wordlist.update(leet_transform(seed))
        wordlist.update(mutate_with_years(seed))
        wordlist.update(mutate_with_numeric_suffixes(seed))
        if case_variants:
            for variant in case_variations(seed):
                wordlist.add(variant)

    if combine and len(base_words) >= 2:
        combined = combine_seeds(base_words)
        wordlist.update(combined)
        for c in combined:
            wordlist.update(mutate_with_years(c))
            if case_variants:
                for variant in case_variations(c):
                    wordlist.add(variant)

    # symbols layer applied last, on top of everything generated so far
    wordlist = set(add_symbols(list(wordlist)))

    if min_length is not None:
        wordlist = {w for w in wordlist if len(w) >= min_length}
    if max_length is not None:
        wordlist = {w for w in wordlist if len(w) <= max_length}

    return sorted(wordlist)


def save_wordlist(words: list[str], path: str) -> int:
    """Write a wordlist to disk, one candidate per line -- directly
    consumable by hashcat (-a 0) or John the Ripper (--wordlist=). Returns
    the number of lines written."""
    with open(path, "w", encoding="utf-8") as f:
        for w in words:
            f.write(w + "\n")
    return len(words)