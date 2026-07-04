import itertools


LEET_MAP = {
    "a": ["a", "@", "4"],
    "i": ["i", "1", "!"],
    "e": ["e", "3"],
    "o": ["o", "0"],
    "s": ["s", "$", "5"],
}


def leet_transform(word: str):
    results = [""]

    for char in word:
        if char.lower() in LEET_MAP:
            replacements = LEET_MAP[char.lower()]
        else:
            replacements = [char]

        results = [prefix + r for prefix in results for r in replacements]

    return results


def mutate_with_years(word: str, years=None):
    if years is None:
        years = ["2024", "2025", "2026"]

    results = []

    for year in years:
        results.append(word + year)
        results.append(year + word)
        results.append(word + "_" + year)

    return results


def add_symbols(words):
    symbols = ["!", "@", "#", "$"]

    results = []

    for w in words:
        results.append(w)
        for s in symbols:
            results.append(w + s)
            results.append(s + w)

    return results


def generate_wordlist(seeds: list[str]):
    wordlist = set()

    for seed in seeds:
        seed = seed.lower()

        # base word
        wordlist.add(seed)

        # leetspeak
        wordlist.update(leet_transform(seed))

        # years mutation
        wordlist.update(mutate_with_years(seed))

    # symbols layer
    wordlist = add_symbols(list(wordlist))

    return sorted(wordlist)