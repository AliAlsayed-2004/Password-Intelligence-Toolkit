import hashlib


def generate_hash(text: str, algorithm: str = "sha256"):

    text = text.encode()

    if algorithm == "md5":
        return hashlib.md5(text).hexdigest()

    elif algorithm == "sha1":
        return hashlib.sha1(text).hexdigest()

    elif algorithm == "sha224":
        return hashlib.sha224(text).hexdigest()

    elif algorithm == "sha256":
        return hashlib.sha256(text).hexdigest()

    elif algorithm == "sha384":
        return hashlib.sha384(text).hexdigest()

    elif algorithm == "sha512":
        return hashlib.sha512(text).hexdigest()

    else:
        raise ValueError("Unsupported algorithm")


def verify_hash(text: str, hash_value: str, algorithm: str = "sha256"):
    return generate_hash(text, algorithm) == hash_value