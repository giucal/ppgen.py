#!/usr/bin/env python3

"""
Passphrase generation module and command.

Author:  Giuseppe Calabrese
Copying: Public Domain
"""

from secrets import randbelow  # Our CSPRNG.
from math import log2
from re import fullmatch, findall

__version__ = "0.0.1"


def select(source, n):
    """
    Randomly select, on-line, from an iterable of unknown length.

    "On-line" means that the iterable is not enumerated upfront;
    rather, the selection is drawn during iteration.

    Take:
        source  a (finite) iterable that provides the elements
        n       the number of elements to select

    Return the selection (as a list) and the number of iterated elements.
    """
    # Provisional selection.
    selection = [next(source) for _ in range(n)]

    # Maintain a random selection as we go over the source.
    for i, el in enumerate(source, n):
        r = randbelow(i)
        if r < n:
            selection[r] = el

    return selection, i + 1


def dictionary(path):
    """
    Create an iterator from a dictionary file.

    Take:
        path    the path of a dictionary file, listing a set of
                words one per line

    A generator yielding each line of the dictionary file, with
    whitespace strip()ed.
    """
    with open(path, "rb") as f:
        for line in f:
            yield line.strip()


class Passphrase(list):
    """
    A passphrase builder.
    """

    def __init__(self, words):
        super().__init__(bytearray(w) for w in words)

    @classmethod
    def random(cls, dictionary, length):
        """
        Generate a random passphrase.

        Take:
            dictionary  an iterable of words
            length      the passphrase length

        Return a passphrase made of a random selection of words,
        and its entropy.
        """
        words, space = select(dictionary, length)
        return Passphrase(words), log2(space) * length

    def replace(self, i, replacement):
        """
        Replace a word.

        Take:
            i               the index of the word to replace
            replacement     the replacement function (or word)

        The `replacement` argument should either be a word or a callable, i.e.
        a function of the generic word or a constant function `lambda _: const`.

        Return self.
        """
        w = replacement(self[i]) if callable(replacement) else replacement
        self[i] = w
        return self

    def capitalize(self, i=0):
        """
        Capitalize the first letter of the i-th word.

        Return self.
        """
        return self.replace(i, bytearray.title)

    def randomize(self, charsets, keep_if_complies=False):
        """
        Swap characters at random positions with characters from the given
        charsets (without replacement).

        Take:
            charsets    an iterable of sequences of characters

        Honor charsets multiplicity; that is, swap a charset as many
        times as it appears in `charsets`.

        This method can be used to satisfy rigid password policies,
        or to defeat dictionary attacks even in the case of short
        passphrases.

        Return self.
        """
        replacements = set()
        for cs in charsets:
            c = cs[randbelow(len(cs))]
            while True:
                i = randbelow(len(self))
                j = randbelow(len(self[i]))
                if (i, j) not in replacements:
                    break
            self[i][j] = c
            replacements.add((i, j))

        return self

    def translate(self, table):
        """
        Apply a translation to all the words.

        Same arguments and semantics as bytearray.translate().

        Return self.
        """
        for i in range(len(self)):
            self[i] = self[i].translate(table)
        return self

    def join(self, separator=b" "):
        """
        Joins the words of this passphrase.

        Take:
            separator   a str-like object to separate words (default is space)

        Return a byte-string.
        """
        return bytes(separator).join(self)


class CharRange:
    """
    A character range.
    """

    def __init__(self, first, last):
        self.ord_range = range(ord(first), ord(last) + 1)
        self.start = self.first = first
        self.stop = chr(ord(last) + 1)
        self.last = last

    def __iter__(self):
        return (chr(i) for i in self.ord_range)


# Predefined charsets.
COMMON_CHARSETS = {
    "d": set(CharRange("0", "9")),
    "u": set(CharRange("A", "Z")),
    "l": set(CharRange("a", "z")),
    "s": set().union(
        CharRange("!", "/"),
        CharRange(":", "@"),
        CharRange("[", "`"),
        CharRange("{", "~"),
    )
}


def parse_charset(expr):
    """
    Parse a charset expression.

    An expression can be of two forms:

      - A regexp-like set (e.g. [-.?!0-9], which represents the set
        {'-', '.', '?', '!', '0', ..., '9'}).
      - A combination of the four letters 'd', 'u', 'l', and 's',
        which represent, respectively,
          - decimal digits,
          - ASCII upper-case letters,
          - ASCII lower-case letters, and
          - ASCII symbols.

    Return the represented charset.
    """
    if expr[0] == "[":
        # Parse a charset spec, e.g. [-.?!0-9].
        spec, unexpected = expr[1:].split("]", 1)
        if unexpected:
            raise ValueError(
                "unexpected content after closing ']': '%s'", empty
            )

        if not fullmatch(r"-?([^-]-[^-]|[^-])*"):
            raise ValueError("bad charset spec: %s" % spec)

        chars = set()
        for sub in findall(r"[^-]-[^-]|[^-]|-", spec):
            if len(sub) == 1:
                chars.add(sub)
            else:
                chars.update(char_range(*sub.split("-")))

        return tuple(chars)

    # Parse a charset union, e.g. 'ds'.
    try:
        return tuple(set().union(list(COMMON_CHARSETS[c]) for c in expr))
    except KeyError as e:
        raise ValueError("unknown charset: %s" % e.args)


def main():
    from getopt import getopt
    from os.path import basename
    from sys import argv, stderr

    def usage(msg=None):
        print("Usage: %s [-h] [options] <length>" % basename(__file__))

        if msg:
            print("Error: %s" % msg, file=stderr)
        else:
            print(
                "\nOptions:"
                "\n    -C --capitalize              capitalize the first character (if applicable)"
                "\n    -I --intermix=<charset>      intermix the given charset"
                "\n    -S --separator=<string>      separate words with <string> (default: space)"
                "\n    -T --translate=<xs>:<ys>     translate corresponding characters of <xs> to <ys>"
                "\n    -E --least-entropy=<H>       require at least <H> bits of entropy"
                "\n    -f --file=<dictionary-file>  draw words from <dictionary-file>"
                "\n    -h --help                    print this message",
                file=stderr
            )
        return 2

    def error(msg, exit_status=1):
        print("Error: %s" % msg, file=stderr)
        return exit_status

    source = dictionary("/usr/share/dict/words")
    capitalize = False
    randomize = []
    least_entropy = 0
    translate = bytearray(range(256))
    separator = b" "

    options, positionals = getopt(
        argv[1:],
        "CR:S:T:E:f:h",
        (
            "--capitalize",
            "--randomize=",
            "--separator=",
            "--translate="
            "--least-entropy=",
            "--file=",
            "--help",
        ),
    )

    for flag, arg in options:
        if flag in ("-h", "--help"):
            return usage()

        if flag in ("-f", "--file"):
            source = dictionary(arg)

        elif flag in ("-C", "--capitalize"):
            capitalize = True

        elif flag in ("-R", "--randomize"):
            randomize.append(parse_charset(arg))

        elif flag in ("-S", "--separator"):
            separator = arg.encode("UTF-8")

        elif flag in ("-T", "--translate"):
            chars, repls = arg.split(":", 1)
            if len(chars) != len(repls):
                return error("unbalanced mapping: %s", arg)
            for i in range(len(chars)):
                translate[ord(chars[i])] = ord(repls[i])

        elif flag in ("-E", "--entropy", "--least-entropy"):
            try:
                least_entropy = float(arg)
            except ValueError:
                return error("bad entropy value: %s" % arg)

    if len(positionals) != 1:
        return usage()
    try:
        length = int(positionals[0])
    except ValueError:
        return error("invalid length: %s" % v)
    if length < 1:
        return error("length must be positive")

    pp, entropy = Passphrase.random(source, length)

    if entropy < least_entropy:
        return error(
            "insufficient entropy (%f < %f): "
            "generate a longer passphrase or use a bigger dictionary"
            % (entropy, least_entropy)
        )

    pp.translate(translate)
    if randomize:
        print(randomize)
        pp.randomize(randomize)
    if capitalize:
        pp.capitalize()

    print(pp.join(separator).decode())


if __name__ == "__main__":
    from sys import exit

    exit(main())
