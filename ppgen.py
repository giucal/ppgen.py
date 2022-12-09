#!/usr/bin/env python3

"""
Passphrase generation module and command.

Author:  Giuseppe Calabrese
Copying: Public Domain
"""

from secrets import randbelow  # Our default CSPRNG.
from math import log2
from re import fullmatch, findall

__version__ = "0.5.0"


def select(source, n, randbelow=randbelow):
    """
    Randomly select, on-line, from an iterable of unknown length.

    "On-line" means that the iterable is not enumerated upfront;
    rather, the selection is drawn during iteration.

    Take:
        source      a (finite) iterable that provides the elements
        n           the number of elements to select
        randbelow   a random integer generator (default: secrets.randbelow)

    The `randbelow` argument must be a function that accepts a positive
    integer `n` and returns a random integer in the range [0, `n`).

    Return the selection (as a list) and the number of iterated elements.
    """
    if n < 0:
        raise ValueError("selection size must be non-negative")
    if n == 0:
        return [], 0

    source = iter(source)

    # Provisional selection.
    try:
        head = [next(source) for _ in range(n)]
    except StopIteration:
        raise RuntimeError("source was too short")
    selection = [head.pop(randbelow(len(head))) for _ in range(n)]

    # Maintain a random selection as we go over the source.
    i = n - 1
    for i, el in enumerate(source, n):
        r = randbelow(i)
        if r < n:
            selection[r] = el

    return selection, i + 1


def dictionary(path, encoding=None):
    """
    Create an iterator from a dictionary file.

    Take:
        path     the path of a dictionary file, listing a set of
                 words one per line
        encoding the text encoding of the file; None (default)
                 means that the encoding depends on the current
                 locale

    A generator yielding each line of the dictionary file, with
    whitespace strip()ed.
    """
    with open(path, "rt", encoding=encoding) as f:
        for line in f:
            yield line.strip()


class Passphrase(list):
    """
    A passphrase builder.
    """

    def __init__(self, words, randbelow=randbelow):
        super().__init__(list(w) for w in words)
        self._randbelow = randbelow

    @classmethod
    def random(cls, dictionary, length, randbelow=randbelow):
        """
        Generate a random passphrase.

        Take:
            dictionary  an iterable of words
            length      the passphrase length

        Return a passphrase made of a random selection of words,
        and its entropy.
        """
        if length <= 0:
            raise ValueError("passphrase length must be positive")

        words, space = select(dictionary, length, randbelow)
        entropy = sum(log2(n) for n in range(space, space - length, -1))
        return Passphrase(words, randbelow), entropy

    def replace(self, i, replacement):
        """
        Replace a word.

        Take:
            i               the index of the word to replace
            replacement     the replacement function (or word)

        The `replacement` argument should either be a word, or a callable that
        takes a word and returns a replacement.

        Return self.
        """
        if callable(replacement):
            self[i] = list(replacement("".join(self[i])))
        else:
            self[i] = list(replacement)
        return self

    def capitalize(self, i=0):
        """
        Capitalize the first letter of the i-th word.

        Return self.
        """
        return self.replace(i, str.title)

    def case_fold(self):
        """
        Down-case all letters.
        """
        for i in range(len(self)):
            self[i] = [c.lower() for c in self[i]]
        return self

    def shorten_each(self, max_length):
        """
        Shorten words.

        Take:
            max_length  maximum word length

        Truncate words to `max_length` characters (if they are longer).

        Return self.
        """
        for i in range(len(self)):
            self[i] = self[i][:max_length]
        return self

    def randomize(self, charsets):
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
            if not cs:
                continue
            c = cs[self._randbelow(len(cs))]
            while True:
                i = self._randbelow(len(self))
                j = self._randbelow(len(self[i]))
                if (i, j) not in replacements:
                    break
            self[i][j] = c
            replacements.add((i, j))

        return self

    def translate(self, table):
        """
        Apply a translation to all the words.

        Same arguments and semantics as str.translate().

        Return self.
        """
        for i in range(len(self)):
            self[i] = list("".join(self[i]).translate(table))
        return self

    def join(self, separator=" "):
        """
        Join the words of this passphrase.

        Take:
            separator   a str-like object to separate words (default is space)

        Return a byte-string.
        """
        return separator.join("".join(w) for w in self)


def char_range(first, last):
    """
    A bounds-included range of characters.

    Take:
        first   the first character in the range
        last    the last character in the range

    Return a generator of the characters from `first` to `last` inclusive.
    """
    return (chr(i) for i in range(ord(first), ord(last) + 1))


# Predefined charsets.
CHARSETS_TAGS = {
    "d": set(char_range("0", "9")),
    "u": set(char_range("A", "Z")),
    "l": set(char_range("a", "z")),
    "s": set().union(
        char_range("!", "/"),
        char_range(":", "@"),
        char_range("[", "`"),
        char_range("{", "~"),
    ),
}


def parse_charset(expr):
    """
    Parse a charset expression.

    A charset expression can contain two forms of charset specifications:
    unions and enumerations.

    Formally:

        <charset> -> [ <union> ] [ <enum> [ <union> ] ]

    At most one enumeration can appear in a given expression (because it
    is matched greedily; see below).

    Unions
    ------

    A union is a juxtaposition of any of the predefined charsets' tags:

      | Charset                  | Tag |
      | ------------------------ | --- |
      | decimal digits           | `d` |
      | ASCII upper-case letters | `u` |
      | ASCII lower-case letters | `l` |
      | ASCII symbols            | `s` |

    Formally:

        <union> -> ( "d" | "u" | "l" | "s" ) ...

    Enumerations
    ------------

    An enumeration is a regex-like set, e.g. `[0-9A-Z-.@!?]`.

    Formally:

        <enumeration> -> "[" ( <range> | <character> ) ... "]"
        <range>       -> <character> "-" <character>
        <character>   -> any character

    The only special character is the dash.

    A `<character>` can also be a dash or square bracket.

    The closing bracket is the right-most one in `expr`. This allows for
    square brackets inside the enumeration without the need for an escaping
    scheme.

    An enumeration is matched as a sequence of adjacent `<range>`s,
    left to right; falling back to matching a single `<character>` only if
    and when that should fail (and then reverting to matching ranges again).

    Return the represented charset.
    """
    charset = set()

    if not expr:
        return charset

    if expr[0] == "[":
        # Parse an enumeration.
        try:
            spec, rest = expr[1:].rsplit("]", 1)
        except ValueError:
            raise ValueError("bad charset specification: %s" % expr)

        if rest:
            charset.update(parse_charset(rest))

        for sub in findall(r"[^-]-[^-]|.", spec):
            if len(sub) == 1:
                charset.add(sub)
            else:
                charset.update(char_range(*sub.split("-")))

        return charset

    # Parse a union.
    for i, tag in enumerate(expr):
        if tag == "[":
            return charset.union(parse_charset(expr[i:]))
        try:
            charset.update(CHARSETS_TAGS[tag])
        except KeyError as e:
            raise ValueError("unknown charset tag: %s" % e.args)

    return charset


def main():
    from getopt import getopt, GetoptError
    from os.path import basename
    from sys import argv, stderr

    def usage(msg=None):
        print("Usage: %s [-h] [options] <length>" % basename(argv[0]))

        if msg:
            print("Error: %s" % msg, file=stderr)
        else:
            print(
                "\nRandom passphrase generator."
                "\n"
                "\nOptions:"
                "\n    -C --capitalize              capitalize the first character (if applicable)"
                "\n    -F --case-fold               down-case all letters to begin with"
                "\n    -W --word-length=<n>         take just <n> characters per word"
                "\n    -R --randomize=<charset>     swap random character with another from <charset>"
                "\n    -T --translate=<xs>:<ys>     translate corresponding characters of <xs> to <ys>"
                "\n    -E --least-entropy=<H>       require at least <H> bits of entropy"
                "\n    -s --separator=<string>      separate words with <string> (default: space)"
                "\n    -f --file=<dictionary-file>  draw words from <dictionary-file>"
                "\n    -h --help                    print this message",
                file=stderr
            )
        return 2

    def error(msg, exit_status=1):
        print("Error: %s" % msg, file=stderr)
        return exit_status

    source = dictionary("/usr/share/dict/words", "UTF-8")
    capitalize = False
    case_fold = False
    randomize = []
    least_entropy = 0
    translate = {}
    separator = " "
    max_word_length = False

    try:
        options, positionals = getopt(
            argv[1:],
            "CFW:R:T:E:s:f:h",
            (
                "capitalize",
                "case-fold",
                "word-length=",
                "randomize=",
                "translate=",
                "least-entropy=",
                "separator=",
                "file=",
                "help",
            ),
        )
    except GetoptError as err:
        return error(err, 2)

    for flag, arg in options:
        if flag in ("-h", "--help"):
            return usage()

        if flag in ("-f", "--file"):
            source = dictionary(arg)

        elif flag in ("-C", "--capitalize"):
            capitalize = True

        elif flag in ("-F", "--case-fold"):
            case_fold = True

        elif flag in ("-W", "--word-length"):
            try:
                max_word_length = int(arg)
            except ValueError:
                return error("%s: not a length: %s" % (flag, arg))
            if max_word_length <= 0:
                return error("%s: illegal maximum word length: %s <= 0" % (flag, arg))

        elif flag in ("-R", "--randomize"):
            try:
                cs = parse_charset(arg)
            except ValueError as e:
                return error("%s: %s" % (flag, *e.args))
            randomize.append(tuple(cs))

        elif flag in ("-s", "--separator"):
            separator = arg

        elif flag in ("-T", "--translate"):
            xs, ys = arg.split(":", 1)
            if len(xs) < len(ys):
                return error("%s: characters in <ys> outnumber <xs>" % flag)
            for x, y in zip(xs, ys):
                translate[ord(x)] = y
            for x in xs[len(ys):]:
                translate[ord(x)] = None

        elif flag in ("-E", "--least-entropy"):
            try:
                least_entropy = float(arg)
            except ValueError:
                return error("%s: bad entropy value: %s" % (flag, arg))

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

    if max_word_length:
        pp.shorten_each(max_word_length)
    if case_fold:
        pp.case_fold()
    pp.translate(translate)
    if randomize:
        pp.randomize(randomize)
    if capitalize:
        pp.capitalize()

    print(pp.join(separator))


if __name__ == "__main__":
    from sys import exit

    exit(main())
