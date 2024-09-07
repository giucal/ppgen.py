ppgen
=====

A passphrase generation module and command.

Usage
-----

The simplest usage is:

    ppgen <length>

Example:

    % ppgen 6
    solanum stokehold cowpea firmisternous cockbird dionymal

(We'll use the same words over again to emphasize the differences between
the various invocations.)

### Checks

One check is currently supported: that of least entropy.

**Least entropy.**
To ensure that the generated passphrase contains at least a minimum bits of
entropy:

    -E<min-allowed-entropy>
    --least-entropy=<min-allowed-entropy>

The length argument is nevertheless *required*. Ppgen will simply check that the
entropy bound is satisfied, given the provided length and dictionary size.
If the bound is not satisfied, ppgen will terminate with an error and will not
output any passphrase.

Examples:

    # Assuming a /usr/share/dict/words of 235886 words...
    % wc /usr/share/dict/words
      235886  235886 2493109 /usr/share/dict/words

    % ppgen -E90 5
    Error: insufficient entropy (89.238590 < 90.000000): generate a longer passphrase or use a bigger dictionary

    % ppgen -E90 6
    solanum stokehold cowpea firmisternous cockbird dionymal

### Transformations

Transformations alter the passphrase, deterministically or randomly.

**Capitalize.**
To capitalize the first letter of the first word:

    -C
    --capitalize

Example:

    % ppgen -C 6
    Solanum stokehold cowpea firmisternous cockbird dionymal

**Randomize.**
To randomize one character in a random position, specifying from which
charset it is to be re-drawn:

    -R<charset>
    --randomize=<charset>

The `<charset>` argument is a combination of:

  - *one* optional regex-like charset, e.g. `[0-9A-F]`, surrounded by
  - unions of the predefined charsets

      | Charset                  | Tag |
      | ------------------------ | --- |
      | decimal digits           | `d` |
      | ASCII upper-case letters | `u` |
      | ASCII lower-case letters | `l` |
      | ASCII symbols            | `s` |

    expressed as concatenations of their tags, e.g. `duls`.

Examples:

Randomize with one printable, non-blank, ASCII character.

    % ppgen -Rduls 6
    solanum stokehold cowpea firmisternous cockbird dionymFl
                                                          ^

(The indicator is added for the sake of the reader.)

Randomize with two printable, non-blank, ASCII characters.

    % ppgen -Rduls -Rduls 6
    s5lanum stokehold cowpea firmisternous c2ckbird dionymal
     ^                                      ^

(They both happened to be digits.)

Randomize with a digit, an upper-case letter, and a symbol.

    % ppgen -Rd -Ru -Rs 6
    solanum stokehold cowpea firmiUternous cockbird di/ny9al
                                  ^                   ^  ^

This is a typical password requirement.

Randomize with the characters "`.,?!@_-#`" (and only these).

    % ppgen '-R[-.,?!@_#]' 6
    solanum stokehold cowpea firmisternous cockbird !ionymal
                                                    ^

Again, this is a typical requirement (if utterly idiotic in its arbitrary
strictness).

Note two things. We single-quote the argument to make it opaque to the
shell. Otherwise, we might get errors like:

    -bash: !@_#]: event not found

Or worse, unexpected behaviour.

We also put the dash, `-`, first in the charset, to avoid confusion as to
whether it carries the special meaning of range operator, as e.g. in `[A-Z]`.

To be precise, the syntax for a regex-like charset is:

    <enumeration> -> "[" (<range> | <character>) ... "]"
    <range>       -> <character> "-" <character>
    <character>   -> any character that the shell lets through

So `<character>` can also be a dash or a square bracket. How?

  - Ppgen tries to match zero or more adjacent `<range>`s, left to right,
    optionally intermixed with `<character>`s.

    In general, a dash appearing where it cannot be interpreted as an operator
    stands for itself.

    So, for example, `[----]` represents, literally, the characters from `-` to
    `-`, plus the `-` character; while `[-a-z]` and `[a-z-]` both represent the
    character `-` plus the ASCII lower-case letters.

  - Given a `<charset>` expression, `<enumeration>`s are matched greedily, so at
    most one of them can appear per expression (the upside being that they can
    contain square brackets without any escaping).

**Translate.**
To apply deterministic substitutions:

    -T<xs>:<ys>
    --translate=<xs>:<ys>

Each character of `<xs>` will be replaced with the corresponding character
of `<ys>`. Surplus characters, which do not have an image in `<ys>`, will be
deleted.

Examples:

    % ppgen -Tabc:XYZ 6
    solXnum stokehold ZowpeX firmisternous ZoZkYird dionymXl
       ^              ^    ^               ^ ^ ^          ^

    % ppgen -Talet:@137 6
    so1@num s7ok3ho1d cowp3@ firmis73rnous cockbird dionym@1
      ^^     ^  ^  ^      ^^       ^^                     ^^

    % ppgen -Thate:love -Twar: 6
    solnum svokelold cope fimisvenous cockbid dionyml
       a    ^   ^      w a  r  ^ r          r       a

(Missing characters have been indicated under their old word-wise position.)

**Shorten words.**
To take just the first `<n>` characters of each word:

    -W<n>
    --word-length=<n>

Example:

    % ppgen -W4 6
    sola stok cowp firm cock dion

### Presentation

To use a given character (or string) `<sep>` as word separator:

    -s<sep>
    --separator=<sep>

Example:

    % ppgen -s- 6
    solanum-stokehold-cowpea-firmisternous-cockbird-dionymal

### Dictionary

To choose a different dictionary file:

    -f<dictionary>
    --file=<dictionary>

The `<dictionary>` argument should point to a file containing one word
per line. The file will be processed on-line, hence it can be a non-seekable
stream, and have any finite length.

Installation
------------

With `pipx`:

    pipx install git+https://github.com/giucal/ppgen.py

With `pip`:

    pip3 install --user git+https://github.com/giucal/ppgen.py
