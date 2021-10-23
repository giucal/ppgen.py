Changelog
=========

Relevant changes from version to version.

0.2.0
-----

  - Compute entropy properly
  - Add `--just` option for truncating words

0.1.0
-----

  - Rework `parse_charset()` almost from scratch
  - Handle empty `--randomize` charsets (by ignoring them)
  - Catch `--random` charset format error
  - Check lengths in `select()` and `Passphrase.random()`

WIP (0.0.1)
-----------

  - Remove unused function `char_range`
  - `common_charsets` -> `COMMON_CHARSETS`
  - Add `__version__`
  - Declare callable `main()` entry point
  - Don't call `exit()` from `main()`
  - Rename method and option 'intermix' to 'randomize'
  - Clarify documentation for `Passphrase.randomize()`
  - Replace `CharRange` class with an `ord_range` function
  - Make the `--randomize` option work
  - Correct getopt long-options specification
  - Remove check for unspecified `--entropy` abbreviation
  - Fix reference-before-assignment edge case in `select()`
  - Fix regex-like charset parsing in `parse_charset()`
  - Let 'translate' method and option support deletion
  - Replace `--intermix` with `--randomize` in usage
  - Support customization of the RNG
  - Ensure that a selection is always random
  - Remove unused argument from `Passphrase.randomize()`
  - Fix refactoring overlook
  - Replace overlooked `char_range()` with `ord_range()`
