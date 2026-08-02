# Contributing

Thanks for looking at this. It's a small, single-purpose tool and contributions are welcome.

## Setup

```
git clone https://github.com/munzzyy/sessionxray
cd sessionxray
```

There's nothing to install. sessionxray is pure standard library, and so is its test suite.

## Running the tests

```
python -m unittest discover -s tests -t .
```

That's the whole suite: unit tests per rule, engine tests, and a labeled corpus in `tests/fixtures/`. CI runs the same command across Linux, macOS, and Windows on Python 3.9 through 3.13.

## Adding or fixing a rule

Every rule change lands with a fixture, so coverage only goes up:

- Something worrying slipped through? Add a transcript under `tests/fixtures/malicious/`. The corpus test asserts every malicious fixture gets at least a HIGH finding and a D or F grade.
- A false positive on ordinary agent behavior? Add a clean transcript under `tests/fixtures/benign/`. The corpus test asserts every benign fixture stays free of HIGH/CRITICAL findings and grades A or B.

If you fix a bug with no fixture attached, it can silently come back. A fixture is how the fix stays fixed.

Keep rules specific. A pattern that fires on ordinary tool use is worse than one that misses an edge case, because noise trains people to ignore the tool.

The two corpora pull against each other on purpose. Recall is guarded by `tests/fixtures/malicious/` and precision by `tests/fixtures/benign/`, and neither floor may be lowered to make a change pass. If a rule change makes a malicious fixture grade too lenient, the change is wrong. If it makes a benign fixture go loud, add the case you actually meant to catch and narrow the pattern. `tests/test_corpus.py` also tracks the benign corpus as a number (how many fixtures, how many MEDIUMs) so a slow slide shows up before a fixture flips.

The README's two example blocks are real output over these fixtures, and `tests/test_readme.py` regenerates them. Change a rule and that test tells you the docs went stale.

## Zero dependencies

sessionxray has no runtime dependencies and that's a feature. If a change needs a new package, that's a reason to reconsider the change, not a to-do.

## License

By opening a PR you agree your contribution is offered under the project's MIT license.
