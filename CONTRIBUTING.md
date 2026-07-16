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

## Zero dependencies

sessionxray has no runtime dependencies and that's a feature. If a change needs a new package, that's a reason to reconsider the change, not a to-do.

## License

By opening a PR you agree your contribution is offered under the project's MIT license.
