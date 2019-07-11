# Changelog
All notable changes to this project will be documented in this file.
This project adheres to [Semantic Versioning](http://semver.org/).

## [Unreleased]
### Added
- Parallelization for OMEN+
- Incorporation of feedback based learning into OMEN
- Refactoring of the sorting algorithm for the n-grams (cpp std library sort?)
- Internal processing uses UTF-32 ([Issue #1](https://github.com/RUB-SysSec/OMEN/issues/1))
- Allow running from other directories ([Issue #2](https://github.com/RUB-SysSec/OMEN/issues/2))
- Allow resuming from a specific point ([Issue #3](https://github.com/RUB-SysSec/OMEN/issues/3))

## [0.3.2] - 2018-12-25
### Fixed
- `enumNG`: Fixed overflow in `--maxattempts` (`-m`) option. Changed the data type for the argument parsing via *GNU Gengetopt* from `int` to `longlong` to allow 1 to 10^15 guesses.

## [0.3.1] - 2017-06-07
### Fixed
- `alphabetCreator`: Allow missing `-a` option, defaulting to `/dev/null`
- Updated README and CHANGELOG

## [0.3.0] - 2016-07-21
### Added
- Modus OMEN+: boost hints and enumerate based on modified levels
- Input format for usage of OMEN+:
  - `hint-file`: new line separated lines containing tab separated additional information attributes, each line has to have the same attribute order
  - `alpha-file`: tab separated alpha values for each additional information attribute, alphas has to be integers

## [0.2.0] - 2016-01-31
### Added
- Use more standard headers (`stdbool.h` and `inttypes.h`)
- Replace argumentInterpreter by auto-generated parser from the *GNU getopt* tool
- Change project directory structure
- Add version numbers
- Add README
- Solve bug with results folder, and remove its subfolders
- defines.h to remove dependency circles
- Increase maximum attempts of guesses to 10^15
- Adjust default settings (change default n-gram size to 4, and adjust smoothing parameters)

## [0.1.0] - 2013-05-22
### Added
- Initial version for OMEN
- Main modules: training (`createNG`) and enumeration (`enumNG`)
- Utility modules: `alphabetCreator` and `evalPW`
