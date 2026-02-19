---
status: "accepted"
date: 2025-02-06
decision-makers: Patrick Fenerty
---

# Use caarlos0/env for Configuration Management

## Context and Problem Statement

OCIDex needs to load configuration from environment variables with defaults, required field validation, and type safety. Which library should we use?

## Decision Drivers

* Zero or minimal dependencies
* Struct-based declarative configuration
* Support for defaults, required fields, and type conversion
* Small, focused library — not a multi-source config framework
* Actively maintained

## Considered Options

* Raw os.Getenv
* caarlos0/env
* kelseyhightower/envconfig
* spf13/viper
* knadh/koanf

## Decision Outcome

Chosen option: "caarlos0/env", because it is zero-dependency, actively maintained, and provides declarative struct tags with defaults and required support via a single-call API (`env.Parse(&cfg)`). It does one thing well.

### Consequences

* Good, because zero transitive dependencies
* Good, because declarative struct tags (`env:"VAR"`, `envDefault:"value"`)
* Good, because `required` tag support
* Good, because actively maintained by a well-known Go maintainer
* Good, because minimal API surface — `env.Parse(&cfg)` is the entire interface
* Neutral, because no built-in validation beyond `required` — pair with custom validation if needed
* Bad, because adds one module dependency for something achievable with raw `os.Getenv`

### Confirmation

Confirmed by verifying all configuration is loaded through a single `config.Load()` function that calls `env.Parse` on a config struct. No raw `os.Getenv` calls elsewhere in the codebase.

## Pros and Cons of the Options

### Raw os.Getenv

* Good, because zero dependencies, maximum control
* Bad, because becomes boilerplate-heavy past ~10 variables
* Bad, because no declarative schema — defaults, required checks, type conversion all manual

### caarlos0/env

* Good, because zero transitive dependencies
* Good, because struct tags with defaults, required, prefix/nesting, custom parsers
* Good, because actively maintained (v11, 2024)
* Good, because minimal API — does one thing (env → struct)

### kelseyhightower/envconfig

* Good, because zero dependencies, simple API
* Bad, because effectively archived — last meaningful commit 2020
* Bad, because no slice/map support, no env var expansion

### spf13/viper

* Good, because supports every config source imaginable
* Bad, because ~30+ transitive dependencies
* Bad, because global singleton by default
* Bad, because batteries-included philosophy conflicts with project principles

### knadh/koanf

* Good, because modular provider architecture
* Bad, because over-engineered for env-only config
* Bad, because provider/parser abstraction adds indirection with no value for this use case

## More Information

* [caarlos0/env](https://github.com/caarlos0/env)
