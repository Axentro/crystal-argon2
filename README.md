# crystal-argon2

[![Build Status](https://www.travis-ci.org/SushiChain/crystal-argon2.svg?branch=master)](https://www.travis-ci.org/SushiChain/crystal-argon2)

This Crystal shard provides C bindings, and a simplified interface, to the Argon2 algorithm. [Argon2](https://github.com/P-H-C/phc-winner-argon2) is the official winner of the Password Hashing Competition, a several year project to identify a successor to bcrypt/PBKDF/scrypt methods of securely storing passwords. This is an independent project and not official from the PHC team.

This project is mostly a clone of this awesome ruby project [technion/ruby-argon2](https://github.com/technion/ruby-argon2)

## Installation

1. Add the dependency to your `shard.yml`:
```yaml
dependencies:
  crystal-argon2:
    github: sushichain/crystal-argon2
```
2. Run `shards install`

## Design

This project has several key tenants to its design:

* The reference Argon2 implementation is to be used "unaltered". To ensure compliance with this goal, and encourage regular updates from upstream, the upstream library is implemented as a git submodule, and is intended to stay that way.
* Security and maintainability take top priority. This can have an impact on platform support. A PR that contains platform specific code paths is unlikely to be accepted.
* Tested versions are Crystal 0.27.0 on MacOS and Linux. No assertions are made on other platforms.
* Errors from the C interface are raised as Exceptions. There are a lot of exception classes, but they tend to relate to things like very broken input, and code bugs. Calls to this library should generally not require a rescue.
* Test suite should aim for 100% code coverage.
* Default work values should not be considered constants. They may change.
* Not exposing the threads parameter is a design choice. I believe there is significant risk, and minimal gain in using a value other than '1'. Four threads on a four core box completely ties up the entire server to process one user logon. If you want more security, increase m_cost.

## Usage

```crystal
require "crystal-argon2"
```

To generate a hash using specific time and memory cost:

```crystal
hasher = Argon2::Password.new(t_cost: 2, m_cost: 16)
hasher.create("password")
    => "$argon2i$v=19$m=65536,t=2,p=1$jL7lLEAjDN+pY2cG1N8D2g$iwj1ueduCvm6B9YVjBSnAHu+6mKzqGmDW745ALR38Uo"
```

To utilise default costs:

```crystal
hasher = Argon2::Password.new
hasher.create("password")
```

If you follow this pattern, it is important to create a new `Argon2::Password` every time you generate a hash, in order to ensure a unique salt. See [issue 23](https://github.com/technion/ruby-argon2/issues/23) for more information.
Alternatively, use this shotcut:

```crystal
Argon2::Password.create("password")
    => "$argon2i$v=19$m=65536,t=2,p=1$61qkSyYNbUgf3kZH3GtHRw$4CQff9AZ0lWd7uF24RKMzqEiGpzhte1Hp8SO7X8bAew"
```

You can then use this function to verify a password against a given hash. Will return either true or false.

```crystal
Argon2::Password.verify_password("password", secure_password)
```

## Development

* build the C library `cd ext && make`
* run specs: `crystal spec`

## Contributing

1. Fork it (<https://github.com/sushichain/crystal-argon2/fork>)
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create a new Pull Request

## Contributors

- [Kingsley Hendrickse](https://github.com/kingsleyh) - creator and maintainer
