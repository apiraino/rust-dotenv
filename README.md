rust-dotenv [![Build Status](https://travis-ci.org/apiraino/rust-dotenv.svg?branch=master)](https://travis-ci.org/apiraino/rust-dotenv)
====

### **This fork is archived, development will continue on the (official) [repository](https://github.com/dotenv-rs/dotenv)** 
(please contribute there issues and pull requests)

**Achtung!** This is a v0.\* version! Expect bugs and issues all around.
Submitting pull requests and issues is highly encouraged!

Quoting [bkeepers/dotenv][dotenv]:

> Storing [configuration in the environment](http://www.12factor.net/config)
> is one of the tenets of a [twelve-factor app](http://www.12factor.net/).
> Anything that is likely to change between deployment environments–such as
> resource handles for databases or credentials for external services–should
> be extracted from the code into environment variables.

This library is meant to be used on development or testing environments in
which setting environment variables is not practical. It loads environment
variables from a `.env` file, if available, and mashes those with the actual
environment variables provided by the operative system.

Usage
----

The easiest and most common usage consists on calling `dotenv::dotenv` when the
application starts, which will load environment variables from a file named
`.env` in the current directory or any of its parents; after that, you can just call
the environment-related method you need as provided by `std::os`.

If you need finer control about the name of the file or its location, you can
use the `from_filename` and `from_path` methods provided by the crate.

`dotenv_codegen` provides the `dotenv!` macro, which
behaves identically to `env!`, but first tries to load a `.env` file at compile
time.

Examples
----

A `.env` file looks like this:

```sh
# a comment, will be ignored
REDIS_ADDRESS=localhost:6379
MEANING_OF_LIFE=42
```

You can optionally prefix each line with the word `export`, which will
conveniently allow you to source the whole file on your shell.

A sample project using Dotenv would look like this:

```rust
extern crate dotenv;

use dotenv::dotenv;
use std::env;

fn main() {
    dotenv().ok();

    for (key, value) in env::vars() {
        println!("{}: {}", key, value);
    }
}
```

Using the `dotenv!` macro
------------------------------------

Add `dotenv_codegen` to your dependencies, and add the following to the top of
your crate:

```rust
#[macro_use]
extern crate dotenv_codegen;
```

Then, in your crate:

```rust
fn main() {
  println!("{}", dotenv!("MEANING_OF_LIFE"));
}
```

[dotenv]: https://github.com/bkeepers/dotenv


Using CLI command
-----------------

You can also use `dotenv` as a CLI command that reads environment variables from `.env` file.

For that you need to install `dotenv` with the following command

```
cargo install dotenv --bin dotenv --features=cli
```
