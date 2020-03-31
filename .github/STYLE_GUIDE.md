# Style Guide

## Rust Code Format

Medietas is based on Parity Ethereum,
so [Parity-Ethereum-Style-Guide](https://wiki.parity.io/Parity-Ethereum-Style-Guide) is followed to keep code style consistent.

### Format code with rustfmt

Using a format tool like [rustfmt](https://github.com/rust-lang/rustfmt) helps to ensure everyone to use the same style.
So we recommend using `rustfmt` to format changed rust files.

However, the original Parity Ethereum codebase has not been formatted using rustfmt.
So for files in original Parity codebase, only rustfmt it when you are making a significant change.

Since some of the configuration in `rustfmt.toml` only works in nightly version.
We use the nightly version of rustfmt to format the file.

Example command:

```sh
rustfmt +nightly rpc/src/v1/traits/origo.rs
```

## Comment Style

Comment helps to keep code readable.
Rust also has a particular kind of comment for documentation, known conveniently as a documentation comment,
that will generate HTML documentation.
Documentation comments use three slashes, `///`, instead of two and support Markdown notation for formatting the text.
More details can be found [here](https://doc.rust-lang.org/book/ch14-02-publishing-to-crates-io.html#making-useful-documentation-comments).

Here are guidelines about how to write specific comments,
it's based on the [google-cpp-style-guide](https://google.github.io/styleguide/cppguide.html#Comments).

### Struct Comment

Every non-obvious class declaration should have an accompanying comment
that describes what it is for and how it should be used.
Struct comment is part of documentation comments, so `///` is used.

Example:

```rust
/// A set of information describing an externally-originating message call
/// or contract creation operation.
#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct Transaction {
    /// Nonce.
    pub nonce: U256,
    /// Gas price.
    pub gas_price: U256,
    ...
```

### Function Comment

Most non-trivial function
should have comments immediately preceding it that describe what the function does and how to use it.
Function comment is part of documentation comments, so `///` is used.

Example:

```rust
/// Tries to find a phrase for address, given the number
/// of expected words and a partial phrase.
///
/// Returns `None` if phrase couldn't be found.
pub fn brain_recover(
    address: &Address,
    known_phrase: &str,
    expected_words: usize,
)
```

### Implementation Comment

In your implementation, you should have comments in tricky, non-obvious, interesting, or important parts of your code.

Here's an example that explains no-trivial logic:

```rust
    // Disallow unsigned transactions in case EIP-86 is disabled.
    if !allow_empty_signature && self.is_unsigned() {
        return Err(ethkey::Error::InvalidSignature.into());
    }
    // EIP-86: Transactions of this form MUST have gasprice = 0, nonce = 0, value = 0, and do NOT increment the nonce of account 0.
    if allow_empty_signature && self.is_unsigned() && !(self.gas_price.is_zero() && self.value.is_zero() && self.nonce.is_zero()) {
        return Err(ethkey::Error::InvalidSignature.into())
    }
```
