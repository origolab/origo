![Origo Network](docs/logo-origo-network.png)


<h2 align="center">The Privacy Preserving Platform for Decentralized Applications</h2>

<p align="center"><strong><a href="https://github.com/origolab/origo-binary/releases">» Download the latest release «</a></strong></p>

<p align="center"><a href="https://www.gnu.org/licenses/gpl-3.0.en.html" target="_blank"><img src="https://img.shields.io/badge/license-GPL%20v3-green.svg" /></a></p>

**What is Origo?** Origo network is a project dedicated to building privacy preserving platform for decentralized applications.
- <a href="https://github.com/origolab/documents/blob/master/Private-Transaction-Protocol.md">Origo Protocol</a></strong>: Complete privacy preserving solution that supports normal hardware for transaction input and output, backed by cryptography primitives like **zero knowledge proof**.
- Public/Private Transaction: Flexible design for users to choose either public or private transaction feature on demand, suitable for various use cases with different privacy needs.

Origo Network enables easy-to-use toolchain for utilizing privacy technology, developers pay more attention on their business logic with minimum learning curve on our platform.

## Quick Start

## Dependencies

Origo network requires **latest stable Rust version** to build.

We recommend installing Rust through [rustup](https://www.rustup.rs/). If you don't already have `rustup`, you can install it like this:

- Linux:
  ```bash
  $ curl https://sh.rustup.rs -sSf | sh
  ```

  Origo network also requires `gcc`, `g++`, `libudev-dev`, `pkg-config`, `file`, `make`, and `cmake` packages to be installed.

- OSX:
  ```bash
  $ curl https://sh.rustup.rs -sSf | sh
  ```

  `clang` is required. It comes with Xcode command line tools or can be installed with homebrew.

- Windows
  Make sure you have Visual Studio 2015 with C++ support installed. Next, download and run the `rustup` installer from
  https://static.rust-lang.org/rustup/dist/x86_64-pc-windows-msvc/rustup-init.exe, start "VS2015 x64 Native Tools Command Prompt", and use the following command to install and set up the `msvc` toolchain:
  ```bash
  $ rustup default stable-x86_64-pc-windows-msvc
  ```

Once you have `rustup` installed, then you need to install:
* [Perl](https://www.perl.org)
* [Yasm](https://yasm.tortall.net)

Make sure that these binaries are in your `PATH`. After that, you should be able to build Parity Ethereum from source.

## Build from Source Code

```bash
# download Origo network code
$ git clone https://github.com/origolab/origo.git
$ cd origo

# build in release mode
$ cargo build --release --features final
```

This produces an executable in the `./target/release` subdirectory.

Note: if cargo fails to parse manifest try:

```bash
$ ~/.cargo/bin/cargo build --release
```

Note, when compiling a crate and you receive errors, it's in most cases your outdated version of Rust, or some of your crates have to be recompiled. Cleaning the repository will most likely solve the issue if you are on the latest stable version of Rust, try:

```bash
$ cargo clean
```

This always compiles the latest nightly builds. If you want to build stable or beta, do a

```bash
$ git checkout stable
```

or

```bash
$ git checkout beta
```

## Tutorials
These tutorials walk the users to understand basic usages and features of Origo Network, please follow them to play around.

### Origo Private Transaction Usage
 <p><strong><a href="https://github.com/origolab/origo-binary/blob/master/docs/pt_tutorial.md">Private Transaction tutorial </a></strong> will guide you through executing your first private transaction on the Origo Blockchain.</p>
 
### CPU Mining Tutorial (Not Recommended)
<p><strong><a href="https://github.com/origolab/origo-binary/blob/master/docs/cpu_mining_tutorial.md">Cpu mining tutorial</a></strong> will guide you to build a miner client which can do equihash mining with cpu.</p>
 
### GPU Mining Tutorial
<p><strong><a href="https://github.com/origolab/origo-binary/blob/master/docs/gpu_mining_tutorial.md">GPU Mining Tutorial</a></strong> will help you mine with GPU card with our gpu miner, because the CPU has limitd performance on the PoW race, and too inefficient to hold any value</p>

### Origo JSON-RPC APIs.
<p><strong><a href="https://rpcdoc.origo.network/">JSON-RPC APIs for Origo Network</a></strong></p>

## Contribution
If you'd like to contribute to origo network, please follow below.
<p><strong><a href="https://github.com/origolab/origo/blob/master/.github/CONTRIBUTING.md">Contributing Guidelines for Origo Network.</a></strong></p>
<p><strong><a href="https://github.com/origolab/origo/blob/master/.github/STYLE_GUIDE.md">Code Style Guide for Origo Network.</a></strong></p>

## Documentation

Official website: https://origo.network/

Be sure to [check out our medium](https://medium.com/@origonetwork) for more information.

## License
<p><strong><a href="https://github.com/origolab/origo/blob/master/LICENSE">GNU GENERAL PUBLIC LICENSE</a></strong></p>
