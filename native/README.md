# Fangida native ABI

`include/fangida_native.h` defines the shared ABI implemented independently by
the C++ and Rust libraries. Each provides a bounded byte histogram and ASCII
string scan encoded as UTF-8 JSON. Load **one** implementation at a time;
their exported symbol names are deliberately identical. Check the major ABI
version before calling, and release every successful result through that same
library. The output bytes are not NUL terminated.

Build and test the C++ implementation with CMake:

```sh
cmake -S native/cpp -B build/native-cpp
cmake --build build/native-cpp
ctest --test-dir build/native-cpp --output-on-failure
```

Build and test the Rust implementation with Cargo:

```sh
cargo test --manifest-path native/rust/Cargo.toml
cargo build --release --manifest-path native/rust/Cargo.toml
```

Neither library performs disassembly or CFG recovery yet. This is the stable
FFI foundation for moving analysis hotspots into either language.
