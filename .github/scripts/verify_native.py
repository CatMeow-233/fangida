"""Exercise both freshly built native libraries through the installed Python API."""
from pathlib import Path
import sys

from fangida.native_bridge import NativeBridge


def main() -> None:
    if sys.platform == "win32":
        cpp_name = "fangida_native_cpp.dll"
        rust_name = "fangida_native_rust.dll"
        cpp_directory = Path("build/native-cpp/Release")
    elif sys.platform == "darwin":
        cpp_name = "libfangida_native_cpp.dylib"
        rust_name = "libfangida_native_rust.dylib"
        cpp_directory = Path("build/native-cpp")
    else:
        cpp_name = "libfangida_native_cpp.so"
        rust_name = "libfangida_native_rust.so"
        cpp_directory = Path("build/native-cpp")

    libraries = (cpp_directory / cpp_name, Path("native/rust/target/debug") / rust_name)
    sample = b'\x00hello"\\world\x00ABCD'
    histogram = [sample.count(index) for index in range(256)]
    results = []
    for library in libraries:
        assert library.is_file(), f"Native build did not produce {library}"
        bridge = NativeBridge(library)
        result = bridge.analyze(sample)
        assert result["size"] == len(sample), f"Incorrect byte count from {library}"
        assert result["histogram"] == histogram, f"Incorrect histogram from {library}"
        assert result["strings"] == [
            {"offset": 1, "text": 'hello"\\world'},
            {"offset": 14, "text": "ABCD"},
        ], f"Incorrect escaped string result from {library}"
        assert result["strings_truncated"] is False
        for _ in range(3):
            empty = bridge.analyze(b"")
            assert empty["size"] == 0 and empty["histogram"] == [0] * 256
            assert empty["strings"] == []
        results.append(result)
        print(f"Python ABI verified: {library}")
    assert results[0] == results[1], "C++ and Rust implementations disagree"


if __name__ == "__main__":
    main()
