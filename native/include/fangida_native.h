#ifndef FANGIDA_NATIVE_H
#define FANGIDA_NATIVE_H
#include <stdint.h>

#if defined(_WIN32) && defined(FANGIDA_NATIVE_BUILD)
#define FANGIDA_API __declspec(dllexport)
#elif defined(_WIN32)
#define FANGIDA_API __declspec(dllimport)
#else
#define FANGIDA_API
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* Stable C ABI. Either the C++ or Rust shared library can provide the symbols.
 * Clients must load only one implementation into a given symbol namespace. */
#define FANGIDA_ABI_MAJOR 1
#define FANGIDA_ABI_MINOR 0
#define FANGIDA_MAX_INPUT_BYTES (64ULL * 1024ULL * 1024ULL)

typedef struct fangida_buffer { uint8_t *data; uint64_t length; } fangida_buffer;
typedef enum fangida_status { FANGIDA_OK = 0, FANGIDA_INVALID = 1, FANGIDA_FAILED = 2 } fangida_status;

/* Returns (major << 16) | minor. No exceptions or panics cross the ABI. */
FANGIDA_API uint32_t fangida_abi_version(void);

/* Accepts at most FANGIDA_MAX_INPUT_BYTES. data may be NULL only for length 0.
 * out must be non-NULL, writable, and must not overlap input. It must not
 * contain a live result; call fangida_release before reusing it. It is set to
 * {NULL, 0} before other validation.
 * On success, out owns UTF-8 JSON bytes (not NUL terminated):
 * {"schema_version":1,"size":N,"histogram":[256 unsigned counts],
 *  "strings":[{"offset":N,"text":"..."}],"strings_truncated":bool}
 * Strings are contiguous printable ASCII runs of at least 4 bytes. At most
 * 32 runs and the first 128 bytes of each run are retained; strings_truncated
 * is true when either limit excludes data. Offsets are file byte offsets.
 * Histogram covers the entire input. Release the buffer with the matching
 * library's fangida_release before unloading it. Do not free it yourself. */
FANGIDA_API fangida_status fangida_analyze(const uint8_t *data, uint64_t length, fangida_buffer *out);

/* Accepts NULL. A non-NULL buffer must be a live result from this library.
 * Sets the buffer to {NULL, 0}; calling twice on the same buffer is safe. */
FANGIDA_API void fangida_release(fangida_buffer *buffer);
#ifdef __cplusplus
}
#endif
#endif
