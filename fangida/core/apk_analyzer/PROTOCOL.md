# Android worker protocol

此路径是旧协议文档的兼容入口。实现位于独立 `apk-analyzer` 项目，Fangida
通过 `fangida.plugins.apk_bridge` 启动并连接该项目，不包含 APK Loader/处理器。
可设置 `FANGIDA_APK_ANALYZER_PROJECT` 或 `FANGIDA_APK_ANALYZER_COMMAND`。

The plugin starts a Python subprocess on its first request and reuses it until
`teardown()`. Independent file requests may use separate persistent children,
bounded by the configured `parse_threads` and a hard cap of four children per
plugin. Each child handles one `analyze` request at a time. Archive members in
one request remain sequential, preserving output order and decompression
budgets. Communication is JSON-RPC 2.0, one UTF-8 JSON object per line over
stdin/stdout. A separate thread in each child keeps its protocol responsive
to cancellation.

| Method | Parameters | Result |
| --- | --- | --- |
| `analyze` | `AnalysisTask` fields | `AnalysisResult`, or a page descriptor |
| `result_page` | `handle`, zero-based `index` | `index`, base64 `data` |
| `release_result` | `handle` | `true` |
| `$/cancelRequest` | `id` of an active analysis | Notification; no response |

Progress is a `$/progress` notification with `request_id`, `stage`, and
integer `percent`. Callers opt in by putting `"progress": true` at the top
level of their `analyze` request; without it, small one-shot calls receive a
single response line as before. The request ID distinguishes notifications
from responses. A cancelled analysis replies with JSON-RPC error `-32800`. A busy
worker replies with `-32001`. The parent serializes its calls and returns an
error result on timeout; it kills and reaps timed-out workers.

Small results return inline. Larger results return `{paged: true, handle,
pages, size, sha256}`; the parent fetches pages of at most 256 KiB, checks
the byte length and SHA-256 digest, and releases the buffer. A result is
limited to 256 MiB and each wire line to 512 KiB. A subsequent `analyze`
replaces an unreleased result. The child is restarted once when its transport
crashes during analysis. Sending one request and then closing stdin remains
supported for older stdio callers: the child finishes the request before it
exits. Large responses use the page protocol and require a persistent stdin.

Cancellation is checked while waiting for a free child, between archive
members, inside container/method/instruction parsing, during bounded xref batches,
CFG construction and result encoding. The parent request's wall-time deadline includes any time
spent waiting for a worker and can always terminate a running child.
