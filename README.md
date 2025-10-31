# TemporalFS

TemporalFS is a lightweight, content-defined deduplication and version-tracking system.
It uses a rolling-hash (buzhash) algorithm, SHA-256 verification, SQLite metadata, and AES encryption for chunk storage.

---

## Features

- Real-time tracking via inotify
- Content-defined chunking with variable-size segments
- Deduplication across all file versions
- Automatic rollback on duplicate hashes
- Version restore and verification
- Atomic commits with SQLite transactions
- Optional encryption and compression for chunk data

---

## Directory Layout

<pre>
<WATCH_DIR>/
├── file.txt
└── .temporalfs/
    ├── temporal.db   # SQLite metadata database
    ├── chunks/       # encrypted chunk storage
    ├── key, iv       # encryption key and IV
</pre>

---

## Command Line Usage

<pre>
TemporalFS — rolling-hash deduplication and version tracking

Usage:
  FileWatcher                           Start inotify watcher
  FileWatcher --verify &lt;file&gt; [ver_id]  Verify file integrity
  FileWatcher --restore &lt;file&gt; &lt;ver_id&gt; Restore a previous version
  FileWatcher --list &lt;file&gt;             List available versions
  FileWatcher --status                  Show stats and totals
  FileWatcher --clean                   Remove unreferenced chunks
  FileWatcher --purge                   Clear all database records
  FileWatcher --set-paths               Redefine directories interactively
</pre>

---

## Environment Variables

Override default paths at startup:

    export TEMPORALFS_WATCH=/data
    export TEMPORALFS_META=/data/.temporalfs
    export TEMPORALFS_CHUNKS=/data/.temporalfs/chunks
    export TEMPORALFS_DB=/data/.temporalfs/temporal.db

---

## Build

Dependencies:
- GCC or Clang
- libssl-dev (OpenSSL 3.0+)
- libsqlite3-dev
- zlib1g-dev

Build command:

    make clean && make

---

## Example Usage

    ./FileWatcher &
    # modify files under WATCH_DIR
    ./FileWatcher --list example.txt
    ./FileWatcher --restore example.txt 3
    ./FileWatcher --verify example.txt 3

---

## Design Notes

- SQLite in WAL mode with PRAGMA synchronous=FULL
- Atomic temp-file rename during chunk writes
- Directory fsync() after commits for durability
- Safe rollback on transaction failure
- Graceful exit handling during interruptions

---

## License

MIT License © 2025 CalamityTheMadSoothsayer
