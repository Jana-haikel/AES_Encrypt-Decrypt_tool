# aes-tool

A command-line file encryption tool written in C++ using AES-256-CTR via OpenSSL.

Run it on a file or directory — it automatically detects whether to encrypt or decrypt based on a magic header stamped into every encrypted file. No flags, no arguments, just a path.

## How it works

- A 4-byte magic header is written at the start of every encrypted file so the tool can identify and reverse the operation automatically
- A fresh random 16-byte IV is generated per file and stored in the header — ensures identical files never produce identical ciphertext
- The AES-256 key is generated once on first run and saved to `aes_tool.key` — loaded automatically on every subsequent run

## Build

```bash
g++ -std=c++17 aes_tool.cpp -o aes_tool -lssl -lcrypto
```

**Dependencies**

- OpenSSL (`libssl-dev` on Linux, `brew install openssl` on macOS)
- C++17 or later

## Usage

```bash
./aes_tool
Path (file or directory): /path/to/file_or_folder
```

Run it once to encrypt, run it again on the same path to decrypt.

## Important

- Do not delete or encrypt `aes_tool.key` — it is the only thing that can decrypt your files
- Keep `aes_tool.key` in the same directory as the executable

## License

MIT
