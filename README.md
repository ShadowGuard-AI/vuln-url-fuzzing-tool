# vuln-URL-Fuzzing-Tool

Performs URL fuzzing against an operator named base URL to discover hidden endpoints and files. Before probing, it requests a certainly absent path as a baseline; a path is reported as found only when its status code or response length differs from that baseline, so a server that answers every path the same way produces no false findings. The base URL path prefix is kept whether or not the URL ends with a slash.

## Install
`git clone https://github.com/ShadowGuardAI/vuln-url-fuzzing-tool`

## Usage
`./vuln-url-fuzzing-tool [params]`

## Parameters
- `-h`: Show help message and exit
- `-w`: Path to a custom wordlist file. If the file cannot be read or is empty, the run exits non-zero; a named wordlist is never silently replaced with the built in set.
- `-e`: Comma-separated list of file extensions to fuzz (e.g. php,html,js)
- `-d`: Comma-separated list of directories to fuzz
- `-o`: Path to save the results to a file. Refused if it resolves to the wordlist input file.
- `-t`: Number of threads to use for concurrent requests (default: 1)
- `--no-common`: Disable the use of common extensions and directories. With no other targets supplied, the run exits non-zero.
- `--recursive`: Recurse into discovered directories and fuzz the same path set under each, up to a depth of 2

When no custom targets are supplied and `--no-common` is not set, the tool states that fact and probes the common directories plus named common files (index with each common extension). It never probes a bare extension as a path.

Exit codes: 0 only when the scan ran against a reachable target. An invalid URL, an unreadable or empty wordlist, no targets under `--no-common`, or an unreachable target all exit non-zero with no findings reported.

## License
Copyright (c) ShadowGuardAI
