import argparse
import logging
import sys
import uuid
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse, urljoin

import requests

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Define common file extensions for fuzzing
COMMON_EXTENSIONS = ['.php', '.html', '.txt', '.xml', '.js', '.json', '.log', '.bak', '.config']

# Define common directory names for fuzzing
COMMON_DIRECTORIES = ['admin', 'backup', 'uploads', 'api', 'include', 'config', 'tmp']

# Maximum extra depth for --recursive fuzzing into discovered directories.
MAX_RECURSIVE_DEPTH = 2


def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.
    """
    parser = argparse.ArgumentParser(description="Intelligent URL Fuzzing Tool")
    parser.add_argument("url", help="The base URL to fuzz")
    parser.add_argument("-w", "--wordlist", help="Path to a custom wordlist file", required=False)
    parser.add_argument("-e", "--extensions", help="Comma-separated list of file extensions to fuzz (e.g., php,html,js)", required=False)
    parser.add_argument("-d", "--directories", help="Comma-separated list of directories to fuzz", required=False)
    parser.add_argument("-o", "--output", help="Path to save the results to a file", required=False)
    parser.add_argument("-t", "--threads", help="Number of threads to use for concurrent requests (default: 1)", type=int, default=1, required=False)
    parser.add_argument("--no-common", help="Disable the use of common extensions and directories", action="store_true", required=False)
    parser.add_argument("--recursive", action="store_true", help="Recurse into discovered directories and fuzz one combined path set under each, up to a depth of 2", required=False)
    return parser.parse_args()


def is_valid_url(url):
    """
    Validates if the provided URL is valid.

    Args:
        url (str): The URL to validate.

    Returns:
        bool: True if the URL is valid, False otherwise.
    """
    try:
        result = urlparse(url)
        return all([result.scheme in ("http", "https"), result.netloc])
    except Exception:
        return False


def read_wordlist(filepath):
    """
    Reads a wordlist from the specified file.

    Args:
        filepath (str): The path to the wordlist file.

    Returns:
        list: A list of words from the wordlist file.

    Raises:
        OSError: If the file cannot be read. A wordlist the operator named
            is never silently replaced with another target set.
    """
    with open(filepath, 'r') as f:
        return [line.strip() for line in f.readlines() if line.strip()]


def normalize_base_url(base_url):
    """Return the base URL with a trailing slash so urljoin keeps the
    operator supplied path prefix whether or not it ended with a slash."""
    return base_url if base_url.endswith('/') else base_url + '/'


def build_probe_url(base_url, prefix, path):
    """Join prefix and path under the base URL, keeping the base path."""
    relative = '/'.join(part for part in (prefix.strip('/'), path.strip('/')) if part)
    return urljoin(normalize_base_url(base_url), relative)


def probe(session_url):
    """Fetch one URL. Returns (url, status_code, body_length) or raises
    requests.exceptions.RequestException on transport failure."""
    response = requests.get(session_url, timeout=5)
    return session_url, response.status_code, len(response.content)


def fuzz_url(base_url, wordlist=None, extensions=None, directories=None, output_file=None,
             threads=1, recursive=False):
    """
    Performs URL fuzzing based on the provided parameters.

    A baseline probe of a certainly absent path is taken first. A path is
    reported as found only when its status code or body length differs
    from that baseline, so a server that answers every path the same way
    (a catchall) produces no false findings.

    Returns:
        int: 0 when the scan ran, 1 when the target could not be reached
        or no probe succeeded.
    """
    if not is_valid_url(base_url):
        logging.error(f"Invalid URL: {base_url}")
        return 1

    all_paths = []

    if wordlist:
        all_paths.extend(wordlist)

    if extensions:
        for ext in extensions:
            ext = ext if ext.startswith('.') else '.' + ext
            all_paths.extend([f"{word}{ext}" for word in (wordlist if wordlist else ['index'])])

    if directories:
        all_paths.extend(directories)

    if not all_paths:
        logging.warning("No wordlist, extensions, or directories provided. Using common directories and named common files (index with each common extension).")
        all_paths.extend(COMMON_DIRECTORIES)
        all_paths.extend([f"index{ext}" for ext in COMMON_EXTENSIONS])

    if directories:
        directory_paths = set(directories)
    elif not (wordlist or extensions):
        directory_paths = set(COMMON_DIRECTORIES)
    else:
        directory_paths = set()

    results = []
    probed = 0
    succeeded = 0

    prefixes = ['']
    depth = 0
    while prefixes:
        next_prefixes = []
        for prefix in prefixes:
            baseline_token = f"__baseline_absent_{uuid.uuid4().hex}__"
            baseline_url = build_probe_url(base_url, prefix, baseline_token)
            try:
                _, baseline_status, baseline_length = probe(baseline_url)
            except requests.exceptions.RequestException as e:
                logging.error(f"Target could not be reached at {baseline_url}: {e}")
                return 1
            urls = [build_probe_url(base_url, prefix, path) for path in all_paths]
            path_by_url = dict(zip(urls, all_paths))
            if threads and threads > 1:
                with ThreadPoolExecutor(max_workers=threads) as pool:
                    outcomes = list(pool.map(lambda u: _probe_or_none(u), urls))
            else:
                outcomes = [_probe_or_none(u) for u in urls]
            for url, outcome in zip(urls, outcomes):
                probed += 1
                if outcome is None:
                    logging.warning(f"Error accessing {url}")
                    continue
                succeeded += 1
                _, status_code, length = outcome
                if status_code != baseline_status or length != baseline_length:
                    line = f"{url} - Status Code: {status_code}"
                    results.append(line)
                    logging.info(line)
                    if recursive and depth < MAX_RECURSIVE_DEPTH:
                        rel = path_by_url[url]
                        if rel in directory_paths:
                            next_prefix = '/'.join(part for part in (prefix.strip('/'), rel.strip('/')) if part)
                            next_prefixes.append(next_prefix)
        prefixes = next_prefixes
        depth += 1

    if succeeded == 0:
        logging.error("No probe succeeded; the scan did not run against the target.")
        return 1

    if output_file:
        try:
            with open(output_file, "w") as f:
                for result in results:
                    f.write(result + "\n")
            logging.info(f"Results saved to {output_file}")
        except Exception as e:
            logging.error(f"Error writing to output file: {e}")
            return 1

    logging.info(f"Fuzzing complete. {probed} paths probed, {len(results)} found beyond the baseline.")
    return 0


def _probe_or_none(url):
    try:
        return probe(url)
    except requests.exceptions.RequestException:
        return None
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        return None


def main():
    """
    Main function to execute the URL fuzzing tool.

    Returns:
        int: Process exit code. Non-zero when the URL is invalid, a named
        wordlist cannot be read, no targets were supplied with
        --no-common, or the target could not be reached.
    """
    args = setup_argparse()

    if not is_valid_url(args.url):
        logging.error("Invalid URL provided. Please provide a valid URL.")
        return 1

    if args.threads < 1:
        logging.error("--threads must be at least 1.")
        return 1

    if args.wordlist and args.output:
        import os
        if os.path.realpath(args.wordlist) == os.path.realpath(args.output):
            logging.error("Output path resolves to the wordlist input file; refusing in-place output.")
            return 1

    wordlist = None
    if args.wordlist:
        try:
            wordlist = read_wordlist(args.wordlist)
        except OSError as e:
            logging.error(f"Could not read wordlist file {args.wordlist}: {e}")
            return 1
        if not wordlist:
            logging.error(f"Wordlist file {args.wordlist} contains no words.")
            return 1

    extensions = args.extensions.split(',') if args.extensions else None
    directories = args.directories.split(',') if args.directories else None

    if args.no_common:
        if not wordlist and not extensions and not directories:
            logging.error("No fuzzing targets provided. Please use --wordlist, --extensions, or --directories to specify target types. Exiting.")
            return 1
    else:
        if not wordlist and not extensions and not directories:
            logging.info("No custom targets provided. Using common directories and named common files.")

    return fuzz_url(args.url, wordlist, extensions, directories, args.output,
                    threads=args.threads, recursive=args.recursive)


if __name__ == "__main__":
    # Example usage
    # python main.py http://example.com -w wordlist.txt -e php,html,js -o results.txt
    # python main.py http://example.com --no-common -d admin,backup
    # python main.py http://example.com
    sys.exit(main())
