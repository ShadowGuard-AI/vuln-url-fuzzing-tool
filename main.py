import argparse
import logging
import requests
import os
from urllib.parse import urlparse, urljoin

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Define common file extensions for fuzzing
COMMON_EXTENSIONS = ['.php', '.html', '.txt', '.xml', '.js', '.json', '.log', '.bak', '.config']

# Define common directory names for fuzzing
COMMON_DIRECTORIES = ['admin', 'backup', 'uploads', 'api', 'include', 'config', 'tmp']


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
    parser.add_argument("-t", "--threads", help="Number of threads to use for concurrent requests (default: 1)", type=int, default=1, required=False) # Not implemented yet
    parser.add_argument("--no-common", help="Disable the use of common extensions and directories", action="store_true", required=False)
    parser.add_argument("--recursive", action="store_true", help="Enable recursive fuzzing (experimental)", required=False) # Not implemented yet
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
        return all([result.scheme, result.netloc])
    except:
        return False


def read_wordlist(filepath):
    """
    Reads a wordlist from the specified file.

    Args:
        filepath (str): The path to the wordlist file.

    Returns:
        list: A list of words from the wordlist file.
    """
    try:
        with open(filepath, 'r') as f:
            return [line.strip() for line in f.readlines()]
    except FileNotFoundError:
        logging.error(f"Wordlist file not found: {filepath}")
        return []
    except Exception as e:
        logging.error(f"Error reading wordlist file: {e}")
        return []


def fuzz_url(base_url, wordlist=None, extensions=None, directories=None, output_file=None):
    """
    Performs URL fuzzing based on the provided parameters.

    Args:
        base_url (str): The base URL to fuzz.
        wordlist (list, optional): A list of words to use for fuzzing. Defaults to None.
        extensions (list, optional): A list of file extensions to fuzz. Defaults to None.
        directories (list, optional): A list of directory names to fuzz. Defaults to None.
        output_file (str, optional): Path to output file. Defaults to None.
    """
    if not is_valid_url(base_url):
        logging.error(f"Invalid URL: {base_url}")
        return

    all_paths = []

    if wordlist:
        all_paths.extend(wordlist)

    if extensions:
        for ext in extensions:
            all_paths.extend([f"{word}.{ext}" for word in (wordlist if wordlist else ['index'])])

    if directories:
        all_paths.extend(directories)
    
    if not all_paths:
        logging.warning("No wordlist, extensions, or directories provided. Using common extensions and directories.")
        all_paths.extend(COMMON_EXTENSIONS)
        all_paths.extend(COMMON_DIRECTORIES)

    results = []
    
    try:
        for path in all_paths:
            fuzzed_url = urljoin(base_url, path)
            try:
                response = requests.get(fuzzed_url, timeout=5)
                if response.status_code != 404:  # Exclude "Not Found" responses
                    results.append(f"{fuzzed_url} - Status Code: {response.status_code}")
                    logging.info(f"{fuzzed_url} - Status Code: {response.status_code}")
            except requests.exceptions.RequestException as e:
                logging.warning(f"Error accessing {fuzzed_url}: {e}")
            except Exception as e:
                logging.error(f"An unexpected error occurred: {e}")

        # Output results to file
        if output_file:
            try:
                with open(output_file, "w") as f:
                    for result in results:
                        f.write(result + "\n")
                logging.info(f"Results saved to {output_file}")
            except Exception as e:
                logging.error(f"Error writing to output file: {e}")


    except Exception as e:
        logging.error(f"An unexpected error occurred during fuzzing: {e}")


def main():
    """
    Main function to execute the URL fuzzing tool.
    """
    args = setup_argparse()

    # Validate URL
    if not is_valid_url(args.url):
        logging.error("Invalid URL provided. Please provide a valid URL.")
        return

    # Prepare wordlist, extensions, and directories
    wordlist = read_wordlist(args.wordlist) if args.wordlist else None
    extensions = args.extensions.split(',') if args.extensions else None
    directories = args.directories.split(',') if args.directories else None

    if args.no_common:
        if not wordlist and not extensions and not directories:
            logging.warning("No fuzzing targets provided.  Please use --wordlist, --extensions, or --directories to specify target types. Exiting.")
            return
    else:
        if not wordlist and not extensions and not directories:
            logging.info("No custom targets provided.  Using common extensions and directories.")

    # Perform URL fuzzing
    fuzz_url(args.url, wordlist, extensions, directories, args.output)


if __name__ == "__main__":
    # Example usage
    # python main.py http://example.com -w wordlist.txt -e php,html,js -o results.txt
    # python main.py http://example.com --no-common -d admin,backup
    # python main.py http://example.com
    main()