import os
import re
import shutil
import sys
import threading
import zipfile
import zlib
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor

from rich.console import Console
from rich.table import Table

console = Console()
url_counts = defaultdict(int)
url_counts_lock = threading.Lock()  # Lock for thread-safe operations on the URL count dictionary
suspicious_files_count = 0
suspicious_files_lock = threading.Lock()  # Lock for thread-safe incrementing of suspicious files count


def extract_urls_from_stream(stream):
    try:
        decompressed_data = zlib.decompress(stream)
        urls = re.findall(b'https?://[^\s<>"\'{}|\\^`]+', decompressed_data)
        return urls
    except zlib.error:
        return []


def process_pdf_file(pdf_path):
    with open(pdf_path, 'rb') as file:
        pdf_content = file.read()

    streams = re.findall(b'stream[\r\n\s]+(.*?)[\r\n\s]+endstream', pdf_content, re.DOTALL)
    found_urls = []
    for stream in streams:
        urls = extract_urls_from_stream(stream)
        if urls:
            found_urls.extend(urls)

    return found_urls


def check_domain(url):
    allowed_domains = [
        'microsoft.com', 'w3.org', 'verisign.com', 'adobe.com', 'openxmlformats.org', 'purl.org',
        'mozzila.org', 'google.com', 'apache.org', 'mvnrepository.com', 'oracle.com', 'sun.com',
        'android.com', 'npmjs.org', 'asp.net', 'opengis.net', 'github.com', 'yarnpkg.com',
        'xceed.com', 'redis.io', 'wikipedia.org', 'github.io', 'facebook.com', 'twitter.com',
        'linkedin.com', 'instagram.com', 'youtube.com', 'pinterest.com', 'globalsign.net',
        'thawte.com', 'entrust.net', 'rabbitmq.com', 'couchbase.com', 'couchdb.org','fb.me','libreoffice.org'
    ]
    for domain in allowed_domains:
        if re.search(rf'https?://([a-zA-Z0-9.-]+\.)?{re.escape(domain)}', url):
            return False
    return True


def decompress_and_scan(file_path):
    is_file_suspicious = False
    temp_dir = "temp_extracted"
    os.makedirs(temp_dir, exist_ok=True)

    try:
        with zipfile.ZipFile(file_path, 'r') as zip_ref:
            zip_ref.extractall(temp_dir)

        url_pattern = re.compile(r'https?://\S+')

        for root, _, files in os.walk(temp_dir):
            for file_name in files:
                extracted_file_path = os.path.join(root, file_name)
                with open(extracted_file_path, 'r', errors='ignore') as extracted_file:
                    contents = extracted_file.read()
                    urls = url_pattern.findall(contents)
                    for url in urls:
                        if check_domain(url):
                            console.print(f"URL Found in [bold]{file_path}[/bold]: [red]{url}[/red]", style="bright_yellow")
                            with url_counts_lock:
                                url_counts[url] += 1
                            is_file_suspicious = True
    except Exception as e:
        console.print(f"Error processing file {file_path}: {e}", style="red")

    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)

    if is_file_suspicious:
        with suspicious_files_lock:
            global suspicious_files_count
            suspicious_files_count += 1

    return is_file_suspicious


def is_suspicious_file(file_path):
    if file_path.lower().endswith(('.zip', '.docx', '.xlsx', '.pptx')):
        return decompress_and_scan(file_path)
    elif file_path.lower().endswith('.pdf'):
        urls = process_pdf_file(file_path)
        if urls:
            suspicious_urls = set(url.decode('utf-8', 'ignore').replace('/QXUGUTAENT)', '') for url in urls if check_domain(url.decode('utf-8', 'ignore')))
            if suspicious_urls:
                console.print(f"The file [bold]{file_path}[/bold] is suspicious. URLs found:", style="bright_yellow")
                for url in suspicious_urls:
                    console.print(f"[red]{url}[/red]", style="bright_yellow")
                    with url_counts_lock:
                        url_counts[url] += 1
                with suspicious_files_lock:
                    global suspicious_files_count
                    suspicious_files_count += 1
                return True
    return False


def print_stats():
    table = Table(show_header=True, header_style="bold blue")
    table.add_column("URL", overflow="fold")
    table.add_column("Count", justify="right")
    for url, count in url_counts.items():
        table.add_row(url, str(count))
    console.print(table)
    console.print(f"Suspicious files found: [bold]{suspicious_files_count}[/bold]", style="bright_yellow")


def main():
    if len(sys.argv) != 2:
        console.print("Usage: python script.py FILE_OR_DIRECTORY_PATH", style="bright_yellow")
        sys.exit(1)

    file_or_directory_path = sys.argv[1]

    if not os.path.exists(file_or_directory_path):
        console.print(f"The path [bold]{file_or_directory_path}[/bold] does not exist.", style="bright_yellow")
        return

    file_paths = []
    if os.path.isfile(file_or_directory_path):
        file_paths.append(file_or_directory_path)
    elif os.path.isdir(file_or_directory_path):
        for root, _, files in os.walk(file_or_directory_path):
            for file_name in files:
                file_paths.append(os.path.join(root, file_name))

    with ThreadPoolExecutor() as executor:
        # Use a list comprehension to start the file processing in parallel
        futures = [executor.submit(is_suspicious_file, file_path) for file_path in file_paths]

        # We don't need the results from the futures, the counts are maintained globally
        for future in futures:
            try:
                future.result()
            except Exception as e:
                # An error has occurred during processing
                console.print(f"An error occurred: {e}", style="red")

    print_stats()


if __name__ == "__main__":
    main()
