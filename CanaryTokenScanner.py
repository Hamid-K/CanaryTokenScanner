import os
import zipfile
import re
import shutil
import sys
import zlib
from rich.console import Console
from rich.table import Table
from collections import defaultdict

console = Console()

if len(sys.argv) != 2:
    console.print("Usage: python script.py FILE_OR_DIRECTORY_PATH", style="bright_yellow")
    sys.exit(1)

FILE_OR_DIRECTORY_PATH = sys.argv[1]
suspicious_files_count = 0
url_counts = defaultdict(int)

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
        'microsoft.com',
        'w3.org',
        'verisign.com',
        'adobe.com',
        'openxmlformats.org',
        'purl.org',
        'mozzila.org',
        'google.com',
        'apache.org',
        'mvnrepository.com',
        'oracle.com',
        'sun.com',
        'android.com',
        'npmjs.org',
        'asp.net',
        'opengis.net',
        'github.com',
        'yarnpkg.com',
        'xceed.com',
        'redis.io',
        'wikipedia.org',
        'github.io',
        'google.com',
        'facebook.com',
        'twitter.com',
        'linkedin.com',
        'instagram.com',
        'youtube.com',
        'pinterest.com',
        'globalsign.net',
        'thawte.com',
        'entrust.net',
        'rabbitmq.com',
        'couchbase.com',
        'couchdb.org'
    ]
    for domain in allowed_domains:
        if re.search(rf'https?://([a-zA-Z0-9.-]+\.)?{re.escape(domain)}', url):
            return False
    return True

def decompress_and_scan(file_path):
    temp_dir = "temp_extracted"
    os.makedirs(temp_dir, exist_ok=True)
    global suspicious_files_count

    is_file_suspicious = False
    try:
        with zipfile.ZipFile(file_path, 'r') as zip_ref:
            zip_ref.extractall(temp_dir)

        url_pattern = re.compile(r'https?://\S+')

        for root, dirs, files in os.walk(temp_dir):
            for file_name in files:
                extracted_file_path = os.path.join(root, file_name)
                with open(extracted_file_path, 'r', errors='ignore') as extracted_file:
                    contents = extracted_file.read()
                    urls = url_pattern.findall(contents)
                    for url in urls:
                        if check_domain(url):
                            console.print(f"URL Found in [bold]{file_path}[/bold]: [red]{url}[/red]", style="bright_yellow")
                            url_counts[url] += 1
                            is_file_suspicious = True
    except Exception as e:
        console.print(f"Error processing file {file_path}: {e}", style="red")

    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)

    if is_file_suspicious:
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
                    url_counts[url] += 1
                global suspicious_files_count
                suspicious_files_count += 1
                return True
    return False

def print_stats():
    if url_counts:
        table = Table(show_header=True, header_style="bold blue")
        table.add_column("URL", overflow="fold")
        table.add_column("Count", justify="right")
        for url, count in url_counts.items():
            table.add_row(url, str(count))
        console.print(table)
    console.print(f"Suspicious files found: [bold]{suspicious_files_count}[/bold]", style="bright_yellow")

def main():
    if os.path.exists(FILE_OR_DIRECTORY_PATH):
        if os.path.isfile(FILE_OR_DIRECTORY_PATH):
            is_suspicious_file(FILE_OR_DIRECTORY_PATH)
        elif os.path.isdir(FILE_OR_DIRECTORY_PATH):
            for root, dirs, files in os.walk(FILE_OR_DIRECTORY_PATH):
                for file_name in files:
                    current_file_path = os.path.join(root, file_name)
                    is_suspicious_file(current_file_path)
    else:
        console.print(f"The path [bold]{FILE_OR_DIRECTORY_PATH}[/bold] does not exist.", style="bright_yellow")
    print_stats()

if __name__ == "__main__":
    main()
