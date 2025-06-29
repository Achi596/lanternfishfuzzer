import json
import csv
import xml.etree.ElementTree as ET
import json
import csv
import xml.etree.ElementTree as ET
from enum import Enum
import re

class FileType(Enum):
    JSON = 'JSON'
    XML = 'XML'
    JPEG = 'JPEG'
    ELF = 'ELF'
    PDF = 'PDF'
    CSV = 'CSV'
    PLAINTEXT = 'Plaintext'
    UNKNOWN = 'Unknown'

def determine_format(file_path):
    try:
        # Read the whole file
        with open(file_path, 'rb') as f:
            content = f.read()
    except IOError as e:
        raise Exception(f"Unable to open file: {file_path}") from e

    # Binary format checks are easy so we do them first
    if content.startswith(b'\xFF\xD8'):
        # Possible JPEG file
        if content.endswith(b'\xFF\xD9'):
            return FileType.JPEG

    elif content.startswith(b'\x7FELF'):
        return FileType.ELF

    elif content.startswith(b'%PDF'):
        return FileType.PDF

    # decode content to text so that we can parse
    try:
        f_text = content.decode('utf-8')
    except UnicodeDecodeError:
        return FileType.UNKNOWN # if we cant decode to utf-8 we donno what it is

    # Find the first non-whitespace character in content with regex
    first_char = re.search(r'\S', f_text).group(0)

    # Check for JSON format
    if first_char in ('{', '['):
        try:
            json.loads(f_text)
            return FileType.JSON
        except json.JSONDecodeError:
            pass  # Not valid JSON

    # Check for XML format
    if first_char == '<':
        try:
            ET.fromstring(f_text)
            return FileType.XML
        except ET.ParseError:
            pass  # Not valid XML

    # Check for CSV format
    if len(f_text.splitlines()) >= 2: # we assume that all csv files have at least 2 lines (otherwise detection is fucky)
        try:
            csv.Sniffer().sniff(f_text)
            return FileType.CSV
        except (csv.Error):
            pass  # Not valid CSV

    # Assume plaintext if all other checks fail
    return FileType.PLAINTEXT

