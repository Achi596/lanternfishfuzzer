import json
import csv
import xml.etree.ElementTree as ET
from json_mutator import JSONMutator
from xml_mutator import XMLMutator
from csv_mutator import CSVMutator
from plaintext_mutator import PlaintextMutator
#from unknown_mutator import UnknownMutator  # dummy class (we could just return Plaintext instead maybe)

def get_mutator(file_path):
    try:
        # Read the whole file as a binary
        with open(file_path, 'rb') as f:
            content = f.read()
    except IOError as e:
        raise Exception(f"Unable to open file: {file_path}") from e

    # Check for binary file formats first since theyre easy
    # jpg check
    if content.startswith(b'\xFF\xD8'):
        if content.endswith(b'\xFF\xD9'):
            # Initialize and return a JPEGMutator
            pass

    # elf check
    elif content.startswith(b'\x7FELF'):
        # Initialize and return an ELFMutator
        pass

    # pdf check
    elif content.startswith(b'%PDF'):
        # Initialize and return a PDFMutator
        pass

    # Try decoding content to text for text-based formats
    try:
        f_text = content.decode('utf-8')
    except UnicodeDecodeError:
        return UnknownMutator # if the file is a binary that we do not have a method for

    # Check for JSON format
    try:
        json_content = json.loads(f_text)
        # pass json object to mutator
        return JSONMutator(f_text)
    except json.JSONDecodeError:
        pass  # Not valid JSON

    # Check for XML format
    try:
        ET.fromstring(f_text)
        # pass xml object to mutator
        return XMLMutator(f_text)
    except ET.ParseError:
        pass  # Not valid XML

    # Check for CSV format
    if len(f_text.splitlines()) >= 2: # we assume that a csv will have more than 2 lines
        try:
            csv.Sniffer().sniff(f_text)
            # If sniffing is successful, initialize CSVMutator with the csv text
            return CSVMutator(f_text)
        except csv.Error:
            pass  # Not valid CSV

    # assume plaintext if all other checks fail
    return PlaintextMutator(f_text)


