import fitz  # PyMuPDF
import subprocess
import re
import binascii
import difflib
import os

# Magic numbers for common file types
MAGIC_NUMBERS = {
    "JPEG": "FFD8FF",
    "PNG": "89504E47",
    "GIF": "47494638",
    "PDF": "25504446",
    "ZIP": "504B0304",
    "RAR": "52617221",
    "EXE": "4D5A",
    "ELF": "7F454C46"
}

def get_file_hex(file_path):
    with open(file_path, 'rb') as f:
        content = f.read()
    return binascii.hexlify(content).upper()

def identify_file_type(hex_content):
    for file_type, magic in MAGIC_NUMBERS.items():
        if hex_content.startswith(magic.encode()):
            return file_type
    return "Unknown"

def find_nearest_magic(hex_content):
    nearest_matches = difflib.get_close_matches(hex_content[:6].decode(), MAGIC_NUMBERS.values(), n=1)
    if nearest_matches:
        for file_type, magic in MAGIC_NUMBERS.items():
            if magic == nearest_matches[0]:
                return file_type
    return "Unknown"

def check_file_with_file_command(file_path):
    result = subprocess.run(['file', file_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return result.stdout.decode().strip()

def analyze_pdf_with_exiftool(file_path):
    result = subprocess.run(['exiftool', file_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return result.stdout.decode().strip()

def check_for_malicious_content(exiftool_output):
    suspicious_tags = [
        "/OpenAction", "/AA", "/JavaScript", "/JS", "/AcroForm", "/XFA",
        "/URI", "/SubmitForm", "/GoToR", "/RichMedia", "/ObjStm", "/XObject"
    ]

    for line in exiftool_output.splitlines():
        for tag in suspicious_tags:
            if re.search(rf"{tag}", line, re.IGNORECASE):
                print(f"  Suspicious content found: {line}")

def extract_and_check_pdf_content(file_path):
    suspicious_tags = [
        "/OpenAction", "/AA", "/JavaScript", "/JS", "/AcroForm", "/XFA",
        "/URI", "/SubmitForm", "/GoToR", "/RichMedia", "/ObjStm", "/XObject"
    ]
    
    pdf_document = fitz.open(file_path)
    for page_num in range(len(pdf_document)):
        page = pdf_document.load_page(page_num)
        content = page.get_text("text")
        
        # Check for suspicious content in page text
        for tag in suspicious_tags:
            if re.search(rf"{tag}", content, re.IGNORECASE):
                print(f"  Suspicious content found on page {page_num + 1}: {tag}")

    # Check for embedded files manually
    for xref in range(1, pdf_document.xref_length()):
        if "/EmbeddedFile" in pdf_document.xref_object(xref):
            file_info = pdf_document.xref_object(xref)
            file_data = pdf_document.extract_file(xref)
            print(f"  Embedded file found at xref {xref}")
            print(f"  File Info: {file_info}")
            print(f"  File Size: {len(file_data['filedata'])} bytes")
            if file_info.endswith('.pdf'):
                extract_and_check_pdf_content(file_info)

def analyze_file_with_binwalk(file_path):
    result = subprocess.run(['binwalk', file_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return result.stdout.decode().strip()

def analyze_file_with_stegseek(file_path):
    rockyou_path = 'rockyou.txt'
    if not os.path.exists(rockyou_path):
        return "  rockyou.txt not found in the current directory."

    result = subprocess.run(['stegseek', file_path, rockyou_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return result.stdout.decode().strip() if result.stdout else result.stderr.decode().strip()

def main():
    file_path = input("Enter the path to the file: ")
    
    # Check file type using the 'file' command
    print("Checking file type using 'file' command...")
    file_command_output = check_file_with_file_command(file_path)
    print("File command output:")
    print("---------------------")
    print(file_command_output)
    print("---------------------\n")
    
    # Convert file content to hex
    print("Converting file content to hex...")
    hex_content = get_file_hex(file_path)
    file_type = identify_file_type(hex_content)
    
    if file_type == "Unknown":
        file_type = find_nearest_magic(hex_content)
    
    print("Hex Content (first 50 characters):")
    print("---------------------")
    print(hex_content[:50])  # Displaying the first 50 hex characters
    print("---------------------\n")
    print(f"Identified File Type: {file_type}\n")

    # Analyze file with binwalk
    print("Analyzing file with binwalk...")
    binwalk_output = analyze_file_with_binwalk(file_path)
    print("Binwalk output:")
    print("---------------------")
    print(binwalk_output)
    print("---------------------\n")

    if file_type in ["JPEG", "PNG", "GIF"]:
        # Analyze file with stegseek
        print("Checking for hidden files with stegseek...")
        stegseek_output = analyze_file_with_stegseek(file_path)
        print("Stegseek output:")
        print("---------------------")
        print(stegseek_output)
        print("---------------------\n")

    if file_type == "PDF":
        # Analyze PDF with exiftool
        print("Analyzing PDF with exiftool...")
        exiftool_output = analyze_pdf_with_exiftool(file_path)
        print("ExifTool output:")
        print("---------------------")
        print(exiftool_output)
        print("---------------------\n")
        
        # Check for malicious content in metadata
        print("Checking for malicious content in PDF metadata...")
        print("---------------------")
        check_for_malicious_content(exiftool_output)
        print("---------------------\n")

        # Extract and check PDF content for suspicious elements
        print("Extracting and checking PDF content for suspicious elements...")
        print("---------------------")
        extract_and_check_pdf_content(file_path)
        print("---------------------\n")

if __name__ == "__main__":
    main()
