import os
import magic
import olefile
from oletools.olevba import VBA_Parser
import pandas as pd
import openpyxl
from openpyxl.utils.dataframe import dataframe_to_rows
import stegano
from stegano import lsb
from tabulate import tabulate

def check_file(file_path):
    # Check file extension
    file_extension = os.path.splitext(file_path)[1]
    mime = magic.Magic(mime=True)
    file_mime_type = mime.from_file(file_path)
    
    print(f"File Extension: {file_extension}")
    print(f"File MIME Type: {file_mime_type}")
    
    if file_extension.lower() in ['.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx']:
        if "Microsoft" not in file_mime_type:
            print("File extension does not match the MIME type. Attempting to repair magic header...")
            # Add logic to repair magic header if needed
        else:
            print("File extension matches the MIME type.")
            return True
    else:
        print("Unsupported file type.")
        return False

def extract_macros(file_path):
    if olefile.isOleFile(file_path):
        vba_parser = VBA_Parser(file_path)
        if vba_parser.detect_vba_macros():
            print("VBA Macros found:")
            for (filename, stream_path, vba_filename, vba_code) in vba_parser.extract_all_macros():
                print(f"Filename: {vba_filename}")
                print(vba_code)
        else:
            print("No VBA macros found.")
    else:
        print("Not an OLE file.")

def extract_hidden_sheets(file_path):
    if file_path.endswith('.xlsx') or file_path.endswith('.xlsm'):
        wb = openpyxl.load_workbook(file_path, data_only=True)
        hidden_sheets = [sheet for sheet in wb.sheetnames if wb[sheet].sheet_state == 'hidden']
        
        if hidden_sheets:
            print("Hidden Sheets found:")
            for sheet in hidden_sheets:
                ws = wb[sheet]
                df = pd.DataFrame(ws.values)
                print(f"Sheet Name: {sheet}")
                print(tabulate(df, headers='keys', tablefmt='psql'))
        else:
            print("No hidden sheets found.")
    else:
        print("File is not an Excel workbook.")

def apply_stego_tools(file_path):
    try:
        secret = lsb.reveal(file_path)
        if secret:
            print("Hidden data found using steganography:")
            print(secret)
        else:
            print("No hidden data found using steganography.")
    except Exception as e:
        print(f"Error applying steganography tools: {e}")

def main(file_path):
    if check_file(file_path):
        extract_macros(file_path)
        extract_hidden_sheets(file_path)
        apply_stego_tools(file_path)
    else:
        print("File check failed.")

if __name__ == "__main__":
    file_path = input("Enter the path to the file: ")
    main(file_path)
