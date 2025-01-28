import subprocess
import sys

def pdf_to_text(pdf_path, txt_path):
    try:
        # Run pdftotext command
        subprocess.run(['pdftotext', pdf_path, txt_path], check=True)
        print(f"Conversion successful: {txt_path}")
    except subprocess.CalledProcessError as e:
        print(f"Error during conversion: {e}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python pdf_to_text.py <input_pdf> <output_txt>")
        sys.exit(1)
    
    input_pdf = sys.argv[1]
    output_txt = sys.argv[2]
    
    pdf_to_text(input_pdf, output_txt)
