import os
import markdown
from xhtml2pdf import pisa

def run_conversion():
    md_path = r"C:\Users\veren\.gemini\antigravity-ide\brain\8d2160fd-5d76-4509-8377-c529372a68c2\project_documentation.md"
    pdf_path = r"C:\Users\veren\.gemini\antigravity-ide\brain\8d2160fd-5d76-4509-8377-c529372a68c2\project_documentation.pdf"
    image_path = r"C:\Users\veren\.gemini\antigravity-ide\brain\8d2160fd-5d76-4509-8377-c529372a68c2\architecture_diagram_1782235034042.png"

    print(f"Reading Markdown from: {md_path}")
    with open(md_path, "r", encoding="utf-8") as f:
        md_text = f.read()

    # Replace the markdown image placeholder with a styled HTML image block using the absolute path
    html_image = f'<div style="text-align: center; margin: 15px 0;"><img src="{image_path}" style="width: 500px; border: 1px solid #1a263f;"/></div>'
    md_text = md_text.replace("![AegisShield Architecture Diagram](/architecture_diagram_1782235034042.png)", html_image)

    # Convert markdown to html
    print("Converting Markdown to HTML...")
    html_body = markdown.markdown(md_text, extensions=['extra'])

    # Clean formatting for printing/PDF
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
    <meta charset="utf-8">
    <style>
        @page {{
            size: a4;
            margin: 2.2cm 2cm 2.2cm 2cm;
        }}
        body {{
            font-family: Helvetica, Arial, sans-serif;
            font-size: 10pt;
            line-height: 1.5;
            color: #222;
        }}
        h1 {{
            font-size: 20pt;
            color: #0b0f19;
            border-bottom: 2px solid #00f2fe;
            padding-bottom: 6px;
            margin-top: 0;
            margin-bottom: 20px;
            text-align: center;
        }}
        h2 {{
            font-size: 14pt;
            color: #0b0f19;
            margin-top: 25px;
            margin-bottom: 12px;
            border-bottom: 1px solid #ddd;
            padding-bottom: 4px;
        }}
        h3 {{
            font-size: 11pt;
            color: #3b82f6;
            margin-top: 15px;
            margin-bottom: 6px;
        }}
        p {{
            margin-bottom: 12px;
            text-align: justify;
        }}
        code {{
            font-family: Courier, monospace;
            background-color: #f3f4f6;
            padding: 1px 3px;
            font-size: 8.5pt;
        }}
        pre {{
            background-color: #f8fafc;
            border: 1px solid #e2e8f0;
            padding: 8px;
            font-size: 8pt;
            margin-bottom: 12px;
            font-family: Courier, monospace;
        }}
        pre code {{
            background-color: transparent;
            padding: 0;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 15px 0;
            font-size: 9pt;
        }}
        th, td {{
            border: 1px solid #cbd5e1;
            padding: 6px;
            text-align: left;
        }}
        th {{
            background-color: #f1f5f9;
            font-weight: bold;
            color: #0f172a;
        }}
        ul, ol {{
            margin-bottom: 12px;
        }}
        li {{
            margin-bottom: 4px;
            margin-left: 15px;
        }}
        blockquote {{
            border-left: 3px solid #00f2fe;
            background-color: #f0fdfa;
            padding: 8px 12px;
            margin: 10px 0;
            font-size: 9pt;
        }}
    </style>
    </head>
    <body>
        {html_body}
    </body>
    </html>
    """

    print(f"Writing PDF output to: {pdf_path}")
    with open(pdf_path, "w+b") as out_file:
        pisa_status = pisa.CreatePDF(html_content, dest=out_file)
        
    if not pisa_status.err:
        print("SUCCESS: PDF generated successfully!")
    else:
        print("ERROR: PDF conversion failed:", pisa_status.err)

if __name__ == "__main__":
    run_conversion()
