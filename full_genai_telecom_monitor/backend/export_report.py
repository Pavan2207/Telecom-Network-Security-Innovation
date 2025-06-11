from jinja2 import Environment, FileSystemLoader
import pdfkit

def export_to_pdf(summary_text, output_pdf):
    env = Environment(loader=FileSystemLoader('templates'))
    template = env.get_template('report.html')
    html_out = template.render(summary=summary_text)
    pdfkit.from_string(html_out, output_pdf)
