from transformers import pipeline

summarizer = pipeline("summarization")

def summarize_report(text):
    if len(text) < 50:
        return "Nothing significant to summarize."
    return summarizer(text, max_length=150, min_length=40, do_sample=False)[0]['summary_text']