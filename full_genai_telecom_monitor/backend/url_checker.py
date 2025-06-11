def check_url(url):
    if url.startswith("https"):
        return "Secure (HTTPS) website."
    elif url.startswith("http"):
        return "Unsecure (HTTP) website detected."
    else:
        return "Invalid or non-web URL."
