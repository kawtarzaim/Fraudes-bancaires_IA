import requests


def get_client_ip(request):
    """Get the real client IP address from request headers."""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0].strip()
        return ip
    return request.META.get('REMOTE_ADDR', '127.0.0.1')


def get_country_from_ip(ip_address: str) -> str:
    """Find the country from the IP using a free API or fallback values."""
    if ip_address.startswith('127.') or ip_address.startswith('192.') or ip_address.startswith('10.'):
        return 'Local'

    try:
        url = f'https://ipapi.co/{ip_address}/country_name/'
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            country = response.text.strip()
            if country:
                return country
    except requests.RequestException:
        pass

    # Fallback if API is not available.
    return 'Unknown'
