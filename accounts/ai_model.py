import pandas as pd
from sklearn.tree import DecisionTreeClassifier


# Balanced training dataset for a simple student fraud-detection model.
#
# Why suspicious detection almost disappeared:
# The previous dataset reduced false positives by teaching the model that many
# late logins are normal. That was useful, but it removed too many realistic
# suspicious cases. The Decision Tree then had very few fraud examples to learn
# from, so it almost always predicted "Normal Login".
#
# How this dataset restores balanced detection:
# We keep many normal examples, including late logins from the home country, but
# we add realistic fraud examples using only existing project features:
# IP score, country code, login hour, and failed attempts.
#
# Labels:
# 0 = Normal Login
# 1 = Suspicious Login
training_data = [
    # Format: [ip_score, country_code, login_hour, failed_attempts, label]

    # Normal: home/local country, normal or local IP, any hour.
    [0, 0, 8, 0, 0],
    [0, 0, 14, 0, 0],
    [0, 0, 20, 0, 0],
    [0, 0, 23, 0, 0],
    [0, 0, 2, 0, 0],
    [1, 0, 7, 0, 0],
    [1, 0, 11, 0, 0],
    [1, 0, 16, 0, 0],
    [1, 0, 22, 0, 0],
    [1, 0, 3, 0, 0],

    # Normal: late login alone is allowed when the country/IP are normal.
    [1, 0, 0, 0, 0],
    [1, 0, 1, 0, 0],
    [1, 0, 4, 0, 0],

    # Normal: travel from nearby/known countries with a normal IP.
    [1, 1, 8, 0, 0],
    [1, 1, 12, 0, 0],
    [1, 1, 18, 0, 0],
    [1, 1, 21, 0, 0],
    [1, 2, 10, 0, 0],
    [1, 2, 15, 0, 0],

    # Normal: one or two failed attempts can be a user mistake.
    [1, 0, 9, 1, 0],
    [1, 0, 19, 2, 0],
    [1, 1, 13, 1, 0],
    [1, 1, 20, 2, 0],

    # Suspicious: more than 3 failed attempts.
    [1, 0, 9, 4, 1],
    [1, 0, 21, 4, 1],
    [1, 1, 14, 4, 1],
    [1, 2, 16, 4, 1],
    [0, 0, 2, 4, 1],

    # Suspicious: suspicious IP combined with failed attempts.
    [2, 0, 10, 1, 1],
    [2, 0, 22, 2, 1],
    [2, 1, 12, 1, 1],
    [2, 2, 18, 1, 1],

    # Suspicious: suspicious IP plus foreign country.
    [2, 1, 9, 0, 1],
    [2, 1, 23, 0, 1],
    [2, 2, 11, 0, 1],
    [2, 2, 3, 0, 1],

    # Suspicious: unusual hour plus foreign country plus some failed attempts.
    [1, 1, 2, 2, 1],
    [1, 1, 3, 2, 1],
    [1, 2, 1, 1, 1],
    [1, 2, 4, 2, 1],
]

feature_names = ['ip_score', 'country_code', 'login_hour', 'failed_attempts']

model = DecisionTreeClassifier(random_state=42, max_depth=4)


def train_model():
    """Train and return the Decision Tree classifier."""
    df = pd.DataFrame(training_data, columns=feature_names + ['label'])
    X = df[feature_names]
    y = df['label']
    model.fit(X, y)
    return model


def encode_ip_address(ip_address: str) -> int:
    """
    Convert an IP address into a simple risk score.

    0 = local/trusted IP
    1 = normal external IP
    2 = suspicious IP from the project's example blocklist
    """
    if ip_address.startswith('127.') or ip_address.startswith('192.') or ip_address.startswith('10.'):
        return 0

    suspicious_ips = ['185.33.34.1', '77.55.66.10', '123.45.67.89']
    if ip_address in suspicious_ips:
        return 2

    return 1


def encode_country(country: str) -> int:
    """
    Convert country to a simple code.

    0 = home/local country
    1 = nearby/known foreign countries
    2 = other foreign countries
    """
    if country in ['Morocco', 'Local', 'Unknown']:
        return 0
    if country in ['France', 'Spain', 'Germany', 'Italy']:
        return 1
    return 2


def predict_login(ip_address: str, country: str, login_hour: int, failed_attempts: int = 0) -> str:
    """
    Predict whether a login is normal or suspicious.

    The Decision Tree uses only existing project features:
    IP address analysis, country checking, login hour, and failed attempts.

    Extra simple rules are kept before the model so the expected behavior is
    clear and easy to explain:
    - more than 3 failed attempts is suspicious
    - suspicious IP plus any failed attempts is suspicious
    - late hour alone is not suspicious
    """
    ip_score = encode_ip_address(ip_address)
    country_code = encode_country(country)

    if failed_attempts > 3:
        return 'Suspicious Login'

    if ip_score == 2 and failed_attempts > 0:
        return 'Suspicious Login'

    trained_model = train_model()
    features = pd.DataFrame(
        [[ip_score, country_code, login_hour, failed_attempts]],
        columns=feature_names,
    )
    prediction = trained_model.predict(features)[0]

    if prediction == 0:
        return 'Normal Login'
    return 'Suspicious Login'
