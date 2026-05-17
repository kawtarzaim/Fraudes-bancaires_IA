import pandas as pd
from sklearn.tree import DecisionTreeClassifier


# Simple training dataset inside the code.
# Hna dataset sghir bzaaf bach l student yfham AI b easily.
training_data = [
    # ip_score, country_code, login_hour, label
    [0, 0, 9, 0],  # local IP, home country, normal morning login
    [1, 0, 14, 0],  # normal IP, home country, afternoon login
    [1, 1, 2, 1],  # normal IP, foreign country, late night login -> suspicious
    [2, 1, 3, 1],  # suspicious IP, foreign country, early morning login -> suspicious
    [1, 2, 22, 1],  # normal IP, new country, late night -> suspicious
    [0, 0, 19, 0],  # local IP, home country, evening login
    [1, 0, 23, 1],  # normal IP, home country, very late login -> suspicious
]

feature_names = ['ip_score', 'country_code', 'login_hour']

# Create a simple Decision Tree model for beginner.
model = DecisionTreeClassifier(random_state=42)


def train_model():
    """Train a small model and return it."""
    df = pd.DataFrame(training_data, columns=feature_names + ['label'])
    X = df[feature_names]
    y = df['label']
    model.fit(X, y)
    return model


def encode_ip_address(ip_address: str) -> int:
    """Convert an IP address into a simple numeric score."""
    if ip_address.startswith('127.') or ip_address.startswith('192.') or ip_address.startswith('10.'):
        return 0
    suspicious_ips = ['185.33.34.1', '77.55.66.10', '123.45.67.89']
    if ip_address in suspicious_ips:
        return 2
    return 1


def encode_country(country: str) -> int:
    """Convert country to a simple code for the AI model."""
    if country in ['Morocco', 'Local', 'Unknown']:
        return 0
    if country in ['France', 'Spain', 'Germany', 'Italy']:
        return 1
    return 2


def predict_login(ip_address: str, country: str, login_hour: int) -> str:
    """Predict if this login is normal or suspicious."""
    # AI kay7لل wach login مشبوه ولا لا
    trained_model = train_model()
    features = [[encode_ip_address(ip_address), encode_country(country), login_hour]]
    prediction = trained_model.predict(features)[0]
    if prediction == 0:
        return 'Normal Login'
    return 'Suspicious Login'
