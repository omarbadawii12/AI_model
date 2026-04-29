import pickle
from features_extractor import extract_features

model = pickle.load(open("model.pkl", "rb"))

def predict_ai(url):
    features = extract_features(url)
    pred = model.predict([features])
    return int(pred[0])  # 1 = phishing, 0 = legitimate