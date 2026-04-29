import pandas as pd
import pickle
from sklearn.ensemble import RandomForestClassifier
from features_extractor import extract_features

df = pd.read_csv("final_dataset.csv")  

X_train = [extract_features(url) for url in df['url']]
y_train = df['label'].values

model = RandomForestClassifier(n_estimators=200, max_depth=10, random_state=42)
model.fit(X_train, y_train)

pickle.dump(model, open("model.pkl", "wb"))
print("Model trained and saved as model.pkl")