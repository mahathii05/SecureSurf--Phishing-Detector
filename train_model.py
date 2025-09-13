import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
import joblib

def clean_labels(label):
    # Convert to int if possible (0 = legitimate, 1 = phishing)
    try:
        return int(label)
    except:
        return 0

def train_and_save():
    print("[INFO] Loading dataset...")
    df = pd.read_csv("phishing_data.csv")  # make sure file name is correct

    # Drop NaN values in essential columns
    df = df.dropna(subset=["URL", "ClassLabel"])

    # Clean labels
    df["ClassLabel"] = df["ClassLabel"].apply(clean_labels)

    # Features (X) = URLs
    X = df["URL"].astype(str)

    # Target (y) = Class labels
    y = df["ClassLabel"].astype(int)

    print("[INFO] Splitting dataset...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    print("[INFO] Vectorizing URLs...")
    vectorizer = TfidfVectorizer()
    X_train_vec = vectorizer.fit_transform(X_train)
    X_test_vec = vectorizer.transform(X_test)

    print("[INFO] Training model...")
    model = LogisticRegression(max_iter=1000)
    model.fit(X_train_vec, y_train)

    acc = model.score(X_test_vec, y_test)
    print(f"[INFO] Model trained with accuracy: {acc:.2f}")

    # Save model + vectorizer
    joblib.dump(model, "phishing_model.pkl")
    joblib.dump(vectorizer, "vectorizer.pkl")
    print("[INFO] Model and vectorizer saved successfully!")

if __name__ == "__main__":
    train_and_save()
