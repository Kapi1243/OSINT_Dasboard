from osint_dashboard.nlp import ThreatNLP


if __name__ == "__main__":
    model = ThreatNLP()
    model.train_and_save_model()
    print("Model and vectorizer saved.")
