import numpy as np
from sklearn.ensemble import IsolationForest

class AnomalyModel:
    def __init__(self):
        self.model = IsolationForest(n_estimators=100, contamination=0.1, random_state=42)

    def train(self, data):
        """Train the model with the given data."""
        self.model.fit(data)

    def predict(self, data):
        """Predict anomalies in the given data.

        Returns:
            1 for normal, -1 for anomaly.
        """
        return self.model.predict(data)

    def save_model(self, filepath):
        """Save the trained model to a file."""
        import joblib
        joblib.dump(self.model, filepath)

    def load_model(self, filepath):
        """Load a trained model from a file."""
        import joblib
        self.model = joblib.load(filepath)
