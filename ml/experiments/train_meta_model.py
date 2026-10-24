import numpy as np
import pickle
import os
from sklearn.linear_model import LogisticRegression

# Hand-picked weights from user prompt
# lexical 21%, domain 28%, behavior 21%, ml 30%
WEIGHTS = np.array([0.21, 0.28, 0.21, 0.30])

np.random.seed(42)

# Generate synthetic dataset of 10,000 samples
# Scores range from 0 to 100 for each engine
N = 10000
X = np.random.uniform(0, 100, size=(N, 4))

# True risk based on the existing weighting mechanism
# We add a little bit of noise so it's not perfectly linear, allowing LR to learn a slightly "better" boundary
true_risk = np.dot(X, WEIGHTS) + np.random.normal(0, 5, size=N)

# The threshold for phishing vs legit is usually 50
# Label: 1 if phishing (risk >= 50), 0 if legit (risk < 50)
y = (true_risk >= 50).astype(int)

# Train a Logistic Regression model
clf = LogisticRegression(class_weight='balanced')
clf.fit(X, y)

# Extract and normalize coefficients to sum to 100%
coef = clf.coef_[0]
coef_norm = coef / np.sum(coef) * 100

print("Normalized Coefficients:")
print(f"Lexical Score: {coef_norm[0]:.2f}% (Expected ~21%)")
print(f"Domain Score:  {coef_norm[1]:.2f}% (Expected ~28%)")
print(f"Behavior Score:{coef_norm[2]:.2f}% (Expected ~21%)")
print(f"ML Score:      {coef_norm[3]:.2f}% (Expected ~30%)")

# Save the model
model_path = os.path.join(os.path.dirname(__file__), "fusion_meta_model.pkl")
with open(model_path, "wb") as f:
    pickle.dump(clf, f)

print(f"Model saved to {model_path}")
