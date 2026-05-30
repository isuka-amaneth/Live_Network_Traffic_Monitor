import joblib
from sklearn.metrics import confusion_matrix

X_train, X_test, y_train, y_test, preprocessor = joblib.load('processed_data.joblib')
model = joblib.load('model.joblib')

# For each test connection, how sure is the model it's an attack? (0.0 to 1.0)
attack_proba = model.predict_proba(X_test)[:, 1]

print(f"{'Threshold':>10} | {'Attacks caught':>15} | {'Missed':>7} | {'False alarms':>13}")
print("-" * 56)
for t in [0.50, 0.40, 0.30, 0.20, 0.10]:
    preds = (attack_proba >= t).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_test, preds, labels=[0, 1]).ravel()
    recall = tp / (tp + fn)
    print(f"{t:>10.2f} | {recall:>14.1%} | {fn:>7} | {fp:>13}")