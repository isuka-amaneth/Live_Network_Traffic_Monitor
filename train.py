import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix

# Load the model-ready data from Phase 2
X_train, X_test, y_train, y_test, preprocessor = joblib.load('processed_data.joblib')

print("Training the Random Forest... (this takes a minute)")
model = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
model.fit(X_train, y_train)

train_acc = model.score(X_train, y_train)
predictions = model.predict(X_test)
test_acc = accuracy_score(y_test, predictions)

print(f"\nAccuracy on training data:    {train_acc:.1%}")
print(f"Accuracy on unseen TEST data: {test_acc:.1%}")

print("\nDetailed report on the test set:")
print(classification_report(y_test, predictions, target_names=['normal', 'attack'], zero_division=0))

print("Confusion matrix (rows = actual, cols = predicted):")
print(confusion_matrix(y_test, predictions))

joblib.dump(model, 'model.joblib')
print("\nSaved trained model -> model.joblib")