from ai.predictor import predict_malware, feature_columns

# Create a dummy APK feature vector
# Every trained feature starts at 0
features = {
    column: 0
    for column in feature_columns
}

result = predict_malware(features)

print("=" * 50)
print("AI PREDICTION TEST")
print("=" * 50)

print("Predicted family :", result["family"])
print(
    "Confidence       : "
    f"{result['confidence'] * 100:.2f}%"
)
print("Prediction ID    :", result["prediction_id"])