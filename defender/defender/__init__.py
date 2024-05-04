from flask import Flask, request, jsonify
import joblib, os, pickle, hashlib, torch, time
# import pandas
# import numpy as np
import hashlib
from defender.utils.feature_extraction import extract_features
from defender.utils.load_models import load_model
# from defender.defender.utils.feature_extraction import extract_features
# from defender.defender.utils.load_models import load_model

LOCAL_FILE_PATH=os.path.join(os.path.dirname(os.path.realpath(__file__)), "../data/sample/002ce0d28ec990aadbbc89df457189de37d8adaadc9c084b78eb7be9a9820c81.exe")

def model_thresholds(rf, malconv1, malconv2, attn1, attn2):
    results = []
    results.append(int(rf[1] > 0.56))
    results.append(int(malconv1 > 0.6))
    results.append(int(malconv2 > 0.59))
    results.append(int(attn1 > 0.52))
    results.append(int(attn2 > 0.12))
    return results
def pipeline(pred_labels):
    malconv = pred_labels[1] or pred_labels[2]
    attn = pred_labels[3] or pred_labels[4]
    
    if (pred_labels[0] + malconv + attn) >= 2:
        return 1
    else:
        return 0
    
def create_app():
    """Create a Flask application."""
    app = Flask(__name__)

    @app.route("/", methods=["POST"])
    def handle_request():
        # Check if the request contains a file of type application/octet-stream
        if request.headers["Content-Type"] != "application/octet-stream":
            return jsonify({"error": "expecting application/octet-stream"}), 400

        data = request.get_data()
        print(f"Received {len(data)} bytes of data.")

        # Extract the features and header from the data
        features_data, header = extract_features(data)

        # Load the Models
        rf_model_path = "../models/rf_ember_subset_2.joblib"
        malconv1_path = "../models/malconv_custom_v0.pt"
        malconv2_path = "../models/malconv_merge.pt"
        attn1_path = "../models/attn_custom_v0.pt"
        attn2_path = "../models/attn_merge.pt"
        rf_model = load_model("RF", rf_model_path)
        malconv1 = load_model("Malconv", malconv1_path)
        malconv2 = load_model("Malconv", malconv2_path)
        attn1 = load_model("AttnRCNN", attn1_path)
        attn2 = load_model("AttnRCNN", attn2_path)
        # rf_model = joblib.load(os.path.join(os.path.dirname(os.path.realpath(__file__)), "../models/rf_ember_subset.joblib"))

        # Initial Variables
        predictions = []

        # Make Predictions
        rf_prediction = rf_model.predict_proba(features_data).tolist()[0]
        malconv1_prediction = malconv1.predict(header).tolist()[0]
        malconv2_prediction = malconv2.predict(header).tolist()[0]
        attn1_prediction = attn1.predict(header).tolist()[0]
        attn2_prediction = attn2.predict(header).tolist()[0]
        # rf_label = rf_prediction.index(max(rf_prediction))
        # malconv_label = int(malconv_prediction > 0.5)
        pred_labels = model_thresholds(rf_prediction, malconv1_prediction, malconv2_prediction, attn1_prediction, attn2_prediction)
        # predictions = [rf_prediction[0], rf_prediction[1], malconv_prediction]
        pipeline_prediction = pipeline(pred_labels)

        return jsonify({
            "malware": int(pipeline_prediction == 1),
            "predictions": predictions
        })
    
    return app

# Append Predictions
# predictions.append(int(rf_model_prediction[0]))

# Majority Voting
# malware = False
# if sum(predictions) >= len(predictions) / 2:
#     malware = True

# return jsonify({
#     "malware": malware,
#     "predictions": predictions
# })
