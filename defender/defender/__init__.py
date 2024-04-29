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

def pipeline(malconv, rf_prob0, rf_prob1):
    if rf_prob0 > 0.43:
        return 0
    elif malconv > 0.3 :
        return 1
    else:
        return 1
    
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
        malconv_path = "../models/malconv_v2.pt"
        rf_model = load_model("RF", rf_model_path)
        malconv = load_model("Malconv", malconv_path)
        # rf_model = joblib.load(os.path.join(os.path.dirname(os.path.realpath(__file__)), "../models/rf_ember_subset.joblib"))

        # Initial Variables
        predictions = []

        # Make Predictions
        rf_prediction = rf_model.predict_proba(features_data).tolist()[0]
        malconv_prediction = malconv.predict(header).tolist()[0]
        rf_label = rf_prediction.index(max(rf_prediction))
        malconv_label = int(malconv_prediction > 0.5)
        predictions = [rf_label, malconv_label]

        # predictions = [rf_prediction[0], rf_prediction[1], malconv_prediction]
        pipeline_prediction = pipeline(malconv_prediction, rf_prediction[0], rf_prediction[1])

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
