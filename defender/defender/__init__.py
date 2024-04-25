import pandas
from flask import Flask, request, jsonify
import joblib, os, pickle, hashlib, torch, time
import numpy as np
import hashlib
from defender.feature_extraction import extract_features

LOCAL_FILE_PATH=os.path.join(os.path.dirname(os.path.realpath(__file__)), "../data/sample/002ce0d28ec990aadbbc89df457189de37d8adaadc9c084b78eb7be9a9820c81.exe")

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
        features_data = extract_features(data)

        # Load the Models

        # Initial Variables
        predictions = []

        # Majority Voting
        malware = False
        if sum(predictions) >= len(predictions) / 2:
            malware = True
        
        return jsonify({
            "malware": malware,
            "predictions": predictions
        })

    return app
