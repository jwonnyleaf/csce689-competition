from flask import Flask, request, jsonify
import joblib, os, pickle, hashlib, torch, time
import numpy as np
from defender.models import MalConvPlus
import hashlib
from tensorflow.keras.models import model_from_json
import ember

LOCAL_FILE_PATH=os.path.join(os.path.dirname(os.path.realpath(__file__)), "../data/sample/002ce0d28ec990aadbbc89df457189de37d8adaadc9c084b78eb7be9a9820c81.exe")

def create_app():
    """Create a Flask application."""
    app = Flask(__name__)

    @app.route("/hello", methods=["GET"])
    def hello():
        return "Hello, World!"

    @app.route("/", methods=["POST"])
    def handle_request():
        start_time = time.time()
        malware = 0

        if request.headers["Content-Type"] != "application/octet-stream":
            return jsonify({"error": "expecting application/octet-stream"}), 400

        data = request.get_data()
        print(f"Received {len(data)} bytes of data.")

        # Use Ember to extract features
        extractor = ember.PEFeatureExtractor()
        features = extractor.feature_vector(data)
        features = np.array(features).reshape(1, -1)

        predictions = []

        # Load Neural Network Model
        model_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), "../models/model.json")
        weights_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), "../models/model.h5")
        with open(model_path, "r") as json_file:
            model = json_file.read()

        nn_model = model_from_json(model)
        nn_model.load_weights(weights_path)

        nn_prediction = nn_model.predict(features)
        predictions.append(nn_prediction[0][0])
        
        # Majority Voting
        if sum(predictions) >= 1:
            malware = 1
        
        end_time = time.time() 
        elapsed_time = end_time - start_time
        return jsonify({
            "malware": malware,
            "elapsed_time": elapsed_time,
            "predictions": predictions
        })
    
    @app.route("/model", methods=["GET"])
    def get_model():
        return jsonify({"model": "tbd"})

    return app
