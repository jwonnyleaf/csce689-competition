from flask import Flask, request, jsonify
from dotenv import load_dotenv
import joblib
import os
import pickle
import numpy as np
import hashlib
import torch
from defender.models import MalConvPlus

from src.extract.feature_extraction import extract_features

load_dotenv()

LOCAL_FILE_PATH=os.path.join(os.path.dirname(os.path.realpath(__file__)), "../data/sample/002ce0d28ec990aadbbc89df457189de37d8adaadc9c084b78eb7be9a9820c81.exe")

def create_app():
    """Create a Flask application."""
    app = Flask(__name__)

    @app.route("/hello", methods=["GET"])
    def hello():
        return "Hello, World!"

    @app.route("/", methods=["POST"])
    def handle_request():
        if request.headers["Content-Type"] != "application/octet-stream":
            return jsonify({"error": "expecting application/octet-stream"}), 400

        data = request.get_data()
        print(f"Received {len(data)} bytes of data.")

        # Extract features from the data
        features_data, header = extract_features(data)

        # Load the model and make a prediction
        clf = joblib.load(os.path.join(os.path.dirname(os.path.realpath(__file__)), "../models/malware_classifier.joblib"))
        features = pickle.load(open(os.path.join(os.path.dirname(os.path.realpath(__file__)), "../models/features.pkl"), "rb"))
        pe_features = np.array([features_data[feature] for feature in features])
        prediction = clf.predict([pe_features])

        # Load MalConV mocdel
        embed_dim = 8
        max_len = 4096
        out_channels = 128
        window_size = 32
        dropout = 0.5
        weight_path = "../models/malconv_plus.pt"
        if torch.cuda.available():
            device = torch.device("cuda")
        else:
            device = torch.device("cpu")
        model = MalConvPlus(embed_dim, max_len, out_channels, window_size, dropout)
        model.load_state_dict(torch.load(weight_path))
        model.to(device)
        model.eval()
        input = torch.tensor(header).unsqueeze(0).to(device)
        prediction2 = model(input)
        prediction2 = (prediction2 > 0).to(int)

        if int(prediction[0]) or int(prediction2[0]):
            return jsonify({"prediction": 1})
        else:
            return jsonify({"prediction": 0})
        # return jsonify({"prediction": int(prediction[0])})

    @app.route("/model", methods=["GET"])
    def get_model():
        return jsonify({"model": "model.h5"})

    return app
