from flask import Flask, request, jsonify
import joblib, os, pickle, hashlib, torch, time
import numpy as np
from defender.models import MalConvPlus
import hashlib

from src.extract.feature_extraction import extract_features

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

        predictions = []

        # Extract features from the data
        features_data, header = extract_features(data)

        # Load Initial Model
        clf = joblib.load(os.path.join(os.path.dirname(os.path.realpath(__file__)), "../models/malware_classifier.joblib"))
        features = pickle.load(open(os.path.join(os.path.dirname(os.path.realpath(__file__)), "../models/features.pkl"), "rb"))
        pe_features = np.array([features_data[feature] for feature in features])
        prediction1 = clf.predict([pe_features])
        predictions.append(int(prediction1[0]))

        # Load Malconv Model
        embed_dim = 8
        max_len = 4096
        out_channels = 128
        window_size = 32
        dropout = 0.5
        weight_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), "../models/malconv_plus.pt")
        if torch.cuda.is_available():
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
        predictions.append(int(prediction2[0].item()))

        # Load Bodmas Model
        bodmas_clf = joblib.load(os.path.join(os.path.dirname(os.path.realpath(__file__)), "../models/bodmas/model.joblib"))
        
        prediction3 = bodmas_clf.predict([pe_features])
        predictions.append(int(prediction3[0]))
        
        # Majority Votingß
        if sum(predictions) >= 2:
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
