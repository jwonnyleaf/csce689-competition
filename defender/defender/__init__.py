from flask import Flask, request, jsonify
import joblib, os, pickle, hashlib, torch, time
import numpy as np
from defender.models import MalConvPlus
import hashlib
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

        # Load PyTorch model (malware detection)
        class MalwareDetector(nn.Module):
            def __init__(self, input_size, hidden_size, output_size):
                super(MalwareDetector, self).__init__()
                self.rnn = nn.RNN(input_size, hidden_size, batch_first=True)
                self.fc = nn.Linear(hidden_size, output_size)

            def forward(self, x):
                x = x.unsqueeze(1)
                out, _ = self.rnn(x)
                last_output = out[:, -1, :]
                out = self.fc(last_output)
                return out


        input_size = features.shape[1]
        hidden_size = 64
        output_size = 2
        dl_model = MalwareDetector(input_size, hidden_size, output_size)
        dl_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), "../models/malware_detector.pth")
        dl_model.load_state_dict(torch.load(dl_path))
        dl_model.eval()

        with torch.no_grad():
            features = torch.tensor(features, dtype=torch.float32)
            output = dl_model(features)
            _, predicted = torch.max(output, 1)
            predictions.append(predicted.item())

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
