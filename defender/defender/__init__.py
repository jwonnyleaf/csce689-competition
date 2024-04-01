from flask import Flask, request, jsonify
from dotenv import load_dotenv

load_dotenv()

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
        return jsonify({"data": data.decode("utf-8")}, 200)

    @app.route("/model", methods=["GET"])
    def get_model():
        return jsonify({"model": "model.h5"})

    return app
