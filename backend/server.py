from flask import Flask, jsonify
from flask_cors import CORS
from secure_ai import SecureDecisionModel

app = Flask(__name__)
CORS(app) 

model = SecureDecisionModel()

@app.route('/api/traffic', methods=['GET'])
def get_traffic_analysis():
    result = model.analyze_packet()
    return jsonify(result)

if __name__ == '__main__':
    print("AI Security Engine is running on port 5000...")
    app.run(host='0.0.0.0', port=5001)