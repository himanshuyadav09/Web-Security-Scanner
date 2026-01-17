from flask import Flask, render_template, request, jsonify
from scanner import analyze_security

app = Flask(__name__)

# --- ROUTE 1: The Homepage ---
@app.route('/')
def home():
    """
    Renders the main dashboard (index.html).
    """
    return render_template('index.html')

# --- ROUTE 2: The Scanning API ---
@app.route('/scan', methods=['POST'])
def scan():
    """
    Receives a URL from the frontend, sends it to scanner.py,
    and returns the security report as JSON.
    """
    try:
        # 1. Get data from the frontend request
        data = request.json
        url = data.get('url')
        
        # 2. Basic Validation
        if not url:
            return jsonify({"error": "Please provide a valid URL."}), 400
            
        # 3. Call the Scanner Engine (The "Brain")
        report = analyze_security(url)
        
        # 4. Check if the scanner returned an internal error
        if "error" in report:
            return jsonify(report), 400
            
        # 5. Send the full report back to the frontend
        return jsonify(report)

    except Exception as e:
        return jsonify({"error": f"Internal Server Error: {str(e)}"}), 500

if __name__ == '__main__':
    app.run(debug=True, port=5000)