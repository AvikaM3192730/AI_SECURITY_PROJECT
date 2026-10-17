"""
Enterprise API Server for MI_GUARD
===================================
Provides a secure REST API endpoint to access the judge_agent.

Setup:
1. pip install Flask Flask-Limiter
2. python3 server.py

Test using:
curl -X POST http://127.0.0.1:5000/api/analyze -H "Content-Type: application/json" -d '{"prompt": "Hello"}'
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# Import our secure LangGraph pipeline.
# NOTE: it must NOT be named `app` here - that name belongs to the Flask app.
# (The original code imported it as `app` and then overwrote it with the
# Flask instance, so /api/analyze crashed on every request.)
from judge_agent import app as judge_app

app = Flask(__name__)
CORS(app)

# Initialize Rate Limiter
# This will track requests by the user's IP address (get_remote_address)
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["100 per day", "10 per minute"],
    storage_uri="memory://"
)

# Global session memory store for IP addresses (for demonstration)
session_memories = {}

@app.route("/api/analyze", methods=["POST"])
@limiter.limit("5 per minute")  # Strict rate limit for the expensive LLM endpoint
def analyze_prompt():
    """
    Endpoint that accepts a JSON payload with a 'prompt'
    and returns the Security Judge's evaluation.
    """
    data = request.get_json()
    
    if not data or "prompt" not in data:
        return jsonify({"error": "Missing 'prompt' in JSON body"}), 400
        
    user_prompt = data["prompt"]
    client_ip = get_remote_address()
    
    # Initialize session memory for this IP if it doesn't exist
    if client_ip not in session_memories:
        session_memories[client_ip] = []
        
    try:
        # Run the enterprise LangGraph pipeline
        result_state = judge_app.invoke({
            "user_input": user_prompt,
            "session_history": session_memories[client_ip]
        })

        verdict = result_state.get("verdict", "UNKNOWN")
        reason = result_state.get("reason", "")
        critic_score = result_state.get("critic_score", 0.0)
        
        # Update session memory (sliding window of 4)
        session_memories[client_ip].append(user_prompt)
        if len(session_memories[client_ip]) > 4:
            session_memories[client_ip].pop(0)
            
        return jsonify({
            "status": "success",
            "verdict": verdict,
            "reason": reason,
            "critic_score": critic_score,
            "rate_limit_policy": "5 requests per minute"
        })
        
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500

@app.errorhandler(429)
def ratelimit_handler(e):
    """Custom error handling when a hacker hits the Rate Limit (DDoS defense)."""
    print(f"\n[Security Alert] DDoS Attempt Blocked! Rate limit exceeded by IP.\n")
    return jsonify({
        "status": "blocked",
        "error": "RATE_LIMIT_EXCEEDED",
        "message": "You have exceeded the maximum allowed requests (5 per minute). Firewall active."
    }), 429

if __name__ == "__main__":
    print("=" * 60)
    print("  MI_GUARD | Enterprise API Server")
    print("  Rate Limiting Active: 5 requests / minute per IP")
    print("=" * 60)
    app.run(host="0.0.0.0", port=5001)
