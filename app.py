# Import the Flask class from the flask package
from flask import Flask, jsonify

# Create an instance of the Flask class.
# __name__ is a special Python variable that gets the name of the current module.
# Flask uses this to know where to look for resources like templates and static files.
app = Flask(__name__)

# Define a route. This tells Flask what URL should trigger the following function.
# When someone visits the root URL ('/') of your application, this function will run.
@app.route('/')
def home():
    """
    This function handles requests to the homepage.
    It returns a simple JSON response.
    """
    return jsonify({"message": "Welcome to the Awards Voting Backend!"})

# Define another route for a simple API endpoint.
# When someone visits '/api/status', this function will run.
@app.route('/api/status')
def status():
    """
    This function provides a simple status check for the API.
    It returns a JSON response indicating the API is operational.
    """
    return jsonify({"status": "API is up and running!"})

# This block ensures that the Flask development server only runs when
# the script is executed directly (not when imported as a module).
if __name__ == '__main__':
    # Run the Flask application in debug mode.
    # Debug mode provides helpful error messages in your browser
    # and automatically reloads the server when you make code changes.
    # IMPORTANT: Do NOT use debug=True in a production environment due to security risks.
    app.run(debug=True)