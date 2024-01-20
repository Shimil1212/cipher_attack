from flask import Flask, render_template, request
import pickle
from scapy.all import IP, TCP
import numpy as np

# Load the pre-trained model
with open("rf_1.pkl", "rb") as file:
    model = pickle.load(file)

# Function to make predictions
def make_prediction(protocol_type, service, flag, src_bytes, dst_bytes, land, wrong_fragment, urgent,
                    hot, num_failed_logins, logged_in, num_compromised, root_shell, su_attempted,
                    num_file_creations, num_shells, num_access_files, num_outbound_cmds,
                    is_host_login, is_guest_login, count, srv_count, serror_rate, rerror_rate,
                    same_srv_rate, diff_srv_rate, srv_diff_host_rate, dst_host_count,
                    dst_host_srv_count, dst_host_same_srv_rate, dst_host_diff_srv_rate,
                    dst_host_same_src_port_rate, dst_host_srv_diff_host_rate):

    # Create a feature array
    features = [protocol_type, service, flag, src_bytes, dst_bytes, land,
                wrong_fragment, urgent, hot, num_failed_logins, logged_in,
                num_compromised, root_shell, su_attempted, num_file_creations,
                num_shells, num_access_files, num_outbound_cmds, is_host_login,
                is_guest_login, count, srv_count, serror_rate, rerror_rate,
                same_srv_rate, diff_srv_rate, srv_diff_host_rate, dst_host_count,
                dst_host_srv_count, dst_host_same_srv_rate, dst_host_diff_srv_rate,
                dst_host_same_src_port_rate, dst_host_srv_diff_host_rate]
    
    # Convert features to a NumPy array
    features = np.array([features]) 

    # Make a prediction
    result = model.predict(features)
    return result

# Create a Flask web application
app = Flask(__name__)

# Route for the home page
@app.route('/')
def index():
    return render_template('home.html')

# Route to handle form submission and display result
@app.route('/get_data', methods=['POST'])
def get_data():
    if request.method == 'POST':
        # Get form data
        form_data = {field: request.form.get(field) for field in request.form}
        
        # Make a prediction using the form data
        result = make_prediction(**form_data)

        # Render the result template
        return render_template('result.html', data=result)

if __name__ == '__main__':
    # Run the Flask app in debug mode
    app.run(debug=True)
