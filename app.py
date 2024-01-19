from flask import Flask, render_template, request
import pickle
from scapy.all import IP, TCP
import numpy as np

with open("rf_1.pkl", "rb") as file:
    model = pickle.load(file)




def prediction_(protocol_type, service, flag, src_bytes, dst_bytes, land, wrong_fragment, urgent,
                hot, num_failed_logins, logged_in, num_compromised, root_shell, su_attempted,
                num_file_creations, num_shells, num_access_files, num_outbound_cmds,
                is_host_login, is_guest_login, count, srv_count, serror_rate, rerror_rate,
                same_srv_rate, diff_srv_rate, srv_diff_host_rate, dst_host_count,
                dst_host_srv_count, dst_host_same_srv_rate, dst_host_diff_srv_rate,
                dst_host_same_src_port_rate, dst_host_srv_diff_host_rate):

    features=[ protocol_type, service,flag, src_bytes,dst_bytes, land,
        wrong_fragment, urgent, hot, num_failed_logins, logged_in,
        num_compromised, root_shell, su_attempted, num_file_creations,
        num_shells, num_access_files, num_outbound_cmds, is_host_login,
        is_guest_login,count, srv_count, serror_rate, rerror_rate,
        same_srv_rate, diff_srv_rate, srv_diff_host_rate,dst_host_same_srv_rate,
        dst_host_count, dst_host_srv_count, dst_host_diff_srv_rate,
        dst_host_same_src_port_rate, dst_host_srv_diff_host_rate]
    len(features)
    features = np.array([features]) 
    result=model.predict(features)
    print(result)
    return result



app = Flask(__name__)
@app.route('/')
def index():
    return render_template('home.html')

@app.route('/get_data', methods=['GET', 'POST'])
def get_data():
    if request.method == 'POST':
        protocol_type = request.form.get('protocol_type')
        service = request.form.get('service')
        flag = request.form.get('flag')
        src_bytes = request.form.get('src_bytes')
        dst_bytes = request.form.get('dst_bytes')
        land = request.form.get('land')
        wrong_fragment = request.form.get('wrong_fragment')
        urgent = request.form.get('urgent')
        hot = request.form.get('hot')
        num_failed_logins = request.form.get('num_failed_logins')
        logged_in = request.form.get('logged_in')
        num_compromised = request.form.get('num_compromised')
        root_shell = request.form.get('root_shell')
        su_attempted = request.form.get('su_attempted')
        num_file_creations = request.form.get('num_file_creations')
        num_shells = request.form.get('num_shells')
        num_access_files = request.form.get('num_access_files')
        num_outbound_cmds = request.form.get('num_outbound_cmds')
        is_host_login = request.form.get('is_host_login')
        is_guest_login = request.form.get('is_guest_login')
        count = request.form.get('count')
        srv_count = request.form.get('srv_count')
        serror_rate = request.form.get('serror_rate')
        rerror_rate = request.form.get('rerror_rate')
        same_srv_rate = request.form.get('same_srv_rate')
        diff_srv_rate = request.form.get('diff_srv_rate')
        srv_diff_host_rate = request.form.get('srv_diff_host_rate')
        dst_host_count = request.form.get('dst_host_count')
        dst_host_srv_count = request.form.get('dst_host_srv_count')
        dst_host_same_srv_rate = request.form.get('dst_host_same_srv_rate')
        dst_host_diff_srv_rate = request.form.get('dst_host_diff_srv_rate')
        dst_host_same_src_port_rate = request.form.get('dst_host_same_src_port_rate')
        dst_host_srv_diff_host_rate = request.form.get('dst_host_srv_diff_host_rate')

        result=prediction_(protocol_type, service, flag, src_bytes, dst_bytes, land, wrong_fragment, urgent,
                hot, num_failed_logins, logged_in, num_compromised, root_shell, su_attempted,
                num_file_creations, num_shells, num_access_files, num_outbound_cmds,
                is_host_login, is_guest_login, count, srv_count, serror_rate, rerror_rate,
                same_srv_rate, diff_srv_rate, srv_diff_host_rate, dst_host_count,
                dst_host_srv_count, dst_host_same_srv_rate, dst_host_diff_srv_rate,
                dst_host_same_src_port_rate, dst_host_srv_diff_host_rate)
        return render_template('result.html', data=result)
if __name__ == '__main__':
    app.run(debug=True)
