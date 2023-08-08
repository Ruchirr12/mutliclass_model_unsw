from flask import Flask, render_template, request
import pickle
import numpy as np
import pandas as pd

filename = 'randomforestmulti.pkl'
classifier = pickle.load(open(filename,'rb'))
model = pickle.load(open('randomforestmulti.pkl','rb'))

app = Flask(__name__, template_folder= "template") #template folder

@app.route('/',methods=['GET'])
def index():
    return render_template('index.html')

@app.route('/',methods=['POST'])
def predict_value():
    input_features = [int(x) for x in request.form.values()]
    features_value = [np.array(input_features)]
    feature_name = ['dttl','swin','dwin','tcprtt','synack',
                    'ackdat','proto_tcp','proto_udp','service_dns','state_CON',
                    'state_FIN','attack_cat_Analysis','attack_cat_DoS',
                    'attack_cat_Exploits','attack_cat_Normal']
    df = pd.DataFrame(features_value, columns = feature_name)
    output = model.predict(df)
    if output == 1:
        resvalue = 'intrusion detect'
    else:
        resvalue = " not being detected"
        
    return render_template('parkinsonresult.html', prediction_text='Following Diagnosis is made:{}'. format(resvalue))
    
if __name__ == "__main__":
    app.run(host="0.0.0.0",port=8080)