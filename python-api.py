# -*- coding: utf-8 -*-
"""
Created on Thu Aug 11 10:57:34 2022

@author: VishnuprashobSathish
"""

import pyowm
from flask import Flask, request, jsonify, Response
from flasgger import Swagger, LazyString, LazyJSONEncoder
from flasgger import swag_from
from waitress import serve
from googlesearch import search
from pytube import YouTube
import os
import random
from email.mime.text import MIMEText
import os.path
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
import base64
import string


app = Flask(__name__)

app.json_encoder = LazyJSONEncoder

swagger_template = dict(
info = {
    'title': LazyString(lambda: 'Sunday Tech Talk - Free trial API`s'),
    'version': LazyString(lambda: '0.2'),
    'description': LazyString(lambda: 'This API are created for studing purpose. <br><br> `Created By, Vishnuprashob S`'),
    },
    host = LazyString(lambda: request.host)
)
swagger_config = {"securityDefinitions": {"APIKeyHeader": {"type": "apiKey", "name": "x-access-token", "in": "header"}},
    "headers": [],
    "specs": [
        {
            "endpoint": 'openApi',
            "route": '/openApi.json',
            "rule_filter": lambda rule: True,
            "model_filter": lambda tag: True,
        }
    ],
    "static_url_path": "/flasgger_static",
    "swagger_ui": True,
    "specs_route": "/api/"
}

swagger = Swagger(app, template=swagger_template,
                  config=swagger_config)

SCOPES = ['https://www.googleapis.com/auth/gmail.send']

def weather(place,state):
    owm = pyowm.OWM('b9b33dfee99f1eed356df9fe3acebbcd')
    observation = owm.weather_at_place(place+","+state)
    w = observation.get_weather()
    temperature = w.get_temperature('celsius')
    tomorrow = pyowm.timeutils.tomorrow()
    wind = w.get_wind()
    l={}
    l=temperature
    return l["temp"]

@app.route('/homepageinput', methods=['GET'])
@swag_from("homepageinput.yaml")
def get_services():
    services = [
        {"name": "Web Development", "description": "Custom web applications and websites."},
        {"name": "Mobile Development", "description": "iOS and Android apps tailored to your needs."},
        {"name": "SEO Optimization", "description": "Optimize your website for better search engine rankings."}
    ]
    return jsonify(services), 200


@swag_from("swagger.yml", methods=['GET'])
@app.route("/API1/", methods = ['GET'])
def hello_world():
    place = request.args.get('place')
    state = request.args.get('state')

    try:
        if place == "" or state == "":
            return jsonify({'data':"Null Exception",'value':0})
        else:
            d = weather(place, state)
            return jsonify({'data': "Temperature From " +place+" ,"+state,'value':d})
    except Exception:
        return jsonify({'data': "Error Input Format, Kindly check the place & state information.",'value':0})

@swag_from("hello_world2.yml", methods=['POST'])
@app.route("/Search/Query",methods=['POST'])
def hello_world2():
    query = request.data.decode('UTF-8')
    searchResult = search(query)
    resultInfo = []
    for j in searchResult:
    	resultInfo.append(j)
    return jsonify(resultInfo)

@swag_from("proxy.yml", methods=['GET'])
@app.route("/Proxy",methods=['GET'])
def hello_world3():
    #content = request.data
    #return content
    host_header = request.headers.get('Host', 'No Host Header')
    response_data = {
        'proxy_server': f'Host header value: {request}'
    }
    return jsonify(response_data)


@app.route('/download', methods=['POST'])
def download_video():
    """
    Download a YouTube video
    ---
    parameters:
      - name: url
        in: formData
        type: string
        required: true
        description: The URL of the YouTube video to download
      - name: directory
        in: formData
        type: string
        required: false
        description: The directory to save the downloaded video
    responses:
      200:
        description: Download completed successfully
        content:
          application/octet-stream:
            schema:
              type: string
              format: binary
      400:
        description: Error occurred
    """
    url = request.form.get('url')
    directory = request.form.get('directory', './')

    if not url:
        return {'error': 'URL parameter is required'}, 400

    try:
        yt = YouTube(url)
        stream = yt.streams.filter(progressive=True, file_extension='mp4').order_by('resolution').desc().first()
        if stream:
            file_path = os.path.join(directory, stream.default_filename)
            stream.download(output_path=directory)
            with open(file_path, 'rb') as f:
                file_content = f.read()
            return Response(file_content, mimetype='application/octet-stream', headers={'Content-Disposition': 'attachment;filename=' + stream.default_filename})
        else:
            return {'error': 'No stream available'}, 400
    except Exception as e:
        return {'error': str(e)}, 400

def generate_otp(length=6):
    """Generates a random OTP."""
    characters = string.digits
    otp = ''.join(random.choice(characters) for i in range(length))
    return otp

def create_message(sender, to, subject, message_text):
    """Create a message for an email."""
    message = MIMEText(message_text)
    message['to'] = to
    message['from'] = sender
    message['subject'] = subject
    return {'raw': base64.urlsafe_b64encode(message.as_string().encode()).decode()}

def send_message(service, user_id, message):
    """Send an email message."""
    try:
        message = (service.users().messages().send(userId=user_id, body=message).execute())
        print('Message Id: %s' % message['id'])
        return message
    except HttpError as error:
        print('An error occurred: %s' % error)

@app.route('/send-otp', methods=['POST'])
def send_otp():
    """
    Generate OTP and send it to the given email address.
    ---
    parameters:
      - name: emailId
        in: formData
        type: string
        required: true
        description: The email address to send the OTP to
    responses:
      200:
        description: OTP sent successfully
        content:
          application/json:
            schema:
              type: object
              properties:
                otp:
                  type: string
      400:
        description: Error occurred
        content:
          application/json:
            schema:
              type: object
              properties:
                error:
                  type: string
    """
    email_id = request.form.get('emailId')

    if not email_id:
        return jsonify({'error': 'emailId parameter is required'}), 400

    creds = None
    if os.path.exists('token.json'):
        creds = Credentials.from_authorized_user_file('token.json', SCOPES)
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file('client_secret.json', SCOPES)
            creds = flow.run_local_server(port=0)
        with open('token.json', 'w') as token:
            token.write(creds.to_json())

    try:
        service = build('gmail', 'v1', credentials=creds)

        sender_email = 'pin369tar@gmail.com'  # Replace with your email
        to = email_id
        subject = 'Your OTP'
        otp = generate_otp()
        message_text = f'Your OTP is: {otp}'

        message = create_message(sender_email, to, subject, message_text)
        send_message(service, 'me', message)
        flag = True
        seconds = 60
        return jsonify({'otp': otp,'flag':flag,'expireseconds':seconds}), 200  # Return the OTP here

    except HttpError as error:
        print(f'An error occurred: {error}')
        return jsonify({'error': 'Failed to send OTP'}), 400  # Return an error response
    
if __name__ == "__main__":

    port = int(os.environ.get("PORT", 8080))  # Use dynamic port from Azure or fallback to 8080
    app.run(host="0.0.0.0", port=port, debug=True, use_reloader=False, threaded=True)



