import os.path
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
import base64
from email.mime.text import MIMEText
import random
import string

# If modifying these scopes, delete the file token.json.
SCOPES = ['https://www.googleapis.com/auth/gmail.send']

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

def main():
    """Composes and sends an email with a random OTP using the Gmail API."""
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
        to = 'vishnuprashob07@gmail.com'
        subject = 'Your OTP'
        otp = generate_otp()
        message_text = f'Your OTP is: {otp}'

        message = create_message(sender_email, to, subject, message_text)
        send_message(service, 'me', message)

    except HttpError as error:
        print(f'An error occurred: {error}')

if __name__ == '__main__':
    main()