import os.path
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
import smtplib
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import base64

# If modifying these scopes, delete the file token.json.
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly', 'https://www.googleapis.com/auth/gmail.send']

def send_email(sender_email, sender_password, receiver_email, subject, body, html=False):
    """Sends an email.

    Args:
        sender_email: The sender's email address.
        sender_password: The sender's email password or app password.
        receiver_email: The recipient's email address.
        subject: The email subject.
        body: The email body (plain text or HTML).
        html: Boolean indicating if the body is HTML.
    """
    message = MIMEMultipart("alternative")
    message["Subject"] = subject
    message["From"] = sender_email
    message["To"] = receiver_email

    # Create the plain-text and HTML version of your message
    if html:
        part = MIMEText(body, "html")
    else:
        part = MIMEText(body, "plain")

    # Add HTML/plain-text parts to MIMEMultipart message
    # The email client will try to render the last part first
    message.attach(part)

    # Create secure connection with server and send email
    context = ssl.create_default_context()
    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=context) as server: # or your email provider's SMTP server and port
            server.login(sender_email, sender_password)
            server.sendmail(
                sender_email, receiver_email, message.as_string()
            )
        print("Email sent successfully!")

    except Exception as e:
        print(f"An error occurred: {e}")

def create_message(sender, to, subject, message_text):
  """Create a message for an email.

  Args:
    sender: Email address of the sender.
    to: Email address of the receiver.
    subject: The subject of the email message.
    message_text: The text of the email message.

  Returns:
    An object containing a base64url encoded email object.
  """
  message = MIMEText(message_text)
  message['to'] = to
  message['from'] = sender
  message['subject'] = subject
  return {'raw': base64.urlsafe_b64encode(message.as_string().encode()).decode()}

def send_message(service, user_id, message):
  """Send an email message.

  Args:
    service: Authorized Gmail API service instance.
    user_id: User's email address. The special value "me"
    can be used to indicate the authenticated user.
    message: Message to be sent.

  Returns:
    Sent Message.
  """
  try:
    message = (service.users().messages().send(userId=user_id, body=message)
               .execute())
    print('Message Id: %s' % message['id'])
    return message
  except HttpError as error:
    print('An error occurred: %s' % error)

def main():
    """Shows basic usage of the Gmail API.
    Lists the user's Gmail labels and retrieves email subjects.
    """
    creds = None
    # The file token.json stores the user's access and refresh tokens, and is
    # created automatically when the authorization flow completes for the first
    # time.
    if os.path.exists('token.json'):
        creds = Credentials.from_authorized_user_file('token.json', SCOPES)
    # If there are no (valid) credentials available, let the user log in.
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(
                'client_secret.json', SCOPES)
            creds = flow.run_local_server(port=0)
        # Save the credentials for the next run
        with open('token.json', 'w') as token:
            token.write(creds.to_json())

    try:
        # Call the Gmail API
        service = build('gmail', 'v1', credentials=creds)
        # Get email messages
        results = service.users().messages().list(userId='me').execute()
        messages = results.get('messages',)
        if not messages:
            print('No messages found.')
        else:
            print('Messages:')
            for message in messages:
                msg = service.users().messages().get(userId='me', id=message['id']).execute()
                headers = msg['payload']['headers']
                subject = [header['value'] for header in headers if header['name'] == 'Subject']
                print(f"Subject: {subject[0] if subject else 'No Subject'}")

        # Send an email to vishnuprashob07@gmail.com
        sender_email = 'pin369tar@gmail.com'  # Replace with your email
        to = 'vishnuprashob07@gmail.com'
        subject = 'Email from Gmail API'
        message_text = 'This is a test email sent from the Gmail API.'
        #create_message(sender_email, to, subject, message_text)
        send_message(service,'me',create_message(sender_email, to, subject, message_text))

    except HttpError as error:
        # TODO(developer) - Handle errors from gmail API.
        print(f'An error occurred: {error}')


if __name__ == '__main__':
    main()