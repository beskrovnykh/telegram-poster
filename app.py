import datetime
import google.oauth2.credentials
import google_auth_oauthlib.flow

from ast import literal_eval
from http.cookies import SimpleCookie
from urllib.parse import urlencode
from chalice import Chalice, Response
from googleapiclient.discovery import build

CLIENT_SECRETS_FILE = "chalicelib/client_secret.json"
REDIRECT_URI = 'https://1cb0-46-246-96-169.ngrok-free.app/oauth2callback'
SCOPES = [
    'https://www.googleapis.com/auth/drive.readonly'
]

app = Chalice(app_name='console')


@app.route('/')
def index():
    return {'hello': 'world'}


@app.route('/authorize')
def authorize():
    flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE,
        scopes=SCOPES)

    flow.redirect_uri = REDIRECT_URI

    authorization_url, state = flow.authorization_url(
        access_type='offline',
        include_granted_scopes='true')
    return Response(
        body='',
        headers={
            'Location': authorization_url,
            'Set-Cookie': "state=%s" % (state)
        },
        status_code=302
    )


@app.route('/oauth2callback')
def oauth2callback():
    print("oauth2callback")
    try:
        req = app.current_request
        cookieData = req.headers.get('Cookie')
        cookie = SimpleCookie()
        cookie.load(cookieData)
        state = cookie.get('state').value
        flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(CLIENT_SECRETS_FILE, scopes=SCOPES, state=state)
        flow.redirect_uri = REDIRECT_URI
        authorization_response = 'https://' + req.headers.get('host') + req.context.get('path') + '?' + urlencode(req.query_params)
        flow.fetch_token(authorization_response=authorization_response)
        credentials = flow.credentials
        credentials_dict = credentials_to_dict(credentials)

        return Response(
            body='',
            headers={
                'Location': '/client',
                'Set-Cookie': "credentials=\"%s\"" % (credentials_dict)
            },
            status_code=302
        )

    except Exception as e:
        raise e






@app.route('/client')
def client():
    req = app.current_request
    cookieData = req.headers.get('Cookie')
    cookie = SimpleCookie()
    cookie.load(cookieData)
    cookie_credentials = literal_eval(cookie.get('credentials').value)
    if (cookie_credentials is None):
        return Response(
            body='',
            headers={'Location': '/authorize'},
            status_code=302
        )
    credentials = google.oauth2.credentials.Credentials(
        **cookie_credentials)

    service = build('drive', 'v3', credentials=credentials)
    results = service.files().list(
        pageSize=10, fields="nextPageToken, files(id, name, mimeType)").execute()
    items = results.get('files', [])

    return {'files': items}


def credentials_to_dict(credentials):
    return {'token': credentials.token,
            'refresh_token': credentials.refresh_token,
            'token_uri': credentials.token_uri,
            'client_id': credentials.client_id,
            'client_secret': credentials.client_secret,
            'scopes': credentials.scopes
            }
