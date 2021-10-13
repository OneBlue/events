import logging
import os
import pytest
from threading import Thread
from ecdsa import SigningKey
from .access import *
from datetime import datetime, timedelta
from .errors import *
from . import create_app
from .subscribe import override_send_email
from icalendar import Calendar, Event
from urllib.parse import quote_plus
from flask_wtf.csrf import generate_csrf
from flask import session, current_app, session
from flask.testing import FlaskClient as BaseFlaskClient

event_1 = Event()
event_1.add('dtstart', datetime(2010, 10, 10, 10, 0, 0))
event_1['summary'] = 'event_1'
event_1['uid'] = 'event_1'
event_1.add('location', 'Location_1')

event_2 = Event()
event_2.add('dtstart', datetime(2011, 10, 10, 10, 0, 0))
event_2['summary'] = 'event_2'
event_2['location'] = 'location_2'
event_2.add('created', datetime(2011, 10, 10, 10, 0, 0))
event_2['uid'] = 'event_2'

event_3 = Event()
event_3.add('dtstart', datetime(2012, 10, 10, 10, 0, 0))
event_3['summary'] = 'event_3'
event_3.add('created', datetime(2012, 10, 10, 10, 0, 0))
event_3['uid'] = 'event_3'
event_3.add('attendee', 'MAILTO:foo@bar.com')

event_4 = Event()
event_4.add('dtstart', datetime(2012, 10, 10, 10, 0, 0))
event_4['summary'] = 'event_4'
event_4.add('created', datetime(2012, 10, 10, 10, 0, 0))
event_4['uid'] = 'event_4'
event_4.add('attendee', 'MAILTO:foo@bar.com')
event_4.add('attendee', 'MAILTO:foo2@bar.com')



save_event_override = None

class TestCollection:
    def get_event(self, name: str):
        if name == 'event_1.ics':
            event = event_1
        elif name == 'event_2.ics':
            event = event_2
        elif name == 'event_3.ics':
            event = event_3
        elif name == 'event_4.ics':
            event = event_4

        if not event:
            raise NotFoundException(f'Event {name} not found')

        calendar = Calendar()
        calendar.add_component(event)

        return calendar

    def save_event(self, name: str, event):
        global save_event_override
        if save_event_override:
            return save_event_override(name, event)

    def all_events(self):
        return [event_1, event_2, event_3]

class Config:
    collections = {'1': TestCollection()}
    port = 1111
    host = '127.0.0.1'
    time_format = '%Y-%m-%d %H:%M:%S'
    email_from = 'email@example.com'
    smtp_server = '127.0.0.1'
    smtp_port = 1112
    secret_key = os.urandom(32)
    recent_count = 20

    external_url = 'http://127.0.0.1:1111'
    signing_key = SigningKey.generate()

    def is_admin(self, request):
        return request.headers.get('X-Admin', None) == 'true'


# Hack to get csrf token in tests
class RequestShim(object):
    def __init__(self, client):
        self.client = client
        self.vary = set()

    def set_cookie(self, key, value='', *args, **kwargs):
        server_name = current_app.config["SERVER_NAME"] or "localhost"
        return self.client.set_cookie(server_name, key=key, value=value, *args, **kwargs)

    def delete_cookie(self, key, *args, **kwargs):
        server_name = current_app.config["SERVER_NAME"] or "localhost"
        return self.client.delete_cookie(server_name, key=key, *args, **kwargs)



settings = Config()
app = create_app(settings)

class FlaskClient(BaseFlaskClient):
    @property
    def csrf_token(self):
        request = RequestShim(self)
        environ_overrides = {}
        self.cookie_jar.inject_wsgi(environ_overrides)
        with app.app_context():
            with current_app.test_request_context("/login", environ_overrides=environ_overrides):
                csrf_token = generate_csrf()
                current_app.session_cookie_name = 'dummy'
                current_app.session_interface.save_session(current_app, session, request)
                return csrf_token


app.test_client_class = FlaskClient


def tearDown(self):
    app_context.pop()

@pytest.fixture
def client():
    logging.basicConfig(level=logging.DEBUG)

    return app.test_client()

def test_valid_token():
    url = '/foo'

    token = generate_token(settings, url, expires=datetime.now() + timedelta(days=1))
    validate_token(settings, token, url) # Shouldn't throw

def test_valid_token_wrong_url():
    token = generate_token(settings, '/url', expires=datetime.now() + timedelta(days=1))

    with pytest.raises(InvalidToken):
        validate_token(settings, token, '/otherurl')

def test_expired_token():
    token = generate_token(settings, '/url', expires=datetime.now() - timedelta(days=1))
    with pytest.raises(ExpiredToken):
        validate_token(settings, token, '/url')

def test_bad_token():
    with pytest.raises(InvalidToken):
        validate_token(settings, '0xfoo', '/url')

def test_non_admin_home(client):
    response = client.get('/')

    assert response.status_code == 404

def test_admin_home(client):
    response = client.get('/', headers={'X-Admin': 'true'})

    assert response.status_code == 200

def test_view_event_admin(client):
    response = client.get('/1/event_1.ics', headers={'X-Admin': 'true'})

    assert response.status_code == 200
    assert 'Admin' in response.data.decode()

def test_view_event_non_admin(client):
    response = client.get('/1/event_1.ics')

    assert response.status_code == 404

def test_view_event_expired_token(client):
    token = quote_plus(generate_token(settings, '/1/event_1.ics', expires=datetime.now() - timedelta(days=1)))
    response = client.get(f'/1/event_1.ics?t={token}')

    assert response.status_code == 200
    assert response.data == b'Token expired'

def test_view_event_bad_token_url(client):
    token = quote_plus(generate_token(settings, '/1/event_2.ics', expires=datetime.now() - timedelta(days=1)))
    response = client.get(f'/1/event_1.ics?t={token}')

    assert response.status_code == 404

def test_view_event(client):
    token = quote_plus(generate_token(settings, '/1/event_1.ics', expires=datetime.now() + timedelta(days=1)))
    response = client.get(f'/1/event_1.ics?t={token}')

    assert response.status_code == 200
    assert 'Admin' not in response.data.decode()
    assert 'Location_1' in response.data.decode()

def test_view_event_ics(client):
    token = quote_plus(generate_token(settings, '/1/event_1.ics', expires=datetime.now() + timedelta(days=1)))
    response = client.get(f'/1/event_1.ics/ics?t={token}')

    assert response.status_code == 200
    assert response.data.decode() == 'BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nSUMMARY:event_1\r\nDTSTART;VALUE=DATE-TIME:20101010T100000\r\nUID:event_1\r\nLOCATION:Location_1\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n'

def test_view_event_ics_no_token(client):
    response = client.get(f'/1/event_1.ics/ics')

    assert response.status_code == 404

def test_view_event_ics_admin(client):
    response = client.get(f'/1/event_1.ics/ics', headers={'X-Admin': 'true'})

    assert response.status_code == 200
    assert response.data.decode() == 'BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nSUMMARY:event_1\r\nDTSTART;VALUE=DATE-TIME:20101010T100000\r\nUID:event_1\r\nLOCATION:Location_1\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n'

def test_subscribe_no_csrf(client):
    response = client.get(f'/1/event_1.ics/subscribe', data='email=foo@bar.com&updates=on')

    assert response.status_code == 405

def test_subscribe_with_csrf_no_token(client):
    token = quote_plus(generate_token(settings, '/1/event_1.ics', expires=datetime.now() + timedelta(days=1)))
    response = client.post(f'/1/event_1.ics/subscribe', data={'email': 'foo@bar.com', 'csrf_token': client.csrf_token})

    assert response.status_code == 404

def test_subscribe_with_csrf_and_token(client):
    global save_event_override

    called = False
    def send_email(source: str, destination: list, content: str):
        nonlocal called
        assert source == settings.email_from
        assert destination == ['foo@bar.com']
        assert 'Subject: Event_1' in content
        called = True

    def save_event(*args):
        assert False

    save_event_override = save_event

    override_send_email(send_email)

    token = generate_token(settings, '/1/event_1.ics', expires=datetime.now() + timedelta(days=1))
    response = client.post(f'/1/event_1.ics/subscribe', data={'email': 'foo@bar.com', 'csrf_token': client.csrf_token, 't': token})

    assert response.status_code == 200
    assert called


def test_subscribe_with_csrf_and_token(client):
    global save_event_override

    called = False
    def send_email(source: str, destination: list, content: str):
        nonlocal called
        assert source == settings.email_from
        assert destination == ['foo@bar.com']
        assert 'Subject: event_1' in content
        called = True

    save_called = False
    def save_event(name: str, event):
        nonlocal save_called

        assert name == 'event_1.ics'
        assert event.subcomponents[0]['attendee'].title() == 'Mailto:Foo@Bar.Com'
        save_called = True

    save_event_override = save_event

    override_send_email(send_email)

    token = generate_token(settings, '/1/event_1.ics', expires=datetime.now() + timedelta(days=1))
    response = client.post(f'/1/event_1.ics/subscribe', data={'email': 'foo@bar.com', 'csrf_token': client.csrf_token, 't': token, 'updates': 'on'})

    assert response.status_code == 200
    assert called
    assert save_called

def test_subscribe_with_csrf_and_double_quoted_token(client):
    global save_event_override

    called = False
    def send_email(source: str, destination: list, content: str):
        nonlocal called
        assert source == settings.email_from
        assert destination == ['double@bar.com']
        assert 'Subject: event_2' in content
        called = True

    save_called = False
    def save_event(name: str, event):
        nonlocal save_called

        assert name == 'event_2.ics'
        assert event.subcomponents[0]['attendee'].title() == 'Mailto:Double@Bar.Com'
        save_called = True

    save_event_override = save_event

    override_send_email(send_email)

    token = generate_token(settings, '/1/event_2.ics', expires=datetime.now() + timedelta(days=1))
    response = client.post(f'/1/event_2.ics/subscribe', data={'email': 'double@bar.com', 'csrf_token': client.csrf_token, 'updates': 'on', 't': quote_plus(token)})

    assert response.status_code == 200
    assert called
    assert save_called


def test_subscribe_with_csrf_and_token_duplicate(client):
    global save_event_override

    called = False
    def send_email(source: str, destination: list, content: str):
        nonlocal called
        assert source == settings.email_from
        assert destination == ['foo@bar.com']
        assert 'Subject: event_3' in content
        called = True

    def save_event(name: str, event):
        assert False

    save_event_override = save_event

    override_send_email(send_email)

    token = generate_token(settings, '/1/event_3.ics', expires=datetime.now() + timedelta(days=1))
    response = client.post(f'/1/event_3.ics/subscribe', data={'email': 'foo@bar.com', 'csrf_token': client.csrf_token, 't': token, 'updates': 'on'})

    assert response.status_code == 200
    assert called

def test_subscribe_with_csrf_and_token_duplicate_list(client):
    global save_event_override

    called = False
    def send_email(source: str, destination: list, content: str):
        nonlocal called
        assert source == settings.email_from
        assert destination == ['foo@bar.com']
        assert 'Subject: event_4' in content
        called = True

    def save_event(name: str, event):
        assert False

    save_event_override = save_event

    override_send_email(send_email)

    token = generate_token(settings, '/1/event_4.ics', expires=datetime.now() + timedelta(days=1))
    response = client.post(f'/1/event_4.ics/subscribe', data={'email': 'foo@bar.com', 'csrf_token': client.csrf_token, 't': token, 'updates': 'on'})

    assert response.status_code == 200
    assert called

def test_subscribe_with_csrf_and_token_list_new(client):
    global save_event_override

    called = False
    def send_email(source: str, destination: list, content: str):
        nonlocal called
        assert source == settings.email_from
        assert destination == ['foo3@bar.com']
        assert 'Subject: event_4' in content
        called = True

    save_called = False
    def save_event(name: str, event):
        nonlocal save_called

        assert name == 'event_4.ics'
        assert [str(e) for e in event.subcomponents[0]['attendee']] == ['MAILTO:foo@bar.com','MAILTO:foo2@bar.com', 'MAILTO:foo3@bar.com']
        save_called = True

    save_event_override = save_event

    override_send_email(send_email)

    token = generate_token(settings, '/1/event_4.ics', expires=datetime.now() + timedelta(days=1))
    response = client.post(f'/1/event_4.ics/subscribe', data={'email': 'foo3@bar.com', 'csrf_token': client.csrf_token, 't': token, 'updates': 'on'})

    assert response.status_code == 200
    assert called
    assert save_called
