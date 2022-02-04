import logging
import os
import pytest
import json
import pytz
import time
import email
from threading import Thread
from ecdsa import SigningKey
from .access import *
from .collection import remove_ics, Collection
from datetime import datetime, timedelta, date
from .errors import *
from . import create_app
from .subscribe import override_send_email, send_event_email, subscribe_to_event
from icalendar import Calendar, Event, vCalAddress
from urllib.parse import quote_plus
from flask_wtf.csrf import generate_csrf
from flask import session, current_app, session
from flask.testing import FlaskClient as BaseFlaskClient


os.environ['TZ'] = 'America/Los_Angeles'
time.tzset()

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

event_5 = Event()
event_5.add('dtstart', datetime(2012, 10, 10, 10, 0, 0))
event_5['summary'] = 'event_5'
event_5.add('created', datetime(2012, 10, 10, 10, 0, 0))
event_5['uid'] = 'event_5'

event_6 = Event()
event_6.add('dtstart', datetime(2012, 10, 10, 10, 0, 0))
event_6['summary'] = 'event_6'
event_6.add('created', datetime(2012, 10, 10, 10, 0, 0))

event_7 = Event()
event_7.add('dtstart', datetime(2012, 10, 10, 10, 0, 0))
event_7['summary'] = 'event_7'
event_7.add('created', datetime(2012, 10, 10, 10, 0, 0))
event_7['uid'] = 'event_7'
event_7['description'] = 'description for event_7'
event_7.add('organizer', vCalAddress('MAILTO:organizer@foo.com'))

event_8 = Event()
event_8.add('dtstart', datetime(2012, 10, 10, 10, 0, 0))
event_8['summary'] = 'event_8'
event_8.add('created', datetime(2012, 10, 10, 10, 0, 0))
event_8['uid'] = 'event_8'
event_8['description'] = '-::~:~::~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~::~:~::- Dummy gcal content. -::~:~::~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~::~:~::-'

event_9 = Event()
event_9.add('dtstart', datetime(2012, 10, 10, 10, 0, 0))
event_9['summary'] = 'event_9'
event_9.add('created', datetime(2012, 10, 10, 10, 0, 0))
event_9['uid'] = 'event_9'
event_9['description'] = '''-::~:~::~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~::~:~::- Dummy
                                                                                                                    gcal
                                                                                                                    content
                                                                                                                    (multine)
                            -::~:~::~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~::~:~::-'''


event_10 = Event()
event_10.add('dtstart', date(2012, 10, 10))
event_10['summary'] = 'event_10'
event_10.add('dtend', datetime(2012, 10, 10, 10, 0, 0))
event_10['uid'] = 'event_10'


save_event_override = None

class CollectionMock(Collection):
    def __init__(self):
        super().__init__(None, None)

        self.content = {'event_1': event_1,
                        'event_2': event_2,
                        'event_3': event_3,
                        'event_4': event_4,
                        'event_5': event_5,
                        'event_7': event_7,
                        'event_8': event_8,
                        'event_9': event_9,
                        'event_10': event_10,
                        }

    def get_event_impl(self, name: str):

        event = self.content.get(remove_ics(name))

        if not event:
            raise NotFoundException(f'Event {name} not found')

        calendar = Calendar()
        calendar.add_component(event)

        return calendar

    def save_event(self, name: str, event):
        global save_event_override
        if save_event_override:
            self.content[name] = event.subcomponents[0]
            return save_event_override(name, event)

    def all_events(self):
        return [event_1, event_2, event_3]

class Config:
    collections = {'1': CollectionMock()}
    port = 1111
    host = '127.0.0.1'
    time_format = '%Y-%m-%d %H:%M:%S'
    email_from = 'email@example.com'
    smtp_server = '127.0.0.1'
    smtp_port = 1112
    secret_key = os.urandom(32)
    recent_count = 20
    default_event_organizer = vCalAddress('MAILTO:default_organizer@foo.com')

    external_url = 'http://127.0.0.1:1111'
    signing_key = SigningKey.generate()
    timezone = pytz.timezone(os.environ['TZ'])

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

def test_view_event_ics_old_token(client):
    token = quote_plus(generate_token(settings, '/1/event_1.ics', expires=datetime.now() + timedelta(days=1)))
    response = client.get(f'/1/event_1/ics?t={token}')

    assert response.status_code == 200
    assert response.data.decode() == 'BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nSUMMARY:event_1\r\nDTSTART;VALUE=DATE-TIME:20101010T100000\r\nUID:event_1\r\nLOCATION:Location_1\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n'


def test_view_event_ics_new_token(client):
    token = quote_plus(generate_token(settings, '/1/event_1', expires=datetime.now() + timedelta(days=1)))
    response = client.get(f'/1/event_1/ics?t={token}')

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

def test_subscribe_bad_email_no_updates(client):
    global save_event_override

    called = False
    def send_email(source: str, destination: list, content: str):
        assert False

    save_called = False
    def save_event(name: str, event):
        assert False

    save_event_override = save_event

    override_send_email(send_email)

    token = generate_token(settings, '/1/event_1.ics', expires=datetime.now() + timedelta(days=1))
    response = client.post(f'/1/event_1.ics/subscribe', data={'email': 'foo', 'csrf_token': client.csrf_token, 't': token, 'updates': 'off'})

    assert response.status_code == 200
    assert 'Invalid email: foo' in response.data.decode()

def test_subscribe_bad_email_with_updates(client):
    global save_event_override

    called = False
    def send_email(source: str, destination: list, content: str):
        assert False

    save_called = False
    def save_event(name: str, event):
        assert False

    save_event_override = save_event

    override_send_email(send_email)
    token = generate_token(settings, '/1/event_1.ics', expires=datetime.now() + timedelta(days=1))
    response = client.post(f'/1/event_1.ics/subscribe', data={'email': 'foo', 'csrf_token': client.csrf_token, 't': token, 'updates': 'on'})

    assert response.status_code == 200
    assert 'Invalid email: foo' in response.data.decode()

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
    assert response.headers['Set-Cookie'] == 'email=foo3@bar.com; Secure; SameSite=Strict; Path=/'
    assert called
    assert save_called

def test_subscribe_api_non_admin(client):
    response = client.post(f'api/1/event_4.ics/subscribe', data=json.dumps({'email': 'foo3@bar.com', 'updates': 'on'}), content_type='application/json')

    assert response.status_code == 404

def test_subscribe_api_admin_no_email(client):
    response = client.post(f'api/1/event_4.ics/subscribe', data=json.dumps({'updates': 'on'}), headers={'X-Admin': 'true'}, content_type='application/json')

    assert response.status_code == 400

def test_subscribe_api_admin_no_json(client):
    response = client.post(f'api/1/event_4.ics/subscribe', data='koi', content_type='application/json', headers={'X-Admin': 'true'})

    assert response.status_code == 400

def test_subscribe_api_admin(client):
    global save_event_override

    called = False
    def send_email(source: str, destination: list, content: str):
        nonlocal called
        assert source == settings.email_from
        assert destination == ['foo5@bar.com']
        assert 'Subject: event_5' in content
        called = True

    save_called = False
    def save_event(name: str, event):
        nonlocal save_called

        assert name == 'event_5.ics'

        assert event.subcomponents[0]['attendee'].title() == 'Mailto:Foo5@Bar.Com'
        save_called = True

    save_event_override = save_event
    override_send_email(send_email)

    response = client.post(f'api/1/event_5.ics/subscribe', data=json.dumps({'updates': True, 'email': 'foo5@bar.com'}), headers={'X-Admin': 'true'}, content_type='application/json')
    assert response.status_code == 200
    assert called
    assert save_called

def test_subscribe_api_admin_no_updates(client):
    global save_event_override

    called = False
    def send_email(source: str, destination: list, content: str):
        nonlocal called
        assert source == settings.email_from
        assert destination == ['foo5@bar.com']
        assert 'Subject: event_5' in content
        called = True

    def save_event(name: str, event):
        assert False

    save_event_override = save_event
    override_send_email(send_email)

    response = client.post(f'api/1/event_5.ics/subscribe', data=json.dumps({'updates': False, 'email': 'foo5@bar.com'}), headers={'X-Admin': 'true'}, content_type='application/json')
    assert response.status_code == 200
    assert called

def test_subscribe_api_admin_no_bad_email_no_updates(client):
    global save_event_override

    def send_email(source: str, destination: list, content: str):
        assert False

    def save_event(name: str, event):
        assert False

    save_event_override = save_event
    override_send_email(send_email)

    response = client.post(f'api/1/event_5.ics/subscribe', data=json.dumps({'updates': False, 'email': 'koi'}), headers={'X-Admin': 'true'}, content_type='application/json')
    assert response.status_code == 400
    assert response.data == b'Invalid email address: koi'

def test_subscribe_api_admin_no_bad_email_updates(client):
    global save_event_override

    def send_email(source: str, destination: list, content: str):
        assert False

    def save_event(name: str, event):
        assert False

    save_event_override = save_event
    override_send_email(send_email)

    response = client.post(f'api/1/event_5.ics/subscribe', data=json.dumps({'updates': True, 'email': 'koi'}), headers={'X-Admin': 'true'}, content_type='application/json')
    assert response.status_code == 400
    assert response.data == b'Invalid email address: koi'


def test_event_api_non_admin(client):
    response = client.get(f'api/1/event_5.ics')
    assert response.status_code == 404

def test_event_api_admin(client):
    response = client.get(f'api/1/event_5.ics', headers={'X-Admin': 'true'})
    assert response.status_code == 200
    assert response.data == b'{"title": "event_5", "start": "2012-10-10 10:00:00", "start_ts": 1349888400.0, "attendees": ["foo5@bar.com"], "end": null, "description": null, "location": null}'


def test_event_api_admin_with_location(client):
    response = client.get(f'api/1/event_1.ics', headers={'X-Admin': 'true'})
    assert response.status_code == 200
    assert response.data == b'{"title": "event_1", "start": "2010-10-10 10:00:00", "start_ts": 1286730000.0, "location": "Location_1", "attendees": ["foo@bar.com"], "end": null, "description": null}'

def test_event_api_admin_without_ics(client):
    response = client.get(f'api/1/event_4', headers={'X-Admin': 'true'})
    assert response.status_code == 200
    assert response.data == b'{"title": "event_4", "start": "2012-10-10 10:00:00", "start_ts": 1349888400.0, "attendees": ["foo@bar.com", "foo2@bar.com", "foo3@bar.com"], "end": null, "description": null, "location": null}'

def test_event_api_admin_with_end(client):
    response = client.get(f'api/1/event_10', headers={'X-Admin': 'true'})
    assert response.status_code == 200
    print(response.data)
    assert response.data == b'{"title": "event_10", "start": "2012-10-10 00:00:00", "start_ts": 1349852400.0, "end": "2012-10-10 10:00:00", "end_ts": 1349888400.0, "description": null, "location": null, "attendees": null}'

def test_create_event_without_admin(client):
    response = client.post(f'api/1', data='')
    assert response.status_code == 404

def test_create_event_empty_caldav(client):
    response = client.post(f'api/1', data='', headers={'X-Admin': 'true'})
    assert response.status_code == 400


def test_create_event_valid_vevent(client):
    response = client.post(f'api/1', data=event_6.to_ical(), headers={'X-Admin': 'true'})
    assert response.status_code == 400

def test_create_event_valid_no_sub_components(client):
    response = client.post(f'api/1', data=Calendar().to_ical(), headers={'X-Admin': 'true'})
    assert response.status_code == 400

def test_create_event_valid_no_bad_component(client):
    calendar = Calendar()
    calendar.add_component(Calendar())
    response = client.post(f'api/1', data=calendar.to_ical(), headers={'X-Admin': 'true'})
    assert response.status_code == 400


def test_create_event_valid(client):
    uid = None
    def save_event(name: str, event):
        nonlocal uid
        uid = event.subcomponents[0]['uid']
        assert name == uid
        assert event.subcomponents[0]['summary'] == 'event_6'

    global save_event_override
    save_event_override = save_event

    calendar = Calendar()
    calendar.add_component(event_6)

    response = client.post(f'api/1', data=calendar.to_ical(), headers={'X-Admin': 'true'})
    assert response.status_code == 200

    content = json.loads(response.data)
    assert content['uid'] == uid

    page_response = client.get(content['week_access_url'])
    assert page_response.status_code == 200


def test_add_default_organizer(client):
    global save_event_override

    called = False
    def send_email(source: str, destination: list, content: str):
        nonlocal called
        assert source == settings.email_from
        assert destination == ['foo@bar.com']
        assert 'Subject: event_1' in content

        message = email.message_from_string(content)
        cal_content = next(e for e in message.walk() if e.get_content_type() == 'text/calendar').get_payload(decode=True)
        vcal = Calendar.from_ical(cal_content)
        vevent = vcal.subcomponents[0]

        assert vevent['organizer'].to_ical() == b'MAILTO:default_organizer@foo.com'
        called = True

    def save_event(*args):
        assert False

    save_event_override = save_event

    override_send_email(send_email)

    token = generate_token(settings, '/1/event_1.ics', expires=datetime.now() + timedelta(days=1))
    response = client.post(f'/1/event_1.ics/subscribe', data={'email': 'foo@bar.com', 'csrf_token': client.csrf_token, 't': token})

    assert response.status_code == 200
    assert called

def test_dont_override_existing_organizer(client):
    global save_event_override

    called = False
    def send_email(source: str, destination: list, content: str):
        nonlocal called
        assert source == settings.email_from
        assert destination == ['foo@bar.com']
        assert 'Subject: event_7' in content

        message = email.message_from_string(content)
        cal_content = next(e for e in message.walk() if e.get_content_type() == 'text/calendar').get_payload(decode=True)
        vcal = Calendar.from_ical(cal_content)
        vevent = vcal.subcomponents[0]

        assert vevent['organizer'].to_ical() == b'MAILTO:organizer@foo.com'
        called = True

    def save_event(*args):
        assert False

    save_event_override = save_event

    override_send_email(send_email)

    token = generate_token(settings, '/1/event_7.ics', expires=datetime.now() + timedelta(days=1))
    response = client.post(f'/1/event_7.ics/subscribe', data={'email': 'foo@bar.com', 'csrf_token': client.csrf_token, 't': token})

    assert response.status_code == 200
    assert called

def test_view_event_gmail_filter(client):
    token = quote_plus(generate_token(settings, '/1/event_8.ics', expires=datetime.now() + timedelta(days=1)))
    response = client.get(f'/1/event_8.ics?t={token}')

    assert response.status_code == 200
    assert 'Admin' not in response.data.decode()
    assert 'event_8' in response.data.decode()
    assert 'gcal' not in response.data.decode()
    assert '[GCAL content filtered]' in response.data.decode()

def test_view_event_gmail_filter_multiline(client):
    token = quote_plus(generate_token(settings, '/1/event_9.ics', expires=datetime.now() + timedelta(days=1)))
    response = client.get(f'/1/event_9.ics?t={token}')

    assert response.status_code == 200
    assert 'Admin' not in response.data.decode()
    assert 'event_9' in response.data.decode()
    assert 'gcal' not in response.data.decode()
    assert '[GCAL content filtered]' in response.data.decode()


def test_view_event_gmail_filter_negative(client):
    token = quote_plus(generate_token(settings, '/1/event_7.ics', expires=datetime.now() + timedelta(days=1)))
    response = client.get(f'/1/event_7.ics?t={token}')

    assert response.status_code == 200
    assert 'event_7' in response.data.decode()
    assert 'description for event_7' in response.data.decode()
    assert '[GCAL content filtered]' not in response.data.decode()


def test_view_event_gmail_filter_ics(client):
    token = quote_plus(generate_token(settings, '/1/event_8.ics', expires=datetime.now() + timedelta(days=1)))
    response = client.get(f'/1/event_8.ics/ics?t={token}')

    assert response.status_code == 200
    assert 'event_8' in response.data.decode()
    assert 'gcal' in response.data.decode()

