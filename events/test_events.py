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
event_1.add('dtend', datetime(2010, 10, 10, 11, 0, 0))
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

event_11 = Event()
event_11.add('dtstart', date(2012, 10, 10))
event_11['summary'] = 'event_11'
event_11.add('dtend', datetime(2012, 10, 10, 10, 0, 0))
event_11['uid'] = 'event_11'
event_11.add('last-modified', datetime(2012, 10, 10, 10, 0, 0))


event_12 = Event()
event_12.add('dtstart', date(2012, 10, 10))
event_12['summary'] = 'event_12'
event_12.add('dtend', datetime(2012, 10, 10, 10, 0, 0))
event_12['uid'] = 'event_12'
event_12.add('last-modified', datetime(2013, 10, 10, 10, 0, 0))

event_13 = Event()
event_13.add('dtstart', date(2012, 10, 10))
event_13['summary'] = 'event_13'
event_13.add('dtend', datetime(2012, 10, 10, 10, 0, 0))
event_13['uid'] = 'event_13'
event_13.add('last-modified', datetime(2011, 10, 10, 10, 0, 0))

event_14 = Event()
event_14.add('dtstart', datetime(2013, 10, 10, 10, 0, 0))
event_14['summary'] = 'event_14'
event_14.add('created', datetime(2013, 10, 10, 10, 0, 0))
event_14['uid'] = 'event_14'
event_14.add('attendee', 'MAILTO:foo14@bar.com')
event_14['sequence'] = 11

yearly_repeating_event = Event()
yearly_repeating_event.add('rrule', {'FREQ': 'YEARLY'})
yearly_repeating_event.add('dtstart', datetime(2013, 10, 10, 10, 0, 0))
yearly_repeating_event.add('dtend', datetime(2013, 10, 10, 10, 0, 0))
yearly_repeating_event['summary'] = 'yearly_repeating_event'
yearly_repeating_event.add('created', datetime(2013, 10, 10, 10, 0, 0))
yearly_repeating_event['uid'] = 'yearly_repeating_event'


save_event_override = None

class CollectionMock(Collection):
    def __init__(self, read_only):
        super().__init__(None, None, read_only=read_only, default_organizer=vCalAddress('MAILTO:default_organizer@foo.com'))

        self.content = {'event_1': event_1,
                        'event_2': event_2,
                        'event_3': event_3,
                        'event_4': event_4,
                        'event_5': event_5,
                        'event_7': event_7,
                        'event_8': event_8,
                        'event_9': event_9,
                        'event_10': event_10,
                        'event_11': event_11,
                        'event_12': event_12,
                        'event_13': event_13,
                        'event_14': event_14,
                        'yearly_repeating_event': yearly_repeating_event,
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
        return self.content.values()

class Config:
    collections = {'1': CollectionMock(False), '2': CollectionMock(True)}
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

def test_search_api_without_admin(client):
    response = client.post(f'api/1/search', data='')
    assert response.status_code == 404


def search_api(client, pattern: str, before: int = None, after: int = None, exact: bool = None) -> list:
    body = {'pattern': pattern}

    if before is not None:
        body['before'] = before

    if after is not None:
        body['after'] = after

    if exact is not None:
        body['exact'] = exact

    response = client.post(f'api/1/search', data=json.dumps(body), headers={'X-Admin': 'true', 'Content-Type': 'application/json'})
    assert response.status_code == 200

    return json.loads(response.data)

def test_search_api_one_match(client):
    content = search_api(client, 'event_2')
    del content[0]['access_link']

    assert content == json.loads('[{"attendees": null,  "description": null,  "end": null,  "location": "location_2",  "start": "2011-10-10 10:00:00",  "start_ts": 1318266000.0,  "title": "event_2"}]')

def test_search_api_no_match(client):
    assert search_api(client, 'nomatch') == []

def test_search_api_multiple_match_sorted(client):
    content = search_api(client, "event_1")
    order = [e['title'] for e in content]

    assert order == ['event_12', 'event_11', 'event_13', 'event_14', 'event_10', 'event_1']

def test_search_api_exact(client):
    content = search_api(client, "event_1", exact=True)
    order = [e['title'] for e in content]

    assert order == ['event_1']

def test_search_api_before(client):
    before = datetime.timestamp(event_1['dtstart'].dt)
    content = search_api(client, "event_1", exact=True, before=before)
    order = [e['title'] for e in content]
    assert order == ['event_1']

def test_search_api_before_negative(client):
    before = datetime.timestamp(event_1['dtstart'].dt) - 1
    assert search_api(client, "event_1", exact=True, before=before) == []

def test_search_api_after(client):
    after = datetime.timestamp(event_1['dtend'].dt)
    content = search_api(client, "event_1", exact=True, after=after)
    order = [e['title'] for e in content]
    assert order == ['event_1']

def test_search_api_after_negative(client):
    after = datetime.timestamp(event_1['dtend'].dt) + 1
    content = search_api(client, "event_1", exact=True, after=after)
    assert content == []

def test_search_api_before_and_after(client):
    after = datetime.timestamp(event_1['dtend'].dt)
    before = datetime.timestamp(event_1['dtstart'].dt)
    content = search_api(client, "event_1", exact=True, after=after, before=before)
    order = [e['title'] for e in content]
    assert order == ['event_1']


def test_search_api_strip(client):
    after = datetime.timestamp(event_1['dtend'].dt)
    before = datetime.timestamp(event_1['dtstart'].dt)
    content = search_api(client, " event_1 ", exact=True)
    order = [e['title'] for e in content]
    assert order == ['event_1']

def test_search_rrule_exact_match(client):
    after = datetime.timestamp(yearly_repeating_event['dtend'].dt)
    before = datetime.timestamp(yearly_repeating_event['dtstart'].dt)
    content = search_api(client, "yearly_repeating_event", before=before, after=after)
    assert [e['title'] for e in content] == ['yearly_repeating_event']

def test_search_rrule_negative(client):
    after = datetime.timestamp(yearly_repeating_event['dtend'].dt)
    before = datetime.timestamp(yearly_repeating_event['dtstart'].dt - timedelta(hours=1))
    content = search_api(client, "yearly_repeating_event", before=before, after=after)
    assert content == []

def test_search_rrule_after_only(client):
    after = datetime.timestamp(yearly_repeating_event['dtend'].dt)
    content = search_api(client, "yearly_repeating_event", after=after)
    assert [e['title'] for e in content] == ['yearly_repeating_event']

def test_search_rrule_before_only(client):
    before = datetime.timestamp(yearly_repeating_event['dtstart'].dt + timedelta(hours=1))
    content = search_api(client, "yearly_repeating_event", before=before)
    assert [e['title'] for e in content] == ['yearly_repeating_event']

def test_search_rrule_title_only(client):
    content = search_api(client, "yearly_repeating_event")
    assert [e['title'] for e in content] == ['yearly_repeating_event']

def test_search_rrule_before_first_occurence(client):
    after = datetime.timestamp(yearly_repeating_event['dtend'].dt - timedelta(days=365))
    before = datetime.timestamp(yearly_repeating_event['dtstart'].dt - timedelta(days=365))
    content = search_api(client, "yearly_repeating_event", before=before, after=after)
    assert content == []

def test_search_rrule_occurence(client):
    after = datetime.timestamp(yearly_repeating_event['dtend'].dt + timedelta(days=365))
    before = datetime.timestamp(yearly_repeating_event['dtstart'].dt + timedelta(days=365))
    content = search_api(client, "yearly_repeating_event", before=before, after=after)
    assert [e['title'] for e in content] == ['yearly_repeating_event']

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
    assert response.data.decode() == 'BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nSUMMARY:event_1\r\nDTSTART;VALUE=DATE-TIME:20101010T100000\r\nDTEND;VALUE=DATE-TIME:20101010T110000\r\nUID:event_1\r\nLOCATION:Location_1\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n'

def test_view_event_ics_old_token(client):
    token = quote_plus(generate_token(settings, '/1/event_1.ics', expires=datetime.now() + timedelta(days=1)))
    response = client.get(f'/1/event_1/ics?t={token}')

    assert response.status_code == 200
    assert response.data.decode() == 'BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nSUMMARY:event_1\r\nDTSTART;VALUE=DATE-TIME:20101010T100000\r\nDTEND;VALUE=DATE-TIME:20101010T110000\r\nUID:event_1\r\nLOCATION:Location_1\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n'


def test_view_event_ics_new_token(client):
    token = quote_plus(generate_token(settings, '/1/event_1', expires=datetime.now() + timedelta(days=1)))
    response = client.get(f'/1/event_1/ics?t={token}')

    assert response.status_code == 200
    assert response.data.decode() == 'BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nSUMMARY:event_1\r\nDTSTART;VALUE=DATE-TIME:20101010T100000\r\nDTEND;VALUE=DATE-TIME:20101010T110000\r\nUID:event_1\r\nLOCATION:Location_1\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n'

def test_view_event_ics_no_token(client):
    response = client.get(f'/1/event_1.ics/ics')

    assert response.status_code == 404

def test_view_event_ics_admin(client):
    response = client.get(f'/1/event_1.ics/ics', headers={'X-Admin': 'true'})

    assert response.status_code == 200
    assert response.data.decode() == 'BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nSUMMARY:event_1\r\nDTSTART;VALUE=DATE-TIME:20101010T100000\r\nDTEND;VALUE=DATE-TIME:20101010T110000\r\nUID:event_1\r\nLOCATION:Location_1\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n'

def test_update_no_csrf(client):
    response = client.post(f'/1/event_1.ics/update', data='')

    assert response.status_code == 400

def test_update_csrf_no_admin(client):
    response = client.post(f'/1/event_1.ics/update', data={'csrf_token': client.csrf_token})
    assert response.status_code == 404

def test_update_csrf_no_admin_with_token(client):
    token = quote_plus(generate_token(settings, '/1/event_1.ics', expires=datetime.now() + timedelta(days=1)))
    response = client.post(f'/1/event_1.ics/update', data={'csrf_token': client.csrf_token, 't': token})
    assert response.status_code == 404

def test_update_no_attendees(client):
    global save_event_override
    response = client.post(f'/1/event_1.ics/update', data={'csrf_token': client.csrf_token}, headers={'X-Admin': 'true'})

    def save_event(name: str, event):
        assert False

    save_event_override = save_event

    assert response.status_code == 200
    assert 'Event has no attendees' in response.data.decode()

def test_update_read_only(client):
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

    response = client.post(f'/2/event_3.ics/update', data={'csrf_token': client.csrf_token}, headers={'X-Admin': 'true'})

    assert response.status_code == 200
    assert 'Event sent to: foo@bar.com. SEQUENCE=[ABSENT]' in response.data.decode()
    assert called

def test_update_one_attendee(client):
    global save_event_override

    called = False
    def send_email(source: str, destination: list, content: str):
        nonlocal called
        assert source == settings.email_from
        assert destination == ['foo@bar.com']
        assert 'Subject: event_3' in content
        called = True

    saved = False
    def save_event(name: str, event):
        nonlocal saved
        saved= True

        assert event.subcomponents[0]['sequence'] == 1

    save_event_override = save_event
    override_send_email(send_email)

    response = client.post(f'/1/event_3.ics/update', data={'csrf_token': client.csrf_token}, headers={'X-Admin': 'true'})

    assert response.status_code == 200
    assert 'Event sent to: foo@bar.com. SEQUENCE=1' in response.data.decode()
    assert called
    assert saved

def test_update_two_attendees(client):
    global save_event_override
    emails = []
    def send_email(source: str, destination: list, content: str):
        nonlocal emails
        assert source == settings.email_from
        emails += destination
        assert 'Subject: event_4' in content
        called = True

    saved = False
    def save_event(name: str, event):
        nonlocal saved
        saved= True

        assert event.subcomponents[0]['sequence'] == 1

    save_event_override = save_event
    override_send_email(send_email)

    response = client.post(f'/1/event_4.ics/update', data={'csrf_token': client.csrf_token}, headers={'X-Admin': 'true'})

    assert response.status_code == 200
    assert 'Event sent to: foo@bar.com, foo2@bar.com. SEQUENCE=1' in response.data.decode()
    assert emails == ['foo@bar.com', 'foo2@bar.com']
    assert saved


def test_update_increase_seq_number(client):
    global save_event_override

    called = False
    def send_email(source: str, destination: list, content: str):
        nonlocal called
        assert source == settings.email_from
        assert destination == ['foo14@bar.com']
        assert 'Subject: event_14' in content
        called = True

    saved = False
    def save_event(name: str, event):
        nonlocal saved
        saved= True

        assert event.subcomponents[0]['sequence'] == 12

    save_event_override = save_event
    override_send_email(send_email)

    response = client.post(f'/1/event_14.ics/update', data={'csrf_token': client.csrf_token}, headers={'X-Admin': 'true'})

    assert response.status_code == 200
    assert 'Event sent to: foo14@bar.com. SEQUENCE=12' in response.data.decode()
    assert called
    assert saved

def test_subscribe_no_csrf(client):
    response = client.post(f'/1/event_1.ics/subscribe', data='email=foo@bar.com&updates=on')

    assert response.status_code == 400

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

def test_subscribe_updates_read_only(client):
    global save_event_override

    called = False
    def send_email(source: str, destination: list, content: str):
        nonlocal called
        called = True

    def save_event(name: str, event):
        assert False

    save_event_override = save_event

    override_send_email(send_email)

    token = generate_token(settings, '/2/event_1.ics', expires=datetime.now() + timedelta(days=1))
    response = client.post(f'/2/event_1.ics/subscribe', data={'email': 'foo@bar.com', 'csrf_token': client.csrf_token, 't': token, 'updates': 'on'})

    assert response.status_code == 200
    assert called

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

def test_subscribe_api_read_only(client):
    global save_event_override

    called = False
    def send_email(source: str, destination: list, content: str):
        nonlocal called
        assert source == settings.email_from
        assert destination == ['foo6@bar.com']
        assert 'Subject: event_5' in content
        called = True

    def save_event(name: str, event):
        assert False

    save_event_override = save_event
    override_send_email(send_email)

    response = client.post(f'api/2/event_5.ics/subscribe', data=json.dumps({'updates': True, 'email': 'foo6@bar.com'}), headers={'X-Admin': 'true'}, content_type='application/json')
    assert response.status_code == 200
    assert called


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

    content = json.loads(response.data)
    del content['access_link']
    assert json.dumps(content) == '{"title": "event_5", "start": "2012-10-10 10:00:00", "start_ts": 1349888400.0, "attendees": ["foo5@bar.com"], "end": null, "description": null, "location": null}'


def test_event_api_admin_with_location(client):
    response = client.get(f'api/1/event_1.ics', headers={'X-Admin': 'true'})
    assert response.status_code == 200

    content = json.loads(response.data)
    del content['access_link']
    assert json.dumps(content) == '{"title": "event_1", "start": "2010-10-10 10:00:00", "start_ts": 1286730000.0, "end": "2010-10-10 11:00:00", "end_ts": 1286733600.0, "location": "Location_1", "attendees": ["foo@bar.com"], "description": null}'

def test_event_api_admin_without_ics(client):
    response = client.get(f'api/1/event_4', headers={'X-Admin': 'true'})
    assert response.status_code == 200

    content = json.loads(response.data)
    del content['access_link']
    assert json.dumps(content) == '{"title": "event_4", "start": "2012-10-10 10:00:00", "start_ts": 1349888400.0, "attendees": ["foo@bar.com", "foo2@bar.com", "foo3@bar.com"], "end": null, "description": null, "location": null}'

def test_event_api_admin_with_end(client):
    response = client.get(f'api/1/event_10', headers={'X-Admin': 'true'})
    assert response.status_code == 200

    content = json.loads(response.data)
    del content['access_link']

    assert json.dumps(content) == '{"title": "event_10", "start": "2012-10-10 00:00:00", "start_ts": 1349852400.0, "end": "2012-10-10 10:00:00", "end_ts": 1349888400.0, "description": null, "location": null, "attendees": null}'

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

