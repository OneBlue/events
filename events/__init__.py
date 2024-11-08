#! /usr/bin/python3

import sys
import os
import logging
import traceback
import itertools
import importlib.util
import json
import icalendar.cal
import uuid
import re
from humanize import naturaldelta
from icalendar import vCalAddress
from flask import Flask, request, render_template, Response, redirect
from .errors import *
from .subscribe import send_event_email, subscribe_to_event, validate_email
from .access import validate_token, generate_access_url
from .utils import get_event_component, increase_event_seq_number, get_event_components
from datetime import datetime, date, timedelta
from tzlocal import get_localzone
from flask_wtf.csrf import CSRFProtect
from urllib.parse import quote_plus, urlparse
from dateutil.rrule import rrulestr
from functools import cmp_to_key
from math import inf

GCALENDAR_FILTER  = r'-::~:~::~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~::~:~::-.*-::~:~::~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~::~:~::-'

settings = None
app = Flask(__name__)
csrf = CSRFProtect()
csrf.init_app(app)

def get_collection(collection: str):
    matched_collection = settings.collections.get(collection)
    if not matched_collection:
        raise NotFoundException(f'Collection {collection} not found')

    return matched_collection

def get_event(collection: str, event: str, follow_redirect=False):
    matched_collection = get_collection(collection)

    filename = event

    try:
        matched_event = matched_collection.get_event(event)
    except EventRedirect as redirect:
        if not follow_redirect:
            raise

        logging.warning(f'Following event redirect to: {redirect.filename}')
        matched_event = matched_collection.get_event(redirect.filename)
        filename = redirect.filename # Record the new filename if redirected

    if not matched_event:
        raise NotFoundException(f'Event {event} not found in collection {collection}')

    return matched_event, matched_collection, filename

def get_event_uid(event) -> str:
    if len(event.subcomponents) == 1:
        return event.subcomponents[0].get('uid')
    else:
        logging.warning(f'Found event with more than one subcomponent: {event}')
        return None

def rationalize_time(ts) -> datetime:
    if not isinstance(ts, datetime): # In case of date, convert to datetime (set 00:00)
        assert isinstance(ts, date)
        return settings.timezone.localize(datetime.combine(ts, datetime.min.time()))
    else:
        return ts.astimezone(settings.timezone)

def format_time(ts) -> str:
        return rationalize_time(ts).strftime(settings.time_format)

def admin_only():
    if not settings.is_admin(request):
        raise AdminRequired()

def add_request_auth(fields: dict):
    if 't' in request.args:
        fields['token'] = quote_plus(request.args['t'])
        fields['auth'] = '?t=' + quote_plus(request.args['t'])
    else:
        return ''

def validate_access(token: str = None):
    token = token or request.args.get('t', None)
    if token is None:
        if settings.is_admin(request):
            return
        else:
            raise SuspiciousRequest('Missing token')

    path = request.path
    if path.endswith('/ics'):
        path = path[:-len('/ics')]
    elif path.endswith('/subscribe'):
        path = path[:-len('/subscribe')]

    try:
        validate_access_impl(token, path)
    except InvalidToken as e:
        # Allow old tokens generated with the .ics
        if not path.endswith('.ics'):
            validate_access_impl(token, path + '.ics')
        else:
            raise

def validate_access_impl(token: str, path: str):
    try:
        validate_token(settings, token, path)
    except ExpiredToken:
        raise
    except Exception as e:
        raise InvalidToken() from e

def get_event_fields(component):
    event = {'title': str(component['summary'])}

    if 'dtstart' in component:
        start = component['dtstart'].dt
        event['start'] = format_time(start)
        if not isinstance(start, datetime):
            start = datetime.combine(start, datetime.min.time())

        event['start_ts'] = start.timestamp()

    if 'dtend' in component:
        end = component['dtend'].dt
        event['end'] = format_time(end)
        if not isinstance(end, datetime):
            end = datetime.combine(end, datetime.min.time())

        event['end_ts'] = end.timestamp()

    if 'description' in component :
        event['description'] = re.sub(GCALENDAR_FILTER, '[GCAL content filtered]', str(component['description']), flags=re.DOTALL)

    if 'location' in component:
        event['location'] = str(component['location'])

    if 'rrule' in component:
        event['repeat'] = str(component['rrule'])

    attendees = component.get('attendee')
    if attendees:
        if isinstance(attendees, vCalAddress):
            event['attendees'] = [attendees.lower().replace('mailto:', '')]
        else:
            event['attendees'] = [e.lower().replace('mailto:', '') for e in attendees]

    return event

def render_event(collection_id, event_id, event_data, **extra_fields):
    events = get_event_components(event_data)

    fields = {}
    fields['events'] = [get_event_fields(e) for e in events]
    fields['collection'] = collection_id
    fields['event'] = event_id
    fields['server_timezone'] = settings.timezone.zone
    add_request_auth(fields)

    for e in extra_fields:
        fields[e] = extra_fields[e]

    if settings.is_admin(request):
        fields['admin_links'] = [
                                {'title': '1 day link', 'url': generate_access_url(settings, request.path, datetime.now() + timedelta(days=1))},
                                {'title': '30 days link', 'url': generate_access_url(settings, request.path, datetime.now() + timedelta(days=30))},
                                ]

        if 'dtstart' in events[0]:
            ts = rationalize_time(events[0]['dtstart'].dt)
            fields['admin_links'].append({'title': 'Event date + 1 week link', 'url': generate_access_url(settings, request.path, ts + timedelta(days=7))})

    return render_template('event.jinja', **fields)

def event_json(collection: int, event) -> dict:
    event = get_event_component(event)

    content = get_event_fields(event)
    fields = ['start', 'end', 'description', 'location', 'attendees']
    for e in fields:
        if e not in content:
            content[e] = None

    if 'dtstart' not in event or 'uid' not in event:
        content['access_link'] = None
    else:
        ts = rationalize_time(event['dtstart'].dt)
        content['access_link'] = generate_access_url(settings, f'/{collection}/{event["uid"]}', ts + timedelta(days=7))

    content['sequence'] = event['sequence'] if 'sequence' in event else None

    return content

def make_event_list(events: list, sort_field: str, title: str, max_count: int, allow_nulls=False, reverse=True):
    sortable_events = (e for e in events if sort_field in e[0])

    now = rationalize_time(datetime.now())
    if sort_field != 'DTSTART':
        events_with_date = [(e[0], e[1], rationalize_time(e[0][sort_field].dt)) for e in sortable_events]
    else:
        # Special treatement for reccurence rules
        def next_occurence(event):
            if 'rrule' in event:
                rule = rrulestr(event['rrule'].to_ical().decode(), dtstart=rationalize_time(event['dtstart'].dt))
                return rule.after(now) or rule.before(now) or event['dtstart'].dt
            else:
                return rationalize_time(event['dtstart'].dt)

        # Compute next occurence
        events_with_date = [(e[0], e[1], rationalize_time(e[0][sort_field].dt)) for e in sortable_events]

        # Drop past events
        events_with_date = [e for e in events_with_date if e[2] >= now]

    entries = sorted(events_with_date, key=lambda event: event[2])
    if reverse:
        entries = reversed(entries)

    if sort_field and allow_nulls: # Add non-sortable entries if requested
        entries = itertools.chain(entries, ((e[0], e[1], None) for e in events if sort_field not in e[0]))

    if max_count: # Slice if requested
        entries = itertools.islice(entries, 0, max_count)

    def make_event(event, collection, ts):
        delta = '[NULL]'
        if ts:
            if ts > now:
                delta =  'in ' + naturaldelta(now - ts)
            else:
                delta =  naturaldelta(now - ts) + ' ago'

        return {
                'ts': delta,
                'collection': collection,
                'filename': str(event['uid']),
                'title': str(event['summary'])
                }

    return {'title': title, 'entries': [make_event(*e) for e in entries]}

@app.errorhandler(HTTPException)
def handle_exception(error: HTTPException):
    logging.error(f'Handling exception: {error}, stack trace: {traceback.format_exc()}')

    if isinstance(error, ExpiredToken):
        return 'Token expired', 200

    content = traceback.format_exc().replace('\n', '\r\n') if settings.is_admin(request) else ''
    return content, error.code

@app.route('/<collection>/<event>', methods=['GET'])
def event_page(collection, event):
    validate_access()

    try:
        event_data, _, _ = get_event(collection, event)
    except EventRedirect as e:
        logging.info(f'Redirecting event {event} to {e.filename}')
        assert event.lower() != e.filename.lower()
        return redirect(f'/{collection}/{e.filename}')

    return render_event(collection, event, event_data, admin=settings.is_admin(request))

@app.route('/<collection>/<event_id>/subscribe', methods=['POST'])
def subscribe(collection, event_id):
    token = request.form.get('t', None)
    validate_access(token)

    event, matched_collection, _ = get_event(collection, event_id)
    if not event:
        raise NotFoundException(f'Event {event_id} not found in collection {collection}')

    email = request.form.get('email', None)
    updates = request.form.get('updates', '')

    if not email:
        raise HTTPException(400, 'Invalid request: missing parameter')

    already_subscribed = False

    try:
        if updates and updates == 'on' and not matched_collection.read_only:
            try:
                subscribe_to_event(event, event_id, matched_collection, email)
            except AlreadySubscribed:
                already_subscribed = True
            except:
                logging.error('Failed to subscribe to event: ' + traceback.format_exc())
                raise

        logging.info(f'Emailing event {event_id} to {email}')
        send_event_email(event, email, settings, matched_collection.default_organizer)

        if already_subscribed:
            notification = f'{email} is already subscribed to this event. New invite sent. Check your spam folder'
        else:
            notification = f'Event sent to {email}, check your spam folder'

        response = Response(render_event(collection, event_id, event, notification=notification, token=token, admin= not token and settings.is_admin(request)))
        response.headers['Set-Cookie'] = f'email={email}; Secure; SameSite=Strict; Path=/'
        return response
    except InvalidEmailAddress as e:
        return render_event(collection, event_id, event, notification= f'Invalid email: {str(e)}', token=token, admin=not token and settings.is_admin(request))


def send_event_update_impl(collection: str, event_id: str):
    admin_only()

    event, matched_collection, event_id = get_event(collection, event_id, follow_redirect=True)
    component = get_event_component(event)

    attendees = component.get('attendee', None)
    if isinstance(attendees, icalendar.vCalAddress):
        emails = [attendees.title().lower()]
    elif attendees:
        emails = [e.title().lower() for e in attendees]
    else:
        emails = []

    emails = [e.replace('mailto:', '') for e in emails]

    # Some CalDav client will add a 'user-id' in the attendee list, which might not be a valid email. Drop it to avoid issues
    emails = [e for e in emails if not matched_collection.is_excluded_email(e)]
    if not emails:
        return 'Event has no attendees', event
    else:
        if not matched_collection.read_only:
            logging.info(f'Incrementing sequence id for event {event_id}')
            increase_event_seq_number(event)
            matched_collection.save_event(event_id, event)

        for e in emails:
            logging.info(f'Emailing event {event_id} to {e}')
            send_event_email(event, e, settings, matched_collection.default_organizer)

        return 'Event sent to: ' + ', '.join(emails) + '. SEQUENCE=' + (str(component['sequence'] if 'sequence' in component else '[ABSENT]')), event


@app.route('/<collection>/<event_id>/update', methods=['POST'])
def send_event_update(collection: str, event_id: str):
    notification, event = send_event_update_impl(collection, event_id)
    return render_event(collection, event_id, event, notification=notification, admin=True)

@app.route('/api/<collection>/<event_id>/update', methods=['POST'])
@csrf.exempt
def update_api(collection, event_id):
    _, event = send_event_update_impl(collection, event_id)

    return json.dumps(event_json(collection, event)), 200


@app.route('/api/<collection>/<event_id>/subscribe', methods=['POST'])
@csrf.exempt
def subscribe_api(collection, event_id):
    admin_only()

    event, matched_collection, event_id = get_event(collection, event_id, follow_redirect=True)
    if not event:
        raise NotFoundException(f'Event {event_id} not found in collection {collection}')

    body = request.get_json()
    if body is None:
        raise HTTPException(400, 'Invalid request: empty body')

    email = body.get('email', None)
    updates = body.get('updates', None)
    if email is None or updates is None or not isinstance(updates, bool) :
        raise HTTPException(400, 'Invalid request: Missing parameter')

    try:
        try:
            if updates and not matched_collection.read_only:
                subscribe_to_event(event, event_id, matched_collection, email)
        except AlreadySubscribed:
            pass

        logging.info(f'Emailing event {event_id} to {email}')
        send_event_email(event, email, settings, matched_collection.default_organizer)
    except InvalidEmailAddress as e:
        return e.message, 400

    # Refresh event to include changes before returning it

    try:
        event = matched_collection.get_event(event_id)
    except NotFoundException as e:
        raise RuntimeError(f'Event {event_id} was not found after updating it')

    return json.dumps(event_json(collection, event)), 200

@app.route('/api/<collection>/<event_id>', methods=['GET'])
def event_api(collection, event_id):
    admin_only()

    event, matched_collection, _ = get_event(collection, event_id, follow_redirect=True)

    return json.dumps(event_json(collection, event)), 200

@app.route('/api/<collection>/search', methods=['POST'])
@csrf.exempt
def search_api(collection):
    admin_only()

    body = request.get_json()
    if body is None:
        raise HTTPException(400, 'Invalid request: empty body')

    search_term = body.get('pattern', '').strip()
    before = body.get('before', inf)
    after = body.get('after', 0)
    exact = body.get('exact', False)

    matched_collection = get_collection(collection)

    def match(event) -> bool:
        title = event['summary'].strip()

        if (exact and not search_term == title) or (not exact and search_term.lower() not in title.lower()):
            return False

        # Special case for repeating events
        if 'rrule' in event:
            if not 'dtstart' in event or not 'dtend' in event:
                logging.warning(f'Event {event} has rrule but not dtstart or dtend')
                return False # Invalid event, ignore

            rule = rrulestr(event['rrule'].to_ical().decode(), dtstart=rationalize_time(event['dtstart'].dt))

            begin = None
            if before != inf:
                begin = rule.before(rationalize_time(datetime.fromtimestamp(before)), inc=True)
                if begin is None: # Taken if the event never occured before 'begin'
                    return False

            end = None
            if after != 0:
                duration = event['dtend'].dt - event['dtstart'].dt
                end = (begin or rule.before(rationalize_time(datetime.fromtimestamp(after) - duration), inc=True)) + duration
        else:
            begin = None if not 'dtstart' in event else event['dtstart'].dt
            end = None if not 'dtend' in event else event['dtend'].dt

        if end is not None:
            if datetime.timestamp(rationalize_time(end)) < after:
                return False

        if begin is not None:
            if datetime.timestamp(rationalize_time(begin)) > before:
                return False

        return True


    matched_events = [e for e in matched_collection.all_events() if match(e)]

    def compare_events(left, right):
        def cmp(field: str) -> bool:
            if field not in left and field not in right:
                return 0

            if not field in left:
                return -1
            elif field not in right:
                return 1

            left_value = rationalize_time(left[field].dt)
            right_value = rationalize_time(right[field].dt)

            if left_value == right_value:
                return 0
            elif left_value > right_value:
                return 1
            else:
                return -1

        res = cmp('LAST-MODIFIED')
        if res == 0:
            res = cmp('CREATED')
            if res == 0:
                res = cmp('DTSTART')

        return res

    sorted_events = sorted(matched_events, key=cmp_to_key(compare_events), reverse=True)

    return json.dumps([event_json(collection, e) for e in sorted_events]), 200

@app.route('/api/<collection>', methods=['POST'])
@csrf.exempt
def create_api(collection):
    admin_only()

    matched_collection = get_collection(collection)

    try:
        event = icalendar.Calendar.from_ical(request.data)
    except Exception as e:
        raise InvalidVCal() from e

    if not isinstance(event, icalendar.cal.Calendar):
        logging.error(f'Unexpected vcal type: {type(event)}')
        raise InvalidVCal()

    if not event.subcomponents:
        logging.error('VCAl has no subcomponents')
        raise InvalidVCal()

    vevent = event.subcomponents[0]
    if not isinstance(vevent, icalendar.Event):
        logging.error(f'Unexpected vevent type: {type(vevent)}')
        raise InvalidVCal()

    uid = str(uuid.uuid4())
    vevent['uid'] = uid

    matched_collection.save_event(uid, event)

    url = f'/{collection}/{uid}.ics'
    response = {'week_access_url': generate_access_url(settings, url, datetime.now() + timedelta(days=7)), 'uid': uid}

    return json.dumps(response), 200

@app.route('/<collection>/<event>/ics', methods=['GET'])
def event_ics(collection, event):
    validate_access()

    content, _, _ = get_event(collection, event, follow_redirect=True)
    response = Response(content.to_ical())
    response.headers['Content-Disposition'] = f'Attachement; filename="{event}"'
    response.headers['Content-Type'] = f'content-type:text/calendar'

    return response

@app.route('/', methods=['GET'])
def home():
    admin_only()

    all_events = []

    for c in settings.collections:
        all_events += [(entry,c) for entry in settings.collections[c].all_events()]

    if request.args.get('all', None) == 'true':
        views = [make_event_list(all_events, 'LAST-MODIFIED', 'All events', 0, allow_nulls=True)]
        button = {'text': 'Show recent events', 'url': '/'}
    else:
        views = [
                 make_event_list(all_events, 'LAST-MODIFIED', 'Edited recently', settings.recent_count),
                 make_event_list(all_events, 'CREATED', 'Created recently', settings.recent_count),
                 make_event_list(all_events, 'DTSTART', 'Upcoming', settings.recent_count, reverse=False),
                ]
        button = {'text': 'Show all events', 'url': '/?all=true'}

    return render_template('list.jinja', lists=views, button=button)

def load_settings(path: str):
    spec = importlib.util.spec_from_file_location('settings', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    logging.info(f'Loaded settings from {path}')

    return module

def create_app(config=None):
    if not config:
        path = os.environ.get('EVENTS_CONFIG_PATH', None)
        if not path:
            raise RuntimeError('No config passed. Used either argv[1] or $EVENTS_CONFIG_PATH')

        config = load_settings(path)

    global settings
    settings = config
    app.secret_key = settings.secret_key

    return app

def main():
    if len(sys.argv) != 2:
        print(f'Usage {sys.argv[0]} <config path>')
        sys.exit(1)

    settings = load_settings(sys.argv[1])
    app = create_app(settings)
    app.run(host=settings.host, port=settings.port)

if __name__ == "__main__":
    main()
