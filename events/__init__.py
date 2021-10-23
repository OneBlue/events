#! /usr/bin/python3

import sys
import os
import logging
import traceback
import itertools
import importlib.util
import json
from humanize import naturaldelta
from icalendar import vCalAddress
from flask import Flask, request, render_template, Response
from .errors import *
from .subscribe import send_event_email, subscribe_to_event, validate_email
from .access import validate_token, generate_access_url
from datetime import datetime, date, timedelta
from tzlocal import get_localzone
from flask import request, redirect
from flask_wtf.csrf import CSRFProtect
from urllib.parse import quote_plus
from dateutil.rrule import rrulestr

settings = None
app = Flask(__name__)
csrf = CSRFProtect()
csrf.init_app(app)


def get_collection(collection: str):
    matched_collection = settings.collections.get(collection)
    if not matched_collection:
        raise NotFoundExceptionf(f'Collection {collection} not found')

    return matched_collection

def get_event(collection: str, event: str):
    matched_collection = get_collection(collection)

    matched_event = matched_collection.get_event(event)
    if not matched_event:
        raise NotFoundException(f'Event {event} not found in collection {collection}')

    return matched_event

def rationalize_time(ts) -> datetime:
    if not isinstance(ts, datetime): # In case of date, convert to datetime (set 00:00)
        assert isinstance(ts, date)
        return get_localzone().localize(datetime.combine(ts, datetime.min.time()))
    else:
        return ts.astimezone(get_localzone())

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

def get_event_fields(event):
    component = next(e for e in event.subcomponents if 'summary' in e)

    event = {'title': str(component['summary'])}

    if 'dtstart' in component:
        event['start'] = format_time(component['dtstart'].dt)

    if 'dtend' in component:
        event['end'] = format_time(component['dtend'].dt)

    if 'description' in component :
        event['description'] = str(component['description'])

    if 'location' in component:
        event['location'] = str(component['location'])

    attendees = component.get('attendee')
    if attendees:
        if isinstance(attendees, vCalAddress):
            event['attendees'] = [attendees.lower().replace('mailto:', '')]
        else:
            event['attendees'] = [e.lower().replace('mailto:', '') for e in attendees]

    return event

@app.errorhandler(HTTPException)
def handle_exception(error: HTTPException):
    logging.error(f'Handling exception: {error}, stack trace: {traceback.format_exc()}')

    if isinstance(error, ExpiredToken):
        return 'Token expired', 200

    content = traceback.format_exc().replace('\n', '\r\n') if settings.is_admin(request) else ''
    return content, error.code

def render_event(collection_id, event_id, event_data, **extra_fields):
    fields = get_event_fields(event_data)
    fields['collection'] = collection_id
    fields['event'] = event_id
    add_request_auth(fields)

    for e in extra_fields:
        fields[e] = extra_fields[e]

    if settings.is_admin(request):
        fields['admin_links'] = [
                                {'title': '1 day link', 'url': generate_access_url(settings, request, datetime.now() + timedelta(days=1))},
                                {'title': '30 days link', 'url': generate_access_url(settings, request, datetime.now() + timedelta(days=30))},
                                ]

        component = next(e for e in event_data.subcomponents if 'summary' in e)
        if component and 'dtstart' in component:
            ts = rationalize_time(component['dtstart'].dt)
            fields['admin_links'].append({'title': 'Event date + 1 week link', 'url': generate_access_url(settings, request, ts + timedelta(days=7))})

    return render_template('event.jinja', **fields)


@app.route('/<collection>/<event>', methods=['GET'])
def event_page(collection, event):
    validate_access()

    try:
        event_data = get_event(collection, event)
    except EventRedirect as e:
        logging.info(f'Redirecting event {event} to {e.filename}')
        assert event.lower() != e.filename.lower()
        return redirect(f'/{collection}/{e.filename}')

    return render_event(collection, event, event_data)

@app.route('/<collection>/<event_id>/subscribe', methods=['POST'])
def subscribe(collection, event_id):
    validate_access(request.form.get('t', None))

    matched_collection = get_collection(collection)
    event = matched_collection.get_event(event_id)
    if not event:
        raise NotFoundException(f'Event {event_id} not found in collection {collection}')

    email = request.form.get('email', None)
    updates = request.form.get('updates', '')

    if not email:
        raise HTTPException(400, 'Invalid request: missing parameter')

    already_subscribed = False

    try:
        if updates and updates == 'on':
            try:
                subscribe_to_event(event, event_id, matched_collection, email)
            except AlreadySubscribed:
                already_subscribed = True
            except:
                logging.error('Failed to subscribe to event: ' + traceback.format_exc())
                raise

        logging.info(f'Emailing event {event_id} to {email}')
        send_event_email(event, email, settings)

        if already_subscribed:
            return render_event(collection, event_id, event, notification= f'{email} is already subscribed to this event. New invite sent. Check your spam folder')
        else:
            return render_event(collection, event_id, event, notification=f'Event sent to {email}, check your spam folder')
    except InvalidEmailAddress as e:
        return render_event(collection, event_id, event, notification= f'Invalid email: {str(e)}')

@app.route('/api/<collection>/<event_id>/subscribe', methods=['POST'])
@csrf.exempt
def subscribe_api(collection, event_id):
    admin_only()

    matched_collection = get_collection(collection)
    event = matched_collection.get_event(event_id)
    if not event:
        raise NotFoundException(f'Event {event_id} not found in collection {collection}')

    body = request.get_json()
    email = body.get('email', None)
    updates = body.get('updates', None)
    if email is None or updates is None or not isinstance(updates, bool) :
        raise HTTPException(400, 'Invalid request: Missing parameter')

    try:
        try:
            if updates:
                subscribe_to_event(event, event_id, matched_collection, email)
        except AlreadySubscribed:
            pass

        logging.info(f'Emailing event {event_id} to {email}')
        send_event_email(event, email, settings)
    except InvalidEmailAddress as e:
        return e.message, 400

    return '', 200


@app.route('/api/<collection>/<event_id>', methods=['GET'])
def event_api(collection, event_id):
    admin_only()

    matched_collection = get_collection(collection)
    event = matched_collection.get_event(event_id)

    content = get_event_fields(event)
    fields = ['start', 'end', 'description', 'location', 'attendees']
    for e in fields:
        if e not in content:
            content[e] = None

    return json.dumps(content), 200

@app.route('/<collection>/<event>/ics', methods=['GET'])
def event_ics(collection, event):
    validate_access()

    content = get_event(collection, event).to_ical()
    response = Response(content)
    response.headers['Content-Disposition'] = f'Attachement; filename="{event}"'
    response.headers['Content-Type'] = f'content-type:text/calendar'

    return response

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
