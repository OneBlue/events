import icalendar
import requests
import logging
from .errors import *
from xml.etree import ElementTree
from xml.sax.saxutils import escape


def remove_ics(path: str) -> str:
    if path.endswith('.ics'):
        return path[:-4]
    else:
        return path

class Collection:
    def __init__(self, url: str, auth, show_private=False, uid_only=False, read_only=False):
        self.url = url
        self.auth = auth
        self.show_private = show_private
        self.uid_only = uid_only
        self.read_only = read_only

    def is_event_visible(self, event) -> bool:
        if event.name == 'VTODO':
            return False

        if not self.show_private and 'CLASS' in event and event['class'].title().upper() != 'PUBLIC':
            return False

        for e in event.subcomponents:
            if e.name == 'VTODO':
                return False # VTODO: skipping

            if not self.show_private and 'CLASS' in e and e['class'].title().upper() != 'PUBLIC':
                return False

        return True


    def get_event_impl(self, name: str):
        response = requests.get(self.url + name, auth=self.auth)
        if response.status_code == 404:
            return None

        response.raise_for_status()

        return icalendar.Calendar.from_ical(response.text)


    def get_event(self, name: str):
        if '/' in name or '<' in name or '>' in name or '"' in name or "'" in name:
            raise SuspiciousRequest('Suspicous event name: ' + name)

        if self.uid_only:
            # Special case for calendar providers that don't support individual event queries
            matched_events = [e for e in self.all_events() if e.get('uid') == name]

            if len(matched_events) > 1:
                raise NotFoundException(f'Multiple events with uid "{name}" found')

            if not matched_events:
                raise NotFoundException(f'No event with uid "{name}" found')

            event = matched_events[0]
        else:
            # Try with and without the .ics
            event = self.get_event_impl(name + '.ics') if not name.endswith('.ics') else None
            event = event or self.get_event_impl(name)

            if not event:
                # Unfortunately the uid doesn't always match the filename.
                # In that case we need to lookup the filename for the UID
                # And issue a redirect to the correct page

                raise EventRedirect(self.lookup_event_by_uid(remove_ics(name)))

        if not self.is_event_visible(event):
            logging.info(f'Attempt to access private event: {name}')
            raise SuspiciousRequest(f'Attempt to access private event: {name}')

        return event

    def lookup_event_by_uid(self, uid: str):
        session = requests.Session()
        session.auth = self.auth

        query = f'''
        <C:calendar-query xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav">
            <D:prop>
              <D:getetag/>
            </D:prop>
            <C:filter>
              <C:comp-filter name="VCALENDAR">
                <C:comp-filter name="VEVENT">
                  <C:prop-filter name="UID">
                    <C:text-match>{escape(uid)}</C:text-match>
                  </C:prop-filter>
                </C:comp-filter>
              </C:comp-filter>
            </C:filter>
            </C:calendar-query>'''

        response = session.request(url=self.url, method='REPORT', data=query)
        response.raise_for_status()

        tree = ElementTree.fromstring(response.text)

        entries = tree.findall('./{DAV:}response/{DAV:}href')
        logging.info(f'UID lookup for {uid} returned {len(entries)} entries')

        if len(entries) != 1:
            raise NotFoundException(f'Unique event with UID {uid} not found ({len(entries)} matches)')

        # The url might contain the collection name, but all that we want is the file name
        return remove_ics(entries[0].text.split('/')[-1])

    def save_event(self, name: str, event):
        logging.info(f'Saving event {name} in backend')

        if '/' in name:
            raise SuspiciousRequest('Suspicous event name: ' + name)

        if not name.endswith('.ics'): # Handle ics-less URLS
            name = name + '.ics'

        response = requests.put(self.url + name, auth=self.auth, data=event.to_ical())
        try:
            response.raise_for_status()
        except Exception as e:
            raise RuntimeError(f'Error while saving event. Body: "{e.response.text}"') from e

    def all_events(self):
        response = requests.get(self.url, auth=self.auth)
        response.raise_for_status()

        return [e for e in icalendar.Calendar.from_ical(response.text).subcomponents if e.has_key('summary') and self.is_event_visible(e)]


