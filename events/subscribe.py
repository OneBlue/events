import smtplib
import logging
import icalendar
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email.mime.text import MIMEText
from email.utils import COMMASPACE, formatdate, parseaddr
from email import encoders
from .errors import *
from .utils import get_event_component


# Used for testing
send_email_override = None

def override_send_email(method):
    global send_email_override
    send_email_override = method


def validate_email(email: str):
    try:
        if not '@' in parseaddr(email)[1]:
            raise InvalidEmailAddress(email)
    except:
        raise InvalidEmailAddress(email)

def subscribe_to_event(event, event_name, collection, email):
    validate_email(email)

    component = get_event_component(event)
    attendees = component.get('attendee')

    if attendees:
        expected_field = 'mailto:' + email.lower()
        if (isinstance(attendees, icalendar.vCalAddress) and attendees.title().lower() == expected_field) or any(e.title().lower() == expected_field for e in attendees):
            raise AlreadySubscribed(f'{email} is already subscribed to this event')

    logging.info(f'Adding {email} to event {event_name}')
    attendee = icalendar.vCalAddress('MAILTO:' + email)
    attendee.params['ROLE'] = icalendar.vText('REQ-PARTICIPANT')
    component.add('attendee', attendee)

    collection.save_event(event_name, event)

def send_event_email(event, destination, settings, default_organizer):
    validate_email(destination)

    component = get_event_component(event)

    if not 'organizer' in component and default_organizer:
        component.add('organizer', default_organizer)

    cal = icalendar.Calendar()
    cal.add('prodid', '-//events.bluecode.fr')
    cal.add('version', '2.0')
    cal.add('method', "REQUEST")
    cal.add_component(component)

    content = MIMEMultipart('alternative')
    content['Reply-To'] = settings.email_from
    content['Date'] = formatdate(localtime=True)
    content['Subject'] = str(component['summary'])
    content['From'] = settings.email_from
    content['To'] = destination
    content["Content-class"] = "urn:content-classes:calendarmessage"
    content.attach(MIMEText('Calendar invite for event: ' + str(component['summary'])))

    cal_content = MIMEBase('text', "calendar", method="REQUEST", name='invite.ics')
    cal_content.set_payload(cal.to_ical())
    encoders.encode_base64(cal_content)
    cal_content.add_header('Content-class', 'urn:content-classes:calendarmessage')
    cal_content.add_header('Content-Description', 'invite.ics')
    cal_content.add_header('Filename', 'invite.ics')
    cal_content.add_header('Path', 'invite.ics')

    content.attach(cal_content)

    if send_email_override:
        return send_email_override(settings.email_from, [destination], content.as_string())
    else:
        mailserver = smtplib.SMTP(settings.smtp_server, settings.smtp_port)
        mailserver.ehlo()
        mailserver.starttls()
        mailserver.ehlo()
        mailserver.sendmail(settings.email_from, [destination], content.as_string())
        mailserver.quit()

