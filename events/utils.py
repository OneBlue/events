from .errors import SuspiciousRequest

def get_event_components(event) -> list:
    if 'summary' in event:
        return [event]

    return [e for e in event.subcomponents if e.name == 'VEVENT']

def get_event_component(event):
    components = get_event_components(event)

    if not components:
        raise RuntimeError(f'Not valid components found in event: {event}')

    if len(components) > 2:
        raise RuntimeError(f'Multiple components found in event: {event}')

    return components[0]

def increase_event_seq_number(event):
    component = get_event_component(event)

    if not 'sequence' in component:
        sequence = 1
    else:
        sequence = component['sequence'] + 1

    component['sequence'] = sequence
    return event

def expect_type(value, types, name: str, allow_none=False):
    if value is None and allow_none:
        return

    if not any(isinstance(value, e) for e in types):
        raise SuspiciousRequest(f"Unexpected type for '{name}': {type(value).__name__}")
