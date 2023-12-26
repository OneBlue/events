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
