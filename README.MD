# Events

A web UI to share calendar invites from a private caldav server.


## Configuration

Configuration is done through a .py file. See `config.sample.py`.

## Deploy

Install via:

```
$ git clone https://bitbucket.org/_Blue/events
$ cd events
$ pip install .
```

Run via:

```
events /path/to/config.py
```

## Testing

Run the unit tests via:

```
$ pytest events
```
