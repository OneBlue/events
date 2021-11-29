
class HTTPException(RuntimeError):
    def __init__(self, code: int, message: str):
        self.code = code
        self.message = message


class NotFoundException(HTTPException):
    def __init__(self, message: str):
        super().__init__(404, message)

class SuspiciousRequest(HTTPException):
    def __init__(self, message: str):
        super().__init__(404, message)

class AlreadySubscribed(HTTPException):
    def __init__(self, message: str):
        super().__init__(200, message)

class InvalidEmailAddress(HTTPException):
    def __init__(self, address: str):
        super().__init__(400, f'Invalid email address: {address}')

class InvalidVCal(HTTPException):
    def __init__(self):
        super().__init__(400, f'Caldav data couldnt be parsed')

class AdminRequired(HTTPException):
    def __init__(self):
        super().__init__(404, 'Admin required') # Returning 404 by design to hide admin content

class EventRedirect(RuntimeError):
    def __init__(self, filename: str):
        super().__init__()
        self.filename = filename

class InvalidToken(HTTPException):
    def __init__(self):
        super().__init__(404, 'Invalid token') # Returning 404 by design to hide admin content

class ExpiredToken(HTTPException):
    def __init__(self):
        super().__init__(200, 'Token expired')
