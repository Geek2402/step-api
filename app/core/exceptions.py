class AppError(Exception):
    """Business error with an explicit HTTP status code and message, caught globally in main.py."""

    def __init__(self, status_code: int, message: str):
        self.status_code = status_code
        self.message = message
        super().__init__(message)


class EmailDeliveryError(AppError):
    def __init__(self, message: str = "Unable to send the verification email at the moment, please try again later"):
        super().__init__(503, message)
