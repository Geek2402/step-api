class AppError(Exception):
    """Erreur métier avec code HTTP et message explicites, catchée globalement dans main.py."""

    def __init__(self, status_code: int, message: str):
        self.status_code = status_code
        self.message = message
        super().__init__(message)


class EmailDeliveryError(AppError):
    def __init__(self, message: str = "Impossible d'envoyer l'email de vérification pour le moment, réessayez plus tard"):
        super().__init__(503, message)
