import re
from django.core.exceptions import ValidationError

class CustomPasswordValidator:
    def validate(self, password, user=None, username=None):
        if len(password) < 8:
            raise ValidationError("Password must be at least 8 characters long.")

        if not re.search(r"[A-Z]", password):
            raise ValidationError("Password must include at least one uppercase letter.")

        if not re.search(r"[a-z]", password):
            raise ValidationError("Password must include at least one lowercase letter.")

        if not re.search(r"\d", password):
            raise ValidationError("Password must include at least one digit.")

        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
            raise ValidationError("Password must include at least one special character.")

        if username and username.lower() in password.lower():
            raise ValidationError("Password should not contain the username.")
        
        if password.startswith('_'):
            raise ValidationError("Password cannot start or end with an underscore.")

    def get_help_text(self):
        return (
            "Your password must be at least 8 characters long and include "
            "an uppercase letter, a lowercase letter, a number, and a special character. "
            "It must not contain your username."
        )


class UsernameValidator:
    def validate(self, username):
        if len(username) < 5 or len(username) > 30:
            raise ValidationError("Username must be between 5 and 30 characters long.")

       
        if username.startswith('_') or username.endswith('_'):
            raise ValidationError("Username cannot start or end with an underscore.")

        if '__' in username:
            raise ValidationError("Username cannot contain consecutive underscores.")
    
        if not re.fullmatch(r'[A-Za-z][A-Za-z0-9]*', username):
            raise ValidationError('Username must start with a letter  and only contains letters and numbers')


    def get_help_text(self):
        return (
            "Your username must be 5–30 characters long, start with a letter, "
            "contain only letters, numbers, or underscores, and not start/end with an underscore or include '__'."
        )
