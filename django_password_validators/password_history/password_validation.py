from __future__ import unicode_literals
import warnings

from django.core.exceptions import ValidationError
from django.utils.translation import ugettext as _
from django_password_validators.settings import get_password_hasher
from django_password_validators.password_history.models import (
    PasswordHistory,
    UserPasswordHistoryConfig,
)


class UniquePasswordsValidator(object):
    """
    Validate whether the password was once used by the user
    in a determined range.
    The password is only checked for an existing user.
    """

    def __init__(self, lookup_range=3):
        self.lookup_range = lookup_range if lookup_range >= 0 else float('inf') 

    def _user_ok(self, user):
        if not user:
            return

        user_pk = getattr(user, 'pk', None)
        if user_pk is None:
            warnings.warn(
                'An unsaved user model!s %r'
                % user
            )
            return

        if isinstance(user_pk, property):
            warnings.warn(
                'Not initialized user model! %r'
                % user
            )
            return

        return True

    def validate(self, password, user=None):

        if not self._user_ok(user):
            return

        for user_config in UserPasswordHistoryConfig.objects.filter(user=user):
            password_hash = user_config.make_password_hash(password)
            lookup_range = min(self.lookup_range, 
                PasswordHistory.objects.filter(user_config=user_config).count())
            try:
                if lookup_range == 0:
                    raise PasswordHistory.DoesNotExist
                else:
                    password_history = PasswordHistory.objects.filter(
                        user_config=user_config)[:lookup_range - 1] 
                    
                    repeated_password =  PasswordHistory.objects.get(
                        user_config=user_config,
                        password=password_hash
                    )

                    if repeated_password in password_history:
                        raise ValidationError(
                            _("You cannot use a password that was recently used in this application."),
                            code='password_used'
                        )
            except PasswordHistory.DoesNotExist:
                pass

    def password_changed(self, password, user=None):

        if not self._user_ok(user):
            return

        user_config = UserPasswordHistoryConfig.objects.filter(
            user=user,
            iterations=get_password_hasher().iterations
        ).first()

        if not user_config:
            user_config = UserPasswordHistoryConfig()
            user_config.user = user
            user_config.save()

        password_hash = user_config.make_password_hash(password)

        # We are looking for a hashed password
        # in the last "lookup_range" entries.
        try:
            PasswordHistory.objects.get(
                user_config=user_config,
                password=password_hash
            )
        except PasswordHistory.DoesNotExist:
            ols_password = PasswordHistory()
            ols_password.user_config = user_config
            ols_password.password = password_hash
            ols_password.save()

    def get_help_text(self):
        return _('Your new password can not be identical to any of the '
                 'previously entered.')
