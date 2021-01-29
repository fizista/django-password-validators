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
    in the configured lookup_range.
    The password is only checked for an existing user.
    """

    def __init__(self, lookup_range=float('inf')):
        try:
            self.lookup_range = (
                lookup_range if lookup_range >= 0 else float('inf')
            )
        except BaseException:
            raise TypeError(
                'UniquePasswordsValidator Error: lookup_range is not a '
                'positive integer'
            )
        self.validation_error = ValidationError(
            _(
                "You cannot use a password that was recently used in "
                "this application."
            ),
            code='password_used'
        )

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
            try:
                if self.lookup_range == 0:
                    raise PasswordHistory.DoesNotExist

                current_user_passwords = PasswordHistory.objects.filter(
                    user_config=user_config
                ).order_by('date')

                num_user_passwords = len(current_user_passwords)

                if self.lookup_range >= num_user_passwords:
                    PasswordHistory.objects.get(
                        user_config=user_config,
                        password=password_hash
                    )
                    raise self.validation_error

                else:
                    # At this point, there are passwords we have to delete
                    for entry in current_user_passwords[
                        :len(current_user_passwords) - self.lookup_range
                    ]:
                        entry.delete()

                    if any(
                        entry.user_config == user_config and
                        entry.password == password_hash
                        for entry in current_user_passwords[
                            num_user_passwords - self.lookup_range:
                        ]
                    ):
                        raise self.validation_error

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
        # in the last "lookup_range" entries in the database.
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
