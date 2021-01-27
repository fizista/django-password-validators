from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.test import TestCase, override_settings

from django_password_validators.password_history.password_validation import UniquePasswordsValidator
from django_password_validators.password_history.hashers import (
    HistoryVeryStrongHasher,
    HistoryHasher
)
from django_password_validators.password_history.models import (
    UserPasswordHistoryConfig,
    PasswordHistory
)

from .base import PasswordsTestCase


class UniquePasswordsValidatorTestCase(PasswordsTestCase):

    def test_create_user(self):
        self.create_user(1)
        self.assertEqual(PasswordHistory.objects.all().count(), 1)
        self.assertEqual(UserPasswordHistoryConfig.objects.all().count(), 1)

    def test_none_user(self):
        dummy_user = get_user_model()
        upv = UniquePasswordsValidator()
        upv.validate('qwerty', None)
        upv.password_changed('qwerty', None)

        self.assertEqual(PasswordHistory.objects.all().count(), 0)
        self.assertEqual(UserPasswordHistoryConfig.objects.all().count(), 0)

    def test_not_saved_user(self):
        dummy_user = get_user_model()
        upv = UniquePasswordsValidator()
        upv.validate('qwerty', dummy_user)
        upv.password_changed('qwerty', dummy_user)

        dummy_user = get_user_model()()
        upv = UniquePasswordsValidator()
        upv.validate('qwerty', dummy_user)
        upv.password_changed('qwerty', dummy_user)

        self.assertEqual(PasswordHistory.objects.all().count(), 0)
        self.assertEqual(UserPasswordHistoryConfig.objects.all().count(), 0)

    def test_create_multiple_users(self):
        self.create_user(1)
        self.create_user(2)
        self.assertEqual(PasswordHistory.objects.all().count(), 2)
        self.assertEqual(UserPasswordHistoryConfig.objects.all().count(), 2)

    def test_user_changed_password(self):
        self.create_user(1)
        self.user_change_password(user_number=1, password_number=2)
        # We check that there are no duplicate hashes passwords in the database
        self.user_change_password(user_number=1, password_number=2)
        # They must be only two hashes
        self.assertEqual(PasswordHistory.objects.all().count(), 2)
        self.assert_password_validation_False(user_number=1, password_number=2)
        self.assert_password_validation_True(user_number=1, password_number=3)
        self.user_change_password(user_number=1, password_number=3)
        self.assert_password_validation_False(user_number=1, password_number=3)

    def test_change_number_hasher_iterations(self):
        self.create_user(1)
        self.user_change_password(user_number=1, password_number=2)
        with self.settings(
                DPV_DEFAULT_HISTORY_HASHER='django_password_validators.password_history.hashers.HistoryVeryStrongHasher'):
            self.assert_password_validation_False(
                user_number=1,
                password_number=1
            )
            self.assert_password_validation_False(
                user_number=1,
                password_number=2
            )
            self.assert_password_validation_True(
                user_number=1,
                password_number=3
            )
            self.user_change_password(
                user_number=1,
                password_number=3
            )
            self.assert_password_validation_False(
                user_number=1,
                password_number=3
            )

            self.assertEqual(
                PasswordHistory.objects.filter(
                    user_config__iterations=HistoryHasher.iterations).count(),
                2,
            )
            self.assertEqual(
                PasswordHistory.objects.filter(
                    user_config__iterations=HistoryVeryStrongHasher.iterations).count(),
                1,
            )

    @override_settings(AUTH_PASSWORD_VALIDATORS=[{
        'NAME': 'django_password_validators.password_history.password_validation.UniquePasswordsValidator',
        'OPTIONS': {
            'lookup_range': 5 
        }  
    }])
    def test_lookup_range_true_positive(self):
        # We're considering the last 5 passwords
        self.create_user(1)
        self.user_change_password(user_number=1, password_number=1)
        self.user_change_password(user_number=1, password_number=2)
        self.user_change_password(user_number=1, password_number=3)
        self.assert_password_validation_False(user_number=1, password_number=1)
        self.assert_password_validation_False(user_number=1, password_number=2)
        self.assert_password_validation_False(user_number=1, password_number=3)
        self.assert_password_validation_False(user_number=1, password_number=4)

    @override_settings(AUTH_PASSWORD_VALIDATORS=[{
        'NAME': 'django_password_validators.password_history.password_validation.UniquePasswordsValidator',
        'OPTIONS': {
            'lookup_range': 2
        }  
    }])
    def test_lookup_range_true_negative(self):
        # We're considering the last 2 passwords
        self.create_user(1)
        self.user_change_password(user_number=1, password_number=1)
        self.user_change_password(user_number=1, password_number=2)
        self.assert_password_validation_False(user_number=1, password_number=1)
        self.assert_password_validation_False(user_number=1, password_number=2)
        self.assert_password_validation_True(user_number=1, password_number=3)
        self.user_change_password(user_number=1, password_number=3)
        self.assert_password_validation_False(user_number=1, password_number=3)
        self.assert_password_validation_True(user_number=1, password_number=4)

    @override_settings(AUTH_PASSWORD_VALIDATORS=[{
        'NAME': 'django_password_validators.password_history.password_validation.UniquePasswordsValidator',
        'OPTIONS': {
            'lookup_range': 1
        }  
    }])
    def test_lookup_range_last_password(self):
        # Considers the last password
        self.create_user(1)
        self.user_change_password(user_number=1, password_number=1)
        self.user_change_password(user_number=1, password_number=2)
        self.assert_password_validation_True(user_number=1, password_number=1)
        self.assert_password_validation_False(user_number=1, password_number=2)
        self.user_change_password(user_number=1, password_number=3)
        self.assert_password_validation_False(user_number=1, password_number=3)
        self.assert_password_validation_True(user_number=1, password_number=4)

    @override_settings(AUTH_PASSWORD_VALIDATORS=[{
        'NAME': 'django_password_validators.password_history.password_validation.UniquePasswordsValidator',
        'OPTIONS': {
            'lookup_range': 0
        }  
    }])
    def test_lookup_range_zero(self):
        # If it's a 0, we're considering no passwords
        self.create_user(1)
        self.user_change_password(user_number=1, password_number=1)
        self.user_change_password(user_number=1, password_number=2)
        self.user_change_password(user_number=1, password_number=3)
        self.assert_password_validation_True(user_number=1, password_number=1)
        self.assert_password_validation_True(user_number=1, password_number=2)
        self.assert_password_validation_True(user_number=1, password_number=3)
        self.assert_password_validation_True(user_number=1, password_number=4)
        self.user_change_password(user_number=1, password_number=4)
        self.assert_password_validation_True(user_number=1, password_number=4)

    @override_settings(AUTH_PASSWORD_VALIDATORS=[{
        'NAME': 'django_password_validators.password_history.password_validation.UniquePasswordsValidator',
        'OPTIONS': {
            'lookup_range': -3
        }  
    }])
    def test_lookup_range_invalid(self):
        # If it's negative, defaults to all the passwords
        self.create_user(1)
        self.user_change_password(user_number=1, password_number=1)
        self.user_change_password(user_number=1, password_number=2)
        self.user_change_password(user_number=1, password_number=3)
        self.assert_password_validation_False(user_number=1, password_number=1)
        self.assert_password_validation_False(user_number=1, password_number=2)
        self.assert_password_validation_False(user_number=1, password_number=3)
        self.assert_password_validation_True(user_number=1, password_number=4)
