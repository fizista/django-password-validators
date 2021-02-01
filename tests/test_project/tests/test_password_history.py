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
            'lookup_range': 3
        }
    }])
    def test_lookup_range(self):
        """
        Tests considering the last 3 passwords and setting a valid password.
        """
        self.create_user(1)
        self.user_change_password_number_of_times(user_number=1, num_of_times=4)
        self.assert_password_validation_number_of_times(user_number=1, num_of_times=4, to_assert=False)
        self.assert_password_validation_True(user_number=1, password_number=4)

    def test_lookup_range_not_an_int(self):
        """
        Tests that a TypeError is raised if lookup_range
        is not an integer (considering string, list and dict).
        """
        with self.assertRaises(TypeError):
            UniquePasswordsValidator(lookup_range='something')

        with self.assertRaises(TypeError):
            UniquePasswordsValidator(lookup_range={'foo': 1})

        with self.assertRaises(TypeError):
            UniquePasswordsValidator(lookup_range=[2])

    @override_settings(AUTH_PASSWORD_VALIDATORS=[{
        'NAME': 'django_password_validators.password_history.password_validation.UniquePasswordsValidator',
        'OPTIONS': {
            'lookup_range': 2
        }
    }])
    def test_lookup_range_change_then_retry(self):
        """
        Tests considering the last 2 passwords, entering a valid third one
        then confirming it's no longer valid
        """
        self.create_user(1)
        self.user_change_password_number_of_times(user_number=1, num_of_times=3)
        self.assert_password_validation_number_of_times(user_number=1, num_of_times=3, to_assert=False)
        self.assert_password_validation_True(user_number=1, password_number=3)
        self.user_change_password(user_number=1, password_number=3)
        self.assert_password_validation_False(user_number=1, password_number=2)

        # password_number=1 should now be valid as it was deleted
        self.assert_password_validation_True(user_number=1, password_number=1)
        self.assert_password_validation_False(user_number=1, password_number=3)
        self.assert_password_validation_True(user_number=1, password_number=4)

    @override_settings(AUTH_PASSWORD_VALIDATORS=[{
        'NAME': 'django_password_validators.password_history.password_validation.UniquePasswordsValidator',
        'OPTIONS': {
            'lookup_range': 1
        }
    }])
    def test_lookup_range_last_password(self):
        """
        Tests considering only the last password
        """
        self.create_user(1)
        self.user_change_password_number_of_times(user_number=1, num_of_times=3)
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
        """
        Tests that if lookup_range == 0, we're considering no passwords
        """
        self.create_user(1)
        self.user_change_password_number_of_times(user_number=1, num_of_times=4)
        self.assert_password_validation_number_of_times(user_number=1, num_of_times=5, to_assert=False)
        self.user_change_password(user_number=1, password_number=4)
        self.assert_password_validation_True(user_number=1, password_number=4)

    @override_settings(AUTH_PASSWORD_VALIDATORS=[{
        'NAME': 'django_password_validators.password_history.password_validation.UniquePasswordsValidator',
        'OPTIONS': {
            'lookup_range': -3
        }
    }])
    def test_lookup_range_invalid(self):
        """
        Tests that if lookup_range is negative, defaults to all the passwords
        """
        self.create_user(1)
        self.user_change_password_number_of_times(user_number=1, num_of_times=3)
        self.assert_password_validation_number_of_times(user_number=1, num_of_times=4, to_assert=False)
        self.assert_password_validation_True(user_number=1, password_number=4)

    @override_settings(AUTH_PASSWORD_VALIDATORS=[{
        'NAME': 'django_password_validators.password_history.password_validation.UniquePasswordsValidator',
        'OPTIONS': {
            'lookup_range': 2
        }
    }])
    def test_delete_history_in_lookup_range(self):
        """
        Tests that older passwords outside of lookup_range are deleted whenever a validation takes place
        """
        self.create_user(1)
        self.assertEqual(PasswordHistory.objects.count(), 1)
        self.user_change_password(user_number=1, password_number=2)
        self.assertEqual(PasswordHistory.objects.count(), 2)
        self.user_change_password(user_number=1, password_number=3)
        self.assert_password_validation_False(user_number=1, password_number=2)
        self.assert_password_validation_False(user_number=1, password_number=3)
        self.assert_password_validation_True(user_number=1, password_number=1)
        self.assertEqual(PasswordHistory.objects.count(), 2)

    @override_settings(AUTH_PASSWORD_VALIDATORS=[{
        'NAME': 'django_password_validators.password_history.password_validation.UniquePasswordsValidator',
        'OPTIONS': {
            'lookup_range': 12
        }
    }])
    def test_dont_delete_history_in_lookup_range(self):
        """
        Tests that older passwords inside of lookup_range are not deleted whenever a validation takes place
        """
        self.create_user(1)
        self.assertEqual(PasswordHistory.objects.count(), 1)
        self.user_change_password(user_number=1, password_number=2)
        self.assertEqual(PasswordHistory.objects.count(), 2)
        self.user_change_password(user_number=1, password_number=3)
        self.assert_password_validation_False(user_number=1, password_number=3)
        self.assertEqual(PasswordHistory.objects.count(), 3)

    @override_settings(AUTH_PASSWORD_VALIDATORS=[{
        'NAME': 'django_password_validators.password_history.password_validation.UniquePasswordsValidator',
        'OPTIONS': {
            'lookup_range': 2
        }
    }])
    def test_delete_history_by_dates(self):
        """
        Tests that passwords are deleted by ordering of date,
        not just position, and the correct ones are deleted
        """
        lookup_range = 2
        self.create_user(1)
        self.user_change_password_number_of_times(user_number=1, num_of_times=5)

        all_passwords = list(PasswordHistory.objects.all().order_by('date'))

        self.assert_password_validation_False(user_number=1, password_number=4)
        self.assert_password_validation_True(user_number=1, password_number=5)

        passwords_to_delete = all_passwords[
            :len(all_passwords) - lookup_range
        ]
        passwords_to_lookup = all_passwords[len(all_passwords) - lookup_range:]

        for entry in passwords_to_delete:
            with self.assertRaises(PasswordHistory.DoesNotExist) as context:
                entry.refresh_from_db()
                self.assertTrue(
                    'PasswordHistory.DoesNotExist' in str(
                        context.exception)
                    )

        self.assertEqual(
            len(passwords_to_lookup),
            lookup_range
        )
        self.assertEqual(
            passwords_to_lookup,
            list(PasswordHistory.objects.all().order_by('date'))
        )

    @override_settings(AUTH_PASSWORD_VALIDATORS=[{
        'NAME': 'django_password_validators.password_history.password_validation.UniquePasswordsValidator',
        'OPTIONS': {
            'lookup_range': 16
        }
    }])
    def test_delete_history_in_large_lookup_range(self):
        """
        Tests that if lookup_range > count of PasswordHistory, the validator doesn't delete any
        """
        self.create_user(1)
        self.assert_password_validation_False(user_number=1, password_number=1)
        self.assertEqual(PasswordHistory.objects.count(), 1)
        self.user_change_password_number_of_times(user_number=1, num_of_times=4)
        self.assertEqual(PasswordHistory.objects.count(), 4)
        self.assert_password_validation_False(user_number=1, password_number=1)
        self.assert_password_validation_False(user_number=1, password_number=2)
        self.assert_password_validation_True(user_number=1, password_number=5)
        self.assertEqual(PasswordHistory.objects.count(), 4)

    def test_lookup_range_undefined(self):
        """
        Tests that lookup_range defaults to None (all passwords) if undefined
        """
        self.create_user(1)
        validator = UniquePasswordsValidator()
        lookup_range = validator.lookup_range
        self.assertEqual(lookup_range, float('inf'))
        self.assert_password_validation_number_of_times(user_number=1, num_of_times=4, to_assert=False)
        self.assert_password_validation_True(user_number=1, password_number=4)

    @override_settings(AUTH_PASSWORD_VALIDATORS=[{
        'NAME': 'django_password_validators.password_history.password_validation.UniquePasswordsValidator',
        'OPTIONS': {
            'lookup_range': 3
        }
    }])
    def test_delete_history_many_entries(self):
        """
        Tests that if lookup_range works well with many password entries
        """
        self.create_user(1)
        self.user_change_password_number_of_times(user_number=1, num_of_times=9)
        self.assert_password_validation_number_of_times(user_number=1, num_of_times=6, to_assert=True)
        for i in range(6, 9):
            self.assert_password_validation_False(
                user_number=1, password_number=i
            )

    @override_settings(AUTH_PASSWORD_VALIDATORS=[{
        'NAME': 'django_password_validators.password_history.password_validation.UniquePasswordsValidator',
        'OPTIONS': {
            'lookup_range': 2
        }
    }])
    def test_delete_history_and_invalid_password(self):
        """
        Tests submiting one of the remaining passwords after deletion raises an exception
        """
        self.create_user(1)
        self.user_change_password_number_of_times(user_number=1, num_of_times=4)
        self.assert_password_validation_False(user_number=1, password_number=3)