from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.test import TestCase


class PasswordsTestCase(TestCase):
    """
    Local varibles:
        self.UserModel - user model class
    """

    PASSWORD_TEMPLATE = 'ABCDEFGHIJKLMNOPRSTUWXYZ_%d'

    def create_user(self, number=1):
        return self.UserModel.objects.create_user(
            'test%d' % number,
            email='test%d@example.com' % number,
            password=self.PASSWORD_TEMPLATE % 1
        )

    def user_change_password(self, user_number, password_number):
        user = self.UserModel.objects.get(username='test%d' % user_number)
        user.set_password(self.PASSWORD_TEMPLATE % password_number)
        user.save()

    def user_change_password_number_of_times(self, user_number, num_of_times):
        """
        Performs 'num_of_times' password changes for the test user
        """
        user = self.UserModel.objects.get(username='test%d' % user_number)
        for i in range(num_of_times):
            user.set_password(self.PASSWORD_TEMPLATE % i)
            user.save()

    def assert_password_validation_True(self, user_number, password_number):
        user = self.UserModel.objects.get(username='test%d' % user_number)
        validate_password(
            self.PASSWORD_TEMPLATE % password_number,
            user
        )

    def assert_password_validation_False(self, user_number, password_number):
        user = self.UserModel.objects.get(username='test%d' % user_number)

        try:
            validate_password(
                self.PASSWORD_TEMPLATE % password_number,
                user
            )
        except ValidationError as e:
            for error in e.error_list:
                if e.error_list[0].code == 'password_used':
                    return
            else:
                raise e

    def assert_password_validation_number_of_times(self, user_number, num_of_times, to_assert):
        """
        Asserts password validation is False a 'num_of_times' for the test user
        """
        if to_assert:
            for i in range(num_of_times):
                self.assert_password_validation_True(user_number=user_number, password_number=i)
        else:
            for i in range(num_of_times):
                self.assert_password_validation_False(user_number=user_number, password_number=i)

    def setUp(self):
        self.UserModel = get_user_model()
        super(PasswordsTestCase, self).setUp()

    def tearDown(self):
        self.UserModel.objects.all().delete()
        super(PasswordsTestCase, self).tearDown()
