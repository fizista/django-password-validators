==========================
Django Password Validators
==========================

Additional libraries for validating passwords in Django 2.2.8 or later.

django-password-validators requires Django 2.2.8 or greater.

The application works well under python 3.x and 2.x versions.

Django version after the number 1.9, allows you to configure password validation.
Configuration validation is placed under the variable AUTH_PASSWORD_VALIDATORS_.


Installation
============

Just install ``django-password-validators`` via ``pip``::

    $ pip install django-password-validators
    
    
Validators
==========

------------------------
UniquePasswordsValidator
------------------------
Validator checks if the password was once used by a particular user. 
If the password is used, then an exception is thrown, of course.

For each user, all the passwords are stored in a database.
All passwords are strongly encrypted.

Configuration...

In the file settings.py we add ::

    INSTALLED_APPS = [
        ...
        'django_password_validators',
        'django_password_validators.password_history',
        ...
    ]

   AUTH_PASSWORD_VALIDATORS = [
       ...
       {
           'NAME': 'django_password_validators.password_history.password_validation.UniquePasswordsValidator',
           'OPTIONS': {
               'lookup_range': 3
           }
       },
       ...
   ]

   # 'lookup_range' sets how many previously used passwords to consider.
   # defaults to infinity if not set.
   # Stored passwords outside the 'lookup_range' get deleted.
   # If you want, you can change the default hasher for the password history.
   # DPV_DEFAULT_HISTORY_HASHER = 'django_password_validators.password_history.hashers.HistoryHasher'

And run ::

    python manage.py migrate

--------------------------
PasswordCharacterValidator
--------------------------

The validator checks for the minimum number of characters of a given type.

In the file settings.py we add ::

    INSTALLED_APPS = [
        ...
        'django_password_validators',
        ...
    ]

   AUTH_PASSWORD_VALIDATORS = [
       ...
       {
           'NAME': 'django_password_validators.password_character_requirements.password_validation.PasswordCharacterValidator',
           'OPTIONS': {
                'min_length_digit': 1,
                'min_length_alpha': 2,
                'min_length_special': 3,
                'min_length_lower': 4,
                'min_length_upper': 5,
                'special_characters': "~!@#$%^&*()_+{}\":;'[]"
            }
       },
       ...
   ]


.. _AUTH_PASSWORD_VALIDATORS: https://docs.djangoproject.com/en/1.9/ref/settings/#std:setting-AUTH_PASSWORD_VALIDATORS
