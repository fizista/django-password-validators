import os
from os.path import dirname, realpath

from setuptools import setup, find_packages

from django_password_validators import __version__ as VERSION

__dir__ = realpath(dirname(__file__))

TESTS_REQUIRE = ['tox >= 4.11', 'bump-my-version >= 0.12']

DESCRIPTION = open(
    os.path.join(os.path.dirname(__file__), 'README.rst')).read()

setup(
    name='django-password-validators',
    version=VERSION,
    description="Additional libraries for validating passwords in Django.",
    long_description=DESCRIPTION,
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Environment :: Web Environment',
        'Framework :: Django',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12',
        'Programming Language :: Python',
        'Operating System :: OS Independent',
        'Topic :: Security',
    ],  # strings from http://pypi.python.org/pypi?%3Aaction=list_classifiers
    keywords='django password validator',
    author='Wojciech Banas',
    author_email='fizista@gmail.com',
    url='https://github.com/fizista/django-password-validators',
    license='BSD',
    packages=find_packages(exclude=['tests*', ]),
    include_package_data=True,
    zip_safe=False,
    install_requires=[
        'django >= 3.0',
    ],
    extras_require={
        'test': TESTS_REQUIRE,
    },
)
