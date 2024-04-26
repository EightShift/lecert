from setuptools import setup, find_packages

setup(
    name='lecert',
    version='1.0',
    description='Python module for obtaining SSL certificates from Let\'s Encrypt for self-service projects',
    long_description=open('README.md').read(),
    long_description_content_type='text/markdown',
    author='EightShift',
    author_email='the8shift@gmail.com',
    url='https://github.com/EightShift/lecert',
    packages=find_packages(),
    install_requires=[
        'acme',  # Assuming you have any dependencies
    ],
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
    ],
)