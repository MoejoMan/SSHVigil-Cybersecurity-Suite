import re

# SSH info-line patterns with named groups.
# Extendable: add more dicts with 'name', 'regex', and 'success'.

PATTERNS = [
	{
		'name': 'invalid_user',
		'regex': re.compile(r"Invalid user (?P<username>\S+) from (?P<ip>[0-9a-fA-F:.]+)"),
		'success': False,
	},
	{
		'name': 'failed_password_user',
		'regex': re.compile(r"Failed password for (?P<username>\S+) from (?P<ip>[0-9a-fA-F:.]+)"),
		'success': False,
	},
	{
		'name': 'failed_password_invalid',
		'regex': re.compile(r"Failed password for invalid user (?P<username>\S+) from (?P<ip>[0-9a-fA-F:.]+)"),
		'success': False,
	},
	{
		'name': 'accepted_password',
		'regex': re.compile(r"Accepted password for (?P<username>\S+) from (?P<ip>[0-9a-fA-F:.]+)"),
		'success': True,
	},
	{
		'name': 'accepted_publickey',
		'regex': re.compile(r"Accepted publickey for (?P<username>\S+) from (?P<ip>[0-9a-fA-F:.]+)"),
		'success': True,
	},
]

