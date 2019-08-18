#!/usr/bin/env python3
"""Testing web.archive.org API"""

import json

import requests

WAYBACK = 'https://web.archive.org/web'
WAYBACK_SEARCH = f'{WAYBACK}/timemap'
URL_PREFIX = ('http://definitionupdates.microsoft.com/' +
              'download/DefinitionUpdates/VersionedSignatures/AM///')

r = requests.get(
    WAYBACK_SEARCH, {
        'url': URL_PREFIX,
        'matchType': 'prefix',
        'collapse': 'urlkey',
        'output': 'json',
        'fl': 'original,timestamp',
        'filter': '!statuscode:[45]..',
        'limit': '100000'
    })

RESULTS = json.loads(r.text)[1:]

for res in RESULTS:
    timestamp = res[1]
    archive_url = res[0]
    url = f'{WAYBACK}/{timestamp}/{archive_url}'
    print(url)
    r = requests.get(url, stream=True)
    filename = f'{timestamp}.exe'
    with open(filename, 'wb') as f:
        f.write(r.content)
