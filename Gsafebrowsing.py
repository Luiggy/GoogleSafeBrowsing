import requests
import json


class Gsafebrowsing:
    def __init__(self, API_KEY):
        self.mainurl = 'https://safebrowsing.googleapis.com'
        self.esquema = '{url}/$discovery/rest'.format(url=self.mainurl)
        self.header = {'Content-Type': 'application/json'}
        response_schema = requests.get(self.esquema, headers=self.header)
        if response_schema.status_code == 200:
            self.datos = response_schema.json()
            self.threat_typeslist = self.datos['schemas']['ThreatInfo']['properties']['threatTypes']['items']['enum']
            self.threat_entry_typeslist = \
                self.datos['schemas']['ThreatInfo']['properties']['threatEntryTypes']['items']['enum']
            self.threat_platform_typeslist = \
                self.datos['schemas']['ThreatInfo']['properties']['platformTypes']['items']['enum']
            self.apiendpointsdic = {}
            for nombre in self.datos['resources']:
                for methods in self.datos['resources'][nombre]['methods']:
                    aux = self.datos['resources'][nombre]['methods'][methods]['path']
                    # thread > list
                    aux_nombre = aux.split('/')[1]
                    aux_url = '{url}/{path}'.format(url=self.mainurl, path=aux)
                    self.apiendpointsdic[aux_nombre] = aux_url
        self.client = {"clientId": "libgsba",
                       "clientVersion": "0.3.1"}
        self.apikey = API_KEY

    def search(self, urls=[]):
        if urls:
            threatentries = [{'url':url} for url in urls]
            data = {
                'client': self.client,
                'threatInfo': {
                    'threatTypes':  self.threat_typeslist,
                    'platformTypes':  self.threat_platform_typeslist,
                    'threatEntryTypes': self.threat_entry_typeslist,
                    'threatEntries': threatentries
                }
            }
            response_threat_matches = requests.post(self.apiendpointsdic['threatMatches:find'], headers=self.header, data=json.dumps(data), params={'key':self.apikey})
            if response_threat_matches.status_code == 200:
                if response_threat_matches.json() == {}:
                    return {'OK': dict([(u, {"malicious": False}) for u in urls])}
                else:

                    result = {}
                    for url in urls:
                        # search for matches
                        matches = [match for match in response_threat_matches.json()['matches'] if match['threat']['url'] == url]
                        if matches:
                            result[url] = {
                                'malicious': True,
                                'platforms': list(set([b['platformType'] for b in matches])),
                                'threats': list(set([b['threatType'] for b in matches])),
                                'cache': min([b["cacheDuration"] for b in matches])
                            }
                        else:
                            result[url] = {"malicious": False}
                    return {'OK': result}
            return {'error': "Uno de los parámetros en el campo url es invalido"}
        else:
            return {'error': "debes pasar una lista URLs"}
