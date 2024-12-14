#!/bin/python3

import urllib3
import requests
import re
from cryptography import x509
from datetime import date

pathNewCert = '/opt/.acme.sh/your.domain/domain.cer'
pathNewKey  = '/opt/.acme.sh/your.domain/domain.key'
pathNewCA   = '/opt/.acme.sh/your.domain/ca.cer'
description = '' # Поле "Описание" в списке сертификатов, в интерфейсе Synology. Используется для дальнейшего простого поиска и обновления
default = True

synologyHost = 'nas.host'
synologyPort = 5001
synologyUser = 'admin'
synologyPass = 'password'

class certificate:
    def __init__(self, file):
        with open(file, 'rb') as f:
            self._cert = x509.load_pem_x509_certificate(f.read())
            f.close()

    def CommonName(self):
        return self._cert.subject.get_attributes_for_oid(
            x509.OID_COMMON_NAME
        )[0].value.strip()

    def noValidBefore(self):
        return self._synologyDateFormat(self._cert.not_valid_before)

    def noValidAfter(self):
        return self._synologyDateFormat(self._cert.not_valid_after)

    def algorithmNama(self):
        return self._cert.signature_hash_algorithm.name

    def algorithmOidNama(self):
        return self._cert.signature_algorithm_oid._name

    def _synologyDateFormat(self, d):
        return date.strftime(d,'%b %d %H:%M:%S %Y GMT')

class dsm:
    def __init__(self, host, port):
        self._url = 'https://{}:{}/webapi/entry.cgi'.format(host, port)
        self._cookies = False

    def auth(self, login, password):
        self._login = login
        self._password = password
        try:
            res = requests.post(self._url, verify=False, data={
                'api': 'SYNO.API.Auth',
                'account': self._login,
                'passwd': self._password,
                'version': '7',
                'method': 'login',
                'session': 'Certificate',
                'tabid': '',
                'enable_syno_token': 'no',
                'logintype': '',
                'otp_code': '',
                'enable_device_token': 'no',
                'client': 'script',
            })
            info = res.json()
            if info['success'] == True:
                self._cookies = res.cookies
                return True
            return False
        except Exception as error:
            print('Ошибка: {}\nОтвет сервера: {}\n'.format(error, res.text))
            return False

    def certificateList(self):
        try:
            if self._cookies:
                res = requests.post(self._url, verify=False, cookies=self._cookies, data={
                    'api': 'SYNO.Core.Certificate.CRT',
                    'method': 'list',
                    'version': '1'
                })
                info = res.json()
                if info['success'] == True:
                    return res.json()['data']['certificates'], True
            return [], False
        except Exception as error:
            print('Ошибка: {}\nОтвет сервера: {}\n'.format(error, res.text))
            return [], False

    def findCertByDesc(self, desc):
        certificateList, success = synology.certificateList()
        if success:
            for cert in certificateList:
                if cert['desc'] == desc:
                    return cert
        return False

    def certIdByDesc(self, desk):
        cert = synology.findCertByDesc(desk)
        if (cert):
            return cert['id']
        return ''

    def certificateImport(self, cert, key, ca, cid, desc, asDefault):
        try:
            res = requests.post(self._url + '?api=SYNO.Core.Certificate&method=import&version=1', verify=False, cookies=self._cookies, 
                files={
                    'key':        (re.search('[^\/\\\]+$', key).group(0),  open(key,  'rb'), 'application/x-x509-ca-cert'),
                    'cert':       (re.search('[^\/\\\]+$', cert).group(0), open(cert, 'rb'), 'application/x-x509-ca-cert'),
                    'inter_cert': (re.search('[^\/\\\]+$', ca).group(0),   open(ca,   'rb'), 'application/octet-stream'),
                },
                data={
                    'id': cid,
                    'desc': desc,
                    'as_default': 'true' if asDefault is True else ''
                }
            )
            print(res.text)
            if res.json()['success'] == True:
                return True
            return False
        except Exception as error:
            print('Ошибка: {}\nОтвет сервера: {}\n'.format(error, res.text))
            return False

# https://urllib3.readthedocs.io/en/latest/advanced-usage.html#tls-warnings
urllib3.disable_warnings()

synology = dsm(host=synologyHost, port=synologyPort)
if not synology.auth(login=synologyUser, password=synologyPass):
    print('Ошибка авторизации')
    exit(1)

synoCert = synology.findCertByDesc(description)
synoCertId = ''
if (synoCert):
    newCert = certificate(pathNewCert)
    if (newCert.CommonName() == synoCert['subject']['common_name']) and (newCert.noValidAfter() == synoCert['valid_till']):
        print('Обновление сертификата не требуется')
        exit(0)
    else:
        synoCertId = synoCert['id']
        print('Обновление сертификата: {}'.format(synoCertId))

if not synology.certificateImport(pathNewCert, pathNewKey, pathNewCA, synoCertId, description, default):
    print('Ошибка импорта сертификата')
    exit(1)
