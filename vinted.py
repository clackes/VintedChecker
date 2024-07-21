import json
import newdragon
from datetime import datetime
from bs4 import BeautifulSoup as bs
from vintedome import Datadome

class Logger:
    def message(self, message):
        print(f'[{datetime.now().strftime("%H:%M:%S")}] {message}')

class DatadomeSolver:
    ddk = "E6EAF460AA2A8322D66B42C85B62F9"
    ddv = "4.12.1"
    datadomeDomain = 'https://dd.vinted.lt'
    def solve_datadome(self,session:newdragon.Session, domain):
        resultCookie = Datadome(session, domain, self.ddk, self.ddv, session.headers['User-Agent']).generate_datadome(True)
        session.set_cookie(
            name='datadome', value=resultCookie['value'], domain='.vinted.it', path='/'
        )

class VintedBadStatusCodeException(Exception):
    """Exception caused by bad status code on request"""

class VintedException(Exception):
    """Any Vinted-related exception"""

class Vinted(DatadomeSolver):
    websiteOrigin = 'https://www.vinted.it'
    websiteDomain = 'https://www.vinted.it/'
    productEndpoint = 'https://www.vinted.it/api/v2/items/{itemId}'
    productsEP = "https://www.vinted.it/api/v2/users/152521286/items/favourites"

class VintedFavourites(Vinted, Logger):

    def get_access(self, session:newdragon.Session):
        response = session.get(
            url = f"{self.websiteOrigin}/member/items/favourite_list",
            headers = {
                'cache-control': 'max-age=0',
                'sec-ch-ua': session.sec_ch_ua,
                'x-csrf-token': session.csrf_token,
                'accept-language': 'it,it-IT;q=0.9,en-US;q=0.8,en;q=0.7',
                'sec-ch-ua-mobile': session.sec_ch_ua_mobile,
                'user-agent': session.headers['User-Agent'],
                'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
                'sec-ch-ua-platform': session.sec_ch_ua_platform,              
                'sec-fetch-site': 'same-origin',
                'sec-fetch-mode': 'navigate',
                'sec-fetch-dest': 'document',
                'referer': f"{self.websiteDomain}",
                'accept-encoding': 'gzip, deflate, br',
            }
        )

        if response.ok:
            try:
                self.message(f'Status Code {response.status_code} on Favourite items access.')
            except Exception as e:
                self.message(str(e))
                raise VintedException(e)            
        else:
            self.message(f'Status Code {response.status_code} on Favourite items access.')

            raise VintedBadStatusCodeException(f'Status Code {response.status_code} on Favourite items access.')

    def get_item(self, session: newdragon.Session, user_id: int):
        self.solve_datadome(session,self.datadomeDomain)
        self.get_access(session)
        response = session.get(
            url = self.productsEP,
            headers = {
                'cache-control': 'max-age=0',
                'sec-ch-ua': '"Not.A/Brand";v="8", "Chromium";v="114", "Google Chrome";v="114"',
                'x-csrf-token': session.csrf_token,
                'x-money-object': 'true',
                'accept-language': 'it-fr',
                'sec-ch-ua-mobile': '?0',
                'user-agent': session.headers['User-Agent'],
                'accept': 'application/json, text/plain, */*',
                'sec-ch-ua-platform': '"Windows"',              
                'sec-fetch-site': 'same-origin',
                'sec-fetch-mode': 'cors',
                'sec-fetch-dest': 'empty',
                'referer': "https://www.vinted.it/member/items/favourite_list",
                'accept-encoding': 'gzip, deflate, br',
                'if-none-match':'W/"5f1dc20fc30da2da5210888d6aed2b6e"'
            }
        )

        if response.ok:
            try:
                items = response.json()["items"]
                for item in items:
                    print(item["id"], item["title"], item["original_price_numeric"], item["price_numeric"])
            except Exception as e:
                self.message(str(e))
                raise VintedException(e)            
        else:
            self.message(f'Status Code {response.status_code} on Favourite items.')

            raise VintedBadStatusCodeException(f'Status Code {response.status_code} on Favourite items.')


class VintedCSRF(Vinted, Logger):

    def get_csrf(self, session: newdragon.Session):

        response = session.get(
            url=self.websiteDomain,
            headers={
                'cache-control': 'max-age=0',
                'sec-ch-ua': session.sec_ch_ua,
                'sec-ch-ua-mobile': session.sec_ch_ua_mobile,
                'sec-ch-ua-platform': session.sec_ch_ua_platform,
                'upgrade-insecure-requests': '1',
                'user-agent': session.headers['User-Agent'],
                'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
                'sec-fetch-site': 'none',
                'sec-fetch-mode': 'navigate',
                'sec-fetch-user': '?1',
                'sec-fetch-dest': 'document',
                'referer': self.websiteDomain,
                'accept-encoding': 'gzip, deflate, br',
                'accept-language': 'it',
            }
        )

        soup = bs(markup=response.text, features='html.parser')

        try:
            return soup.find(name='meta', attrs={'name': 'csrf-token'})['content']
        except Exception as e:
            self.message(f'Exception while gathering CSRF: {e}')
            raise VintedException(e)

class VintedLogin(Vinted, Logger):

    def __init__(self, username: str, password: str):
        self.username = username
        self.password = password

    def captchas(self, session: newdragon.Session):

        response = session.post(
            url=f'{self.websiteOrigin}/api/v2/captchas',
            headers={
                'content-length': '',
                'sec-ch-ua': session.sec_ch_ua,
                'x-csrf-token': session.csrf_token,
                'accept-language': 'it-it',
                'sec-ch-ua-mobile': session.sec_ch_ua_mobile,
                'user-agent': session.headers['User-Agent'],
                'content-type': 'application/json',
                'accept': 'application/json, text/plain, */*',
                'sec-ch-ua-platform': session.sec_ch_ua_platform,
                'origin': self.websiteOrigin,
                'sec-fetch-site': 'same-origin',
                'sec-fetch-mode': 'cors',
                'sec-fetch-dest': 'empty',
                'referer': self.websiteDomain,
                'accept-encoding': 'gzip, deflate, br'
            },
            json={
	            "entity_type": "login",
	            "payload": {
	            	"username": self.username
	            }
            }
        )

        if response.ok:
            try:
                response_json = response.json()
            except Exception as e:
                self.message(str(e))
                raise VintedException(e)

            return response_json.get('uuid', None), response_json.get('verified', False)
        else:
            self.message(f'Status Code {response.status_code} on Login/Captchas.')

            if response.headers.get('X-Dd-B', None) is not None:
                self.solve_datadome(session, self.datadomeDomain)

                return self.captchas(session=session)

            raise VintedBadStatusCodeException(f'Status Code {response.status_code} on Login/Captchas.')

    def token(self, session: newdragon.Session, captchasUUID: str):

        response = session.post(
            url=f'{self.websiteOrigin}/oauth/token',
            headers={
                'content-length': '',
                'sec-ch-ua': session.sec_ch_ua,
                'x-csrf-token': session.csrf_token,
                'accept-language': 'it-it',
                'sec-ch-ua-mobile': session.sec_ch_ua_mobile,
                'user-agent': session.headers['User-Agent'],
                'content-type': 'application/json',
                'accept': 'application/json, text/plain, */*',
                'sec-ch-ua-platform': session.sec_ch_ua_platform,
                'origin': self.websiteOrigin,
                'sec-fetch-site': 'same-origin',
                'sec-fetch-mode': 'cors',
                'sec-fetch-dest': 'empty',
                'referer': self.websiteDomain,
                'accept-encoding': 'gzip, deflate, br'
            },
            json={
	            "client_id": "web",
	            "scope": "user",
	            "fingerprint": session.fingerprint,
	            "username": self.username,
	            "password": self.password,
	            "uuid": captchasUUID,
	            "grant_type": "password"
            }
        )

        if response.ok:
            try:
                response_json = response.json()
                #print(response_json)
                access_token = response_json['access_token']
                token_type = response_json['token_type']
                refresh_token = response_json['refresh_token']
                scope = response_json['scope']
            except Exception as e:
                self.message(str(e))
                raise VintedException(e)

            return token_type, scope, access_token, refresh_token
        else:
            self.message(f'Status Code {response.status_code} on Login/Token.')
            raise VintedBadStatusCodeException(f'Status Code {response.status_code} on Login/Token.')

class VintedMonitor(Vinted, Logger):

    def get_item_details(self, session: newdragon.Session, productId: int) -> dict:

        response = session.get(url=self.productEndpoint.replace('{itemId}', str(productId)))

        if response.ok:
            try:
                response_json = response.json()
            except Exception as e:
                self.message('Cannot scrape product correctly.')
                raise VintedException(e)

            return response_json
        else:
            self.message(f'Status Code {response.status_code} on Monitor/Item.')
            raise VintedBadStatusCodeException(f'Status Code {response.status_code} on Monitor/Item.')

    def get_item_price(self, response: dict) -> float:
        return float(response['item']['price']['amount'])

    def get_item_name(self, response: dict) -> str:
        return response['item']['title']

    def get_item_photo(self, response: dict) -> str:
        return response['item']['photos'][0]['url']

    def get_item_data(self, session: newdragon.Session, productId: int) -> tuple[str, str, float]:
        item_data = self.get_item_details(session=session, productId=productId)
        return self.get_item_name(response=item_data), self.get_item_photo(response=item_data), self.get_item_price(response=item_data)

def create_session() -> newdragon.Session:
    with open("E:\OneDrive\lavoro\credentials.json", "r") as f:
        credentials = json.load(f)["default_host"]
        username = credentials["username"]
        password = credentials["password"]
        host = credentials["host"]
        f.close
    session = newdragon.Session()
    session.verify = False
    session.fingerprint = 'a0889d14015abbb0661836e84d2867a2'
    session.csrf_token = ''
    session.sec_ch_ua = '"Not.A/Brand";v="8", "Chromium";v="114", "Google Chrome";v="114"'
    session.sec_ch_ua_mobile = '?0'
    session.sec_ch_ua_platform = '"Windows"'
    session.headers['User-Agent'] = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36'
    #session.proxies = {"http":f"http://{username}:{password}@{host}", "https":f"http://{username}:{password}@{host}"}

    return session

session = create_session()
#session.proxies = {'http': 'http://127.0.0.1:8888', 'https': 'http://127.0.0.1:8888'}
session.csrf_token = VintedCSRF().get_csrf(session=session)

#loginInstance = VintedLogin(username='albertovergani267@gmail.com', password='TiffanyVerga44@')
#captchasUUID, verified = loginInstance.captchas(session=session)
#token_type, scope, access_token, refresh_token = loginInstance.token(session=session, captchasUUID=captchasUUID)

monitor = VintedMonitor()
productName, productPhoto, productPrice = monitor.get_item_data(session=session, productId=3236459851)

print(productName, productPhoto, productPrice)
print(session.cookies)
#VintedFavourites().get_item(session=session, user_id=152521286)