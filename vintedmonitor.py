import newdragon
from datetime import datetime
from bs4 import BeautifulSoup as bs
from lxml import etree

class Logger:
    def message(self, message):
        print(f'[{datetime.now().strftime("%H:%M:%S")}] {message}')
class Vinted(Logger):
    websiteOrigin = 'https://www.vinted.es'
    websiteDomain = 'https://www.vinted.es/'
    productEndpoint = 'https://www.vinted.es/api/v2/items/{itemId}'
    productsEP = "https://www.vinted.es/api/v2/users/152521286/items/favourites"
class VintedBadStatusCodeException(Exception):
    """Exception caused by bad status code on request"""

class VintedException(Exception):
    """Any Vinted-related exception"""
class VintedCSRF(Vinted):

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

class VintedMonitor(Vinted):

    def __init__(self,session: newdragon.Session):
        self.session = session
        resp = session.get(
            url=self.websiteOrigin,
            headers = {
                'authority': 'www.vinted.es',
                'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
                'accept-language': 'it,it-IT;q=0.9,en-US;q=0.8,en;q=0.7',
                'accept-encoding': 'gzip, deflate, br',
                'cache-control': 'max-age=0',
                'referer': 'https://www.vinted.es/',
                'sec-ch-ua': '"Google Chrome";v="117", "Not;A=Brand";v="8", "Chromium";v="117"',
                'sec-ch-ua-mobile': '?0',
                'sec-ch-ua-platform': '"Windows"',
                'sec-fetch-dest': 'document',
                'sec-fetch-mode': 'navigate',
                'sec-fetch-site': 'same-origin',
                'sec-fetch-user': '?1',
                'upgrade-insecure-requests': '1',
                'user-agent': session.headers['User-Agent'],
            })
        #print(resp.text)
        self.message(f"Home: {resp.status_code}")
    def get_item_details(self, productId: int) -> dict:

        response = self.session.get(url=self.productEndpoint.replace('{itemId}', str(productId)), headers = {
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
            })

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
    def get_item_url(self, response: dict) ->str:
        return response['item']['url']
    def get_item_photo(self, response: dict) -> str:
        return response['item']['photos'][0]['url']
    def get_item_description(self, response: dict) -> str:
        return response['item']['description']
    def get_item_size(self, response: dict) -> str:
        return response['item']['size']
    def get_view_count(self, response:dict) ->str:
        return response['item']['view_count']

    def get_item_data(self,productId: int) -> tuple[str, str, float, str, str, str, str]:
        item_data = self.get_item_details(productId=productId)
        return self.get_item_name(response=item_data), self.get_item_photo(response=item_data), self.get_item_price(response=item_data), self.get_item_description(response=item_data), self.get_item_size(response=item_data), self.get_item_url(response=item_data), self.get_view_count(response=item_data)


class VintedViews(VintedMonitor):
    def __init__(self,session: newdragon.Session):
        self.session = session
        resp = session.get(
            url=self.websiteOrigin,
            headers = {
                'authority': 'www.vinted.es',
                'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
                'accept-language': 'it,it-IT;q=0.9,en-US;q=0.8,en;q=0.7',
                'accept-encoding': 'gzip, deflate, br',
                'cache-control': 'max-age=0',
                'referer': 'https://www.vinted.es/',
                'sec-ch-ua': '"Google Chrome";v="117", "Not;A=Brand";v="8", "Chromium";v="117"',
                'sec-ch-ua-mobile': '?0',
                'sec-ch-ua-platform': '"Windows"',
                'sec-fetch-dest': 'document',
                'sec-fetch-mode': 'navigate',
                'sec-fetch-site': 'same-origin',
                'sec-fetch-user': '?1',
                'upgrade-insecure-requests': '1',
                'user-agent': session.headers['User-Agent'],
                'X-Csrf-Token':session.csrf_token
            })
        self.message(f"Home: {resp.status_code}")
    def getproductviews(self, url):
        headers = {
            'authority': 'www.vinted.es',
            'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
            'accept-language': 'en-US,en;q=0.9,it;q=0.8',
            'cache-control': 'max-age=0',
            'sec-ch-ua': '"Google Chrome";v="119", "Chromium";v="119", "Not?A_Brand";v="24"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
            'sec-fetch-dest': 'document',
            'sec-fetch-mode': 'navigate',
            'sec-fetch-site': 'none',
            'sec-fetch-user': '?1',
            'upgrade-insecure-requests': '1',
            'user-agent': self.session.headers["User-Agent"],
        }
        response = self.session.get(url, headers = headers)
        soup = bs(markup=response.text, features='html.parser')

        item = soup.select(".box--item-details")
        print(item)
        print(response.status_code)


def create_session() -> newdragon.Session:
    session = newdragon.Session()
    session.verify = False
    session.fingerprint = 'a0889d14015abbb0661836e84d2867a2'
    session.csrf_token = ''
    session.sec_ch_ua = '"Not.A/Brand";v="8", "Chromium";v="114", "Google Chrome";v="114"'
    session.sec_ch_ua_mobile = '?0'
    session.sec_ch_ua_platform = '"Windows"'
    session.headers['User-Agent'] = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36'
    session.proxies = {'http': 'http://PRIM_SDA6Y9JE11-cc-gb-pool-bd-sessionid-9094594:4DI71ZICJ1SAHO@bright.primedproxiesresi.com:8888', 'https': 'http://PRIM_SDA6Y9JE11-cc-gb-pool-bd-sessionid-9094594:4DI71ZICJ1SAHO@bright.primedproxiesresi.com:8888'}

    return session

session = create_session()

session.csrf_token = VintedCSRF().get_csrf(session=session)

monitor = VintedMonitor(session)
productName, productPhoto, productPrice, des, size, product_url, views = monitor.get_item_data(productId=3805370377)
print(views)
monitor = VintedViews(session)
monitor.getproductviews("https://www.vinted.es/items/3805370377-true-vintage-y2k-droopy-graphic-print-quilted-jacket")

monitor = VintedMonitor(session)
productName, productPhoto, productPrice, des, size, product_url, views = monitor.get_item_data(productId=3805370377)
print(views)

