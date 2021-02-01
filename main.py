import requests
from HMACAuth import HMACAuth

if __name__ == '__main__':
    url = 'https://gateway.ncrplatform.com/catalog/items'

    r = requests.get(url, auth=(HMACAuth()))

    temp = r.json()
    print(temp)