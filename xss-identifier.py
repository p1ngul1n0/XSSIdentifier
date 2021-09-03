import urllib.parse as parse
import requests
import argparse
from selenium import webdriver
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait
from selenium.common import exceptions
from rich import print
from rich.progress import track
from rich.console import Console
from rich.style import Style
from pyfiglet import Figlet

#ArgParser
parser = argparse.ArgumentParser(description = 'Cross-Site-Scripting identifier.')
parser.add_argument('-u', action = 'store', dest = 'url',
                           default = '', required = True,
                           help = 'The URL to be explored with query params, example: -u "http://site.com/search.php?text=example"')
parser.add_argument('-p', action = 'store', dest = 'p',
                           default = 'payloads.txt', required = False,
                           help = 'The payload file, if none is set the defaut list will be used, example: -p myPayloads.txt')
arguments = parser.parse_args()

# Rich text
console = Console()
danger_style = Style(color='red', blink=True, bold=True)
success_style = Style(color='green', blink=True, bold=True)
alert_style = Style(color='yellow', blink=True, bold=True)

f = Figlet(font='doom')
console.print (f.renderText('XSS Identifier'),style=success_style)
console.print ('v1.0')

# Selenium Webdriver
console.log('[-] Starting browser...')
driver = webdriver.Firefox()
wait = WebDriverWait(driver, 5)
console.log('[+] Browser started!', style=success_style)

#url = 'http://192.168.0.18:3000/reflected-xss.php?string=teste'
rawUrl = arguments.url
parsedUrl = parse.urlsplit(arguments.url)
queryArgs = parse.parse_qs(parse.urlsplit(arguments.url).query)

payloadFile = arguments.p

def report(url,payload):
    console.log('[+] XSS Confirmed! :bomb:', style=success_style)
    console.print('Payload: '+payload, style=success_style)
    console.print('URL: '+url, style=success_style)

def readPayloads():
    console.log(f'[-] Reading payload list [{payloadFile}]')
    try:
        readpayloadFile = open(payloadFile, 'r',encoding='utf-8')
        payloadList = readpayloadFile.readlines()
        console.log(f'[+] {len(payloadList)} payloads loaded [{payloadFile}]', style=success_style)
        return payloadList
    except:
        console.log(f"[x] Couldn't read payload file [{payloadFile}]")
        return False
    

def verifyAlert(url):
    driver.get(url)
    try:
        wait.until(EC.alert_is_present())
        alert = driver.switch_to.alert
        alertText = alert.text
        if str(1) in alertText:
            alert.accept()
            return True
    except (exceptions.NoAlertPresentException, exceptions.TimeoutException, exceptions.UnexpectedAlertPresentException):
        return False

def explore(payloadList):
    with console.status('[bold green]Exploring with payloads list...', spinner='material') as status:
        for payload in payloadList:
            newUrl = constructUrl(payload)
            console.log(f'[-] Accessing URL [{newUrl}]')
            response = doRequest(newUrl)
            payload = payload.rstrip()
            if payload in response:
                if verifyAlert(newUrl):
                    console.log(f'[+] Javascript Alert executed! [{payload}]', style=success_style)
                    driver.close()
                    report(newUrl,payload)
                    break
                else:
                    console.log(f'[x] Payload failed [{payload}]', style=danger_style)
            else:
                pass
        try:
            driver.close()
        except:
            pass

def constructUrl(payload):
    newQuery = list(queryArgs)[0]+'='+payload
    newUrl = parsedUrl.scheme+'://'+parsedUrl.netloc+parsedUrl.path+'?'+newQuery
    return newUrl

def doRequest(newUrl):
    response = requests.get(newUrl)
    return str(response.content)

def verifyReflection():
    console.log('[-] Verifying if params reflect on response...')
    #payload = str(uuid.uuid4())
    payload = '<>=/:.'
    newUrl = constructUrl(payload)
    response = doRequest(newUrl)
    if payload in response:
        console.log('[+] Params are reflected!', style=success_style)
        return True
    else:
        console.log('[x] Query params are not reflected.', style=danger_style)
        return False

def verifyConn(url):
    console.log('[-] Verifying connection with URL...')
    try:
        response = requests.request('GET',url)
        console.log(f'[+] URL is reachable! [{response.status_code} {response.reason}]',  style=success_style)
        return True
    except Exception as e:
        console.log(f'[x] URL is unreachable! [{str(e)}]',  style=danger_style)
        return False

if verifyConn(rawUrl):
    if verifyReflection():
        payloadList = readPayloads()
        if payloadList != False:
            explore(payloadList)