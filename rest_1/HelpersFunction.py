import requests
import pdb

def token_gen(attrs):
    username = attrs.get('username', '')
    password = attrs.get('password', '')
    url = "http://127.0.0.1:8000/api/token/"
    data = {'username' :username ,'password' :password}
    response_ = requests.request("POST", url ,data=data)
    access_token = response_.__dict__['_content'].decode().split('access')[1].replace('":"' ,"").replace('"}' ,"").strip()
    refresh_token = response_.__dict__['_content'].decode().split('access')[0].replace('{"refresh":"' ,"").replace('","' ,"").strip()
    tokes = {}
    return access_token


