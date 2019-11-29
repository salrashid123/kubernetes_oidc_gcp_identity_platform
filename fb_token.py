import logging
import json
import httplib2
import os
import pprint
import sys

import urllib,urllib2
from urllib2 import URLError, HTTPError
from oauth2client.service_account import ServiceAccountCredentials
from oauth2client.client import GoogleCredentials


import firebase_admin
from firebase_admin import credentials
from firebase_admin import auth

default_app = None 

# Creates a Firebase Secure Token.

# On the Cloud Identity Console, select `Application setup details` link on the top right and note the  `API_KEY` it provides.   
# Create a service account JSON key as described under [Firebase SDK](https://firebase.google.com/docs/admin/setup#initialize_the_sdk).  
# Copy the JSON certificate file into the `auth_rbac_policy/firebase_cli` folder and save it as `svc_account.json`. 
# Edit `fb_token.py` and add the `API_KEY` into the code.


API_KEY=''


cred = credentials.Certificate('svc_account.json')
default_app = firebase_admin.initialize_app(cred)   


def verifyIdToken(id_token):
    try:
      decoded_token = auth.verify_id_token(id_token)
      uid = decoded_token['uid']
      print("Verified User " + uid)
      return True
    except auth.AuthError as e:
      logging.error(e.detail)
    except Exception as e:
      logging.error(e)
    return False

def getFBToken(uid, groups):
  print("Getting custom id_token")
  try:
      additionalClaims = {
        'isadmin': "true",
        'groups': groups
      }
      token = auth.create_custom_token(uid, additionalClaims)
      return token
      
  except auth.AuthError as e:
      print(e.detail)
  except Exception as e:
      print(e)

def getSTSToken(tok):
  print("Getting STS id_token")
  try:

    # https://cloud.google.com/identity-platform/docs/reference/rest/client/#section-verify-custom-token
    #url = 'https://identitytoolkit.googleapis.com/v1/accounts:signInWithCustomToken?key=' + API_KEY 
    url = 'https://www.googleapis.com/identitytoolkit/v3/relyingparty/verifyCustomToken?key='+ API_KEY
    data = {'returnSecureToken' : True,
            'token' :tok}
    headers = {"Content-type": "application/x-www-form-urlencoded"}
     
    data = urllib.urlencode(data)
    req = urllib2.Request(url, data, headers)
    resp = urllib2.urlopen(req).read()
    parsed = json.loads(resp)
    idToken = parsed.get('idToken')
    refreshToken = parsed.get('refreshToken')
    return idToken, refreshToken
  except Exception as e:
      print(e)

def refreshToken(tok):
  #print("Refreshing Token")
  try:


    url = 'https://securetoken.googleapis.com/v1/token?key=' + API_KEY
    data = {'grant_type' : "refresh_token",
            'refresh_token' :tok}
    headers = {"Content-type": "application/x-www-form-urlencoded"}
     
    data = urllib.urlencode(data)
    req = urllib2.Request(url, data, headers)
    resp = urllib2.urlopen(req).read()
    parsed = json.loads(resp)
    access_token = parsed.get('access_token')
    refresh_token = parsed.get('refresh_token')

    # TODO add "expirationTimestamp": metav1.Time
    r= {
      "apiVersion": "client.authentication.k8s.io/v1beta1",
      "kind": "ExecCredential",
      "status": {
        "token": access_token
      }
    }

    return json.dumps(r)
  except Exception as e:
      print(e)

if __name__ == '__main__':

    if len(sys.argv) < 3:
      print "Usage: python fb_token.py print|refresh|claim $API_KEY ($UID|$REFRESH_TOKEN)"
      sys.exit(1)
    mode=sys.argv[1]
    API_KEY=sys.argv[2]

    if mode=="print":
      if len(sys.argv) < 4:
        print "Must provide Username/uid if mode=print"
        sys.exit(1)       
      fbtok = getFBToken(sys.argv[3],['group1','group2']) 
      print "FB Token for " + sys.argv[3]
      print fbtok
      print '-----------------------------------------------------'
      ststok, refreshToken = getSTSToken(fbtok)
      print "STS Token for " + sys.argv[3]
      print "ID TOKEN: " + ststok
      print '-------'
      print "refreshToken TOKEN: " + refreshToken    
      verifyIdToken(ststok)
      print '-----------------------------------------------------'
    elif mode=='refresh':
      if len(sys.argv) < 4:
        print "Must provide REFRESH TOKEN if mode=refresh"
        sys.exit(1)      
      print refreshToken(sys.argv[3])
      # print accesstok
    elif mode=='claim':
      if len(sys.argv) < 4:
        print "Must provide Username/uid if mode=claim"
        sys.exit(1)   
      uid = sys.argv[3]
      auth.set_custom_user_claims(uid, {'admin': True})
      u = auth.get_user(uid)
      print u.__dict__


