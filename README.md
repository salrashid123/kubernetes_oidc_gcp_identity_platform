
# Kubernetes RBAC with Google Identity Platform Custom Tokens


Simple tutorial on how to setup [Kubernetes RBAC](https://kubernetes.io/docs/reference/access-authn-authz/rbac/) with [Google Identity Platform](https://cloud.google.com/identity-platform/) (aka Firebase Authentication; aka GitKit) 

This tutorial does _not_ cover setting up k8s RBAC for Google OIDC but rather with GCP's Identity Platform's [Custom Tokens](https://cloud.google.com/identity-platform/docs/concepts-admin-auth-api#custom_token_creation) with fine grained claims denoting groups or other privileged claims.  If you are interested in generic google OIDC login for k8s, please see the links in the references.

Identity Platform allows your users to login via any number of mechanims to your application: the well known OIDC providers, SAML, username/password, etc.  No matter the login mechanism, you application can issue a Custom JWT token back to your users.  Within that, you can login to firebase using [signInWithCustomToken()](https://firebase.google.com/docs/reference/js/firebase.auth.Auth.html#signinwithcustomtoken)) and then access select Firebase APIs directly.  Well..what about using these tokens for kubernetes API access and RBAC?

Sure..whenever a firebase app is generated, a _partial_ OIDC endpoint is also generated which kubernetes or other applications can use to verify the token and identify the user.   

This tutorial sets minikube and Cloud Identity Platform as the provider.  In addition, this tutorial demonstrates how to allow RBAC access based on user,groups, required Claims as well as an `exec` provider for `kubectl`.

>> This repo is NOT supported by google; _caveat emptor_

Anyway, lets get started

I'm assuming you've read up on OIDC provider for kubernetes using a standard provider such as Google (see links below).  If you did you're probably wondering what i meant by partial in the intro....Well you can partially sic what i mean by looking at the [/.well-known/openid-configuration](https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationRequest) for google as well as a firebase app.  For example, compare:

* `accounts.google.com`: [https://accounts.google.com/.well-known/openid-configuration](https://accounts.google.com/.well-known/openid-configuration)

vs a sample firebase endpoint:

```json
$ curl -s https://securetoken.google.com/$PROJECT_ID/.well-known/openid-configuration | jq '.'
{
  "issuer": "https://securetoken.google.com/$PROJECT_ID",
  "jwks_uri": "https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com",
  "response_types_supported": [
    "id_token"
  ],
  "subject_types_supported": [
    "public"
  ],
  "id_token_signing_alg_values_supported": [
    "RS256"
  ]
}
```

Note that even the `/token` endpoint to refresh your credentials is missing used to refresh credentials.  Identity Platform uses a different endpoint at [https://developers.google.com/identity/toolkit/reference/securetoken/rest/v1/token](https://developers.google.com/identity/toolkit/reference/securetoken/rest/v1/token) which isn't advertized on discovery url.  We can still refresh the credentials but we need some custom auth plugin handling with `kubectl`.

Anyway, some homework/background

- [Kubernetes OpenID Connect Tokens](https://kubernetes.io/docs/admin/authentication/#openid-connect-tokens)
- [Kubernetes Master Configuration](https://kubernetes.io/docs/reference/access-authn-authz/authentication/#configuring-the-api-server)
- [Cloud Identity](https://console.cloud.google.com/marketplace/details/google-cloud-platform/customer-identity)
- [Cloud Identity/Firebase Custom Tokens](https://firebase.google.com/docs/auth/admin/create-custom-tokens)


- Firebase JWK URL: [https://www.googleapis.com/robot/v1/metadata/jwk/securetoken@system.gserviceaccount.com](https://www.googleapis.com/robot/v1/metadata/jwk/securetoken@system.gserviceaccount.com)


### Create New Project

because...you need one. export it as

```bash
export PROJECT_ID=`gcloud config get-value core/project`
```

1. [Enable Identity Platform](https://console.cloud.google.com/marketplace/details/google-cloud-platform/customer-identity)
     

2. Navigate to the Identity Platform Console: 
   [https://console.cloud.google.com/customer-identity/providers](https://console.cloud.google.com/customer-identity/providers)
       

   Select "Project Settings on the top left" which will show the API key:

![images/cicp_api_key.png](images/cicp_api_key.png)

export the value
```
export API_KEY=AIzaSyBEHKUoYqPQkQus-reaacted
```

3. Create Service Account and download a service account key

```
gcloud iam service-accounts create cicp-admin-client-account --display-name "CICP Admin Client Service Account"
gcloud iam service-accounts keys create svc_account.json --iam-account=cicp-admin-client-account@$PROJECT_ID.iam.gserviceaccount.com
```

4. Setup python client to get initial token

Included in this repo is a sample application which uses the service account to create a new user called `alice` as an Identity Platform user.
This script will also generate a Custom token ad then display`id_token` and `refresh_token`.   Finally, we will use this script later for the kubernetes auth plugin.

You will need `python27`, `python-pip` installed/

```
virtualenv env
source env/bin/activate
pip install -r requirements.txt
```

Now run the script

```
$ python fb_token.py 
Getting custom id_token
FB Token for alice

eyJhbGciOiAiUlMyNTYiLCAidHlwIjogIkpXVCIsICJraWQiOiAiMDBiYWI0NzFkMzJiYzUyMWIyYmI4MWY2NTUzNmZmYzA4NDgwMTc4MiJ9.eyJ1aWQiOiAiYWxpY2UiLCAiaXNzIjogImNpY3AtYWRtaW4tY2xpZW50LWFjY291bnRAY2ljcC1vaWRjLmlhbS5nc2VydmljZWFjY291bnQuY29tIiwgImV4cCI6IDE1NzM1NDI2ODgsICJjbGFpbXMiOiB7ImlzYWRtaW4iOiAidHJ1ZSIsICJncm91cHMiOiBbImdyb3VwMSIsICJncm91cDIiXX0sICJpYXQiOiAxNTczNTM5MDg4LCAiYXVkIjogImh0dHBzOi8vaWRlbnRpdHl0b29sa2l0Lmdvb2dsZWFwaXMuY29tL2dvb2dsZS5pZGVudGl0eS5pZGVudGl0eXRvb2xraXQudjEuSWRlbnRpdHlUb29sa2l0IiwgInN1YiI6ICJjaWNwLWFkbWluLWNsaWVudC1hY2NvdW50QGNpY3Atb2lkYy5pYW0uZ3NlcnZpY2VhY2NvdW50LmNvbSJ9.iUwZ0q_htjMAJKYpbo3aGuFC2XxGeSK2JT1m8vDsqHT_DFK_z3SUl-eL4ClwyTVgecm-HtJ_SCU3rMWVQ91AZqLijuPHXCe1YrVDhl7TAJZ7Ad787i7wKjGoT4bRzJZOKa9KHbTu1jVjh8FNB_qHbSPs3VLnXDcbacLtHomFgxPx1LvUATIFz3xw1Tp_cxGZ0CENw6po4N0_3GzwzJJ4goWVUne5vqDkRQ4cD8cgt4ejWU_UNzuBmPyFPhj5qOl_YowFR8HKnQOsRTv7Y5MV2VfLL1LWID7m3YPcne6poZhx8Ys_sAZ-ySisqAgzcd2nHyCedPCAad9sm2vXKFAkXw
-----------------------------------------------------
Getting STS id_token
STS Token for alice 

ID TOKEN: eyJhbGciOiJSUzI1NiIsImtpZCI6IjI1MDgxMWNkYzYwOWQ5MGY5ODE1MTE5MWIyYmM5YmQwY2ViOWMwMDQiLCJ0eXAiOiJKV1QifQ.eyJpc2FkbWluIjoidHJ1ZSIsImdyb3VwcyI6WyJncm91cDEiLCJncm91cDIiXSwiaXNzIjoiaHR0cHM6Ly9zZWN1cmV0b2tlbi5nb29nbGUuY29tL2NpY3Atb2lkYyIsImF1ZCI6ImNpY3Atb2lkYyIsImF1dGhfdGltZSI6MTU3MzUzOTA4OSwidXNlcl9pZCI6ImFsaWNlIiwic3ViIjoiYWxpY2UiLCJpYXQiOjE1NzM1MzkwODksImV4cCI6MTU3MzU0MjY4OSwiZmlyZWJhc2UiOnsiaWRlbnRpdGllcyI6e30sInNpZ25faW5fcHJvdmlkZXIiOiJjdXN0b20ifX0.pcTsN280IXyIDr3CnPcy4Cy4MR1eRrr3NTugtrRQW0R00IDcuGd6pWCfcmT7kRO8jQ3xYbVS6fQLf80RuMT4Yfri7WYDPLSh5B-9mWJzEBGwmU7wzwIS5f9IMfrvF2u5aCTIWpBAuJrEZxKUSwcxeF2Lhc8gHmDK8ziQ86CcZfcDYhr4ZJ2yoTrUXgg5eUsQbp5ob3_Bde5-zyKbSVL1qpynkSzzY4xlzY2PcLyQRpAZqRuyC5ST6mU5vB59aSW7qAUzkCcHY8oJX-sFMOJkuVslqFlKMT9jdJlA_HoIuT4ZYJ3xpOufPoBYTpjXn4580tvsoTtn7Xqz3-x-yDpK-Q

refreshToken TOKEN: AEu4IL3REDACTED
-----------------------------------------------------
Verified User alice
```

The script will display two tokens:

the first `FB Token` is simply a self-signed JWT issued by the  service account.  Decoded (at `[jwt.io](jwt.io))


```json
{
  "uid": "alice",
  "iss": "cicp-admin-client-account@cicp-oidc.iam.gserviceaccount.com",
  "exp": 1573544650,
  "claims": {
    "isadmin": "true",
    "groups": [
      "group1",
      "group2"
    ]
  },
  "iat": 1573541050,
  "aud": "https://identitytoolkit.googleapis.com/google.identity.identitytoolkit.v1.IdentityToolkit",
  "sub": "cicp-admin-client-account@cicp-oidc.iam.gserviceaccount.com"
}
```


The second token is the one we're interested in.  This is the STS token signed by google which we will use.  Note the `iss:` field.
```json
{
  "isadmin": "true",
  "groups": [
    "group1",
    "group2"
  ],
  "iss": "https://securetoken.google.com/cicp-oidc",
  "aud": "cicp-oidc",
  "auth_time": 1573541050,
  "user_id": "alice",
  "sub": "alice",
  "iat": 1573541050,
  "exp": 1573544650,
  "firebase": {
    "identities": {},
    "sign_in_provider": "custom"
  }
}
```

Also note that `alice` now exists in Identity Platform:

![images/user_alice.png](images/user_alice.png)


Export the STS token and Refresh Tokens
```bash
$ export TOKEN=<value>

$ export REFRESH_TOKEN=<value>
```


5. Start Minikube with RBAC,OIDC configurations

```bash
$ minikube start --vm-driver=kvm2     \
      --bootstrapper=kubeadm \
      --extra-config=apiserver.authorization-mode=RBAC \
      --extra-config=apiserver.oidc-issuer-url=https://securetoken.google.com/$PROJECT_ID \
      --extra-config=apiserver.oidc-username-claim=sub \
      --extra-config=apiserver.oidc-client-id=$PROJECT_ID \
      --extra-config=apiserver.oidc-username-prefix=- \
      --extra-config=apiserver.oidc-groups-claim=groups \
      --extra-config=apiserver.oidc-required-claim=isadmin=true
```

I'm using `kvm2` (you can ofcourse use any driver you want)


6. Verify k8s API access


Use `curl` to verify that  anonymous/authenticated users can't access any api:


```bash
$ export MINIKUBE_IP=`minikube ip`

$ curl -s --cacert $HOME/.minikube/ca.crt  https://$MINIKUBE_IP:8443/api/v1/nodes
{
  "kind": "Status",
  "apiVersion": "v1",
  "metadata": {
    
  },
  "status": "Failure",
  "message": "nodes is forbidden: User \"system:anonymous\" cannot list resource \"nodes\" in API group \"\" at the cluster scope",
  "reason": "Forbidden",
  "details": {
    "kind": "nodes"
  },
  "code": 403
}
```

As well as `alice` using the token:

```bash
$ curl -s --cacert $HOME/.minikube/ca.crt  -H "Authorization: Bearer $TOKEN" https://$MINIKUBE_IP:8443/api/v1/nodes
{
  "kind": "Status",
  "apiVersion": "v1",
  "metadata": {
    
  },
  "status": "Failure",
  "message": "nodes is forbidden: User \"alice\" cannot list resource \"nodes\" in API group \"\" at the cluster scope",
  "reason": "Forbidden",
  "details": {
    "kind": "nodes"
  },
  "code": 403
}
```


7.  Apply RBAC policies

Now allow a role/rolebinding that will give access in the following way:

* `User: alice` can list pods
* Members of `Group: group` can list nodes
* All users that access the k8s API must have claim `isadmin: true`


```bash
$ kubectl apply -f rolebinding.yaml -f clusterrole.yaml 
    clusterrolebinding.rbac.authorization.k8s.io/pod-reader-binding created
    clusterrolebinding.rbac.authorization.k8s.io/node-reader-binding created
    clusterrole.rbac.authorization.k8s.io/pod-reader created
    clusterrole.rbac.authorization.k8s.io/node-reader created
```

8. Check Access to API

Now try to access `pods` and `nodes` as `alice` using curl

```bash
$ curl -s --cacert $HOME/.minikube/ca.crt  -H "Authorization: Bearer $TOKEN" https://$MINIKUBE_IP:8443/api/v1/namespaces/default/pods
{
  "kind": "PodList",
  "apiVersion": "v1",
  "metadata": {
    "selfLink": "/api/v1/namespaces/default/pods",
    "resourceVersion": "905"
  },
  "items": []
}

$ curl -s --cacert $HOME/.minikube/ca.crt  -o /dev/null  -w "%{http_code}\n" -H "Authorization: Bearer $TOKEN" https://$MINIKUBE_IP:8443/api/v1/nodes
200
```

woooo!


10. Configure `kubectl`

The easiest way to use `kubectl` to manage resoruces is to directly specify the `token` we've got without doing anything else

```bash
kubectl get po --token=$TOKEN
```


but...now we gotta add in the token all the time and manage it always...lets configure `kubectl` itself.

The default configurations you are usually using when dealing with GKE or kubernetes is with one of the standard auth plugins:

  - [Client-go plugins](https://kubernetes.io/docs/reference/access-authn-authz/authentication/#client-go-credential-plugins)
  - [https://github.com/kubernetes/client-go/tree/master/plugin/pkg/client/auth](https://github.com/kubernetes/client-go/tree/master/plugin/pkg/client/auth)

While this tutorial is about OIDC, we really can't use that default configuration because of the missing `/token` endpoint and the way its used.  We need to workaround this with a custom auth adapter that actually just returns the token to kubectl automatically (and refreshes it).

The script `fb_token.py` when used with the switch `refresh  $REFRESH_TOKEN $TOKEN` will return a particular JSON string which kubectl understands as a valid credential token to use.

Basically, it implements [ExecCredential](https://godoc.org/k8s.io/client-go/tools/clientcmd/api#ExecConfig) ([proto](https://github.com/kubernetes/client-go/blob/master/pkg/apis/clientauthentication/v1alpha1/types.go)


so how do we configure kubectl...you can either

a) "just edit" `~/.kube/config` and add in lines like the following as user `alice`:

```yaml
users:
- name: alice
  user:
    exec:
      command: /usr/bin/python
      apiVersion: "client.authentication.k8s.io/v1beta1"
      env:
      - name: "FOO"
        value: "bar"
      args:
      - "/path/to/fb_token.py"
      - "refresh"
      - $API_KEY
      - $TOKEN
```      
(ofcourse replace with the actual values of the env-vars)

b) Get a [recent version of kubectl](https://v1-13.docs.kubernetes.io/docs/tasks/tools/install-kubectl/#install-kubectl-binary-using-curl
) that implements the ability to configure the exec adapter via kubectl [#3230](https://github.com/kubernetes/kubernetes/pull/73230)

then run:

```bash
$ kubectl config set-credentials alice \
     --exec-api-version="client.authentication.k8s.io/v1beta1" \
     --exec-command="/usr/bin/python" \
     --exec-env="foo=bar" \
     --exec-env="GOOGLE_APPLICATION_DEFAULT=not_used" \
     --exec-arg="/path/to/fb_token.py","refresh","$REFRESH_TOKEN","$TOKEN"
```

ok, you can view the `.kube/config` file to see if the substitution values are set.

11. Use kubectl 

```
$ kubectl get po --user="alice"
No resources found in default namespace.

$ kubectl get no --user="alice"
NAME       STATUS   ROLES    AGE   VERSION
minikube   Ready    master   13h   v1.14.0

$ kubectl get svc --user="alice"
Error from server (Forbidden): services is forbidden: User "alice" cannot list resource "services" in API group "" in the namespace "default"
```

If you want, set `-v-10` to see all the gory details


12. Remove access to test:

```bash
$ kubectl delete -f clusterrole.yaml 
```

Verify the RBAC roles deny access.

```
$ kubectl get po --user="alice"
Error from server (Forbidden): pods is forbidden: User "alice" cannot list resource "pods" in API group "" in the namespace "default"
```

Note, `fb_token.py` does not send back the Expiration time for the token...thats ok for now because if kubectl will continue to use the current token until it sees a `401` at which point the `exec` script will get called.   Also note the `refresh_token` never expires (unless revoked externally). 

---

### moar references

* Google OIDC with k8s RBAC Tutorials:
  - [Kubernetes Authn/Authz with Google OIDC and RBAC](https://medium.com/@jessgreb01/kubernetes-authn-authz-with-google-oidc-and-rbac-74509ca8267e)
  - [Kubernetes 1.6.1 authentication by using Google OpenID](https://cloud.google.com/community/tutorials/kubernetes-auth-openid-rbac)
* Firebase JWK URL: [https://www.googleapis.com/robot/v1/metadata/jwk/securetoken@system.gserviceaccount.com](https://www.googleapis.com/robot/v1/metadata/jwk/securetoken@system.gserviceaccount.com)


### Known Issues

In the course of testing, i found some things i had to account for or workaround:

- Using `--extra-config=apiserver.oidc-username-prefix=-`

If I did not null the prefix, kubernetes prepended the `issuer-url` to the userID (presumably to disambiguate and for namespacing; i'm not sure).  Anyway, i worked around that by just setting it to `-` which in the docs would prevent this behavior.  You do not have to do this with other OIDC providers so. 

```json
{
  "kind": "Status",
  "apiVersion": "v1",
  "metadata": {
    
  },
  "status": "Failure",
  "message": "pods is forbidden: User \"https://securetoken.google.com/fabled-ray-104117#alice\" cannot list resource \"pods\" in API group \"\" in the namespace \"default\"",
  "reason": "Forbidden",
  "details": {
    "kind": "pods"
  },
  "code": 403
}
```


- Boolean values for `apiserver.oidc-required-claim`

I initially set a custom claim as boolean in the JWT:  `isadmin: true`.  However, kubernetes didn't seem to like that so i set it up as a string

```json
{"log":"E1112 03:45:48.070398  1 authentication.go:65] 
     Unable to authenticate the request due to an error: [invalid bearer token, oidc: parse claim isadmin: json: 
     cannot unmarshal bool into Go value of type string]\n","stream":"stderr","time":"2019-11-12T03:45:48.070786233Z"
}```