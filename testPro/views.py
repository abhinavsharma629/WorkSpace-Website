from django.shortcuts import render
from django.core import serializers
from django.db.models import Q
from django.http import JsonResponse, HttpResponseRedirect
from django.utils import timezone
from django.contrib.auth.models import User
from .models import Tokens, Temp
import json
from django.core.serializers.json import DjangoJSONEncoder
import datetime
from json import dumps, JSONEncoder, JSONDecoder
import requests
from oauth2client.client import OAuth2WebServerFlow
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth import authenticate, login as dj_login

def signup(request):
    return render(request, 'testPro/signup.html')

@csrf_exempt
def signUpInCurrentServer(request):
    if(request.method=="POST"):
        user=User.objects.create_user(username=request.POST.get("username"),
                                 email=request.POST.get("email"),
                                 password=request.POST.get("pass"))
        user.save()
        user.set_password=request.POST.get("pass")
        user.save()

        user.firstname=request.POST.get("firstname")
        user.lastname=request.POST.get("lastname")
        user.save()
        user1 = authenticate(username = user.username, password = request.POST.get("pass"))
        dj_login(request, user1)

        return JsonResponse({"message":"Ok Created", "status":"201"})

    else:
        return JsonResponse({"message":"Error", "status":"500"})


def profile(request):
    try:
        print(request.user)
        obj=Tokens.objects.get(username=request.user)
        return render(request, 'testPro/network1.html', {"username":request.user.username, "access_token":obj.access_token,"refresh_token":obj.refresh_token})
    except:
        return render(request, 'testPro/signin.html')


def saveToken(request):
    if(Tokens.objects.filter(username=request.GET.get('username')).count()==0):
        obj,notif=Tokens.objects.get_or_create(username=request.GET.get('username'), access_token=request.GET.get('access_token'),refresh_token=request.GET.get('refresh_token'))
        if(notif):
            obj.save()
            return render(request, 'testPro/main_profile_page.html', {"username":request.GET.get('username'), "access_token":request.GET.get('access_token'),"refresh_token":request.GET.get('refresh_token')})
    else:
        obj=Tokens.objects.get(username=request.GET.get('username'))
        obj.access_token=request.GET.get('access_token')
        obj.refresh_token=request.GET.get('refresh_token')
        obj.save()
        user1 = authenticate(username = obj.username, password = request.GET.get("pass"))
        dj_login(request, user1)
        return HttpResponseRedirect('https://obscure-bayou-10492.herokuapp.com/test/profile')


def network(request):
    try:
        print(request.user)
        obj=Tokens.objects.get(username=request.user)
        return render(request, 'testPro/network.html', {"username":request.user.username, "access_token":obj.access_token,"refresh_token":obj.refresh_token})
    except:
        return render(request, 'testPro/signin.html')

def clouds(request):
    try:
        print(request.user)
        obj=Tokens.objects.get(username=request.user)
        return render(request, 'testPro/cloudMain.html', {"username":request.user.username, "access_token":obj.access_token,"refresh_token":obj.refresh_token})
    except:
        return render(request, 'testPro/signin.html')

#GOOGLE
flow = OAuth2WebServerFlow(client_id='484263106620-gqflub2lb8d0bvbof404133q236utfkn.apps.googleusercontent.com',
                            client_secret='7dRw6vDma4uEraS7X7xWT_7z',
                            scope=['https://www.googleapis.com/auth/plus.login', 'openid',
                            'https://www.googleapis.com/auth/userinfo.email',
                            'https://www.googleapis.com/auth/drive.readonly',
                            'https://www.googleapis.com/auth/drive.metadata',
                            'https://www.googleapis.com/auth/drive.readonly',
                            'https://www.googleapis.com/auth/drive.scripts',
                            'https://www.googleapis.com/auth/drive.photos.readonly',
                            'https://www.googleapis.com/auth/drive.file',
                            'https://www.googleapis.com/auth/drive.appdata'
                            ],

                            redirect_uri='https://obscure-bayou-10492.herokuapp.com/test/complete/google-oauth2/')

#JSON OBJECTS ENCODER
class PythonObjectEncoder(JSONEncoder):
        def default(self, obj):
            if isinstance(obj, set):
                return list(obj)
            elif isinstance(obj, (datetime.date, datetime.datetime)):
                return DjangoJSONEncoder.default(self, obj)



def login(request):
    auth_uri = flow.step1_get_authorize_url()
    return HttpResponseRedirect(auth_uri)

def gd_oauth2(request):
    code=request.GET.get('code')
    print(code)
    credentials = flow.step2_exchange(code)
    cred=vars(credentials)
    print(cred)
    mainDict={}
    mainDict['id_token']=cred['id_token']
    mainDict['token_response']=cred['token_response']

    outfile=open('createAGoogleDrive.json', 'w')

    dump=json.dumps(vars(credentials), cls=PythonObjectEncoder)
    outfile.write(dump)
    outfile.close()

    headers={}
    headers['Authorization']= 'Bearer '+cred['access_token']
    userDetailsFromToken=requests.get('https://oauth2.googleapis.com/tokeninfo?id_token='+cred['id_token_jwt'], headers=headers)
    userData=userDetailsFromToken.json()

    userDetails=open('googleUserDetails.json', 'w')
    dump=json.dumps(userData)
    userDetails.write(dump)
    userEmail=userData['email']
    print(userEmail)

    obj=Tokens.objects.get(username=request.user)
    headers1={}
    headers1['Authorization']= 'Bearer '+obj.access_token
    url="https://shielded-dusk-55059.herokuapp.com/hi/storeCloud"

    print(cred)
    response=requests.post(url, data={
        'access_token':(vars(credentials)['access_token']),
        'email':userEmail,
        'cred':json.dumps(vars(credentials), cls=PythonObjectEncoder),
        'dump':dump,
        'authName': "GOOGLE DRIVE"
    }, headers=headers1).json()

    print(response)

    if(response['status']=='201'):
        result="A Duplicate User With the Email Of Registered Drive Already Exists in our Database!! Please try again with that account (if its yours) or report an issue if you notice something unusual!!"
    else:
        result="Your Drive Data Will Soon Be Loaded!! We are analysing it!! Be Patient!!"
    return render(request, 'testPro/cloudMain.html', {'data':result, "username":request.user.username, "access_token":obj.access_token,"refresh_token":obj.refresh_token})






def gd_oauth21(request):
    code=request.GET.get('code')
    print(code)
    credentials = flow.step2_exchange(code)
    cred=vars(credentials)

    user=Temp.objects.filter(code=code)
    while(Temp.objects.filter(code=code).count()<0):
        user=Temp.objects.get(code=code)
        continue

    print(user)
    print(user.code)
    print(user.access_token)
    print(user.username)

    print(cred)
    mainDict={}
    mainDict['id_token']=cred['id_token']
    mainDict['token_response']=cred['token_response']

    outfile=open('createAGoogleDrive.json', 'w')

    dump=json.dumps(vars(credentials), cls=PythonObjectEncoder)
    outfile.write(dump)
    outfile.close()

    headers={}
    headers['Authorization']= 'Bearer '+cred['access_token']
    userDetailsFromToken=requests.get('https://oauth2.googleapis.com/tokeninfo?id_token='+cred['id_token_jwt'], headers=headers)
    userData=userDetailsFromToken.json()

    userDetails=open('googleUserDetails.json', 'w')
    dump=json.dumps(userData)
    userDetails.write(dump)
    userEmail=userData['email']
    print(userEmail)

    obj=Tokens.objects.get(username=request.user)
    headers1={}
    headers1['Authorization']= 'Bearer '+obj.access_token
    url="https://shielded-dusk-55059.herokuapp.com/hi/storeCloud"

    print(cred)
    response=requests.post(url, data={
        'access_token':(vars(credentials)['access_token']),
        'email':userEmail,
        'cred':json.dumps(vars(credentials), cls=PythonObjectEncoder),
        'dump':dump,
        'authName': "GOOGLE DRIVE"
    }, headers=headers1).json()

    print(response)

    if(response['status']=='201'):
        result="A Duplicate User With the Email Of Registered Drive Already Exists in our Database!! Please try again with that account (if its yours) or report an issue if you notice something unusual!!"
    else:
        result="Your Drive Data Will Soon Be Loaded!! We are analysing it!! Be Patient!!"
    return render(request, 'testPro/cloudMain.html', {'data':result, "username":request.user.username, "access_token":obj.access_token,"refresh_token":obj.refresh_token})


def dropboxLogin(request):
    clientId="0g2qw3uaxpgwbsf"
    url="https://www.dropbox.com/oauth2/authorize?client_id="+clientId+"&response_type=code&redirect_uri=https://obscure-bayou-10492.herokuapp.com/test/complete/dropbox-oauth2"
    return HttpResponseRedirect(url)


#Folder Hierarchy View
def drop_oauth2(request):
    code=request.GET.get('code')

    print(code)
    url = "https://api.dropboxapi.com/oauth2/token"

    payload1 = "code="+str(code)+"&grant_type=authorization_code&redirect_uri=https://obscure-bayou-10492.herokuapp.com/test/complete/dropbox-oauth2"
    headers1 = {
        'Content-Type': "application/x-www-form-urlencoded",
        'Authorization': "Basic MGcycXczdWF4cGd3YnNmOnl4dHhhMWg0YWU0cDhmMw==",
        'Accept': "*/*",
        'Cache-Control': "no-cache",
        'Host': "api.dropboxapi.com",
        'accept-encoding': "gzip, deflate",
        'content-length': "154",
        'Connection': "keep-alive",
        'cache-control': "no-cache"
        }

    response = requests.request("POST", url, data=payload1, headers=headers1)

    response=response.json()
    print(response)
    try:
        accessToken=response['access_token']
    except Exception as e:
        return HttpResponseRedirect('/test/dropboxLogin')

    print(accessToken)
    uid=response['uid']
    print(uid)
    accountId=response['account_id']
    print(accountId)
    url = "https://api.dropboxapi.com/2/users/get_current_account"

    headers = {
            'Authorization': "Bearer "+str(accessToken)
        }

    response1 = requests.request("POST", url, headers=headers)
    print(response1.json())
    dropBoxDetails={}
    dropBoxCred={}
    dropBoxCred['access_token']=accessToken
    dropBoxCred['uid']=uid
    dropBoxCred['account_id']=accountId
    dropBoxDetails['credentials']=dropBoxCred
    dropBoxDetails['user_details']=response1.json()
    dropBoxFile=open('dropBoxUserDetails.json', 'w')
    json.dump(dropBoxDetails, dropBoxFile)
    dropBoxFile.close()

    email=response1.json()['email']

    obj=Tokens.objects.get(username=request.user)
    headers1={}
    headers1['Authorization']= 'Bearer '+obj.access_token
    url="https://shielded-dusk-55059.herokuapp.com/hi/storeCloud"

    response=requests.post(url, data={
        'access_token':accessToken,
        'email':email,
        'cred':json.dumps(dropBoxCred),
        'dump':json.dumps(dropBoxDetails),
        'authName': "DROPBOX"
    }, headers=headers1).json()

    print(response)

    if(response['status']=='201'):
        result="A Duplicate User With the Email Of Registered Drive Already Exists in our Database!! Please try again with that account (if its yours) or report an issue if you notice something unusual!!"
    else:
        result="Your Drive Data Will Soon Be Loaded!! We are analysing it!! Be Patient!!"
    return render(request, 'testPro/cloudMain.html', {'data':result, "username":request.user.username, "access_token":obj.access_token,"refresh_token":obj.refresh_token})


def personal(request):
    try:
        print(request.user)
        obj=Tokens.objects.get(username=request.user)
        return render(request, 'testPro/personal.html', {"username":request.user.username, "access_token":obj.access_token,"refresh_token":obj.refresh_token})
    except:
        return render(request, 'testPro/signin.html')

def github(request):
    try:
        print(request.user)
        obj=Tokens.objects.get(username=request.user)
        return render(request, 'testPro/gitHub.html', { "username":request.user.username, "access_token":obj.access_token,"refresh_token":obj.refresh_token})
    except:
        return render(request, 'testPro/signin.html')

def gitHubLogin(request):
    return HttpResponseRedirect("https://github.com/login/oauth/authorize?client_id=62214c9c431303a8217c&client_secret=2513fa09a6a01b3956bc1ace331d0c9325fa2b7e&scope=notifications,user,repo:status,read:user,repo,delete_repo,email")


def git_complete(request):
    print(request.GET)
    code=request.GET.get('code')
    print("Code is:- ",code)
    data={
        'client_id':'62214c9c431303a8217c',
        'client_secret':"2513fa09a6a01b3956bc1ace331d0c9325fa2b7e",
        'state':'notifications,user,email,repo',
        'code':code,
        'redirect_uri':"https://obscure-bayou-10492.herokuapp.com/test/complete/gitHub-oauth2"
        }
    headers={}
    headers['Accept']="application/json"
    accessTokenData=requests.post("https://github.com/login/oauth/access_token", data=data, headers=headers)
    #print(accessTokenData.text)
    accessTokenDataToJson=json.loads(accessTokenData.text)
    header={}
    try:
        header['Authorization']="Bearer "+accessTokenDataToJson['access_token']
    except:
        return HttpResponseRedirect('/hi/gitHubLogin')
    userDetails=requests.get("https://api.github.com/user", headers=header)
    #print(userDetails)
    userDetailsToJson=json.loads(userDetails.text)

    url = "https://api.github.com/user/emails"

    headers = {
        'Authorization': "Bearer "+str(accessTokenDataToJson['access_token']),
        'Host': "api.github.com"
        }

    response = requests.request("GET", url, headers=headers)

    userDetailsToJson['email']=response.json()[0]

    concatinatingTheTwoJsonObjects={}
    concatinatingTheTwoJsonObjects['user_details']=userDetailsToJson
    concatinatingTheTwoJsonObjects['token_details']=accessTokenDataToJson

    gitHubCred=open('gitHubCred.json' , 'w')
    json.dump(concatinatingTheTwoJsonObjects, gitHubCred, indent=4)
    gitHubCred.close()

    obj=Tokens.objects.get(username=request.user)
    headers1={}
    headers1['Authorization']= 'Bearer '+obj.access_token
    url="https://shielded-dusk-55059.herokuapp.com/hi/storeCloud"

    response=requests.post(url, data={
        'access_token':accessTokenDataToJson['access_token'],
        'auth_login_name':userDetailsToJson['login'],
        'email':userDetailsToJson['email']['email'],
        'cred':json.dumps(accessTokenDataToJson),
        'dump':json.dumps(userDetailsToJson),
        'authName': "GITHUB"
    }, headers=headers1).json()

    print(response)

    if(response['status']=='201'):
        result="A Duplicate User With the Email Of Registered Drive Already Exists in our Database!! Please try again with that account (if its yours) or report an issue if you notice something unusual!!"
    else:
        result="Your Drive Data Will Soon Be Loaded!! We are analysing it!! Be Patient!!"
    return render(request, 'testPro/gitHub.html', {'data':result, "username":request.user.username, "access_token":obj.access_token,"refresh_token":obj.refresh_token})


def network1(request):
    try:
        print(request.user)
        obj=Tokens.objects.get(username=request.user)
        return render(request, 'testPro/network1.html', {"username":request.user.username, "access_token":obj.access_token,"refresh_token":obj.refresh_token})
    except:
        return render(request, 'testPro/signin.html')

def showNote(request,id):
    try:
        print(request.user)
        obj=Tokens.objects.get(username=request.user)
        return render(request, 'testPro/showNote.html', {"noteId":id , "username":request.user.username, "access_token":obj.access_token,"refresh_token":obj.refresh_token})
    except:
        return render(request, 'testPro/signin.html')


def showGitHub(request, id):
    try:
        print(request.user)
        obj=Tokens.objects.get(username=request.user)
        return render(request, 'testPro/showGitHub.html', {"noteId":id , "username":request.user.username, "access_token":obj.access_token,"refresh_token":obj.refresh_token})
    except:
        return render(request, 'testPro/signin.html')
