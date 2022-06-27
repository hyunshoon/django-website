from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django.contrib.sites import requests
from django.http import HttpResponse
from django.shortcuts import render, redirect
from django.contrib.auth import login as auth_login, login
from django.contrib.auth import logout as auth_logout
from accounts.models import User

def profile(request):

    return render(request, 'account/profile.html')


def getcode(request):
    code = request.GET.get('code')#인가콛
    print(code)
    data = {'grant_type':'authorization_code',
            'client_id':'b39ef4969393ab0e2587a7ad292ae6ae',
            "redirect_uri":"http://127.0.0.1:8000/oauth/redirect",
            'code':code
            #http://127.0.0.1:8000/oauth/redirect 카카오 redirect URI
            }
    headers = {'Content-type': 'application/x-www-form-urlencoded;charset=utf-8'}
    res = requests.post('https://kauth.kakao.com/oauth/token', data=data, headers=headers) # post로 보내면 사용자 정보를 받아갈 수 있는 토큰을 준다.
    token_json = res.json()
    print(token_json)
    access_token = token_json['access_token']
    print(access_token)

    ###토큰으로 get 방식을 통해 사용자 프로필 정보를 받아옴.
    headers = {'Authorization':'Bearer ' +access_token,
               'Content-type':'application/x-www-form-urlencoded;charset=utf-8'}
    res = requests.get('https://kapi.kakao.com/v2/user/me', headers=headers)
    profile_json = res.json()
    print(profile_json)
    print('닉네임:',profile_json['kakao_account']['profile']['nickname'])
    print('나이:',profile_json['kakao_account']['age_range'])
    print('생일:',profile_json['kakao_account']['birthday'])

    '''
    카카오로 부터 회원 정보 수신
    우리 디비에 해당 회원의 정보가 있나 없나 확인
    없으면 회원 가입 후 로그인 처리
    있으면 그냥 바로 로그인 처리 <- 시간되면 구현
    '''
    kakaoid = profile_json['id']
    user = User.objects.filter(email=kakaoid)
    print(user)
    if user.first() is not None:
        login(request, user.first(), backend='django.contrib.auth.backends.ModelBackend')
    else:
        user = User()
        user.email = kakaoid
        user.username = profile_json['properties']['nickname']
        user.save()
        login(request, user)
    return HttpResponse(code)