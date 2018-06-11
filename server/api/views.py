from rest_framework.decorators import api_view
from rest_framework.response import Response
from django.contrib.auth.models import User
from django.contrib.auth.hashers import check_password
from api.models import Site
import pyotp

@api_view(['POST'])
def hello_world(request):
    print(request.POST)
    if request.method == 'POST':
        try:
            requested_site = Site.objects.get(key=request.POST['key'][:-1])
        except Site.DoesNotExist:
            return Response({'DENIED'})
        site_accounts = requested_site.accounts.all()
        for account in site_accounts:
            if account.hotp_activate == True:
                if len(request.POST.get('password')) < 6:
                    return Response({'DENIED'})
                received_token = request.POST.get('password')[-6:]
                hotp = pyotp.HOTP(account.hotp_key)
                if hotp.verify(received_token, account.hotp_iteration):
                    if account.user.username == request.POST.get('username') and check_password(request.POST.get('password')[:-6], account.user.password):
                        account.hotp_iteration = account.hotp_iteration + 1
                        account.save()
                        return Response({'ACCEPTED'})
                else:
                    return Response({'DENIED'})
            else:
                if account.user.username == request.POST.get('username') and check_password(request.POST.get('password'), account.user.password):
                    return Response({'ACCEPTED'})
    return Response({'DENIED'})