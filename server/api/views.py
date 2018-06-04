from rest_framework.decorators import api_view
from rest_framework.response import Response
from django.contrib.auth.models import User
from django.contrib.auth.hashers import check_password
from api.models import Site

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
            print(request.POST.get('username'))
            if account.user.username == request.POST.get('username') and check_password(request.POST.get('password'), account.user.password):
                return Response({'ACCEPTED'})
    return Response({'DENIED'})