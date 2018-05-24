from rest_framework.decorators import api_view
from rest_framework.response import Response
from django.contrib.auth.models import User
from django.contrib.auth.hashers import check_password

@api_view(['POST'])
def hello_world(request):
    if request.method == 'POST':
        print(request)
        print("*" + request.POST['username'] + "*")
        print("$" + request.POST['password'] + "$")
        print("$" + request.POST['key'] + "$")
        requested_user = User.objects.get(username=request.POST['username'])
        print(requested_user)
        if requested_user:
            print('got here')
            if check_password(request.POST['password'], requested_user.password):
                print('and here')
                return Response({'ACCEPTED'})
        else:
            return Response({'DENIED'})
    return Response({"message": "Hello, world!"})