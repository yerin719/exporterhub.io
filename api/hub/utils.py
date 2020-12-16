import os
import json
import jwt

from django.http import JsonResponse

from hub.models import User

SECRET_KEY = os.environ['SECRET_KEY']
ALGORITHM = os.environ['ALGORITHM']

def is_admin(func):
    def wrapper(self, request, *args, **kwargs):
        try:
            token=request.headers.get("Authorization")
            payload=jwt.decode(token, SECRET_KEY, algorithm=ALGORITHM)
            request.user_id=payload['user_id']
            if not User.objects.get(id=request.user_id).is_admin:
                return JsonResponse({'message':'NOT_ADMIN'}, status=400)

        except jwt.exceptions.DecodeError:
            return JsonResponse({'message': 'INVALID_TOKEN'}, status=400)

        return func(self, request, *args, **kwargs)
    return wrapper