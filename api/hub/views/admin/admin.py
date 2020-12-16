import json
import bcrypt
import jwt
import os

from django.views import View
from django.http import JsonResponse

from hub.models import User, Exporter
from hub.utils import is_admin

SECRET_KEY=os.environ['SECRET_KEY']
ALGORITHM=os.environ['ALGORITHM']

class AdminView(View):
    def get(self, request):
        is_admin=User.objects.filter(is_admin=True).exists()
        return JsonResponse({'is_admin':is_admin}, status=200)

    def post(self, request):
        data=json.loads(request.body)
        name=data['name']
        password=data['password']

        if User.objects.filter(is_admin=True).exists():
            user=User.objects.get(is_admin=True)
            if bcrypt.checkpw(password.encode('utf-8'), user.password.encode('utf-8')):
                access_token  = jwt.encode({'user_id':user.id}, SECRET_KEY, algorithm=ALGORITHM)
                decoded_token = access_token.decode('utf-8')
                return JsonResponse({'TOKEN': decoded_token}, status=200)
        
            return JsonResponse({'message':'WRONG_PASSWORD'}, status=400)
        
        hashed_password  = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        decoded_password = hashed_password.decode('utf-8')
        user             = User.objects.create(name=name, password=decoded_password, is_admin=True)
        access_token     = jwt.encode({'user_id':user.id}, SECRET_KEY, algorithm=ALGORITHM)
        decoded_token    = access_token.decode('utf-8')
        
        return JsonResponse({'TOKEN': decoded_token}, status=200)

class AdminMainView(View):
    @is_admin
    def get(self, request):
        try:
            exporters=Exporter.objects.select_related('category', 'official').prefetch_related('release_set').order_by('id')
            data={
                "exporters":
                [
                    {
                        "exporter_id"    : exporter.id,
                        "name"           : exporter.name,
                        "logo_url"       : exporter.logo_url,
                        "category"       : exporter.category.name,
                        "official"       : exporter.official.name,
                        "stars"          : exporter.stars,
                        "repository_url" : exporter.repository_url,
                        "description"    : exporter.description,
                        "recent_release" : exporter.release_set.last().date if exporter.release_set.all() else '1970-01-01',
                        "release"        : [{
                            "release_version": release.version,
                            "release_date"   : release.date,
                            "release_url"    : release.release_url
                        } for release in exporter.release_set.all()],
                    }
                for exporter in exporters]
            }

            return JsonResponse(data, status=200)
        except Exception as e:
            return JsonResponse({'message':f"{e}"}, status=400)