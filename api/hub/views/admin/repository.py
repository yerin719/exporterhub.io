import json
import requests
import base64
import re

from django.views import View
from django.http import JsonResponse

from hub.models import Exporter, Release, Token, Category
from hub.utils import is_admin

api_url = 'https://api.github.com/repos/'
PATTERN = r"!\[(\w*|\s|\w+( \w+)*)\]\(([^,:!]*|\/[^,:!]*\.\w+|\w*.\w*)\)"

categories={category.name:category.id for category in Category.objects.all()}

class RepositoryView(View):
    def get_repo(self, repo_url):
        TOKEN   = Token.objects.filter(is_valid=True).last().token if Token.objects.filter(is_valid=True).exists() else 'NO TOKEN'
        headers = {'Authorization' : 'token ' + TOKEN} 
        
        if 'https://github.com/' not in repo_url:
            return False 
        repo_api_url     = api_url+repo_url.replace('https://github.com/','')
        readme_api_url   = repo_api_url+'/readme'
        release_api_url  = repo_api_url+'/releases'
        repo             = requests.get(repo_api_url, headers=headers)
        
        if repo.status_code==200:
            repo_data    = repo.json()
            readme       = requests.get(readme_api_url, headers=headers)
            readme_data  = readme.json()
            release      = requests.get(release_api_url, headers=headers)
            release_data = release.json()
            
            data={
                "name"           : repo_data["name"],
                "logo_url"       : repo_data["owner"]["avatar_url"],
                "stars"          : repo_data["stargazers_count"],
                "description"    : repo_data["description"],
                "readme_url"     : repo_url+"/blob/master/README.md",
                "readme"         : readme_data["content"],
                "release"        : [{
                        "release_version": release["tag_name"],
                        "release_date"   : release["created_at"],
                        "release_url"    : release["html_url"]
                } for release in release_data]
            }
            return data
        
        elif repo.status_code==401:
            token=Token.objects.filter().last()
            token.is_valid=False
            token.save()
            return 'INVALID_TOKEN'

        return False

    @is_admin
    def post(self, request):
        try:
            data      = json.loads(request.body)
            repo_url  = data["repo_url"]
            category  = data["category"]

            if Exporter.objects.filter(repository_url=repo_url).exists():
                return JsonResponse({'message':'EXISTING_REPOSITORY'}, status=400)
                
            if "prometheus/" in repo_url:
                official = 1
            else:
                official = 2

            repo_info = self.get_repo(repo_url)

            if repo_info == 'INVALID_TOKEN':
                return JsonResponse({'message':'INVALID_TOKEN'}, status=401)
                
            elif repo_info:
                readme    = base64.b64decode(repo_info["readme"]).decode('utf-8')
                matches   = re.findall(PATTERN, readme)
                repo_name = repo_url.replace('https://github.com/','')

                for match in matches:
                    for element in match:
                        if '.' in element:
                            readme=readme.replace(element,f"https://raw.githubusercontent.com/{repo_name}/master/{element}")

                exporter=Exporter.objects.create(
                    category_id    = categories[category],
                    official_id    = official,
                    name           = repo_info["name"],
                    logo_url       = repo_info["logo_url"],
                    stars          = repo_info["stars"],
                    repository_url = repo_url,
                    description    = repo_info["description"],
                    readme_url     = repo_info["readme_url"],
                    readme         = readme.encode('utf-8'),
                )
            
                release=sorted(repo_info["release"], key=lambda x: x["release_date"])
                
                for info in release:
                    Release(
                        exporter_id = exporter.id,
                        release_url = info["release_url"],
                        version     = info["release_version"],
                        date        = info["release_date"]
                    ).save()
                
                return JsonResponse({'message':'SUCCESS'}, status=201)

            return JsonResponse({'message':'WRONG_REPOSITORY'}, status=400)

        except KeyError:
            return JsonResponse({'message':'KEY_ERROR'}, status=400)
        except Exception as e:
            return JsonResponse({'d':f"{e}"})

    @is_admin
    def delete(self, request):
        try:
            exporter_id = request.GET['exporter_id']
            exporter    = Exporter.objects.get(id=exporter_id)
            release     = Release.objects.filter(exporter_id=exporter_id)
            if release.exists():
                release.delete()
            exporter.delete()
            
            return JsonResponse({'message':'SUCCESS'}, status=200)

        except Exporter.DoesNotExist:
            return JsonResponse({'message':'NO_EXPORTER'}, status=400)
        except KeyError:
            return JsonResponse({'message':'KEY_ERROR'}, status=400)

    @is_admin
    def patch(self, request):
        try:
            exporter_id          = request.GET['exporter_id']
            data                 = json.loads(request.body)
            category             = data['category']
            exporter             = Exporter.objects.get(id=exporter_id)
            exporter.category_id = categories[category]
            exporter.save()

            return JsonResponse({'message':'SUCCESS'}, status=200)
        
        except Exporter.DoesNotExist:
            return JsonResponse({'message':'NO_EXPORTER'}, status=400)
        except KeyError:
            return JsonResponse({'message':'KEY_ERROR'}, status=400)