import json

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import authentication, permissions
from django.contrib.auth.models import User
from openedx.core.djangoapps.programs.models import ProgramsApiConfig
from edx_rest_framework_extensions.auth.jwt.authentication import JwtAuthentication

from openedx.core.djangoapps.programs.utils import (
    ProgramProgressMeter,
    get_program_marketing_url,
)


class ProgramListView(APIView):
    authentication_classes = (
        JwtAuthentication,
        authentication.SessionAuthentication,
    )
    permission_classes = (permissions.IsAuthenticated, )

    def get(self, request, *args, **kwargs):
        """
        Return a list programs a user is enrolled in.
        """
        user = request.user
        try:
            mobile_only = json.loads(request.GET.get('mobile_only', 'false'))
        except ValueError:
            mobile_only = False

        programs_config = ProgramsApiConfig.current()
        if not programs_config.enabled:
            raise Http404

        meter = ProgramProgressMeter(site=request.site, user=user, mobile_only=mobile_only)

        context = {
            'marketing_url': get_program_marketing_url(programs_config, mobile_only),
            'programs': meter.engaged_programs,
            'progress': meter.progress()
        }

        return Response(context)
