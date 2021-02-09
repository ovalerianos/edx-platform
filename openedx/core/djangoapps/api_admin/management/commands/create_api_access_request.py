""" Management command to create an ApiAccessRequest for given users """


import logging
from contextlib import contextmanager

from django.contrib.auth.models import User  # lint-amnesty, pylint: disable=imported-auth-user
from django.contrib.sites.models import Site
from django.core.management.base import BaseCommand, CommandError
from django.db.models.signals import post_save, pre_save
from six import text_type

from openedx.core.djangoapps.api_admin.models import (
    ApiAccessConfig,
    ApiAccessRequest,
    send_decision_email,
    send_request_email
)

logger = logging.getLogger(__name__)


@contextmanager
def disconnect_request_email_signals():
    """
    Context manager to be used for temporarily disconnecting the `send_request_email`
    and `send_decision_email` pre/post_save signal receivers from the `ApiAccessRequest` model.
    """
    post_save.disconnect(
        send_request_email, sender=ApiAccessRequest, dispatch_uid="api_access_request_post_save_email"
    )
    pre_save.disconnect(
        send_decision_email, sender=ApiAccessRequest, dispatch_uid="api_access_request_pre_save_email"
    )
    try:
        yield
    finally:
        post_save.connect(
            send_request_email, sender=ApiAccessRequest, dispatch_uid="api_access_request_post_save_email"
        )
        pre_save.connect(
            send_decision_email, sender=ApiAccessRequest, dispatch_uid="api_access_request_pre_save_email"
        )


class Command(BaseCommand):
    """
    Create an ApiAccessRequest for the given user

    Example usage:
        $ ./manage.py lms create_api_request <username> --create-config
    """

    help = 'Create an ApiAccessRequest for the given user'
    DEFAULT_WEBSITE = 'www.test-edx-example-website.edu'
    DEFAULT_REASON = 'Generated by management job create_api_request'

    def add_arguments(self, parser):
        parser.add_argument('username')
        parser.add_argument(
            '--create-config',
            action='store_true',
            help='Create ApiAccessConfig if it does not exist'
        )
        parser.add_argument(
            '--disconnect-signals',
            action='store_true',
            help='Disconnect the Django signal receivers that send emails when ApiAccessRequest records are saved'
        )
        parser.add_argument(
            '--status',
            choices=[choice[0] for choice in ApiAccessRequest.STATUS_CHOICES],
            default=ApiAccessRequest.APPROVED,
            help='Status of the created ApiAccessRequest'
        )
        parser.add_argument(
            '--reason',
            default=self.DEFAULT_REASON,
            help='Reason that the ApiAccessRequest is being created'
        )
        parser.add_argument(
            '--website',
            default=self.DEFAULT_WEBSITE,
            help='Website associated with the user of the created ApiAccessRequest'
        )

    def handle(self, *args, **options):
        if options.get('disconnect_signals'):
            with disconnect_request_email_signals():
                self._handle(*args, **options)
        else:
            self._handle(*args, **options)

    def _handle(self, *args, **options):  # pylint: disable=unused-argument
        if options.get('create_config'):
            self.create_api_access_config()
        user = self.get_user(options.get('username'))
        self.create_api_access_request(
            user,
            options.get('status'),
            options.get('reason'),
            options.get('website'),
        )

    def get_user(self, username):
        try:
            return User.objects.get(username=username)
        except User.DoesNotExist:
            raise CommandError('User {} not found'.format(username))  # lint-amnesty, pylint: disable=raise-missing-from

    def create_api_access_request(self, user, status, reason, website):
        """
        Creates an ApiAccessRequest with the given values.
        """
        try:
            ApiAccessRequest.objects.create(
                user=user,
                status=status,
                website=website,
                reason=reason,
                site=Site.objects.get_current(),
            )
        except OSError as e:
            # Ignore a specific error that occurs in the downstream `send_request_email` receiver.
            # see https://openedx.atlassian.net/browse/EDUCATOR-4478
            error_msg = text_type(e)
            if 'Permission denied' in error_msg and 'mako_lms' in error_msg:
                logger.warning('Error sending email about access request: {}'.format(error_msg))
            else:
                raise CommandError(error_msg)  # lint-amnesty, pylint: disable=raise-missing-from
        except Exception as e:
            msg = 'Unable to create ApiAccessRequest for {}. Exception is {}: {}'.format(
                user.username,
                type(e).__name__,
                e
            )
            raise CommandError(msg)  # lint-amnesty, pylint: disable=raise-missing-from

        logger.info('Created ApiAccessRequest for user {}'.format(user.username))

    def create_api_access_config(self):
        """
        Creates an active ApiAccessConfig if one does not currectly exist
        """
        try:
            _, created = ApiAccessConfig.objects.get_or_create(enabled=True)
        except Exception as e:
            msg = 'Unable to create ApiAccessConfig. Exception is {}: {}'.format(type(e).__name__, e)
            raise CommandError(msg)  # lint-amnesty, pylint: disable=raise-missing-from

        if created:
            logger.info('Created ApiAccessConfig')
        else:
            logger.info('ApiAccessConfig already exists')
