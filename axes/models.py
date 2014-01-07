# coding: utf-8

from django.db import models
from django.utils.translation import ugettext_lazy as _


class CommonAccess(models.Model):
    user_agent = models.CharField(
        max_length=255, verbose_name=_('user agent')
    )

    ip_address = models.IPAddressField(
        verbose_name=_('IP address'),
        null=True,
    )

    username = models.CharField(
        max_length=255,
        null=True,
        verbose_name=_('username')
    )

    # Once a user logs in from an ip, that combination is trusted and not
    # locked out in case of a distributed attack
    trusted = models.BooleanField(
        default=False, verbose_name=_('trusted')
    )

    http_accept = models.CharField(
        verbose_name=_('HTTP Accept'),
        max_length=1025,
    )

    path_info = models.CharField(
        verbose_name=_('path'),
        max_length=255,
    )

    attempt_time = models.DateTimeField(
        auto_now_add=True,
        verbose_name=_('attempt time')
    )

    class Meta:
        abstract = True
        ordering = ['-attempt_time']


class AccessAttempt(CommonAccess):
    get_data = models.TextField(
        verbose_name=_('GET data'),
    )

    post_data = models.TextField(
        verbose_name=_('POST data'),
    )

    failures_since_start = models.PositiveIntegerField(
        verbose_name=_('failed logins'),
    )

    class Meta(CommonAccess.Meta):
        verbose_name = _('access attempt')
        verbose_name_plural = _('access attempts')
        verbose_name_extended = {
            'ru': {
                'add': u'попытку войти',
                'delete': u'попытку войти',
                'change': u'попытку войти',
                'gender': 'she'
            },
            'uk': {
                'add': u'спробу ввійти',
                'delete': u'спробу війти',
                'change': u'спробу війти',
                'gender': 'she'
            }
        }

    @property
    def failures(self):
        return self.failures_since_start

    def __unicode__(self):
        return _(u'Attempted Access: %s') % self.attempt_time


class AccessLog(CommonAccess):
    logout_time = models.DateTimeField(
        null=True,
        blank=True,
        verbose_name=_('logout time')
    )

    class Meta(CommonAccess.Meta):
        verbose_name = _('access log')
        verbose_name_plural = _('access logs')
        verbose_name_extended = {
            'ru': {
                'add': u'историю входа',
                'delete': u'историю входа',
                'change': u'историю входа',
                'gender': 'she'
            },
            'uk': {
                'add': u'історію входу',
                'delete': u'історію входу',
                'change': u'історію входу',
                'gender': 'she'
            }
        }

    def __unicode__(self):
        return _(u'Access Log for %(user)s @ %(attempt)s') % \
            dict(user=self.username, attempt=self.attempt_time)
