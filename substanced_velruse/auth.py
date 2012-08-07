from pyramid.httpexceptions import (
    HTTPForbidden,
    HTTPFound
    )

from pyramid.security import (
    remember,
    )

from pyramid.view import view_config

from pyramid_zodbconn import get_connection

from substanced.sdi import (
    mgmt_view,
    check_csrf_token,
    )

from substanced.service import find_service
from substanced.util import oid_of

from velruse import login_url as velruse_login_url


@mgmt_view(name='login', renderer='templates/login.pt', tab_condition=False)
@mgmt_view(renderer='templates/login.pt', context=HTTPForbidden,
           tab_condition=False)
def login(context, request):
    login_url = request.mgmt_path(request.context, 'login')
    referrer = request.url
    if login_url in referrer: # pragma: no cover
        # never use the login form itself as came_from
        referrer = request.mgmt_path(request.root)
    came_from = request.session.setdefault('came_from', referrer)
    login = ''
    password = ''
    if 'form.submitted' in request.params:
        try:
            check_csrf_token(request)
        except:
            request.session.flash('Failed login (CSRF)', 'error')
        else:
            login = request.params['login']
            password = request.params['password']
            principals = find_service(context, 'principals')
            users = principals['users']
            user = users.get(login)
            if user is not None and user.check_password(password):
                headers = remember(request, oid_of(user))
                request.session.flash('Welcome!', 'success')
                return HTTPFound(location=came_from, headers=headers)
            request.session.flash('Failed login', 'error')

    return dict(
        url=request.mgmt_path(request.root, 'login'),
        came_from=came_from,
        login=login,
        password=password,
        login_url=velruse_login_url,
        providers=request.registry.settings['substanced.login_providers']
        )


@view_config(context='velruse.AuthenticationComplete')
def external_login_complete(request):
    profile = request.context.profile
    email = ''
    if 'verifiedEmail' in profile:
        email = profile['verifiedEmail']
    if 'emails' in profile:
        emails = profile['emails']
        email = emails[0]['value']
    came_from = request.session.get('came_from', request.application_url)
    connection = get_connection(request)
    site_root = connection.root()['app_root']
    principals = find_service(site_root, 'principals')
    users = principals['users']
    user = [user for user in  users.values() if user.email == email]
    if not user or not email:
        return external_login_denied(request)
    headers = remember(request, oid_of(user[0]))
    request.session.flash('Welcome!', 'success')
    return HTTPFound(location=came_from, headers=headers)


@view_config(context='velruse.AuthenticationDenied')
def external_login_denied(request):
    connection = get_connection(request)
    site_root = connection.root()['app_root']
    login_url = request.mgmt_path(site_root, 'login')
    request.session.flash('Failed login', 'error')
    return HTTPFound(location=login_url)


def includeme(config): # pragma: no cover
    settings = config.registry.settings
    providers = settings.get('substanced.login_providers', '')
    providers = filter(None, [p.strip()
        for line in providers.splitlines()
        for p in line.split(', ')])
    settings['substanced.login_providers'] = providers
    if 'github' in providers:
        config.include('velruse.providers.github')
        config.add_github_login_from_settings(prefix='github.')
    if 'twitter' in providers:
        config.include('velruse.providers.twitter')
        config.add_twitter_login_from_settings(prefix='twitter.')
    if 'google' in providers:
        config.include('velruse.providers.google')
        config.add_google_login(
            realm=settings['google.realm'],
            consumer_key=settings['google.consumer_key'],
            consumer_secret=settings['google.consumer_secret'],
        )
    if 'yahoo' in providers:
        config.include('velruse.providers.yahoo')
        config.add_yahoo_login(
            realm=settings['yahoo.realm'],
            consumer_key=settings['yahoo.consumer_key'],
            consumer_secret=settings['yahoo.consumer_secret'],
        )
    config.scan('.')
