from pyramid.config import Configurator

from .site import Site


def main(global_config, **settings):
    """ This function returns a Pyramid WSGI application.
    """
    config = Configurator(settings=settings, root_factory=Site.root_factory)
    config.include('substanced')
    config.include('.auth')
    config.scan()
    return config.make_wsgi_app()
