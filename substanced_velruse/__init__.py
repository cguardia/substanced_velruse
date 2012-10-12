from pyramid.config import Configurator

#from .site import Site
from substanced import root_factory

def main(global_config, **settings):
    """ This function returns a Pyramid WSGI application.
    """
    config = Configurator(settings=settings, root_factory=root_factory)
    config.include('substanced')
    config.include('.auth')
    config.scan()
    return config.make_wsgi_app()
