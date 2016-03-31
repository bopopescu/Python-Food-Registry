
from system.core.router import routes


routes['default_controller'] = 'Foodies'

routes['POST']['/Foodies/add_user'] = 'Foodies#add_user'

routes['POST']['/Foodies/login']='Foodies#login'

routes['/Foodies/logout'] = 'Foodies#logout'



routes['/preferences'] = 'Preferences#preferences'

routes['POST']['/preferences/add'] = 'Preferences#add_prefs'



routes['/Foodies/content'] = 'Foodies#content'

routes['GET']['/get_recipes/<key>'] = 'Foodies#get_recipes'

routes['GET']['/show_recipe/<key>'] = 'Foodies#show_recipe'

routes['GET']['/get_twtr/<key>'] = 'Foodies#get_twtr'