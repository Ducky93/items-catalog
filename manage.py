from flask_script import Manager
from flask_migrate import Migrate, MigrateCommand

from main import app, DBSession

migrate = Migrate(app, DBSession)

manager = Manager(app)
manager.add_command('db', MigrateCommand)


if __name__ == '__main__':
    manager.run()