#! /usr/bin/env python
import json
import random
import string
from functools import wraps

from flask import Flask, render_template, request, flash, abort
from flask import session as login_session
from flask_sqlalchemy import xrange
from oauth2client import client
from sqlalchemy import create_engine, func
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm.exc import NoResultFound

from database_setup import Base, CatalogItem, Category, User

# Set path to the Web application
# client_secret_*.json file you downloaded from the
# Google API Console:
# https://console.developers.google.com/apis/credentials
CLIENT_SECRET_FILE = 'client_secret.json'

# End of login process
app = Flask(__name__)

# Connect to Database and create database session
engine = create_engine('sqlite:///itemscatalog.db?check_same_thread=False')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()

code = ''


# // TODO FIX THE EDITING AND DELETING LINKS SHOWS WHILE NOT LOGGED IN

@app.context_processor
def context_processor():
    global code
    return dict(code=code)


def is_logged_in():
    return 'userId' in login_session


def allow_editing():
    if is_logged_in():
        login_session['show_editing_links'] = 'Visible'
    else:
        login_session['show_editing_links'] = 'Hidden'
    return login_session['show_editing_links']


@app.route('/revalidate', methods=['POST'])
def revalidate():
    if request.method == "POST":
        if not request.headers.get('X-Requested-With'):
            abort(403)
        if not request.data == "b''" or not request.data == '':
            login_session['userId'] = request.data.decode('ascii')
            print(login_session['userId'])
            print('userId' in login_session)
        else:
            return redirect_403(login_session['userId'])
    return 'ok'


def redirect_403(user_id):
    print("user id is : " + user_id)
    if is_logged_in():
        print("owner id is : " + login_session['userId'])
    flash("You don't have the permission to do that"
          ",please make sure you are logged in using "
          "the correct user account!")
    return showCategories()


@app.route('/login', methods=['GET', 'POST'])
def showLogin():
    global code
    picture_url = "/static/img/notlogged.png"
    print("requested login")
    print(request.method)
    if request.method == "POST":
        print("Called login post request method")
        # If this request does not have `X-Requested-With`
        # header, this could be a CSRF
        if not request.headers.get('X-Requested-With'):
            abort(403)
        if request.headers.get('logged-out') == 'true':
            print("a log out request")
            code = ''
            login_session.pop('userId')
            return showCategories()
        print(request.data)
        auth_code = request.data
        # Exchange auth code for access token,
        # refresh token, and ID token
        credentials = \
            client.credentials_from_clientsecrets_and_code(
                CLIENT_SECRET_FILE,
                ['https://www.googleapis.com/auth/drive.appdata',
                 'profile', 'email'],
                auth_code)
        # Call Google API
        print(credentials.id_token)
        # Get profile info from ID token
        userid = credentials.id_token['sub']
        email = credentials.id_token['email']
        picture = credentials.id_token['picture']
        picture_url = picture
        name = credentials.id_token['given_name']
        # check if user already exists
        if session.query(User.id).filter_by(id=userid) \
                .scalar() is None:
            new_user = \
                User(id=userid, name=name,
                     email=email, picture=picture)
            session.add(new_user)
            session.commit()
        login_session['userId'] = userid
        print("Login session user id is : " +
              login_session['userId'])
    state = ''.join(random.choice(
        string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    return render_template('main.html', STATE=state, picture_url=picture_url)


# API/////////////
@app.route('/api/')
@app.route('/api/catalog')
def api_showCategories():
    try:
        categories = session.query(Category).all()
        return json.dumps([row.serialize for row in categories])
    except NoResultFound:
        return json.dumps("There are no results to be shown buddy!")


@app.route('/api/catalog/<string:category_name>/<string:item_name>')
def api_showItem(category_name, item_name):
    try:
        current_category = session.query(Category) \
            .filter_by(name=category_name).one()
        selected_item = session.query(CatalogItem) \
            .filter_by(category_id=current_category.id,
                       name=item_name).all()
        return json.dumps([row.serialize for row in selected_item])
    except NoResultFound:
        return json.dumps("There are no results to be shown buddy!")


@app.route('/api/catalog/<string:category_name>/items')
def api_showItemsPerCategory(category_name):
    try:
        current_category = session.query(Category) \
            .filter_by(name=category_name).one()
        if session.query(func.count(CatalogItem.name)) \
                .filter_by(category_id=current_category.id).scalar() > 0:
            category_items = session.query(CatalogItem) \
                .filter_by(category_id=current_category.id).all()
            return json.dumps([row.serialize for row in category_items])
    except NoResultFound:
        return json.dumps("There are no results to be shown buddy!")


# ///////////////////////////////////////////////////////////
# MAIN APP
@app.route('/')
@app.route('/catalog')
def showCategories():
    categories = session.query(Category).all()
    latest_items = session.query(CatalogItem) \
        .order_by(CatalogItem.created.desc()).limit(10).all()
    return render_template('showCategories.html',
                           show_editing_links=allow_editing(),
                           categories=categories,
                           latest_items=latest_items)


@app.route('/catalog/<string:category_name>/<string:item_name>')
def showItem(category_name, item_name):
    current_category = session.query(Category) \
        .filter_by(name=category_name).one()
    selected_item = session.query(CatalogItem) \
        .filter_by(category_id=current_category.id, name=item_name).one()
    return render_template('showOneItem.html',
                           selected_item=selected_item,
                           show_editing_links=allow_editing())


@app.route('/catalog/<string:category_name>/items')
def showItemsPerCategory(category_name):
    category_items = ''
    categories = session.query(Category).all()
    current_category = session.query(Category) \
        .filter_by(name=category_name).one()
    # checks if the count of items having the requested item name
    # are more than 0 to show the items or just show
    # an empty category message
    if session.query(func.count(CatalogItem.name)) \
            .filter_by(category_id=current_category.id).scalar() > 0:
        category_items = session.query(CatalogItem) \
            .filter_by(category_id=current_category.id).all()
        return render_template('showOneCategory.html',
                               current_category=current_category,
                               category_items=category_items,
                               categories=categories,
                               show_editing_links=allow_editing())
    return render_template('showOneCategory.html',
                           current_category=current_category,
                           category_items=category_items,
                           categories=categories,
                           show_editing_links=allow_editing())


@app.route('/catalog/<string:category_name>/edit',
           methods=['GET', 'POST'])
def editCategory(category_name):
    # i have tried to use a custome decorator @require_login
    # but some errors appeared to me that i should
    # provide positional arguments such as
    # the category_name in this method
    if is_logged_in():
        current_category = session.query(Category) \
            .filter_by(name=category_name).one()
        # checks if the method was request via a post request
        if request.method == 'POST':
            if current_category.user_id == login_session['userId']:
                print(request.form)
                new_category_name = request.form['name']
                current_category.name = new_category_name
                session.add(current_category)
                session.commit()
            else:
                return redirect_403(login_session['userId'])
        return render_template('editCategory.html',
                               current_category=current_category)
    else:
        flash("You aren't logged in")
        return showCategories()


@app.route('/catalog/addCategory', methods=['GET', 'POST'])
def addCategory():
    if is_logged_in():
        if request.method == 'GET':
            return render_template('addCategory.html')
        if request.method == 'POST' \
                and request.form['categoryName'] != '':
            new_category = Category(
                name=request.form['categoryName'],
                user_id=login_session['userId']
            )
            # checks if the category name doesn't exist
            if session.query(func.count(Category.name)) \
                    .filter(Category.name == new_category.name) \
                    .scalar() > 0:
                flash("there is already a category with the name : " +
                      request.form['categoryName'])
                return showCategories()
            session.add(new_category)
            session.commit()
            flash("Category :" + request.form['categoryName'] +
                  " has been added successfuly")
            return showCategories()
    else:
        flash("You aren't logged in")
        return showCategories()


@app.route('/catalog/<string:category_name>/delete', methods=['GET'])
def deleteCategory(category_name):
    if is_logged_in():
        print("Deleting the category with user id : " +
              str(login_session['userId']) +
              " And with name : " + category_name)
        selected_cat = session.query(Category) \
            .filter(Category.name == category_name).filter(
            Category.user_id == str(login_session['userId'])).one()
        # creating a delete query because i didn't know how
        # to do it using the session.query(table)
        # to delete the category requeste and all
        # the item in that category,which
        # can only be done through the category owner
        delete_q = CatalogItem.__table__.delete() \
            .where(CatalogItem.category_id == selected_cat.id)
        session.execute(delete_q)
        session.commit()
        session.delete(selected_cat)
        session.commit()
        flash("Category " + category_name +
              " have been deleted successfully")
        return showCategories()
    else:
        flash("You aren't logged in")
        return showCategories()


@app.route(
    '/catalog/<string:category_name>/<string:item_name>/edit',
    methods=['GET'])
def editItem(category_name, item_name):
    if is_logged_in():
        current_category = session.query(Category) \
            .filter_by(name=category_name).one()
        selected_item = \
            session.query(CatalogItem) \
                .filter_by(category_id=current_category.id,
                           name=item_name).one()
        if selected_item.user_id == login_session['userId']:
            return render_template('editItem.html',
                                   current_item=selected_item)
        else:
            return redirect_403(login_session['userId'])
    else:
        flash("You aren't logged in")
        return showCategories()


@app.route(
    '/catalog/<string:category_name>/<string:item_name>/<string:action_type>',
    methods=['POST'])
def editAndDeleteItem(category_name, item_name, action_type):
    if is_logged_in():
        try:
            # trying to parse the id as int , if failed
            # then the result should be wrong
            # that is relevant to the google
            # authentication,didn't test on other
            # third party methods to auth
            print(login_session['userId'])
            print(int(login_session['userId']))
            int(login_session['userId'])
        except ValueError:
            return redirect_403(login_session['userId'])
        # the code carries on after the last check passes
        # and edits/deletes the item only if it belongs to the
        # person requesting to edit or delete.
        current_category = session.query(Category) \
            .filter_by(name=category_name).one()
        selected_item = \
            session.query(CatalogItem) \
            .filter_by(category_id=current_category.id,
                       name=item_name).one()
        print(login_session['userId'])
        print("owner user id is : " + str(login_session['userId']))
        if login_session['userId'] == selected_item.user_id:
            if action_type == 'edit' and '' \
                    != request.form['itemName'] \
                    and request.method == 'POST':
                print("Editing the item with user id : " +
                      str(login_session['userId']) +
                      " And with name : " + item_name)
                selected_item.name = request.form['itemName']
                selected_item.description = \
                    request.form['itemDescription']
                session.add(selected_item)
                session.commit()
                flash("Item " + selected_item.name +
                      " have been edited successfully")
                return showCategories()
            elif action_type == 'delete' and request.method == 'POST':
                incoming_data = request.data
                json_data = incoming_data.decode('ascii')
                my_item = json.loads(json_data)
                print(my_item)
                print("Deleting the item with user id : " +
                      str(login_session['userId']) +
                      " And with name : " + my_item['name'] +
                      " and category Id :" +
                      my_item['id'])
                selected_item = session.query(CatalogItem) \
                    .filter(CatalogItem.category_id == my_item['id']) \
                    .filter(CatalogItem.name == my_item['name']).one()
                session.delete(selected_item)
                session.commit()
                flash("Item " + my_item['name'] +
                      " have been deleted successfully")
                return 'success'
        else:
            redirect_403(login_session.get('userId'))
    flash("Please make sure you are logged in")
    return showCategories()


@app.route('/catalog/addItem', methods=['GET', 'POST'])
def addItem():
    if is_logged_in():
        categories_names = session.query(Category).all()
        # if the method is GET just show the adding item
        # form.
        if request.method == 'GET':
            return render_template("addItem.html",
                                   categories_names=categories_names)
        # if the method is POST the code will process
        # the sent data and act accordingly
        if request.method == 'POST':
            if request.form['itemName'] == '' \
                    or request.form['category_selection'] == '':
                flash("Couldn't add the "
                      "item because you didn't fill the fields")
                return showCategories()
            item_name = request.form['itemName']
            category_id = request.form['category_selection']
            item_description = request.form['itemDescription']
            new_item = CatalogItem(name=item_name,
                                   category_id=category_id,
                                   user_id=str(login_session['userId']),
                                   description=item_description)
            print("After adding : ")
            print(login_session['userId'])
            session.add(new_item)
            session.commit()
            flash("Item added successfully")
            return showCategories()
    else:
        flash("You aren't logged in")
        return showCategories()


if __name__ == '__main__':
    app.secret_key = '$#*$89a89sdassdaj(*#$&(!)JKASL'
    app.debug = True
    app.run(host='127.0.0.1', port=5000)
