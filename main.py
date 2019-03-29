
#  !/usr/bin/env python

from flask import Flask, render_template, request
from flask import redirect, jsonify, url_for, flash
from sqlalchemy import create_engine, asc
from sqlalchemy.orm import sessionmaker
from models import Base, Category, Product, User
from flask import session as login_session
import random
import string
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests
import os
import pdb

app = Flask(__name__)

CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']

engine = create_engine('sqlite:///database.db?check_same_thread=False')
Base.metadata.create_all(engine)
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


@app.context_processor
# actively update CSS
def override_url_for():
    return dict(url_for=dated_url_for)


def dated_url_for(endpoint, **values):
    if endpoint == 'static':
        filename = values.get('filename', None)
        if filename:
            file_path = os.path.join(app.root_path,
                                     endpoint, filename)
            values['q'] = int(os.stat(file_path).st_mtime)
    return url_for(endpoint, **values)


@app.route('/')
@app.route('/login')
def showLogin():
    # show initial login screen unless user is still logged in
    if 'username' in login_session:
        return redirect('/home')
    randomString = ''.join(
        random.choice(
            string.ascii_uppercase + string.digits)for x in xrange(32))
    login_session['state'] = randomString
    return render_template('login.html', antiForgery=randomString)


@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Make oAuth flow
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    code = request.data
    try:
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(json.dumps('Failed to upgrade the \
        authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Get access token
    access_token = credentials.access_token
    url = (
    'https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
    % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Catch wrong user ID
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(json.dumps("Token's user ID doesn't match\
        given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Catch wrong client ID
    if result['issued_to'] != CLIENT_ID:
        response = make_response(json.dumps("Token's client ID does not\
        match app's."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # See if user is already connected
    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps('Current user is already\
        connected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Make user session information and record
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']

    user = session.query(User).filter_by(
     username=login_session['username']).all()
    if user == []:
        user = User(username=login_session['username'])
        session.add(user)
        session.commit()
        login_session['user'] = user.id
    else:
        login_session['user'] = user[-1].id

    output = ''
    output += '<h1>Logged in as '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 150px; height: 150px;border-radius:\
     150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    flash("Welcome %s" % login_session['username'])
    return output


@app.route('/gdisconnect')
def gdisconnect():
    # disconnect the user
    access_token = login_session['access_token']
    if access_token is None:
        response = make_response(json.dumps('Current user not \
        connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    url = 'https://accounts.google.com/o/oauth2/revoke?token='
    + login_session['access_token']
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    if result['status'] == '200':
        del login_session['access_token']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['picture']
        flash("Successfully Disconnected")
        return redirect(url_for('showLogin'))
    else:
        flash("Disconnect Failed")
        return redirect(url_for('home'))


@app.route('/home/')
def home():
    if 'username' not in login_session:
        return redirect('/login')
    username = login_session['username']
    image = login_session['picture']
    categoryList = session.query(Category).filter_by(
        user_id=login_session["user"]).order_by(asc(Category.title))
    return render_template(
        'index.html', categories=categoryList, image=image, user=username)


@app.route('/category/new/', methods=['GET', 'POST'])
def newCategory():
    if 'username' not in login_session:
        return redirect('/login')
    if request.method == 'POST':
        newCategory = Category(
            title=request.form['title'], user_id=login_session["user"])
        session.add(newCategory)
        flash('%s Has Been Created' % newCategory.title)
        session.commit()
        return redirect(url_for('home'))
    else:
        return render_template('newCategory.html')


@app.route('/category/<int:category_id>/edit/', methods=['GET', 'POST'])
def editCategory(category_id):
    if 'username' not in login_session:
        return redirect('/login')
    editedCategory = session.query(Category).filter_by(id=category_id).one()
    if editedCategory.user_id != login_session['user']:
        flash('You Are Not Authorized To Edit This Category')
        return redirect(url_for('home'))
    if request.method == 'POST':
        if request.form['title']:
            editedCategory.title = request.form['title']
            flash('Category Renamed To %s' % editedCategory.title)
            return redirect(url_for('home'))
    else:
        return render_template('editCategory.html', category=editedCategory)


@app.route('/category/<int:category_id>/delete/', methods=['GET', 'POST'])
def deleteCategory(category_id):
    if 'username' not in login_session:
        return redirect('/login')
    categoryToDelete = session.query(Category).filter_by(id=category_id).one()
    itemsToDelete = session.query(Product).filter_by(
        category_id=category_id).all()
    if categoryToDelete.user_id != login_session['user']:
        flash('You Are Not Authorized To Delete This Category')
        return redirect(url_for('home'))
    if request.method == 'POST':
        session.delete(categoryToDelete)
        for i in itemsToDelete:
            session.delete(i)
        flash('%s Deleted' % categoryToDelete.title)
        session.commit()
        return redirect(url_for('home', category_id=category_id))
    else:
        return render_template(
            'deleteCategory.html', category=categoryToDelete)


@app.route('/category/<int:category_id>/')
@app.route('/category/<int:category_id>/products/')
def showProducts(category_id):
    if 'username' not in login_session:
        return redirect('/login')
    user = login_session['username']
    image = login_session['picture']
    categoryList = session.query(Category).order_by(asc(Category.title))
    categoryActive = session.query(Category).filter_by(id=category_id).one()
    categoryProducts = session.query(Product).filter_by(
        category_id=category_id).all()
    total = 0.0
    for p in categoryProducts:
        total += round(float(p.price), 2)
    return render_template(
        'categoryExpanded.html', products=categoryProducts,
        category=categoryActive, categories=categoryList,
        totalAmount=total, user=user, image=image)


@app.route('/category/<int:category_id>/product/new/', methods=['GET', 'POST'])
def addProduct(category_id):
    if 'username' not in login_session:
        return redirect('/login')
    category = session.query(Category).filter_by(id=category_id).one()
    if request.method == 'POST':
        if request.form["title"] != "":
            newProduct = Product(
                title=request.form['title'],
                description=request.form['description'],
                price=request.form['price'], category_id=category_id)
            session.add(newProduct)
            session.commit()
            flash(' %s Added To %s ' % (newProduct.title, category.title))
        else:
            flash("Unable To Add Blank Product")
        return redirect(url_for('showProducts', category_id=category_id))
    else:
        return render_template('addProduct.html', category_id=category_id)


@app.route(
    '/category/<int:category_id>/product/<int:product_id>/edit',
    methods=['GET', 'POST'])
def editProduct(category_id, product_id):
    if 'username' not in login_session:
        return redirect('/login')
    editedProduct = session.query(Product).filter_by(id=product_id).one()
    category = session.query(Category).filter_by(id=category_id).one()
    if category.user_id != login_session['user']:
        flash('You Are Not Authorized To Edit Products In This Category')
        return redirect(url_for('home'))
    if request.method == 'POST':
        if request.form['title']:
            editedProduct.title = request.form['title']
        if request.form['description']:
            editedProduct.description = request.form['description']
        if request.form['price']:
            editedProduct.price = request.form['price']
        session.add(editedProduct)
        session.commit()
        flash('Changes Saved')
        return redirect(url_for('showProducts', category_id=category_id))
    else:
        return render_template(
            'editProduct.html', category_id=category_id,
            product_id=product_id, product=editedProduct)


@app.route('/category/<int:category_id>/product/<int:product_id>/details')
def productDetails(category_id, product_id):
    if 'username' not in login_session:
        return redirect('/login')
    product = session.query(Product).filter_by(id=product_id).one()
    return render_template(
        'productDetails.html', product=product,
        category_id=category_id)


@app.route(
    '/category/<int:category_id>/product/<int:product_id>/delete',
    methods=['GET', 'POST'])
def deleteProduct(category_id, product_id):
    if 'username' not in login_session:
        return redirect('/login')
    productToDelete = session.query(Product).filter_by(id=product_id).one()
    category = session.query(Category).filter_by(id=category_id).one()
    if category.user_id != login_session['user']:
        flash('You Are Not Authorized To Delete Products In This Category')
        return redirect(url_for('home'))
    if request.method == 'POST':
        session.delete(productToDelete)
        session.commit()
        flash('Product Deleted')
        return redirect(url_for('showProducts', category_id=category_id))
    else:
        return render_template(
            'deleteProduct.html', product=productToDelete,
            category_id=category_id)

# API endpoints.


@app.route('/api/category/<int:category_id>/products/')
def categoryProducts(category_id):
    products = session.query(Product).filter_by(category_id=category_id).all()
    if products == []:
        return "Category Does Not Exist Or Is Empty"
    else:
        return jsonify(details=[i.serialize for i in products])


@app.route('/api/user/<int:user_id>/categories/')
def userCategories(user_id):
    categories = session.query(Category).filter_by(user_id=user_id).all()
    if categories == []:
        return "User Has Not Created Any Categories"
    else:
        return jsonify(details=[i.serialize for i in categories])


@app.route('/api/users/')
def users():
    users = session.query(User).all()
    if users == []:
        return "No Users"
    else:
        return jsonify(details=[i.serialize for i in users])

app.secret_key = '65778bfhu'

if __name__ == '__main__':
    app.debug = False
    app.run(host='0.0.0.0', port=80)
