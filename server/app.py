#!/usr/bin/env python3

from flask import request, session, make_response, jsonify
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError

from config import app, db, api
from models import User, Recipe


class Signup(Resource):
    def post(self):
        data = request.get_json()
        try:
            new_user = User(
                username=data.get('username'),
                image_url=data.get('image_url'),
                bio=data.get('bio'),
            )
            new_user.password_hash = data.get('password')

            db.session.add(new_user)
            db.session.commit()

            session['user_id'] = new_user.id
            return make_response(new_user.to_dict(), 201)
        
        except AssertionError as e:
            return make_response({'message': str(e)}, 422)
        
api.add_resource(Signup, '/signup', endpoint='signup')


class CheckSession(Resource):
    def get(self):
        user_id = session.get('user_id')
        if user_id:
            cur_user = User.query.filter_by(id=user_id).first()
            if cur_user:
                return make_response(cur_user.to_dict(), 200)
            else:
                return make_response({'error': 'User not found'}, 404)
        return make_response({'error': 'Unauthorized'}, 401)

api.add_resource(CheckSession, '/check_session', endpoint='check_session')


class Login(Resource):
    def post(self):
        data = request.get_json()

        user = User.query.filter_by(username=data.get('username')).first()
        if not user:
            return make_response({'message': 'No username found'}, 401)
        if user.authenticate(data.get('password')):
            session['user_id'] = user.id
            return make_response(user.to_dict(), 200)
        else:
            return make_response({"message": 'incorrect password'}, 401)

api.add_resource(Login, '/login', endpoint='login')


class Logout(Resource):
    def delete(self):
        logout = session.pop('user_id', None)
        if logout:
            return make_response({'message': "User is logged out"}, 200)
        else:
            return make_response({'error': 'not logged in'}, 401)

api.add_resource(Logout, '/logout', endpoint='logout')


class RecipeIndex(Resource):
    def get(self):
        user_id = session.get('user_id')
        if not user_id:
            return make_response({'error': 'unauthorized'}, 401)

        user = db.session.get(User, user_id)
        if not user:
            return make_response({'error': 'User not found'}, 404)

        recipes = Recipe.query.filter_by(user_id=user_id).all()
        return make_response(jsonify([recipe.to_dict() for recipe in recipes]), 200)

    def post(self):
        user_id = session.get('user_id')
        if not user_id:
            return make_response({'error': 'unauthorized'}, 401)

        data = request.get_json()
        try:
            new_recipe = Recipe(
                title=data['title'],
                instructions=data['instructions'],
                minutes_to_complete=data.get('minutes_to_complete'),
                user_id=user_id
            )
            db.session.add(new_recipe)
            db.session.commit()
            return make_response(new_recipe.to_dict(), 201)
        except KeyError as e:
            return make_response({'error': f'missing required field: {str(e)}'}, 400)
        except ValueError as e:
            return make_response({'error': str(e)}, 422)
        except IntegrityError:
            db.session.rollback()
            return make_response({'error': 'failed to create recipe'}, 422)
        except Exception as e:
            db.session.rollback()
            return make_response({'error': 'an unexpected error occurred'}, 500)


api.add_resource(RecipeIndex, '/recipes', endpoint='recipes')


if __name__ == '__main__':
    app.run(port=5555, debug=True)