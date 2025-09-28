#!/usr/bin/env python3

from flask import request, session
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError

from config import app, db, api
from models import User, Recipe, bcrypt


# ---------------------------
# SIGNUP
# ---------------------------
class Signup(Resource):
    def post(self):
        data = request.get_json()
        try:
            user = User(
                username=data.get("username"),
                bio=data.get("bio"),
                image_url=data.get("image_url")
            )
            user.password_hash = data.get("password")
            db.session.add(user)
            db.session.commit()

            session['user_id'] = user.id

            return {
                "id": user.id,
                "username": user.username,
                "image_url": user.image_url,
                "bio": user.bio
            }, 201
        except (ValueError, IntegrityError) as e:
            db.session.rollback()
            return {"errors": [str(e)]}, 422


# ---------------------------
# CHECK SESSION (AUTO-LOGIN)
# ---------------------------
class CheckSession(Resource):
    def get(self):
        user_id = session.get("user_id")
        if not user_id:
            return {"errors": ["Not authorized"]}, 401

        user = db.session.get(User, user_id)
        if not user:
            return {"errors": ["User not found"]}, 401

        return {
            "id": user.id,
            "username": user.username,
            "image_url": user.image_url,
            "bio": user.bio
        }, 200


# ---------------------------
# LOGIN
# ---------------------------
class Login(Resource):
    def post(self):
        data = request.get_json()
        username = data.get("username")
        password = data.get("password")

        user = User.query.filter_by(username=username).first()
        if not user or not user.authenticate(password):
            return {"errors": ["Invalid username or password"]}, 401

        session['user_id'] = user.id

        return {
            "id": user.id,
            "username": user.username,
            "image_url": user.image_url,
            "bio": user.bio
        }, 200


# ---------------------------
# LOGOUT
# ---------------------------
class Logout(Resource):
    def delete(self):
        if 'user_id' not in session or session['user_id'] is None:
            return {"errors": ["Not logged in"]}, 401

        session.pop('user_id')
        return {}, 204


# ---------------------------
# RECIPE INDEX (GET & POST)
# ---------------------------
class RecipeIndex(Resource):
    def get(self):
        user_id = session.get("user_id")
        if not user_id:
            return {"errors": ["Not logged in"]}, 401

        recipes = Recipe.query.all()
        return [
            {
                "id": r.id,
                "title": r.title,
                "instructions": r.instructions,
                "minutes_to_complete": r.minutes_to_complete,
                "user": {
                    "id": r.user.id,
                    "username": r.user.username,
                    "image_url": r.user.image_url,
                    "bio": r.user.bio
                }
            } for r in recipes
        ], 200

    def post(self):
        user_id = session.get("user_id")
        if not user_id:
            return {"errors": ["Not logged in"]}, 401

        data = request.get_json()
        try:
            recipe = Recipe(
                title=data.get("title"),
                instructions=data.get("instructions"),
                minutes_to_complete=data.get("minutes_to_complete"),
                user_id=user_id
            )
            db.session.add(recipe)
            db.session.commit()

            return {
                "id": recipe.id,
                "title": recipe.title,
                "instructions": recipe.instructions,
                "minutes_to_complete": recipe.minutes_to_complete,
                "user": {
                    "id": recipe.user.id,
                    "username": recipe.user.username,
                    "image_url": recipe.user.image_url,
                    "bio": recipe.user.bio
                }
            }, 201

        except (ValueError, IntegrityError) as e:
            db.session.rollback()
            return {"errors": [str(e)]}, 422


# ---------------------------
# REGISTER RESOURCES
# ---------------------------
api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(RecipeIndex, '/recipes', endpoint='recipes')


if __name__ == '__main__':
    app.run(port=5555, debug=True)
