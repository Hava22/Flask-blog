##!/usr/bin/env bash


#Setup environment (recommended: create and activate a virtual environment)

python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

#Install dependencies

pip install flask flask_sqlalchemy flask_login flask_wtf markdown

#Initialize the database
#Run a Python shell inside your project folder:

python
>>> from app import db
>>> db.create_all()
>>> exit()

#This will create the blog.db SQLite file.

#Run the app

python app.py

#Open your browser at http://localhost:5000
