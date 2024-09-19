from flask import Blueprint, render_template, request, flash, redirect, url_for, jsonify
from .models import User
from werkzeug.security import generate_password_hash, check_password_hash
from . import db
from flask_login import login_user, login_required, logout_user, current_user
import requests
from bs4 import BeautifulSoup
from datetime import datetime
import pytz

nba_teams_time_zones = {
    "Atlanta": "US/Eastern",
    "Boston": "US/Eastern",
    "Brooklyn": "US/Eastern",
    "Charlotte": "US/Eastern",
    "Chicago": "US/Central",
    "Cleveland": "US/Eastern",
    "Dallas": "US/Central",
    "Denver": "US/Mountain",
    "Detroit": "US/Eastern",
    "Golden State": "US/Pacific",
    "Houston": "US/Central",
    "LA": "US/Pacific",
    "Indiana": "US/Eastern",
    "Los Angeles": "US/Pacific",
    "Memphis": "US/Central",
    "Miami": "US/Eastern",
    "Milwaukee": "US/Central",
    "Minnesota": "US/Central",
    "New Orleans": "US/Central",
    "New York": "US/Eastern",
    "Oklahoma City": "US/Central",
    "Orlando": "US/Eastern",
    "Philadelphia": "US/Eastern",
    "Phoenix": "US/Mountain",
    "Portland": "US/Pacific",
    "Sacramento": "US/Pacific",
    "San Antonio": "US/Central",
    "Toronto": "Canada/Eastern",
    "Utah": "US/Mountain",
    "Washington": "US/Eastern"
}


auth = Blueprint('auth', __name__)

@auth.route('/games_schedule')
@login_required
def bets():
    return render_template("games_schedule.html", user=current_user)

@auth.route('/games_schedule/data')
@login_required
def get_data():
  url = 'https://www.espn.com/nba/schedule'
  heads = {
      "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36"
  }
  games = []
  response = requests.get(url, headers=heads)
  if response.status_code == 200:
    soup = BeautifulSoup(response.text, 'html.parser')
    team1_divs = soup.find_all('span', class_="Table__Team away")
    team2_divs = soup.find_all('td', class_="colspan__col Table__TD")
    gameTime_divs = soup.find_all('td', class_="date__col Table__TD")
    for i in range(0,len(team1_divs)):
       games.append((team1_divs[i].get_text(),team2_divs[i].get_text(), gameTime_divs[i].get_text()))

  # Print or save the extracted data
    for team1, team2, time in games:
       print(f"{team1} vs {team2} at {time}")
    return jsonify({'games' : games})
  else:
    print("Failed to retrieve the webpage. Status code:", response.status_code) 
    return jsonify({'games' : games})

@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        user = User.query.filter_by(email=email).first()
        if user:
            if  check_password_hash(user.password, password):
                flash('Logged in successfully!', category='success')
                login_user(user, remember=True)
                return redirect(url_for('views.home'))
            else:
                flash('Incorrect password, try again.', category='error')
        else:
            flash('User does not exist.', category='error')

    return render_template("login.html", user=current_user)


@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))


@auth.route('/sign-up', methods=['GET','POST'])
def sign_up():
    if request.method == 'POST':
        email = request.form.get('email')
        first_name = request.form.get('firstName')
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')

        user = User.query.filter_by(email=email).first()

        if user:
            flash('Email already exists.', category='error')
        elif len(email) < 4:
            flash('Email must be greater than 3 characters.', category='error')
        elif len(first_name) < 2:
            flash('First name must be greater than 1 characters.', category='error')
        elif password1 != password2:
            flash('Passwords don\'t match.', category='error')
        elif len(password1) < 7:
            flash('Password must be greater than 6 characters.', category='error')
        else:
            new_user = User(email=email, first_name=first_name, password=generate_password_hash(
                password1, method='pbkdf2:sha256'))
            db.session.add(new_user)
            db.session.commit()
            login_user(user, remember=True)
            flash('Account created!', category='success')
            return redirect(url_for('views.home'))

    return render_template("sign_up.html", user=current_user)

