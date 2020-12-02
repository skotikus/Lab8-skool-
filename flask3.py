#Scott Forsyth
#Week 8 Flask basic web page lab
#4/29/2020

#import Flask module and time module
from flask import Flask, render_template, redirect, url_for, request, session, flash
import flask_limiter
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from ip2geotools.databases.noncommercial import DbIpCity
import datetime
import os
import csv
import pandas as pd

#instance the flask application
app = Flask(__name__)
#add the limiter with default config for later
limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

#stating function that will send you to login or succesful login page depending on session state
@app.route("/", methods=['GET','POST'])
def home(error=None,message=None,userID=None,username=None,logs=None):
    ConIP = request.environ['REMOTE_ADDR']
    locationObject = DbIpCity.get(ConIP, api_key='free')
    if not session.get('logged_in'):
        return render_template('login.html', error=error, ConIP=locationObject, message=message)
    else:
        return render_template('loginSuccess.html',ConIP=locationObject, message=message,userID=userID,username=username,logs=logs)

@app.route("/login", methods=['POST'])
#limit the login attempts to 15 per 5 minutes, error displayed until end of 5 min
@limiter.limit('15 per  5 minutes')
def login():
    error = None
    message = None
    userID = None
    username = None
    
    #check for post and grab parameters
    if request.method == 'POST':
        nowDate = str(datetime.date.today())
        nowTime = (datetime.datetime.now()).strftime("%H:%M:%S")
        #open and read the authentication csv for checking the login creds
        csvFile = open('static/auth.csv','r')
        file_reader = csv.reader(csvFile)
    
        #cycle throught the auth list to check creds, sets validated state to true/false
        for row in file_reader:
            if row[1] == request.form['username'] and row[2] == request.form['password']:
                validated = True
                userID = row[0]
                username = row[1]
                break
            else:
                validated = False
        csvFile.close()
        
        #process login based on validation of credentials
        if not validated:
            message = 'Invalid Credentials. Please try again.'
            #log the date, time, and ip address of failed login to log.csv
            badIP = request.environ['REMOTE_ADDR']
            logFile = open('static/log.csv','a')
            logWriter = csv.writer(logFile)
            logWriter.writerow([nowDate,nowTime,badIP])
            logFile.close()
        else:
            #clear the log if credentials were good
            session['logged_in'] = True
            loganalyzer()
            logFile = open('static/log.csv','w')
            logWriter = csv.writer(logFile)
            logWriter.writerow(['date','time','ip'])
            logFile.close()
    #send user to home function with paramerters for display
    return home(error,message,userID,username)

#log analyzer checks at successful login, and takes all instances of the IP
#and does a time delta on them to tell the time difference and places the
#IP, date,time, and lat,long in the failures.log file for keeping and later reading
def loganalyzer():
    unfiltered = pd.read_csv('static/log.csv')
    count = len(unfiltered.index)
    
    if count >= 5:
        minTime = unfiltered.time.min()
        maxTime = unfiltered.time.max()
        logIP = unfiltered.ip.head(1).item()
        logDate = unfiltered.date.head(1).item()
        locationObject = DbIpCity.get(logIP, api_key='free')
        latitude = locationObject.latitude
        longitude = locationObject.longitude
        
        FMT = '%H:%M:%S'
        tdelta = datetime.datetime.strptime(maxTime, FMT) - datetime.datetime.strptime(minTime, FMT)
    
        #print(str(count) + " in less than five min")
        logText1 = logIP + " had " + str(count) + " failed login attempts in " + str(tdelta) + " minutes on " + logDate + "\n"
        logText2 = logIP + " has a lat/long of " + str(latitude) + "/" + str(longitude) + "\n"
        with open('static/failures.log','a') as logFile:
            logFile.write(logText1)
            logFile.write(logText2)
    return None

#simple return to home function with session state change
#logout POST function, changes 'logged_in' state and send back to homepage
@app.route('/logout', methods=['POST'])
def logout():
    session['logged_in'] = False
    message = "You have logged out"
    return home(None,message)

#take form data and checks against all password constraints, if successful, it
#changes the password for the logged in user to the form requested password
#change password POST function    
@app.route('/changePassword', methods=['POST'])
def changePassword():
    userID = request.form['userID']

    #checks the password to be changed against length of 8 and 64 as
    #well as the password list (capitalization not withstanding)
    proposedPass = request.form['newPass']
    if int(len(proposedPass)) < 8:
        message = "Invalid Change: less than 8 characters\n Please select a different password."
        return home(None,message,userID)
    if int(len(proposedPass)) > 64:
        message = "Invalid Change: more than 64 characters\n Please select a different password."
        return home(None,message,userID)
    passList = open('static/CommonPassword.txt','r').read().splitlines()
    if proposedPass in passList:
        message = "Invalid Change: Password is weak (found in common passwords list)\n Please select a different password."
    #if all statements pass then password csv is read, changed, and written back to file
    else:
        csvFile = open('static/auth.csv','r')
        file_reader = csv.reader(csvFile)
        tempFile = list(file_reader)
        csvFile.close()
        tempFile[int(userID)][2] = proposedPass
        csvFile = open('static/auth.csv','w')
        file_writer = csv.writer(csvFile)
        file_writer.writerows(tempFile)
        csvFile.close()
        #passes message that password was changed (no error handling)
        message = "Password Changed Successfully"
    return home(None,message,userID)

#in webpage log checker to display the results of the failed log
@app.route('/logChecker', methods=['POST'])
def logCheck():
    userID = request.form['userID']
    username = request.form['username']
    if os.stat('static/failures.log').st_size == 0:
        logs = "No login failures"
    else:
        with open('static/failures.log','r') as logFile:    
            logs = logFile.read()
    return home(None,None,userID,username,logs)


#set host ip and port for cloud9 env access
if __name__ == "__main__":
    app.secret_key = os.urandom(9)
    app.run(host='0.0.0.0',port=8080)
    
