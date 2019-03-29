The iCatalog application is available at http://54.227.180.102.xip.io

You can ssh into the server using the provided key and the command

---------
ssh -i /pathto/grader_key -p 2200 grader@54.227.180.102
---------

Ssh port is 2200. The configuration process was as follows:

1. Updated ufw to deny incoming except for 2200/tcp, 80, and 123
2. Updated packages with sudo apt-get update
3. Installed the software listed below via apt-get or pip
4. Added and unzipped the catalog application files via scp from local machine
5. configured apache2 to display the app by creating /var/www/catalogApp/myApp.wsgi and /etc/apache2/sites-available/myApp.conf then disabling the default site
6. Debugged the app using the resources below
7. Added grader as a user with sudo access and generated an ssh key pair for them

The software and python packages installed during configuration were:
apache2
libapache2-mod-wsgi
pip
python
oauth2client
flask
sqlalchemy
sqlalchemy-utils
unzip
requests

Resources consulted
https://www.digitalocean.com/community/tutorials/how-to-set-up-a-firewall-with-ufw-on-ubuntu-14-04
https://idroot.us/tutorials/how-to-change-ssh-port-in-ubuntu/
https://umar-yusuf.blogspot.com/2018/02/deploying-python-flask-web-app-on.html
https://stackoverflow.com/questions/26080872/secret-key-not-set-in-flask-session-using-the-flask-session-extension
https://stackoverflow.com/questions/1518729/change-sqlite-database-mode-to-read-write
