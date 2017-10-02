Ionic App Template


This repository is the most awesome thing in the world!! It'll blow your guts off!

Using this template, you can create an app which is:
1. Ionic & web designed (web app built using Ionic).
2. Includes basic Satellizer behaviour using mongodb - Google, Facebook & independent (email + password) authentication.
3. Has an Ionic side menu with example pages (views & controllers).

Follow the instructions to create your next app using this awesome template.

External preparaions:
1. Create a mongodb database (using mlab etc.).
2. Go to "https://github.com/sahat/satellizer" and follow "Obtaining OAuth Keys" instructions for Google & Facebook.
3. Create AWS account, install eb cli, create a key-pair & create new ElasticBeanstalk app & environment (env creation starts EC2 runtime consumption).
4. Install git & git cli on your machine.
5. Clone / download the repository to your workspace.
6. Create a source repo to your EB app using "eb init" -> choose your EB app, follow instructions.

Mandatory code configs:
1. Get mongodb database URI and overwrite value of "MONGO_URI" in /config.js after "process.env.MONGO_URI || ".
2. Get EB app URL from AWS console and:
	a. Add to "Authorized Javascript origins" & "Authorized redirect URIs" in google project (see 2 in External preparations).
	b. Add to "Valid OAuth redirect URIs" in facebook project (add '/' at the end, see 2 in External preparations).
	c. Overwrite the value of "BACKEND_URL" in /ionicApp/www/js/consts.js (add '/' at the end).
3. Get google client secret and overwrite value of "GOOGLE_SECRET" in /config.js after "process.env.GOOGLE_SECRET || ".
4. Get facebook app secret and overwrite value of "FACEBOOK_SECRET" in /config.js after "process.env.FACEBOOK_SECRET || ".
5. Get google OAuth client ID and overwrite the value of "GOOGLE_CLIENT_ID" in /ionicApp/www/js/consts.js.
6. Get facebook App ID and overwrite the value of "FACEBOOK_CLIENT_ID" in /ionicApp/www/js/consts.js.

Mandatory command-line shit:
1. npm install (to install all server npm dependencies)
2. cd ionicApp (to enter ionic app folder from root path)
3. npm install -g cordova ionic (to install cordova cli & ionic cli globally on your machine)
4. npm install (to install all npm dependencies in ionic app)
5. ionic state restore (to install cordova plugins and add android platform in ionic app)

Deploying to AWS EB:
1. git init (to initialize local git repository used by eb cli to deploy the code)
2. git add . (to stage all files except those in .gitignore)
3. git commit -m "first commit" (to commit all staged files to repository)
4. eb deploy (to deploy all commited files in git repository to AWS EB app as a new version)

Testing:
1. npm start (to test the web app on localhost)
2. cd ionicApp, ionic run android (to test android app on emulator using the AWS EB app as backend)
3. eb open (to test the web app served from the AWS EB app)