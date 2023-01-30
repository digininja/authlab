# Authentication Lab

Welcome to the Authentication Lab. The lab is a selection of challenges all related to authentication or authorisation. They are all taken, in some way, from real world examples I've come across during tests or have been suggested by other testers.

You can play the latest version of all the challenges in my <a href="https://authlab.digi.ninja">online version</a> or grab the code from here build your own lab. The lab is written in Golang and should be fairly easy to install and get running.

For more information, see my <a href="https://digi.ninja/projects/authlab.php">project page</a>. This also contains more information and walkthroughs for all the labs in case you get stuck.

## Installation

First you will need Go setup on your machine, I'll leave that up to you to work through as there are plenty of resources out there to help with that.

Next choose where to install the app, I'm going to install it in ~/apps, but the location is up to you and as long as you remember it, it doesn't matter.

Check out my code:

```
cd ~/apps/
git clone https://github.com/digininja/authlab.git
```

Install [Revel](https://github.com/revel/revel):

```
go install github.com/revel/cmd/revel@latest
```

## Starting the lab

You can start the lab with the following command:

```
cd ~/apps/authlab
~/go/bin/revel run -a .
```

When I start it, I get a few errors and warnings. They don't seem to affect anything so I'll look into them at some point, but for now, I'm ignoring them as it all seems to be working.

You should now be able to access the lab by browsing to <http://localhost:9000>

To start in production mode:

```
cd ~/go/src/github.com/digininja/authlab
~/go/bin/revel run -a . -m prod
```

## Logrotate

Set this up to do log rotation on prod otherwise the files will get huge:

```
/xxxx/apps/authlab/log/*.json {
	daily
	rotate 7
	missingok
	compress
	delaycompress
	missingok
	postrotate
		service authlab restart
	endscript
}
```

Can test with:

```
logrotate -d /etc/logrotate.d/authlab
```

And force with:

```
logrotate --force /etc/logrotate.d/authlab 
```

## Service scripts

This controls the app through `systemctl`, put the file in `/etc/systemd/system/authlab.service`.

Replace xxxx with your user if running this from ~/apps. If running it from somewhere else, change the paths appropriately.

```
[Unit]
Description=Authlab Service
After=network.target

[Service]
Type=simple
User=authlab
Environment=PATH=/opt/go/bin:/xxxx/go/bin/:/opt/go/bin:/usr/local/bin:/usr/bin:/bin
Environment=GOPATH=/xxxx/go/
Environment=GOROOT=/opt/go/
WorkingDirectory=/xxxx/apps/authlab
ExecStart=/xxxx/go/bin/revel run --application-path=/home/xxxx/apps/authlab --run-mode=prod
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
```

When changing it, make sure you run `systemctl daemon-reload`.
