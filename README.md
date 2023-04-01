# Freemind - API
This is the Api server of the Freemind project.

## TODOs
- Add more endpoints

## LIMITATIONS
### Elements
Each Element (each entry and directory node) must have an unique ID which is
(as of now) saved and handled as an unsigned 16 bit integer. Meaning you can
have 'only' about 65535 entries. Although the more you approach this number
the longer generation of new entries might take. As of now I don't think that
anyone needs more than 1000 entries registred at once.

## SETUP
### 1. Installation
Put the released binary or your custom compiled binary
in a (created folder) where you want it. Launch the
programm once to generate the config file in the local
directory. Customize the configuration according to your
needs (e.g. fill in the SQL DB login data)

### 2. Set up your SQL database
Assuming you already have a MySql Database (or similiar)
installed, create a new Database (the name is not important
but use the name in your config file). Afterwards generate
the important tables with the following two SQL commands:

`CREATE TABLE logins (username varchar(255) NOT NULL UNIQUE, password varchar(255) NOT NULL, token varchar(255));`

(This one is really important when you want to have an integrated frontend
you may not need this command but the server might fail if you don't have this
table in place. Additionally it may be used more in upcomming releases)
`CREATE TABLE sessions (username varchar(255) NOT NULL, session varchar(255) NOT NULL UNIQUE, expires varchar(255));`

### 3. Run
Start the binary. You can now insert new users into your database.
Please note: passwords and tokens are expected to be saved as a
bcrypt hash in the database

## Endpoints
### Existing
- `/v1/xml/fetch` To fetch the whole XML document.
- `/v1/xml/update` To update the whole XML document.
- `/v1/xml/validate` To validate a XML document but not actually perform any changes.

### Planned
- `/v1/act/delete_old` To delete nodes which are past due
- `/v1/act/delete_past/TIMESTAMP` To delete nodes which due is passed on TIMESTAMP
- `/v1/act/get_next_due` To get the next due node
- `/v1/act/get_next_priority` To get the next node with the highest priority.
- `/v1/act/get_today` To get only nodes wich are due or on today.
- `/v1/act/get_tomoroorw` To get only nodes which are due or on tomorrow.
- `/v1/act/filter/NAME/VALUE` To only get nodes which have subnodes called NAME whose value equals VALUE (not case sensitive)
- `/v1/json/fetch` To fetch the whole XML document but returned as JSON.
- `/v1/json/sort_by/due` To get the nodes as json sorted by due
- `/v1/json/sort_by/priority` To get the nodes as json sorted by priority