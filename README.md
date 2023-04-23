# Freemind - API
This is the Api server of the Freemind project.

## TODOs
- Add more endpoints
- Test the new endpoints
- Use user ID's instead of names as the primary key for stuff
    - Not much needed really:
    - The two Validate functions of the sql mod need to return the id instead of the name
    - The database need to have the id column added (at least in the user table)

## LIMITATIONS
### Elements
Each Element (each entry and directory node) must have an unique ID which is
(as of now) saved and handled as an unsigned 16 bit integer. Meaning you can
have 'only' about 65535 entries. The ID `0` **SHOULD NOT** be used Although
the more you approach this number the longer generation of new entries might
take. As of now I don't think that anyone needs more than 1000 entries
registred at once.

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
- `/xml/filter/NAME/VALUE` To only get nodes which have subnodes called NAME whose value equals VALUE (not case sensitive)
- `/xml/get_by_id/{id}` To fetch a partial XML document specifed by it's id
- `/xml/fetch` To fetch the whole XML document.
- `/xml/update` To update the whole XML document.
- `/xml/validate` To validate a XML document but not actually perform any changes.
- `/xml/due/over` To get only nodes wich were due in the past.
- `/xml/due/today` To get only nodes wich are due or on today.
- `/xml/due/tomorrow` To get only nodes which are due or on tomorrow.
- `/xml/due/in/{start}/{end}` To get only nodes which due date is in between start and end

### Planned
- `/act/delete_past` To delete nodes which are expired
- `/act/delete_past/TIMESTAMP` To delete nodes which are expired after TIMESTAMP
- `/xml/get_next_due` To get the next due node
- `/xml/get_next_priority` To get the next node with the highest priority.
- `/json/fetch` To fetch the whole XML document but returned as JSON.
- `/json/sort_by/due` To get the nodes as json sorted by due
- `/json/sort_by/priority` To get the nodes as json sorted by priority