# Freemind - API
This is the Api server of the Freemind project.

## TODOs
- Clean up expired sessions

## Endpoints
### Existing
`/v1/xml/fetch` To fetch the whole XML document.
`/v1/xml/update` To update the whole XML document.

### Planned
`/v1/act/delete_old` To delete nodes which are past due
`/v1/act/delete_past/TIMESTAMP` To delete nodes which due is passed on TIMESTAMP
`/v1/act/get_next_due` To get the next due node
`/v1/act/get_next_priority` To get the next node with the highest priority.
`/v1/act/get_today` To get only nodes wich are due or on today.
`/v1/act/get_tomoroorw` To get only nodes which are due or on tomorrow.
`/v1/act/filter/NAME/VALUE` To only get nodes which have subnodes called NAME whose value equals VALUE (not case sensitive)

`/v1/json/fetch` To fetch the whole XML document but returned as JSON.
`/v1/json/sort_by/due` To get the nodes as json sorted by due
`/v1/json/sort_by/priority` To get the nodes as json sorted by priority