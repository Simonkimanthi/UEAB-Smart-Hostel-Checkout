# Staff access management

Administrators manage staff access from **Administration Dashboard → Staff
Permissions & Hostel Access**. Select the permissions for each Dean or Security
account and save. Deans also need one or more hostel assignments; a Dean with no
assigned hostels sees no checkout requests. Security accounts are not scoped to
Dean hostel assignments.

New staff accounts receive no action permissions or Dean hostel assignments by
default. Grant `requests.view` before a Dean can open the request dashboard,
then grant key management, approval, or pass viewing as needed. Security needs
`passes.view`, `passes.verify`, and `departures.record` for the corresponding
parts of its existing workflow. Access changes are audited and take effect on
the next request. Administrators always have full access.

After deploying the updated application, sign in as an administrator and
configure the existing staff accounts in this section. Database initialization
creates the staff permission and hostel assignment tables without deleting
existing records.