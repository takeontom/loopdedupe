# Loop de Dupe

Are you a keen photographer who's just screwed up your 8 year archive of digital photos
so badly it made you decide to spend a sunny afternoon writing some Python to de-fuck it
for you?

Loop de Dupe is a command line tool to find files which are exact duplicates of
eachother in all supplied paths. It's smart enough to remember files it's previously
seen to speed up repeated runs.


## Usage

```ssh
$ loopdedupe.py /some/path /another/path
```

This will:

* create a `loopdedupe.db` database in the current working directory
* Recursively scan all the files in the `/some/path` and `/another/path` directories
* Store each file's hash in the database
* Provide a simple report of duplicates in the directories
