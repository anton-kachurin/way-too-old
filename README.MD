# Way-too-old Blog

A multi-user blog hosted on Google Cloud. Features a custom micro-framework built
on top of `Webapp2` and a `Datastore` access abstraction layer. Uses `Jinja2`
as a template engine.

In this blog users can share examples of how things changed in the
programming world over the past years. They can post two snippets
of code demonstrating these changes and discuss it in the comments
with other people. And of course, like their favorites!

Demo is available [here](https://way-too-old.appspot.com/).

### Setup

- Install [Python](https://www.python.org/downloads/)
- Install [Google Cloud SDK](https://cloud.google.com/sdk/docs/).
- Create a new project in [Google’s Developer Console](https://console.cloud.google.com/) using a unique name.
- Use `dev_appserver.py /path/to/project` to run a copy of the app on your own computer, and access it at http://localhost:8080/.
- Deploy this project with `gcloud app deploy`.

##### When running locally

Change this:

    app = micro_framework.WSGIApplication(debug=False)

To this:

    app = micro_framework.WSGIApplication(debug=True)

### License

Anton Kachurin, 2017, [Apache License v2.0](http://www.apache.org/licenses/LICENSE-2.0)

Built with [Bootstra.386](http://kristopolous.github.io/BOOTSTRA.386/index.html) (under[ Apache License v2.0](http://www.apache.org/licenses/LICENSE-2.0))
