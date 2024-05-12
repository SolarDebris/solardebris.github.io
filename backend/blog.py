from glob import glob
from flask import Flask, jsonify
from flask_cors import CORS
import blog
import os
import jwt

app = Flask(__name__)

CORS(app, methods=["GET"], origins="*", send_wildcard=True)
secret_key = os.getenv("SECRET_KEY")
app.config['SECRET_KEY'] = secret_key


@app.route("/posts", methods=["GET"])
def posts():
    articles = get_posts()
    return articles

def jwt_encode(payload):
    token = jwt.encode(payload, secret_key, algorithm="HS256")
    return token

def get_posts():
    posts = {}

    id = 0;

    for file in glob("../blog_entries/**.md"):

        filename = "../html_files/" + file.split("/")[2].split(".")[0] + ".html"

        html_file = open(filename).read()

        post = open(file, "r").read()
        metadata = post.split("---")[1]

        metadict = {}
        postdict = {}
        for line in metadata.split("\n"):
            if len(line.split(":")) > 1:
                metadict[line.split(":")[0]] = line.split(":")[1]

        postdict["id"] = str(id)
        postdict["metadata"] = metadict
        postdict["content"] = html_file
        posts[id] = postdict
     
        id += 1

    return posts

if __name__ == "__main__":
    app.run(debug=False)
