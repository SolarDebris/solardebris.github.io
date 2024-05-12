from glob import glob
from flask import Flask
from flask_cors import CORS
import blog


app = Flask(__name__)

#CORS(app, resources="/posts", origins=["localhost:5173", r"localhost:5173/blog/*", "solardebris.xyz/", r"solardebris.xyz/blog/*" ])
CORS(app, methods=["GET"], origins="*", send_wildcard=True)


@app.route("/posts", methods=["GET"])
def posts():
    articles = get_posts()
    return articles

def get_posts():
    posts = {}

    id = 0;

    for file in glob("../blog_entries/**.md"):
        post = open(file, "r").read()
        metadata = post.split("---")[1]

        metadict = {}
        postdict = {}
        for line in metadata.split("\n"):
            if len(line.split(":")) > 1:
                metadict[line.split(":")[0]] = line.split(":")[1]

        postdict["id"] = str(id)
        postdict["metadata"] = metadict
        postdict["content"] = post.split("---")[2]
        posts[id] = postdict
     
        id += 1

    return posts

if __name__ == "__main__":
    app.run(debug=False)
