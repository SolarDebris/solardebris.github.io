from flask import Flask
import glob

app = Flask(__name__)


@app.route("/blog_headers")
def blog_headers():
    articles = []
    return articles

@app.route("/blog_posts")
def blog_posts():
    articles = []
    return articles


if __name__ == "__main__":
    app.run(debug=True)
