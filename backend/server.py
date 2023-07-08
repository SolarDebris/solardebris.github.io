from flask import Flask
from flask_cors import CORS
import blog

app = Flask(__name__)
CORS(app)

CORS(app, origins=['localhost:5173'], allow_headers=['Content-Type'], supports_credentials=True)

@app.route("/posts", methods=["GET"])
def posts():
    articles = blog.get_posts()
    return articles


if __name__ == "__main__":
    app.run(debug=False)
