from glob import glob


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
    get_posts()
