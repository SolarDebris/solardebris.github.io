import "/src/index.scss";
import "./article.scss";
import React, { useState, useEffect } from "react";
import ReactMarkdown from "react-markdown";

interface Post {
  id: number;
  title: string;
  category: string;
  date: string;
}

const Article: React.FC<Post> = (props) => {
  const [posts, setPosts] = useState<Post[]>([]);
  const [article, setArticle] = useState<Post | null>(null);

  useEffect(() => {
    fetch("http://localhost:5000/posts", {
      method: "GET",
      headers: {
        "Content-Type": "application/json",
      },
    })
      .then((response) => response.json())
      .then((response) => setPosts(response))
      .catch((error) => console.log(error));
  }, []);

  const articles = Object.values(posts);

  useEffect(() => { if (articles.length > 0) {
      const selectedArticle = articles.find((post) => post.id === props.id);
      console.log("Selected Article");
      console.log(selectedArticle);
      console.log("--------");
      setArticle(selectedArticle);
    }
  }, [articles, props.id]);

  if (!article) {
    console.log("Couldn't find article");
    return <div>Loading...</div>;
  }

  const post = Object.values(article);

  if (post.length <= 0) {
    console.log("Post is empty");
    return <div>Loading...</div>;
  }

  console.log("Post");
  console.log(post);
  console.log("+++++");

  return (
    <div className="flex justify-center p-10">
      <div className="pt-14 p-10 bg-dr-current_line/40 w-1/2 h-full rounded-lg">
        <h2 className="text-dr-orange font-bold text-4xl flex justify-center text-center">
          {post[2].category} - {post[2].title}
        </h2>

        <h6 className="text-dr-purple py-1 flex justify-center">
          By SolarDebris
        </h6>
        <h6 className="text-dr-foreground py-1 pb-7 flex justify-center">
          {post[2].date}
        </h6>
        <ReactMarkdown>{post[0]}</ReactMarkdown>
      </div>
    </div>
  );
};

export default Article;
