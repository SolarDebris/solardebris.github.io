import "/src/index.scss";
import "./article.scss";
import React, { useState, useEffect } from "react";
import ReactMarkdown from "react-markdown";

import { Paper, Chip, Stack } from "@mui/material";

const Article = (props) => {
  const [posts, setPosts] = useState([]);
  const [article, setArticle] = useState([]);

  useEffect(() => {
    fetch("http://localhost:5000/posts", {
      methods: "GET",
      headers: {
        "Content-Type": "application/json",
      },
    })
      .then((response) => response.json())
      .then((response) => setPosts(response))
      .catch((error) => console.log(error));
  }, []);

  const articles = Object.values(posts);

  useEffect(() => {
    if (articles.length > 0) {
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
    <div class="flex justify-center p-10">
      <div class="pt-14 p-10 bg-dr-current_line/40 w-1/2 h-full rounded-lg">
        <h2 class="text-dr-orange font-bold text-4xl flex justify-center text-center">
          {post[2].category} - {post[2].title}
        </h2>

        <h6 class="text-dr-purple py-1 flex justify-center">By SolarDebris</h6>
        <h6 class="text-dr-foreground py-1 pb-7 flex justify-center">
          {post[2].date}
        </h6>
        <ReactMarkdown>{post[0]}</ReactMarkdown>
      </div>
    </div>
  );
};

export default Article;
