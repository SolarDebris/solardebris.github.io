import "./index.scss";
import Navbar from "../Navbar";
import ArticleBox from "../ArticleBox";
import React, { useEffect, useState } from "react";
import { Paper, Box, Stack, CssBaseline, Container } from "@mui/material";

const Blog = () => {
  const [posts, setPosts] = useState([]);

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

  console.log("Posts: " + articles);

  return (
    <div class="flex justify-center pt-10 pb-10">
      <div class="pt-14 bg-dr-current_line/40 w-3/5 h-full rounded-lg">
        <div class="text-5xl text-dr-red font-bold p-10 pb-5 flex justify-center">
          <h1>Blog</h1>
        </div>
        <Box
          sx={{
            p: 2,
            "& > :not(style)": {
              m: 5,
              p: 3,
              justify: "center",
              width: "90%",
              height: "100%",
              background: "#44475a",
            },
          }}
        >
          {articles.map((post, index) => (
            <ArticleBox
              category={post.metadata.category}
              title={post.metadata.title}
              date={post.metadata.date}
              description={post.metadata.description}
              id={index}
            />
          ))}
        </Box>
      </div>
    </div>
  );
};

//       {articles.map((article, index) => (
//          <ArticleBox key={index} {...article} />
//       ))}

export default Blog;
