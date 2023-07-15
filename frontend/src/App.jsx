import "./index.scss";
import { Routes, Route } from "react-router-dom";
import Navbar from "./components/Navbar";
import Home from "./components/Home";
import Contact from "./components/Contact";
import Blog from "./components/Blog";
import Article from "./components/Article";
import React, { useEffect, useState } from "react";

function App() {
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
  console.log(articles);

  return (
    <>
      <Routes>
        <Route path="/" element={<Home />} />
        <Route path="/blog" element={<Blog />} />
        {articles.map((post) => (
          <Route path={"/blog/" + post.id} element={<Article id={post.id} />} />
        ))}
        <Route path="/contact" element={<Contact />} />
      </Routes>
    </>
  );
}

export default App;
